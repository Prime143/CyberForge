/**
 * CyberForge Primary Governance & Candidate Activity Tracking Server
 *
 * DevSecOps Hardened Core:
 * - Express HTTP runtime with strict CORS & JSON limits
 * - Parameterized SQLite database integration (Zero SQLi)
 * - Anti-tampering heartbeat & session telemetry
 * - Real-time Discord alerts for candidate lifecycle and task milestones
 * - Automated 60-second governance sweeper
 */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const { db, run, get, all, logAudit, createNotification } = require('./database');
const { sendAlert } = require('./notifier');
const { requireAdmin, requireCandidate } = require('./middleware/auth');
const { startSweeper, runGovernanceSweep } = require('./services/sweeper');
const { seedInitialCandidates } = require('./services/seeder');

const app = express();
const PORT = process.env.PORT || 4000;

// ============================================================================
// Security & Ingress Middlewares
// ============================================================================
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-key']
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Request Telemetry & Audit Logger
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (res.statusCode >= 400) {
      console.warn(`[WARN] [HTTP] ${req.method} ${req.originalUrl} ${res.statusCode} (${duration}ms)`);
    }
  });
  next();
});

// ============================================================================
// Health & System Readiness
// ============================================================================
app.get('/api/health', async (req, res) => {
  try {
    const activeCandidates = await get('SELECT COUNT(*) AS online_count FROM candidates WHERE is_online = 1');
    const openTasks = await get("SELECT COUNT(*) AS open_count FROM tasks WHERE status IN ('pending', 'in_progress')");

    res.json({
      status: 'UP',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      governance: {
        online_candidates: activeCandidates ? activeCandidates.online_count : 0,
        open_tasks: openTasks ? openTasks.open_count : 0
      }
    });
  } catch (err) {
    res.status(503).json({ status: 'DOWN', error: err.message });
  }
});

// ============================================================================
// Candidate Registration & Management (Admin Only)
// ============================================================================

/**
 * POST /api/admin/candidates
 * Provision a new candidate with an auto-generated cryptographically secure token.
 */
app.post('/api/admin/candidates', requireAdmin, async (req, res) => {
  try {
    const { name, role } = req.body;

    if (!name || typeof name !== 'string' || !name.trim()) {
      return res.status(400).json({ error: 'Validation Error', message: 'Candidate name is required.' });
    }

    // Support standard company hierarchy positions & custom company roles
    const candidateRole = (role && typeof role === 'string' && role.trim())
      ? role.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '_').substring(0, 50)
      : 'junior';

    // Cryptographically secure 32-character random hex token
    const token = crypto.randomBytes(16).toString('hex');

    const result = await run(
      'INSERT INTO candidates (name, role, access_token, is_online) VALUES (?, ?, ?, 0)',
      [name.trim(), candidateRole, token]
    );

    await logAudit(result.lastID, 'ADMIN_CANDIDATE_CREATED', {
      adminAction: 'create',
      candidateName: name.trim(),
      role: candidateRole
    });

    const newCandidate = await get(
      'SELECT id, name, role, access_token, is_online, created_at FROM candidates WHERE id = ?',
      [result.lastID]
    );

    res.status(201).json({
      message: 'Candidate provisioned successfully.',
      candidate: newCandidate
    });
  } catch (err) {
    console.error('[ERROR] [Admin::CreateCandidate]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * PATCH /api/admin/candidates/:id/role (Admin Only)
 * Promotes or updates the role/position of an existing candidate.
 */
app.patch('/api/admin/candidates/:id/role', requireAdmin, async (req, res) => {
  try {
    const candidateId = req.params.id;
    const { role, reason } = req.body;

    if (!role || typeof role !== 'string' || !role.trim()) {
      return res.status(400).json({ error: 'Validation Error', message: 'Target role or position is required.' });
    }

    const candidate = await get('SELECT * FROM candidates WHERE id = ?', [candidateId]);
    if (!candidate) {
      return res.status(404).json({ error: 'Not Found', message: `Candidate ID ${candidateId} not found.` });
    }

    const newRole = role.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '_').substring(0, 50);
    const oldRole = candidate.role;

    if (newRole === oldRole) {
      return res.status(400).json({ error: 'Validation Error', message: `Candidate is already in the '${oldRole}' position.` });
    }

    await run('UPDATE candidates SET role = ? WHERE id = ?', [newRole, candidateId]);

    const readableNewRole = newRole.toUpperCase().replace(/_/g, ' ');
    const readableOldRole = oldRole.toUpperCase().replace(/_/g, ' ');

    // Send promotion notification directly to candidate's workstation hub
    await run(
      'INSERT INTO notifications (candidate_id, title, message, type) VALUES (?, ?, ?, ?)',
      [
        candidateId,
        '🎖️ Official Promotion & Position Advancement',
        `You have been promoted from ${readableOldRole} to ${readableNewRole}.${reason ? ` Commendation Notes: ${reason}` : ''}`,
        'success'
      ]
    );

    // Record immutable audit event
    await logAudit(candidateId, 'CANDIDATE_PROMOTED', {
      candidateId,
      name: candidate.name,
      oldRole,
      newRole,
      reason: reason || 'Executive promotion authorized by Lead Administrator'
    });

    const updatedCandidate = await get('SELECT id, name, role, access_token, is_online FROM candidates WHERE id = ?', [candidateId]);

    res.json({
      message: `Candidate ${candidate.name} promoted successfully to ${readableNewRole}.`,
      candidate: updatedCandidate
    });
  } catch (err) {
    console.error('[ERROR] [Admin::PromoteCandidate]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * DELETE /api/admin/candidates/:id (Admin Only)
 * Deletes a candidate and safely unassigns their tasks.
 */
app.delete('/api/admin/candidates/:id', requireAdmin, async (req, res) => {
  try {
    const candidateId = req.params.id;
    const candidate = await get('SELECT * FROM candidates WHERE id = ?', [candidateId]);
    if (!candidate) {
      return res.status(404).json({ error: 'Not Found', message: `Candidate ID ${candidateId} not found.` });
    }

    // 1. Unassign tasks assigned to this candidate
    await run('UPDATE tasks SET assigned_to = NULL WHERE assigned_to = ?', [candidateId]);

    // 2. Delete candidate (cascades delete activity_logs, work_logs, tickets, notifications)
    await run('DELETE FROM candidates WHERE id = ?', [candidateId]);

    // 3. Record audit trail
    await logAudit(null, 'ADMIN_CANDIDATE_DELETED', {
      deletedCandidateId: candidate.id,
      name: candidate.name,
      role: candidate.role
    });

    res.json({
      message: `Candidate #${candidate.id} (${candidate.name}) deleted successfully.`,
      deleted_id: candidate.id
    });
  } catch (err) {
    console.error('[ERROR] [Admin::DeleteCandidate]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * GET /api/admin/candidates
 * Lists all registered candidates with real-time presence, granular telemetry
 * (workstation focus vs external task work vs idle time), active task, and recent logs.
 */
app.get('/api/admin/candidates', requireAdmin, async (req, res) => {
  try {
    const candidates = await all(`
      SELECT 
        c.id,
        c.name,
        c.role,
        c.access_token,
        c.is_online,
        c.created_at,
        COALESCE(SUM(al.active_seconds), 0) AS total_active_seconds,
        ROUND(COALESCE(SUM(al.active_seconds), 0) / 60.0, 2) AS total_active_minutes,
        ROUND(COALESCE(SUM(al.active_seconds), 0) / 3600.0, 2) AS total_active_hours,
        COALESCE(SUM(al.workstation_seconds), 0) AS workstation_seconds,
        COALESCE(SUM(al.external_work_seconds), 0) AS external_work_seconds,
        COALESCE(SUM(al.idle_seconds), 0) AS idle_seconds,
        COALESCE(SUM(al.total_interactions), 0) AS total_interactions,
        (SELECT COUNT(*) FROM tasks t WHERE t.assigned_to = c.id) AS assigned_tasks_count,
        (SELECT COUNT(*) FROM tasks t WHERE t.assigned_to = c.id AND t.status = 'completed') AS completed_tasks_count,
        ROUND((SELECT AVG(score) FROM tasks WHERE assigned_to = c.id AND status = 'completed' AND score IS NOT NULL), 1) AS avg_score,
        (SELECT t.title FROM activity_logs al_cur 
         LEFT JOIN tasks t ON al_cur.active_task_id = t.id 
         WHERE al_cur.candidate_id = c.id AND al_cur.status = 'active' 
         ORDER BY al_cur.id DESC LIMIT 1) AS active_task_title,
        (SELECT al_cur.active_task_id FROM activity_logs al_cur 
         WHERE al_cur.candidate_id = c.id AND al_cur.status = 'active' 
         ORDER BY al_cur.id DESC LIMIT 1) AS active_task_id,
        (SELECT wl.message FROM work_logs wl 
         WHERE wl.candidate_id = c.id 
         ORDER BY wl.id DESC LIMIT 1) AS latest_work_log,
        (SELECT wl.created_at FROM work_logs wl 
         WHERE wl.candidate_id = c.id 
         ORDER BY wl.id DESC LIMIT 1) AS latest_work_log_time
      FROM candidates c
      LEFT JOIN activity_logs al ON c.id = al.candidate_id
      GROUP BY c.id
      ORDER BY c.id ASC;
    `);

    // Enhance with computed focus score percentage and grade
    const enriched = candidates.map(cand => {
      const active = cand.total_active_seconds || 0;
      const idle = cand.idle_seconds || 0;
      const totalSession = active + idle;
      const focusScore = totalSession > 0 ? Math.round((active / totalSession) * 100) : (cand.is_online ? 100 : 0);
      let grade = 'N/A';
      if (cand.avg_score !== null) {
        if (cand.avg_score >= 90) grade = 'A+';
        else if (cand.avg_score >= 80) grade = 'A';
        else if (cand.avg_score >= 70) grade = 'B';
        else if (cand.avg_score >= 60) grade = 'C';
        else grade = 'F';
      }
      return {
        ...cand,
        focus_score: focusScore,
        overall_grade: grade
      };
    });

    res.json({
      total: enriched.length,
      candidates: enriched
    });
  } catch (err) {
    console.error('[ERROR] [Admin::ListCandidates]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

// ============================================================================
// Session & Telemetry Engine (Candidate APIs with External Tab Tracking)
// ============================================================================

/**
 * POST /api/session/login
 * Starts a new tracked workstation session for the authenticated candidate.
 */
app.post('/api/session/login', requireCandidate, async (req, res) => {
  try {
    const candidate = req.candidate;

    // 1. Mark candidate as online
    await run('UPDATE candidates SET is_online = 1 WHERE id = ?', [candidate.id]);

    // 2. Close previous open/dangling sessions for this candidate
    await run(
      "UPDATE activity_logs SET status = 'closed' WHERE candidate_id = ? AND status IN ('active', 'idle')",
      [candidate.id]
    );

    // 3. Create fresh active activity_log entry
    const sessionRes = await run(`
      INSERT INTO activity_logs (candidate_id, session_start, last_heartbeat, active_seconds, workstation_seconds, external_work_seconds, idle_seconds, status)
      VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0, 0, 0, 0, 'active')
    `, [candidate.id]);

    // 4. Record audit log
    await logAudit(candidate.id, 'CANDIDATE_SESSION_LOGIN', {
      sessionId: sessionRes.lastID,
      ip: req.ip
    });

    // 5. Send real-time Discord lead notification
    await sendAlert(
      'Workstation Session Started',
      `**${candidate.name}** logged into CyberForge Workstation`,
      'success',
      [
        { name: 'Candidate', value: candidate.name, inline: true },
        { name: 'Role', value: candidate.role.toUpperCase(), inline: true },
        { name: 'Session ID', value: String(sessionRes.lastID), inline: true }
      ]
    );

    res.status(200).json({
      message: 'Workstation session initialized.',
      session_id: sessionRes.lastID,
      candidate: {
        id: candidate.id,
        name: candidate.name,
        role: candidate.role,
        is_online: 1
      }
    });
  } catch (err) {
    console.error('[ERROR] [Session::Login]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * POST /api/session/heartbeat
 * Heartbeat telemetry ping with external tab tracking and anti-tampering guards.
 * Distinguishes between:
 * 1. Direct CyberForge Workstation focus (is_tab_focused = true)
 * 2. External task work (is_tab_focused = false + active_task_id set: working on GitHub/Docs/IDE on assigned task)
 * 3. Background idle (is_tab_focused = false + no active task)
 */
app.post('/api/session/heartbeat', requireCandidate, async (req, res) => {
  try {
    const candidate = req.candidate;
    const isTabFocused = req.body?.is_tab_focused !== false;
    const overrideTaskId = req.body?.active_task_id ? parseInt(req.body.active_task_id, 10) : null;
    const interactions = Math.min(Math.max(0, parseInt(req.body?.interactions || 0, 10)), 1000);

    // Retrieve candidate's currently active session with delta calculated in SQLite
    const activeSession = await get(`
      SELECT 
        id,
        candidate_id,
        active_seconds,
        COALESCE(workstation_seconds, 0) AS workstation_seconds,
        COALESCE(external_work_seconds, 0) AS external_work_seconds,
        COALESCE(idle_seconds, 0) AS idle_seconds,
        COALESCE(total_interactions, 0) AS total_interactions,
        active_task_id,
        last_heartbeat,
        CAST(strftime('%s', 'now') - strftime('%s', last_heartbeat) AS INTEGER) AS delta_seconds
      FROM activity_logs 
      WHERE candidate_id = ? AND status = 'active'
      ORDER BY id DESC
      LIMIT 1
    `, [candidate.id]);

    if (!activeSession) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No active session found. Please initialize session via POST /api/session/login.'
      });
    }

    const delta = Math.max(0, activeSession.delta_seconds || 0);

    // Anti-tampering rule: If elapsed delta exceeds 180 seconds, transition session to idle
    if (delta > 180) {
      await run("UPDATE activity_logs SET status = 'idle' WHERE id = ?", [activeSession.id]);
      await run('UPDATE candidates SET is_online = 0 WHERE id = ?', [candidate.id]);

      await logAudit(candidate.id, 'HEARTBEAT_EXCEEDED_IDLE', {
        sessionId: activeSession.id,
        deltaSeconds: delta
      });

      await sendAlert(
        'Candidate Idle Alert',
        `**${candidate.name}** went idle / disconnected (Heartbeat gap: ${delta}s)`,
        'warning',
        [
          { name: 'Candidate', value: candidate.name, inline: true },
          { name: 'Status', value: 'idle', inline: true },
          { name: 'Delta', value: `${delta}s`, inline: true }
        ]
      );

      return res.status(200).json({
        status: 'idle',
        message: 'Heartbeat delta exceeded 180s threshold. Session transitioned to idle.',
        active_seconds: activeSession.active_seconds
      });
    }

    // Telemetry classification:
    const currentTaskId = overrideTaskId || activeSession.active_task_id;
    let newWorkstation = activeSession.workstation_seconds;
    let newExternal = activeSession.external_work_seconds;
    let newIdle = activeSession.idle_seconds;
    let newActive = activeSession.active_seconds;

    if (currentTaskId) {
      // Candidate is clocked into an active deliverable!
      if (isTabFocused) {
        newWorkstation += delta;
        newActive += delta;
      } else {
        // Fairly tracked: Candidate is working on another tab/IDE/terminal on their assigned deliverable!
        newExternal += delta;
        newActive += delta;
      }
    } else {
      // Candidate is NOT clocked into any deliverable
      if (isTabFocused) {
        newWorkstation += delta;
        newActive += delta;
      } else {
        // Tab is backgrounded with NO task clocked in -> Classified as Idle / Off-Task!
        newIdle += delta;
      }
    }

    const updatedInteractions = activeSession.total_interactions + interactions;

    await run(`
      UPDATE activity_logs 
      SET active_seconds = ?, 
          workstation_seconds = ?,
          external_work_seconds = ?,
          idle_seconds = ?,
          total_interactions = ?,
          last_heartbeat = CURRENT_TIMESTAMP, 
          status = 'active' 
      WHERE id = ?
    `, [newActive, newWorkstation, newExternal, newIdle, updatedInteractions, activeSession.id]);

    await run('UPDATE candidates SET is_online = 1 WHERE id = ?', [candidate.id]);

    res.status(200).json({
      status: 'acknowledged',
      active_seconds: newActive,
      workstation_seconds: newWorkstation,
      external_work_seconds: newExternal,
      idle_seconds: newIdle,
      active_task_id: currentTaskId,
      mode: currentTaskId ? (isTabFocused ? 'workstation_active' : 'external_task_active') : (isTabFocused ? 'browsing' : 'unassigned_idle')
    });
  } catch (err) {
    console.error('[ERROR] [Session::Heartbeat]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * POST /api/session/logout
 * Closes active session, sets candidate offline, and records audit.
 */
app.post('/api/session/logout', requireCandidate, async (req, res) => {
  try {
    const candidate = req.candidate;

    await run('UPDATE candidates SET is_online = 0 WHERE id = ?', [candidate.id]);
    await run(
      "UPDATE activity_logs SET status = 'closed', last_heartbeat = CURRENT_TIMESTAMP WHERE candidate_id = ? AND status IN ('active', 'idle')",
      [candidate.id]
    );

    await logAudit(candidate.id, 'CANDIDATE_LOGOUT', { ip: req.ip });

    await sendAlert(
      'Workstation Session Ended',
      `**${candidate.name}** logged out of CyberForge Workstation`,
      'info',
      [
        { name: 'Candidate', value: candidate.name, inline: true },
        { name: 'Status', value: 'offline', inline: true }
      ]
    );

    res.status(200).json({
      message: 'Workstation session successfully closed.'
    });
  } catch (err) {
    console.error('[ERROR] [Session::Logout]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

// ============================================================================
// Task Lifecycle Governance
// ============================================================================

/**
 * POST /api/tasks (Admin Only)
 * Creates and assigns a new task with a strict governance deadline.
 */
app.post('/api/tasks', requireAdmin, async (req, res) => {
  try {
    const { title, description, assigned_to, deadline, priority } = req.body;

    if (!title || typeof title !== 'string' || !title.trim()) {
      return res.status(400).json({ error: 'Validation Error', message: 'Task title is required.' });
    }

    if (!deadline || isNaN(Date.parse(deadline))) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Valid deadline (ISO format or parseable date string) is required.'
      });
    }

    const taskPriority = ['critical', 'high', 'medium', 'low'].includes(priority) ? priority : 'medium';

    let candidate = null;
    if (assigned_to) {
      candidate = await get('SELECT id, name, role FROM candidates WHERE id = ?', [assigned_to]);
      if (!candidate) {
        return res.status(404).json({ error: 'Not Found', message: `Candidate ID ${assigned_to} does not exist.` });
      }
    }

    const result = await run(`
      INSERT INTO tasks (title, description, assigned_to, deadline, status, priority)
      VALUES (?, ?, ?, ?, 'pending', ?)
    `, [title.trim(), description ? description.trim() : null, assigned_to || null, deadline, taskPriority]);

    await logAudit(assigned_to || null, 'ADMIN_TASK_CREATED', {
      taskId: result.lastID,
      title: title.trim(),
      deadline,
      priority: taskPriority
    });

    // In-app notification for candidate
    if (assigned_to) {
      await createNotification(
        assigned_to,
        'New Governance Task Assigned',
        `Task "${title.trim()}" has been assigned to you. Deadline: ${new Date(deadline).toLocaleString()}`,
        taskPriority === 'critical' ? 'urgent' : 'info'
      );
    }

    // Alert lead channel via Discord (if enabled)
    const candidateLabel = candidate ? candidate.name : 'Unassigned';
    await sendAlert(
      'New Governance Task Assigned',
      `New Task Assigned to **${candidateLabel}**: **${title.trim()}** (Priority: ${taskPriority.toUpperCase()}, Deadline: ${deadline})`,
      taskPriority === 'critical' ? 'danger' : 'warning',
      [
        { name: 'Task ID', value: String(result.lastID), inline: true },
        { name: 'Assigned To', value: candidateLabel, inline: true },
        { name: 'Priority', value: taskPriority.toUpperCase(), inline: true },
        { name: 'Deadline', value: String(deadline), inline: true }
      ]
    );

    const createdTask = await get('SELECT * FROM tasks WHERE id = ?', [result.lastID]);
    res.status(201).json({
      message: 'Task assigned successfully.',
      task: createdTask
    });
  } catch (err) {
    console.error('[ERROR] [Tasks::Create]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * DELETE /api/tasks/:id (Admin Only)
 * Deletes obsolete or unneeded task and unbinds active tracking sessions.
 */
app.delete('/api/tasks/:id', requireAdmin, async (req, res) => {
  try {
    const taskId = req.params.id;
    const task = await get('SELECT * FROM tasks WHERE id = ?', [taskId]);
    if (!task) {
      return res.status(404).json({ error: 'Not Found', message: `Task ID ${taskId} not found.` });
    }

    // Clear active_task_id in activity_logs if any candidate is currently clocked in
    await run('UPDATE activity_logs SET active_task_id = NULL WHERE active_task_id = ?', [taskId]);

    // Unlink task_id in work_logs
    await run('UPDATE work_logs SET task_id = NULL WHERE task_id = ?', [taskId]);

    // Delete the task
    await run('DELETE FROM tasks WHERE id = ?', [taskId]);

    await logAudit(task.assigned_to, 'ADMIN_TASK_DELETED', {
      taskId: task.id,
      title: task.title
    });

    res.json({
      message: `Deliverable #${task.id} ("${task.title}") deleted successfully.`,
      deleted_id: task.id
    });
  } catch (err) {
    console.error('[ERROR] [Tasks::Delete]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * GET /api/candidate/tasks (Candidate Auth)
 * Returns all governance tasks assigned to the authenticated candidate with computed is_overdue.
 */
app.get('/api/candidate/tasks', requireCandidate, async (req, res) => {
  try {
    const candidate = req.candidate;

    const tasks = await all(
      'SELECT * FROM tasks WHERE assigned_to = ? ORDER BY deadline ASC',
      [candidate.id]
    );

    const now = new Date();
    const enrichedTasks = tasks.map(t => {
      const isOverdue = t.status !== 'completed' && new Date(t.deadline) < now;
      return {
        ...t,
        is_overdue: isOverdue
      };
    });

    res.json({
      total: enrichedTasks.length,
      candidate: { id: candidate.id, name: candidate.name },
      tasks: enrichedTasks
    });
  } catch (err) {
    console.error('[ERROR] [Candidate::Tasks]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * POST /api/tasks/:id/submit (Candidate Auth)
 * Submits work artifact URL for review with automated anti-plagiarism duplicate detection.
 */
app.post('/api/tasks/:id/submit', requireCandidate, async (req, res) => {
  try {
    const taskId = req.params.id;
    const { submission_url, notes } = req.body;
    const candidate = req.candidate;

    if (!submission_url || typeof submission_url !== 'string') {
      return res.status(400).json({ error: 'Validation Error', message: 'submission_url string is required.' });
    }

    const trimmedUrl = submission_url.trim();

    const task = await get('SELECT * FROM tasks WHERE id = ?', [taskId]);

    if (!task) {
      return res.status(404).json({ error: 'Not Found', message: 'Task not found.' });
    }

    if (task.assigned_to !== candidate.id) {
      return res.status(403).json({ error: 'Forbidden', message: 'You are not assigned to this task.' });
    }

    // Plagiarism Guard: Prevent two candidates from submitting the same GitHub / repository URL
    const duplicate = await get(
      "SELECT id, assigned_to, title FROM tasks WHERE LOWER(TRIM(submission_url)) = LOWER(?) AND id != ? AND status IN ('submitted', 'completed')",
      [trimmedUrl, taskId]
    );

    if (duplicate && duplicate.assigned_to !== candidate.id) {
      return res.status(400).json({
        error: 'Duplicate Artifact Rejected',
        message: `Plagiarism Guard: This repository/PR artifact URL has already been submitted for deliverable #${duplicate.id} ("${duplicate.title}"). Duplicate submissions are rejected.`
      });
    }

    await run(`
      UPDATE tasks 
      SET submission_url = ?, status = 'submitted' 
      WHERE id = ?
    `, [trimmedUrl, taskId]);

    await logAudit(candidate.id, 'TASK_SUBMITTED_FOR_REVIEW', {
      taskId,
      title: task.title,
      submission_url: trimmedUrl,
      notes: notes || null
    });

    await sendAlert(
      'Task Submitted for Review',
      `Task Submitted for Review: **${task.title}** by **${candidate.name}**`,
      'info',
      [
        { name: 'Task ID', value: String(taskId), inline: true },
        { name: 'Candidate', value: candidate.name, inline: true },
        { name: 'Artifact URL', value: trimmedUrl, inline: false },
        { name: 'Notes', value: notes || 'None provided', inline: false }
      ]
    );

    const updatedTask = await get('SELECT * FROM tasks WHERE id = ?', [taskId]);
    res.json({
      message: 'Task submitted for lead review.',
      task: updatedTask
    });
  } catch (err) {
    console.error('[ERROR] [Tasks::Submit]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * PATCH /api/tasks/:id/review (Admin Only)
 * Review submitted task with multi-criteria rubric evaluation and 0-100 scoring.
 */
app.patch('/api/tasks/:id/review', requireAdmin, async (req, res) => {
  try {
    const taskId = req.params.id;
    const { status, feedback, score, rubric } = req.body;

    if (!['completed', 'in_progress'].includes(status)) {
      return res.status(400).json({
        error: 'Validation Error',
        message: "Status must be either 'completed' or 'in_progress'."
      });
    }

    const task = await get(`
      SELECT t.*, c.name AS candidate_name 
      FROM tasks t 
      LEFT JOIN candidates c ON t.assigned_to = c.id 
      WHERE t.id = ?
    `, [taskId]);

    if (!task) {
      return res.status(404).json({ error: 'Not Found', message: 'Task not found.' });
    }

    let finalScore = null;
    let finalGrade = null;
    let rubricStr = null;

    if (status === 'completed') {
      if (score !== undefined && score !== null && !isNaN(parseInt(score, 10))) {
        finalScore = Math.max(0, Math.min(100, parseInt(score, 10)));
        if (finalScore >= 90) finalGrade = 'A+';
        else if (finalScore >= 80) finalGrade = 'A';
        else if (finalScore >= 70) finalGrade = 'B';
        else if (finalScore >= 60) finalGrade = 'C';
        else finalGrade = 'F';
      }
      if (rubric && typeof rubric === 'object') {
        rubricStr = JSON.stringify(rubric);
      } else if (typeof rubric === 'string') {
        rubricStr = rubric;
      }
    }

    await run(`
      UPDATE tasks 
      SET status = ?, 
          score = ?, 
          grade = ?, 
          rubric_breakdown = ?, 
          review_feedback = ? 
      WHERE id = ?
    `, [status, finalScore, finalGrade, rubricStr, feedback || null, taskId]);

    await logAudit(task.assigned_to, 'TASK_REVIEW_DECISION', {
      taskId,
      status,
      score: finalScore,
      grade: finalGrade,
      feedback: feedback || null
    });

    const isCompleted = status === 'completed';

    // In-app notification for candidate with evaluation scorecard
    if (task.assigned_to) {
      const gradeText = finalGrade ? ` · Grade: ${finalGrade} (${finalScore}/100)` : '';
      await createNotification(
        task.assigned_to,
        isCompleted ? 'Deliverable Evaluated & Approved' : 'Task Revision Requested',
        `Task "${task.title}" updated to ${status.toUpperCase()}${gradeText}. Remarks: ${feedback || 'No remarks provided.'}`,
        isCompleted ? 'success' : 'warning'
      );
    }

    const alertTitle = isCompleted ? 'Task Review: Completed / Approved' : 'Task Review: Needs Revision';
    const alertColor = isCompleted ? 'success' : 'danger';

    await sendAlert(
      alertTitle,
      `Task **"${task.title}"** assigned to **${task.candidate_name || 'Unassigned'}** was updated to **${status.toUpperCase()}**${finalGrade ? ` (Score: ${finalScore}/100, Grade: ${finalGrade})` : ''}.`,
      alertColor,
      [
        { name: 'Task ID', value: String(taskId), inline: true },
        { name: 'Status', value: status.toUpperCase(), inline: true },
        { name: 'Score / Grade', value: finalScore !== null ? `${finalScore}/100 (${finalGrade})` : 'Unscored', inline: true },
        { name: 'Lead Feedback', value: feedback || 'No additional remarks.', inline: false }
      ]
    );

    const updatedTask = await get('SELECT * FROM tasks WHERE id = ?', [taskId]);
    res.json({
      message: `Task status updated to ${status}.`,
      task: updatedTask
    });
  } catch (err) {
    console.error('[ERROR] [Tasks::Review]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * GET /api/candidate/scorecard (Candidate Auth)
 * Returns the candidate's personal performance scorecard, cumulative GPA, and rubric ratings.
 */
app.get('/api/candidate/scorecard', requireCandidate, async (req, res) => {
  try {
    const candidate = req.candidate;

    const evaluatedTasks = await all(`
      SELECT id, title, description, deadline, status, score, grade, rubric_breakdown, review_feedback, created_at
      FROM tasks 
      WHERE assigned_to = ? AND status = 'completed' AND score IS NOT NULL
      ORDER BY id DESC
    `, [candidate.id]);

    const stats = await get(`
      SELECT 
        COUNT(*) AS total_tasks,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed_tasks,
        SUM(CASE WHEN status = 'submitted' THEN 1 ELSE 0 END) AS submitted_tasks,
        ROUND(AVG(score), 1) AS avg_score
      FROM tasks 
      WHERE assigned_to = ?
    `, [candidate.id]);

    const avgScore = stats.avg_score || 0;
    let overallGrade = 'N/A';
    if (evaluatedTasks.length > 0) {
      if (avgScore >= 90) overallGrade = 'A+';
      else if (avgScore >= 80) overallGrade = 'A';
      else if (avgScore >= 70) overallGrade = 'B';
      else if (avgScore >= 60) overallGrade = 'C';
      else overallGrade = 'F';
    }

    res.json({
      candidate: { id: candidate.id, name: candidate.name, role: candidate.role },
      total_assigned: stats.total_tasks || 0,
      completed_count: stats.completed_tasks || 0,
      submitted_count: stats.submitted_tasks || 0,
      cumulative_score: avgScore,
      overall_grade: overallGrade,
      evaluated_tasks: evaluatedTasks
    });
  } catch (err) {
    console.error('[ERROR] [Candidate::Scorecard]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * GET /api/admin/export/candidates-csv (Admin Only)
 * Generates and streams an executive CSV report of candidate performance, telemetry, and scores.
 */
app.get('/api/admin/export/candidates-csv', requireAdmin, async (req, res) => {
  try {
    const candidates = await all(`
      SELECT 
        c.id,
        c.name,
        c.role,
        c.access_token,
        c.is_online,
        c.created_at,
        COALESCE(SUM(al.active_seconds), 0) AS total_active_seconds,
        COALESCE(SUM(al.workstation_seconds), 0) AS workstation_seconds,
        COALESCE(SUM(al.external_work_seconds), 0) AS external_work_seconds,
        COALESCE(SUM(al.idle_seconds), 0) AS idle_seconds,
        (SELECT COUNT(*) FROM tasks t WHERE t.assigned_to = c.id) AS assigned_tasks_count,
        (SELECT COUNT(*) FROM tasks t WHERE t.assigned_to = c.id AND t.status = 'completed') AS completed_tasks_count,
        ROUND((SELECT AVG(score) FROM tasks WHERE assigned_to = c.id AND status = 'completed' AND score IS NOT NULL), 1) AS avg_score
      FROM candidates c
      LEFT JOIN activity_logs al ON c.id = al.candidate_id
      GROUP BY c.id
      ORDER BY c.id ASC;
    `);

    let csv = 'Candidate ID,Name,Position,Status,Total Active Hours,External Work Hours,Workstation Hours,Idle Hours,Focus Rate %,Assigned Tasks,Completed Tasks,Avg Score,Overall Grade,Token,Registered At\r\n';

    for (const c of candidates) {
      const totalSec = (c.total_active_seconds || 0) + (c.idle_seconds || 0);
      const activeHrs = (c.total_active_seconds / 3600).toFixed(2);
      const extHrs = (c.external_work_seconds / 3600).toFixed(2);
      const workHrs = (c.workstation_seconds / 3600).toFixed(2);
      const idleHrs = (c.idle_seconds / 3600).toFixed(2);
      const focusRate = totalSec > 0 ? Math.round((c.total_active_seconds / totalSec) * 100) : (c.is_online ? 100 : 0);
      const score = c.avg_score !== null ? c.avg_score : 'N/A';
      let grade = 'N/A';
      if (c.avg_score !== null) {
        if (c.avg_score >= 90) grade = 'A+';
        else if (c.avg_score >= 80) grade = 'A';
        else if (c.avg_score >= 70) grade = 'B';
        else if (c.avg_score >= 60) grade = 'C';
        else grade = 'F';
      }
      const onlineStatus = c.is_online === 1 ? 'Online' : 'Offline';

      csv += `"${c.id}","${c.name}","${c.role}","${onlineStatus}",${activeHrs},${extHrs},${workHrs},${idleHrs},${focusRate}%,${c.assigned_tasks_count},${c.completed_tasks_count},"${score}","${grade}","${c.access_token}","${c.created_at}"\r\n`;
    }

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="cyberforge_executive_report_${new Date().toISOString().slice(0, 10)}.csv"`);
    res.send(csv);
  } catch (err) {
    console.error('[ERROR] [Admin::ExportCSV]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * GET /api/admin/backup (Admin Only)
 * Creates a point-in-time atomic SQLite database snapshot and streams it to lead.
 */
app.get('/api/admin/backup', requireAdmin, async (req, res) => {
  try {
    const backupDir = path.resolve(process.cwd(), 'backups');
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFilename = `cyberforge-snapshot-${timestamp}.db`;
    const backupPath = path.join(backupDir, backupFilename);

    await run(`VACUUM INTO ?`, [backupPath]);

    await logAudit(null, 'ADMIN_DATABASE_BACKUP_CREATED', {
      filename: backupFilename,
      sizeBytes: fs.statSync(backupPath).size
    });

    res.download(backupPath, backupFilename);
  } catch (err) {
    console.error('[ERROR] [Admin::Backup]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

// ============================================================================
// Deliverable Clock-In & Proof-of-Work Telemetry Engine
// ============================================================================

/**
 * POST /api/candidate/clock-in
 * Candidate clocks into an assigned deliverable.
 * Binds active session to this task and transitions status from 'pending' to 'in_progress'.
 * Accurately credits external tab work to this deliverable when working in IDEs/GitHub/Docs.
 */
app.post('/api/candidate/clock-in', requireCandidate, async (req, res) => {
  try {
    const candidate = req.candidate;
    const { task_id } = req.body;

    if (!task_id) {
      return res.status(400).json({ error: 'Validation Error', message: 'task_id is required to clock in.' });
    }

    const task = await get('SELECT * FROM tasks WHERE id = ?', [task_id]);
    if (!task) {
      return res.status(404).json({ error: 'Not Found', message: `Task ID ${task_id} does not exist.` });
    }

    if (task.assigned_to && task.assigned_to !== candidate.id) {
      return res.status(403).json({ error: 'Forbidden', message: 'This task is assigned to another candidate.' });
    }

    // Retrieve candidate's active session
    const activeSession = await get(`
      SELECT id FROM activity_logs 
      WHERE candidate_id = ? AND status = 'active' 
      ORDER BY id DESC LIMIT 1
    `, [candidate.id]);

    if (!activeSession) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No active session found. Please initialize session via POST /api/session/login.'
      });
    }

    // Update active session with the selected task
    await run('UPDATE activity_logs SET active_task_id = ? WHERE id = ?', [task.id, activeSession.id]);

    // If task was pending, promote it to in_progress
    if (task.status === 'pending') {
      await run("UPDATE tasks SET status = 'in_progress' WHERE id = ?", [task.id]);
    }

    // Insert automatic checkpoint into work_logs
    await run(`
      INSERT INTO work_logs (candidate_id, task_id, log_type, message)
      VALUES (?, ?, 'checkpoint', ?)
    `, [candidate.id, task.id, `Clocked into deliverable: "${task.title}"`]);

    await logAudit(candidate.id, 'CANDIDATE_CLOCK_IN', {
      taskId: task.id,
      title: task.title,
      sessionId: activeSession.id
    });

    res.json({
      message: `Clocked into task: ${task.title}`,
      task_id: task.id,
      task_title: task.title,
      mode: 'clocked_in'
    });
  } catch (err) {
    console.error('[ERROR] [Candidate::ClockIn]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * POST /api/candidate/clock-out
 * Pauses or unbinds the active deliverable from candidate's session.
 */
app.post('/api/candidate/clock-out', requireCandidate, async (req, res) => {
  try {
    const candidate = req.candidate;

    const activeSession = await get(`
      SELECT id, active_task_id FROM activity_logs 
      WHERE candidate_id = ? AND status = 'active' 
      ORDER BY id DESC LIMIT 1
    `, [candidate.id]);

    if (!activeSession) {
      return res.status(400).json({ error: 'Bad Request', message: 'No active session found.' });
    }

    if (activeSession.active_task_id) {
      const prevTask = await get('SELECT title FROM tasks WHERE id = ?', [activeSession.active_task_id]);
      await run(`
        INSERT INTO work_logs (candidate_id, task_id, log_type, message)
        VALUES (?, ?, 'checkpoint', ?)
      `, [candidate.id, activeSession.active_task_id, `Clocked off deliverable: "${prevTask ? prevTask.title : 'Task #' + activeSession.active_task_id}"`]);
    }

    await run('UPDATE activity_logs SET active_task_id = NULL WHERE id = ?', [activeSession.id]);

    await logAudit(candidate.id, 'CANDIDATE_CLOCK_OUT', {
      previousTaskId: activeSession.active_task_id,
      sessionId: activeSession.id
    });

    res.json({
      message: 'Clocked out of deliverable. Workstation switched to stand-by mode.',
      mode: 'standby'
    });
  } catch (err) {
    console.error('[ERROR] [Candidate::ClockOut]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * POST /api/candidate/work-log
 * Candidate submits a real-time proof-of-work progress log, git commit reference, or milestone.
 */
app.post('/api/candidate/work-log', requireCandidate, async (req, res) => {
  try {
    const candidate = req.candidate;
    const { task_id, log_type, message } = req.body;

    if (!message || typeof message !== 'string' || !message.trim()) {
      return res.status(400).json({ error: 'Validation Error', message: 'Work log message is required.' });
    }

    const cleanMessage = message.trim().substring(0, 500);
    const validLogType = ['progress', 'git_commit', 'blocker', 'checkpoint'].includes(log_type) ? log_type : 'progress';
    let validTaskId = null;
    if (task_id) {
      const parsedId = parseInt(task_id, 10);
      const taskCheck = await get('SELECT id FROM tasks WHERE id = ?', [parsedId]);
      if (taskCheck) {
        validTaskId = taskCheck.id;
      }
    }

    const insertResult = await run(`
      INSERT INTO work_logs (candidate_id, task_id, log_type, message)
      VALUES (?, ?, ?, ?)
    `, [candidate.id, validTaskId, validLogType, cleanMessage]);

    // Update latest work log in the active session
    await run(`
      UPDATE activity_logs 
      SET last_work_log = ? 
      WHERE candidate_id = ? AND status = 'active'
    `, [cleanMessage, candidate.id]);

    await logAudit(candidate.id, 'CANDIDATE_WORK_LOG', {
      logId: insertResult.lastID,
      taskId: validTaskId,
      logType: validLogType,
      message: cleanMessage
    });

    res.status(201).json({
      message: 'Work log recorded successfully.',
      log: {
        id: insertResult.lastID,
        candidate_id: candidate.id,
        candidate_name: candidate.name,
        task_id: validTaskId,
        log_type: validLogType,
        message: cleanMessage,
        created_at: new Date().toISOString()
      }
    });
  } catch (err) {
    console.error('[ERROR] [Candidate::WorkLog]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * GET /api/candidate/work-logs
 * Retrieves the candidate's recent proof-of-work history.
 */
app.get('/api/candidate/work-logs', requireCandidate, async (req, res) => {
  try {
    const candidate = req.candidate;
    const logs = await all(`
      SELECT 
        wl.id,
        wl.log_type,
        wl.message,
        wl.created_at,
        t.id AS task_id,
        t.title AS task_title
      FROM work_logs wl
      LEFT JOIN tasks t ON wl.task_id = t.id
      WHERE wl.candidate_id = ?
      ORDER BY wl.id DESC
      LIMIT 30
    `, [candidate.id]);

    res.json({ total: logs.length, logs });
  } catch (err) {
    console.error('[ERROR] [Candidate::GetWorkLogs]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * GET /api/admin/work-stream (Admin Only)
 * Live high-density activity stream of all candidates' work logs, commits, and check-ins.
 */
app.get('/api/admin/work-stream', requireAdmin, async (req, res) => {
  try {
    const stream = await all(`
      SELECT 
        wl.id,
        wl.candidate_id,
        c.name AS candidate_name,
        c.role AS candidate_role,
        wl.task_id,
        t.title AS task_title,
        wl.log_type,
        wl.message,
        wl.created_at
      FROM work_logs wl
      JOIN candidates c ON wl.candidate_id = c.id
      LEFT JOIN tasks t ON wl.task_id = t.id
      ORDER BY wl.id DESC
      LIMIT 50
    `);

    res.json({ total: stream.length, stream });
  } catch (err) {
    console.error('[ERROR] [Admin::WorkStream]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

// ============================================================================
// Support & Incident Desk Governance (Tickets)
// ============================================================================

/**
 * POST /api/candidate/tickets
 * Candidate files a support / incident / blocker ticket.
 */
app.post('/api/candidate/tickets', requireCandidate, async (req, res) => {
  try {
    const { subject, category, priority, description } = req.body;
    const candidate = req.candidate;

    if (!subject || typeof subject !== 'string' || !subject.trim()) {
      return res.status(400).json({ error: 'Validation Error', message: 'Subject is required.' });
    }

    if (!description || typeof description !== 'string' || !description.trim()) {
      return res.status(400).json({ error: 'Validation Error', message: 'Description is required.' });
    }

    const validCategories = ['technical', 'task_blocker', 'access_issue', 'extension_request', 'general'];
    const validPriorities = ['critical', 'high', 'medium', 'low'];

    const cat = validCategories.includes(category) ? category : 'technical';
    const prio = validPriorities.includes(priority) ? priority : 'medium';

    const result = await run(`
      INSERT INTO tickets (candidate_id, subject, category, priority, description, status)
      VALUES (?, ?, ?, ?, ?, 'open')
    `, [candidate.id, subject.trim(), cat, prio, description.trim()]);

    await logAudit(candidate.id, 'SUPPORT_TICKET_RAISED', {
      ticketId: result.lastID,
      subject: subject.trim(),
      category: cat,
      priority: prio
    });

    // In-app acknowledgment notification
    await createNotification(
      candidate.id,
      'Support Ticket Opened',
      `Ticket #${result.lastID} ("${subject.trim()}") received. Lead engineers have been alerted.`,
      'info'
    );

    // Lead alert via Discord (if configured)
    await sendAlert(
      `Support Ticket Raised: #${result.lastID}`,
      `**${candidate.name}** raised a **${prio.toUpperCase()}** ticket: "${subject.trim()}"\n\n${description.trim()}`,
      prio === 'critical' ? 'danger' : 'warning',
      [
        { name: 'Ticket ID', value: String(result.lastID), inline: true },
        { name: 'Candidate', value: candidate.name, inline: true },
        { name: 'Priority', value: prio.toUpperCase(), inline: true },
        { name: 'Category', value: cat, inline: true }
      ]
    );

    const createdTicket = await get('SELECT * FROM tickets WHERE id = ?', [result.lastID]);
    res.status(201).json({
      message: 'Support ticket successfully submitted.',
      ticket: createdTicket
    });
  } catch (err) {
    console.error('[ERROR] [Tickets::Create]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * GET /api/candidate/tickets
 * Candidate retrieves all their submitted tickets.
 */
app.get('/api/candidate/tickets', requireCandidate, async (req, res) => {
  try {
    const tickets = await all(
      'SELECT * FROM tickets WHERE candidate_id = ? ORDER BY id DESC',
      [req.candidate.id]
    );
    res.json({ total: tickets.length, tickets });
  } catch (err) {
    console.error('[ERROR] [Candidate::Tickets]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * GET /api/admin/tickets
 * Lead retrieves all system tickets with candidate details.
 */
app.get('/api/admin/tickets', requireAdmin, async (req, res) => {
  try {
    const tickets = await all(`
      SELECT 
        t.*,
        c.name AS candidate_name,
        c.role AS candidate_role
      FROM tickets t
      JOIN candidates c ON t.candidate_id = c.id
      ORDER BY 
        CASE 
          WHEN t.status = 'open' THEN 1
          WHEN t.status = 'in_progress' THEN 2
          WHEN t.status = 'resolved' THEN 3
          ELSE 4
        END,
        CASE 
          WHEN t.priority = 'critical' THEN 1
          WHEN t.priority = 'high' THEN 2
          WHEN t.priority = 'medium' THEN 3
          ELSE 4
        END,
        t.id DESC;
    `);
    res.json({ total: tickets.length, tickets });
  } catch (err) {
    console.error('[ERROR] [Admin::Tickets]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * PATCH /api/admin/tickets/:id
 * Lead resolves or updates ticket status with remarks.
 */
app.patch('/api/admin/tickets/:id', requireAdmin, async (req, res) => {
  try {
    const ticketId = req.params.id;
    const { status, admin_notes } = req.body;

    const validStatuses = ['open', 'in_progress', 'resolved', 'closed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        error: 'Validation Error',
        message: "Status must be 'open', 'in_progress', 'resolved', or 'closed'."
      });
    }

    const ticket = await get(`
      SELECT t.*, c.name AS candidate_name
      FROM tickets t
      JOIN candidates c ON t.candidate_id = c.id
      WHERE t.id = ?
    `, [ticketId]);

    if (!ticket) {
      return res.status(404).json({ error: 'Not Found', message: 'Ticket not found.' });
    }

    await run(`
      UPDATE tickets 
      SET status = ?, admin_notes = ?, updated_at = CURRENT_TIMESTAMP 
      WHERE id = ?
    `, [status, admin_notes ? admin_notes.trim() : ticket.admin_notes, ticketId]);

    await logAudit(ticket.candidate_id, 'TICKET_STATUS_UPDATED', {
      ticketId,
      newStatus: status,
      remarks: admin_notes || null
    });

    // Notify candidate of resolution/update
    await createNotification(
      ticket.candidate_id,
      `Support Ticket #${ticketId} Updated`,
      `Your ticket "${ticket.subject}" has been marked as ${status.toUpperCase()}.${admin_notes ? ` Remarks: ${admin_notes}` : ''}`,
      status === 'resolved' ? 'success' : 'info'
    );

    const updated = await get('SELECT * FROM tickets WHERE id = ?', [ticketId]);
    res.json({ message: 'Ticket updated successfully.', ticket: updated });
  } catch (err) {
    console.error('[ERROR] [Admin::TicketUpdate]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * DELETE /api/admin/tickets/:id (Admin Only)
 * Deletes resolved or obsolete support ticket.
 */
app.delete('/api/admin/tickets/:id', requireAdmin, async (req, res) => {
  try {
    const ticketId = req.params.id;
    const ticket = await get('SELECT * FROM tickets WHERE id = ?', [ticketId]);
    if (!ticket) {
      return res.status(404).json({ error: 'Not Found', message: `Ticket ID ${ticketId} not found.` });
    }

    await run('DELETE FROM tickets WHERE id = ?', [ticketId]);

    await logAudit(ticket.candidate_id, 'ADMIN_TICKET_DELETED', {
      ticketId: ticket.id,
      subject: ticket.subject
    });

    res.json({
      message: `Support ticket #${ticket.id} deleted successfully.`,
      deleted_id: ticket.id
    });
  } catch (err) {
    console.error('[ERROR] [Admin::DeleteTicket]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

// ============================================================================
// In-App Notification Center
// ============================================================================

/**
 * GET /api/candidate/notifications
 * Retrieves candidate's notifications (personal + global broadcasts).
 */
app.get('/api/candidate/notifications', requireCandidate, async (req, res) => {
  try {
    const notifs = await all(`
      SELECT * FROM notifications 
      WHERE candidate_id = ? OR candidate_id IS NULL 
      ORDER BY id DESC 
      LIMIT 30;
    `, [req.candidate.id]);

    const unreadCount = notifs.filter(n => n.is_read === 0).length;
    res.json({ unread_count: unreadCount, total: notifs.length, notifications: notifs });
  } catch (err) {
    console.error('[ERROR] [Candidate::Notifications]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * POST /api/candidate/notifications/:id/read
 * Marks single notification as read.
 */
app.post('/api/candidate/notifications/:id/read', requireCandidate, async (req, res) => {
  try {
    await run('UPDATE notifications SET is_read = 1 WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/candidate/notifications/read-all
 * Marks all notifications as read for the candidate.
 */
app.post('/api/candidate/notifications/read-all', requireCandidate, async (req, res) => {
  try {
    await run(
      'UPDATE notifications SET is_read = 1 WHERE candidate_id = ? OR candidate_id IS NULL',
      [req.candidate.id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/admin/broadcast
 * Lead broadcasts an announcement banner / notification to all candidate workstations.
 */
app.post('/api/admin/broadcast', requireAdmin, async (req, res) => {
  try {
    const { title, message, type } = req.body;

    if (!title || !message) {
      return res.status(400).json({ error: 'Validation Error', message: 'Title and message are required.' });
    }

    const notifType = ['info', 'warning', 'urgent', 'success'].includes(type) ? type : 'info';

    const result = await run(`
      INSERT INTO notifications (candidate_id, title, message, type)
      VALUES (NULL, ?, ?, ?)
    `, [title.trim(), message.trim(), notifType]);

    await logAudit(null, 'ADMIN_BROADCAST_EMITTED', {
      broadcastId: result.lastID,
      title: title.trim(),
      type: notifType
    });

    res.status(201).json({ message: 'Broadcast emitted to all workstations successfully.' });
  } catch (err) {
    console.error('[ERROR] [Admin::Broadcast]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

// ============================================================================
// Audit Trail Telemetry Endpoint (Admin Only)
// ============================================================================
app.get('/api/admin/audit', requireAdmin, async (req, res) => {
  try {
    const logs = await all(`
      SELECT 
        a.id,
        a.candidate_id,
        c.name AS candidate_name,
        a.event_type,
        a.details,
        a.timestamp
      FROM audit_trail a
      LEFT JOIN candidates c ON a.candidate_id = c.id
      ORDER BY a.id DESC
      LIMIT 100;
    `);

    res.json({ count: logs.length, audit_trail: logs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/admin/tasks
 * Returns all system tasks for the admin governance board.
 */
app.get('/api/admin/tasks', requireAdmin, async (req, res) => {
  try {
    const tasks = await all(`
      SELECT 
        t.*,
        c.name AS candidate_name,
        c.role AS candidate_role
      FROM tasks t
      LEFT JOIN candidates c ON t.assigned_to = c.id
      ORDER BY 
        CASE 
          WHEN t.status = 'submitted' THEN 1
          WHEN t.status = 'overdue' THEN 2
          WHEN t.status = 'in_progress' THEN 3
          WHEN t.status = 'pending' THEN 4
          ELSE 5
        END,
        t.deadline ASC;
    `);

    const now = new Date();
    const enriched = tasks.map(t => ({
      ...t,
      is_overdue: t.status !== 'completed' && new Date(t.deadline) < now
    }));

    res.json({ total: enriched.length, tasks: enriched });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/admin/sweeper/trigger
 * Manual trigger for background governance sweeper.
 */
app.post('/api/admin/sweeper/trigger', requireAdmin, async (req, res) => {
  try {
    await runGovernanceSweep();
    await logAudit(null, 'ADMIN_MANUAL_SWEEPER_TRIGGER', { triggeredBy: 'admin' });
    res.json({ message: 'Governance sweep executed successfully.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// Frontend Portal Routes (Hardened & Obscured)
// ============================================================================
const LEAD_PORTAL_ROUTE = process.env.LEAD_PORTAL_ROUTE || '/lead-hub';

// Secure Lead Governance Console on custom obscured slug
app.get(LEAD_PORTAL_ROUTE, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'lead-portal.html'));
});

// Candidate Workstation Portal
app.get('/workstation', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'workstation.html'));
});

// Explicit rejection for common administrative discovery scans
app.get(['/admin', '/administrator', '/admin-panel', '/wp-admin'], (req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

// Default gateway root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================================
// Global Error & 404 Handlers
// ============================================================================
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', path: req.originalUrl });
});

app.use((err, req, res, next) => {
  const statusCode = err.status || err.statusCode || 500;
  if (statusCode >= 500) {
    console.error('[CRITICAL] Unhandled Server Exception:', err);
  }
  res.status(statusCode).json({
    error: statusCode === 413 ? 'Payload Too Large' : (err.name || 'Error'),
    message: err.message
  });
});

// ============================================================================
// Server Bootstrap & Lifecycle
// ============================================================================
const server = app.listen(PORT, async () => {
  console.log(`\n================================================================`);
  console.log(`[DevSecOps] CyberForge Governance Server listening on port ${PORT}`);
  console.log(`[DevSecOps] Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`================================================================`);

  // Seed cohort candidates if registry is empty
  await seedInitialCandidates();

  // Start background governance sweeper (session idle & task overdue checks)
  startSweeper();
});

module.exports = { app, server };

