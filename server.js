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

const { db, run, get, all, logAudit } = require('./database');
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

    if (!role || !['core', 'junior'].includes(role)) {
      return res.status(400).json({
        error: 'Validation Error',
        message: "Candidate role must be either 'core' or 'junior'."
      });
    }

    // Cryptographically secure 32-character random hex token
    const token = crypto.randomBytes(16).toString('hex');

    const result = await run(
      'INSERT INTO candidates (name, role, access_token, is_online) VALUES (?, ?, ?, 0)',
      [name.trim(), role, token]
    );

    await logAudit(result.lastID, 'ADMIN_CANDIDATE_CREATED', {
      adminAction: 'create',
      candidateName: name.trim(),
      role
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
 * GET /api/admin/candidates
 * Lists all registered candidates with real-time presence, aggregated active time, and task counts.
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
        (SELECT COUNT(*) FROM tasks t WHERE t.assigned_to = c.id) AS assigned_tasks_count
      FROM candidates c
      LEFT JOIN activity_logs al ON c.id = al.candidate_id
      GROUP BY c.id
      ORDER BY c.id ASC;
    `);

    res.json({
      total: candidates.length,
      candidates
    });
  } catch (err) {
    console.error('[ERROR] [Admin::ListCandidates]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

// ============================================================================
// Session & Heartbeat Tracking Engine (Candidate APIs)
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
      INSERT INTO activity_logs (candidate_id, session_start, last_heartbeat, active_seconds, status)
      VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0, 'active')
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
 * Heartbeat telemetry ping. Enforces anti-tampering idle detection (>180s).
 */
app.post('/api/session/heartbeat', requireCandidate, async (req, res) => {
  try {
    const candidate = req.candidate;

    // Retrieve candidate's currently active session with delta calculated in SQLite
    const activeSession = await get(`
      SELECT 
        id,
        candidate_id,
        active_seconds,
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

    // Normal heartbeat: accumulate elapsed active seconds and update last_heartbeat
    const updatedActiveSeconds = activeSession.active_seconds + delta;
    await run(`
      UPDATE activity_logs 
      SET active_seconds = ?, 
          last_heartbeat = CURRENT_TIMESTAMP, 
          status = 'active' 
      WHERE id = ?
    `, [updatedActiveSeconds, activeSession.id]);

    await run('UPDATE candidates SET is_online = 1 WHERE id = ?', [candidate.id]);

    res.status(200).json({
      status: 'acknowledged',
      active_seconds: updatedActiveSeconds
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
    const { title, description, assigned_to, deadline } = req.body;

    if (!title || typeof title !== 'string' || !title.trim()) {
      return res.status(400).json({ error: 'Validation Error', message: 'Task title is required.' });
    }

    if (!deadline || isNaN(Date.parse(deadline))) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Valid deadline (ISO format or parseable date string) is required.'
      });
    }

    let candidate = null;
    if (assigned_to) {
      candidate = await get('SELECT id, name, role FROM candidates WHERE id = ?', [assigned_to]);
      if (!candidate) {
        return res.status(404).json({ error: 'Not Found', message: `Candidate ID ${assigned_to} does not exist.` });
      }
    }

    const result = await run(`
      INSERT INTO tasks (title, description, assigned_to, deadline, status)
      VALUES (?, ?, ?, ?, 'pending')
    `, [title.trim(), description ? description.trim() : null, assigned_to || null, deadline]);

    await logAudit(assigned_to || null, 'ADMIN_TASK_CREATED', {
      taskId: result.lastID,
      title: title.trim(),
      deadline
    });

    // Alert lead channel via Discord
    const candidateLabel = candidate ? candidate.name : 'Unassigned';
    await sendAlert(
      'New Governance Task Assigned',
      `New Task Assigned to **${candidateLabel}**: **${title.trim()}** (Deadline: ${deadline})`,
      'warning',
      [
        { name: 'Task ID', value: String(result.lastID), inline: true },
        { name: 'Assigned To', value: candidateLabel, inline: true },
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
 * Submits work artifact URL for review.
 */
app.post('/api/tasks/:id/submit', requireCandidate, async (req, res) => {
  try {
    const taskId = req.params.id;
    const { submission_url, notes } = req.body;
    const candidate = req.candidate;

    if (!submission_url || typeof submission_url !== 'string') {
      return res.status(400).json({ error: 'Validation Error', message: 'submission_url string is required.' });
    }

    const task = await get('SELECT * FROM tasks WHERE id = ?', [taskId]);

    if (!task) {
      return res.status(404).json({ error: 'Not Found', message: 'Task not found.' });
    }

    if (task.assigned_to !== candidate.id) {
      return res.status(403).json({ error: 'Forbidden', message: 'You are not assigned to this task.' });
    }

    await run(`
      UPDATE tasks 
      SET submission_url = ?, status = 'submitted' 
      WHERE id = ?
    `, [submission_url.trim(), taskId]);

    await logAudit(candidate.id, 'TASK_SUBMITTED_FOR_REVIEW', {
      taskId,
      title: task.title,
      submission_url: submission_url.trim(),
      notes: notes || null
    });

    await sendAlert(
      'Task Submitted for Review',
      `Task Submitted for Review: **${task.title}** by **${candidate.name}**`,
      'info',
      [
        { name: 'Task ID', value: String(taskId), inline: true },
        { name: 'Candidate', value: candidate.name, inline: true },
        { name: 'Artifact URL', value: submission_url.trim(), inline: false },
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
 * Review submitted task: accepts 'completed' or pushes back to 'in_progress'.
 */
app.patch('/api/tasks/:id/review', requireAdmin, async (req, res) => {
  try {
    const taskId = req.params.id;
    const { status, feedback } = req.body;

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

    await run('UPDATE tasks SET status = ? WHERE id = ?', [status, taskId]);

    await logAudit(task.assigned_to, 'TASK_REVIEW_DECISION', {
      taskId,
      status,
      feedback: feedback || null
    });

    const isCompleted = status === 'completed';
    const alertTitle = isCompleted ? 'Task Review: Completed / Approved' : 'Task Review: Needs Revision';
    const alertColor = isCompleted ? 'success' : 'danger';

    await sendAlert(
      alertTitle,
      `Task **"${task.title}"** assigned to **${task.candidate_name || 'Unassigned'}** was updated to **${status.toUpperCase()}**.`,
      alertColor,
      [
        { name: 'Task ID', value: String(taskId), inline: true },
        { name: 'Status', value: status.toUpperCase(), inline: true },
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

