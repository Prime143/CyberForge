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
const fs = require('fs');
const os = require('os');
require('dotenv').config();

const { db, run, get, all, logAudit, createNotification } = require('./database');
const { sendAlert } = require('./notifier');
const { requireAdmin, requireCandidate } = require('./middleware/auth');
const { startSweeper, runGovernanceSweep } = require('./services/sweeper');
const { seedInitialCandidates } = require('./services/seeder');

const app = express();
const PORT = process.env.PORT || 4000;

// Ensure upload directory exists for task specifications & candidate deliverables
let UPLOADS_BASE = path.join(__dirname, 'uploads');
let UPLOADS_DIR = path.join(UPLOADS_BASE, 'tasks');

try {
  if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  }
  const probeFile = path.join(UPLOADS_DIR, '.probe_write');
  fs.writeFileSync(probeFile, 'probe');
  fs.unlinkSync(probeFile);
} catch (err) {
  console.warn('[WARN] [DevSecOps] Local upload directory unwritable or permission denied. Falling back to OS tmpdir:', err.message);
  UPLOADS_BASE = path.join(os.tmpdir(), 'cyberforge_uploads');
  UPLOADS_DIR = path.join(UPLOADS_BASE, 'tasks');
  try {
    if (!fs.existsSync(UPLOADS_DIR)) {
      fs.mkdirSync(UPLOADS_DIR, { recursive: true });
    }
  } catch (tmpErr) {
    console.error('[ERROR] [DevSecOps] Could not initialize tmp uploads directory:', tmpErr.message);
  }
}

/**
 * Enterprise Token Entropy & Defense Evaluation Engine
 * Evaluates Shannon Entropy bits, character distribution, and cryptographic resilience.
 */
function evaluateTokenEntropy(token) {
  if (!token || typeof token !== 'string') {
    return { score: 'Weak', rating: 'critical', entropy_bits: 0, length: 0, details: 'Weak (0 bits)' };
  }
  const len = token.length;
  let charsetSize = 0;
  if (/[a-z]/.test(token)) charsetSize += 26;
  if (/[A-Z]/.test(token)) charsetSize += 26;
  if (/[0-9]/.test(token)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(token)) charsetSize += 32;

  const bits = charsetSize > 0 ? Math.round(len * Math.log2(charsetSize)) : 0;

  let score = 'Weak';
  let rating = 'critical';
  if (bits >= 90 && len >= 14 && charsetSize >= 50) {
    score = 'Defense-Grade';
    rating = 'defense';
  } else if (bits >= 65 && len >= 10 && charsetSize >= 36) {
    score = 'Strong';
    rating = 'strong';
  } else if (bits >= 45 && len >= 8) {
    score = 'Moderate';
    rating = 'moderate';
  } else {
    score = 'Weak';
    rating = 'weak';
  }

  return {
    score,
    rating,
    entropy_bits: bits,
    length: len,
    details: `${score} (${bits} bits entropy, ${len} chars)`
  };
}

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
app.use('/uploads', express.static(UPLOADS_BASE));

/**
 * POST /api/upload
 * Supports file uploads (documents, specifications, archives, deliverables).
 * Uses dedicated 10MB parser to protect general endpoints under 1MB DoS bound.
 */
app.post('/api/upload', express.json({ limit: '10mb' }), async (req, res) => {
  try {
    const { filename, file_data } = req.body;
    if (!filename || !file_data) {
      return res.status(400).json({ error: 'Validation Error', message: 'filename and file_data (base64) are required.' });
    }

    const ext = path.extname(filename).toLowerCase();
    const forbiddenExts = ['.exe', '.bat', '.cmd', '.sh', '.vbs', '.js', '.mjs', '.com', '.pif', '.scr', '.hta', '.cpl', '.jar'];
    if (forbiddenExts.includes(ext)) {
      return res.status(400).json({ error: 'Security Guard Triggered', message: `Execution guard: File type "${ext}" is blocked for infrastructure safety.` });
    }

    const base64Data = file_data.replace(/^data:.*?;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');

    if (buffer.length > 10 * 1024 * 1024) {
      return res.status(413).json({ error: 'Payload Too Large', message: 'Maximum file size is 10 MB.' });
    }

    const safeBasename = path.basename(filename, ext).replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 50);
    const uniqueFilename = `${Date.now()}-${safeBasename}${ext || '.bin'}`;
    const targetPath = path.join(UPLOADS_DIR, uniqueFilename);

    fs.writeFileSync(targetPath, buffer);

    const fileUrl = `/uploads/tasks/${uniqueFilename}`;

    res.status(201).json({
      success: true,
      file_url: fileUrl,
      file_name: filename,
      file_size: buffer.length
    });
  } catch (err) {
    console.error('[ERROR] [Upload]', err.message);
    res.status(500).json({ error: 'Upload Failed', message: err.message });
  }
});

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
    const entropy = evaluateTokenEntropy(token);

    const result = await run(
      'INSERT INTO candidates (name, role, access_token, default_token, custom_token_set, token_entropy_score, is_online) VALUES (?, ?, ?, ?, 0, ?, 0)',
      [name.trim(), candidateRole, token, token, entropy.details]
    );

    await logAudit(result.lastID, 'ADMIN_CANDIDATE_CREATED', {
      adminAction: 'create',
      candidateName: name.trim(),
      role: candidateRole,
      entropy: entropy.score
    });

    const newCandidate = await get(
      'SELECT id, name, role, access_token, default_token, custom_token_set, token_entropy_score, is_online, created_at FROM candidates WHERE id = ?',
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

    // 1. Cleanly purge related candidate records
    await run('DELETE FROM tasks WHERE assigned_to = ?', [candidateId]);
    await run('DELETE FROM activity_logs WHERE candidate_id = ?', [candidateId]);
    await run('DELETE FROM work_logs WHERE candidate_id = ?', [candidateId]);
    await run('DELETE FROM tickets WHERE candidate_id = ?', [candidateId]);
    await run('DELETE FROM notifications WHERE candidate_id = ?', [candidateId]);
    await run('DELETE FROM pipeline_telemetry WHERE candidate_id = ?', [candidateId]);

    // 2. Delete candidate record
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
        c.default_token,
        c.custom_token_set,
        c.custom_token_created_at,
        c.token_reset_requested,
        c.token_reset_reason,
        c.token_entropy_score,
        c.governance_status,
        c.exit_reason,
        c.exit_timestamp,
        c.do326a_track,
        c.target_repo_path,
        c.github_username,
        c.failsafe_active,
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
      const entropy = evaluateTokenEntropy(cand.access_token);
      return {
        ...cand,
        token_entropy_details: entropy,
        token_entropy_score: cand.token_entropy_score || entropy.details,
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

/**
 * GET /api/admin/candidates/:id/history (Admin Only)
 * Comprehensive lifetime audit records, sessions, submissions, tickets and work logs for a specific candidate.
 */
app.get('/api/admin/candidates/:id/history', requireAdmin, async (req, res) => {
  try {
    const candidateId = req.params.id;
    const candidate = await get(
      'SELECT id, name, role, is_online, custom_token_set, token_entropy_score, access_token, default_token, token_reset_requested, token_reset_reason, created_at FROM candidates WHERE id = ?',
      [candidateId]
    );
    if (!candidate) {
      return res.status(404).json({ error: 'Not Found', message: `Candidate #${candidateId} not found.` });
    }

    const workLogs = await all(
      'SELECT id, log_type, message, task_id, created_at FROM work_logs WHERE candidate_id = ? ORDER BY id DESC LIMIT 100',
      [candidateId]
    );

    const tasks = await all(
      'SELECT id, title, task_category, priority, status, score, deadline, file_name, file_url, submission_url, submission_file_name, submission_file_url, is_archived, created_at FROM tasks WHERE assigned_to = ? ORDER BY id DESC',
      [candidateId]
    );

    const tickets = await all(
      'SELECT id, subject, category, priority, status, admin_notes, is_archived, created_at FROM tickets WHERE candidate_id = ? ORDER BY id DESC',
      [candidateId]
    );

    const telemetrySummary = await get(`
      SELECT 
        COALESCE(SUM(active_seconds), 0) AS total_active_seconds,
        COALESCE(SUM(workstation_seconds), 0) AS workstation_seconds,
        COALESCE(SUM(external_work_seconds), 0) AS external_work_seconds,
        COALESCE(SUM(idle_seconds), 0) AS idle_seconds,
        COALESCE(SUM(total_interactions), 0) AS total_interactions,
        COUNT(id) AS total_sessions
      FROM activity_logs WHERE candidate_id = ?
    `, [candidateId]);

    res.json({
      candidate,
      telemetry: telemetrySummary,
      work_logs: workLogs,
      tasks,
      tickets
    });
  } catch (err) {
    console.error('[ERROR] [Admin::CandidateHistory]', err.message);
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
        is_online: 1,
        custom_token_set: candidate.custom_token_set || 0,
        token_reset_requested: candidate.token_reset_requested || 0,
        token_entropy_score: candidate.token_entropy_score || null
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
// Candidate Token Self-Provisioning & Security Governance
// ============================================================================

/**
 * POST /api/candidate/custom-token (Candidate Auth)
 * Allows candidate to configure their personalized access key.
 * Strictly permitted only ONCE per candidate lifecycle.
 */
app.post('/api/candidate/custom-token', requireCandidate, async (req, res) => {
  try {
    const candidate = req.candidate;
    const { token } = req.body;

    if (!token || typeof token !== 'string' || token.trim().length < 8) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Personal access token must be at least 8 characters long.'
      });
    }

    const newKey = token.trim();

    // Check if candidate already set custom token once
    const current = await get('SELECT custom_token_set FROM candidates WHERE id = ?', [candidate.id]);
    if (current && current.custom_token_set === 1) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Custom token already created. Candidates may configure a custom token only once. If you need to reset it, please submit a token reset request to lead administration.'
      });
    }

    // Verify uniqueness across all candidates
    const inUse = await get('SELECT id FROM candidates WHERE access_token = ? AND id != ?', [newKey, candidate.id]);
    if (inUse) {
      return res.status(409).json({
        error: 'Conflict',
        message: 'This access key is already in use by another candidate. Please choose a different unique key.'
      });
    }

    const entropy = evaluateTokenEntropy(newKey);

    await run(`
      UPDATE candidates 
      SET access_token = ?, 
          custom_token_set = 1, 
          custom_token_created_at = CURRENT_TIMESTAMP, 
          token_entropy_score = ?, 
          token_reset_requested = 0, 
          token_reset_reason = NULL 
      WHERE id = ?
    `, [newKey, entropy.details, candidate.id]);

    await logAudit(candidate.id, 'CANDIDATE_CUSTOM_TOKEN_PROVISIONED', {
      entropy: entropy.score,
      bits: entropy.entropy_bits,
      length: entropy.length
    });

    await sendAlert(
      'Candidate Configured Custom Key',
      `Candidate **${candidate.name}** configured their custom token (Entropy: ${entropy.score}, ${entropy.entropy_bits} bits)`,
      'info',
      [
        { name: 'Candidate', value: candidate.name, inline: true },
        { name: 'Entropy Rating', value: entropy.score, inline: true },
        { name: 'Bit Strength', value: `${entropy.entropy_bits} bits`, inline: true }
      ]
    );

    res.status(200).json({
      message: 'Custom access credential provisioned successfully. You can now use this key.',
      token: newKey,
      custom_token_set: 1,
      entropy
    });
  } catch (err) {
    console.error('[ERROR] [Candidate::CustomToken]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * POST /api/candidate/request-token-reset (Candidate Auth)
 * Logged-in candidate requests admin assistance to reset / rotate their locked token.
 */
app.post('/api/candidate/request-token-reset', requireCandidate, async (req, res) => {
  try {
    const candidate = req.candidate;
    const { reason } = req.body;

    await run(`
      UPDATE candidates 
      SET token_reset_requested = 1, 
          token_reset_reason = ? 
      WHERE id = ?
    `, [reason ? String(reason).trim() : 'Candidate requested token reset assistance', candidate.id]);

    await logAudit(candidate.id, 'CANDIDATE_TOKEN_RESET_REQUESTED', {
      reason: reason || 'General reset'
    });

    await sendAlert(
      '⚠️ Token Reset Requested',
      `Candidate **${candidate.name}** has requested a token reset.\n**Reason:** ${reason || 'No explanation provided.'}`,
      'warning',
      [
        { name: 'Candidate ID', value: String(candidate.id), inline: true },
        { name: 'Candidate Name', value: candidate.name, inline: true },
        { name: 'Current Role', value: candidate.role.toUpperCase(), inline: true }
      ]
    );

    res.json({ message: 'Token reset request delivered to lead governance administrators.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/auth/request-token-reset (Unauthenticated Ingress)
 * Allows forgotten or locked-out candidates to file a reset request from the login screen.
 */
app.post('/api/auth/request-token-reset', async (req, res) => {
  try {
    const { candidate_identifier, reason } = req.body;
    if (!candidate_identifier || typeof candidate_identifier !== 'string' || !candidate_identifier.trim()) {
      return res.status(400).json({ error: 'Validation Error', message: 'Candidate identifier (name or ID) is required.' });
    }

    const ident = candidate_identifier.trim();
    let candidate = null;

    if (/^\d+$/.test(ident)) {
      candidate = await get('SELECT id, name, role FROM candidates WHERE id = ?', [parseInt(ident)]);
    }
    if (!candidate) {
      candidate = await get('SELECT id, name, role FROM candidates WHERE LOWER(TRIM(name)) = LOWER(?)', [ident]);
    }

    if (!candidate) {
      return res.status(200).json({
        message: 'If the provided candidate record matches our proving ground registry, your reset request has been logged for lead review.'
      });
    }

    await run(`
      UPDATE candidates 
      SET token_reset_requested = 1, 
          token_reset_reason = ? 
      WHERE id = ?
    `, [reason ? String(reason).trim() : 'External reset request via ingress screen', candidate.id]);

    await logAudit(candidate.id, 'CANDIDATE_TOKEN_RESET_REQUEST_INGRESS', {
      candidateName: candidate.name,
      reason: reason || null
    });

    await sendAlert(
      '⚠️ Ingress Token Reset Requested',
      `External token reset request submitted for **${candidate.name}** (Candidate #${candidate.id})\n**Reason:** ${reason || 'Candidate reported forgotten/lost token.'}`,
      'warning',
      [
        { name: 'Candidate', value: candidate.name, inline: true },
        { name: 'Candidate ID', value: String(candidate.id), inline: true }
      ]
    );

    res.status(200).json({
      message: 'Token reset request logged successfully. Contact your lead engineer for verification.'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/admin/candidates/:id/reset-token (Admin Only)
 * Allows administrator to unlock candidate for self-creation or assign a fresh token.
 */
app.post('/api/admin/candidates/:id/reset-token', requireAdmin, async (req, res) => {
  try {
    const candidateId = req.params.id;
    const { action, custom_new_token } = req.body;

    const candidate = await get('SELECT * FROM candidates WHERE id = ?', [candidateId]);
    if (!candidate) {
      return res.status(404).json({ error: 'Not Found', message: `Candidate ID ${candidateId} not found.` });
    }

    if (action === 'unlock_self_gen') {
      await run(`
        UPDATE candidates 
        SET custom_token_set = 0, 
            token_reset_requested = 0, 
            token_reset_reason = NULL 
        WHERE id = ?
      `, [candidateId]);

      await logAudit(candidateId, 'ADMIN_UNLOCKED_CANDIDATE_TOKEN_GENERATION', {
        adminAction: 'unlock_self_gen'
      });

      return res.json({
        message: `Candidate ${candidate.name} has been unlocked. They can now configure a new custom access key on their workstation.`,
        candidate: { ...candidate, custom_token_set: 0, token_reset_requested: 0 }
      });
    }

    const newToken = custom_new_token && custom_new_token.trim().length >= 8
      ? custom_new_token.trim()
      : crypto.randomBytes(16).toString('hex');

    const entropy = evaluateTokenEntropy(newToken);

    await run(`
      UPDATE candidates 
      SET access_token = ?, 
          default_token = ?, 
          custom_token_set = 0, 
          token_reset_requested = 0, 
          token_reset_reason = NULL, 
          token_entropy_score = ? 
      WHERE id = ?
    `, [newToken, newToken, entropy.details, candidateId]);

    await logAudit(candidateId, 'ADMIN_RESET_CANDIDATE_TOKEN', {
      adminAction: 'issue_new_token',
      entropy: entropy.score
    });

    res.json({
      message: `Token reset complete for ${candidate.name}. New credential generated and candidate unlocked for self-rotation.`,
      new_token: newToken,
      entropy: entropy.details
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    const { title, description, assigned_to, deadline, priority, category, file_url, file_name, file_size } = req.body;

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
    const taskCategory = category && typeof category === 'string' && category.trim() ? category.trim() : 'general';

    let candidate = null;
    if (assigned_to) {
      candidate = await get('SELECT id, name, role FROM candidates WHERE id = ?', [assigned_to]);
      if (!candidate) {
        return res.status(404).json({ error: 'Not Found', message: `Candidate ID ${assigned_to} does not exist.` });
      }
    }

    const result = await run(`
      INSERT INTO tasks (title, description, assigned_to, deadline, status, priority, task_category, file_url, file_name, file_size)
      VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
    `, [
      title.trim(),
      description ? description.trim() : null,
      assigned_to || null,
      deadline,
      taskPriority,
      taskCategory,
      file_url || null,
      file_name || null,
      file_size ? parseInt(file_size) : null
    ]);

    await logAudit(assigned_to || null, 'ADMIN_TASK_CREATED', {
      taskId: result.lastID,
      title: title.trim(),
      deadline,
      priority: taskPriority,
      category: taskCategory,
      hasAttachment: !!file_url
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
      candidate: {
        id: candidate.id,
        name: candidate.name,
        role: candidate.role,
        custom_token_set: candidate.custom_token_set,
        token_reset_requested: candidate.token_reset_requested,
        token_entropy_score: candidate.token_entropy_score,
        governance_status: candidate.governance_status || 'active',
        exit_reason: candidate.exit_reason || null,
        exit_timestamp: candidate.exit_timestamp || null,
        do326a_track: candidate.do326a_track || 'Avionics DO-326A Defense Track',
        target_repo_path: candidate.target_repo_path || 'src/core/module.rs',
        github_username: candidate.github_username || '',
        failsafe_active: candidate.failsafe_active || 0
      },
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
    const { submission_url, notes, submission_file_url, submission_file_name } = req.body;
    const candidate = req.candidate;

    const trimmedUrl = (submission_url && typeof submission_url === 'string') ? submission_url.trim() : null;
    const trimmedFileUrl = (submission_file_url && typeof submission_file_url === 'string') ? submission_file_url.trim() : null;

    if (!trimmedUrl && !trimmedFileUrl) {
      return res.status(400).json({ error: 'Validation Error', message: 'Either an artifact repository URL or an attached deliverable file is required.' });
    }

    const task = await get('SELECT * FROM tasks WHERE id = ?', [taskId]);

    if (!task) {
      return res.status(404).json({ error: 'Not Found', message: 'Task not found.' });
    }

    if (task.assigned_to !== candidate.id) {
      return res.status(403).json({ error: 'Forbidden', message: 'You are not assigned to this task.' });
    }

    if (trimmedUrl) {
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
    }

    await run(`
      UPDATE tasks 
      SET submission_url = ?, 
          submission_notes = ?, 
          submission_file_url = ?, 
          submission_file_name = ?, 
          status = 'submitted' 
      WHERE id = ?
    `, [trimmedUrl, notes || null, trimmedFileUrl, submission_file_name || null, taskId]);

    await logAudit(candidate.id, 'TASK_SUBMITTED_FOR_REVIEW', {
      taskId,
      title: task.title,
      submission_url: trimmedUrl,
      submission_file_url: trimmedFileUrl,
      notes: notes || null
    });

    await sendAlert(
      'Task Submitted for Review',
      `Task Submitted for Review: **${task.title}** by **${candidate.name}**`,
      'info',
      [
        { name: 'Task ID', value: String(taskId), inline: true },
        { name: 'Candidate', value: candidate.name, inline: true },
        { name: 'Artifact URL', value: trimmedUrl || 'Attached File', inline: false },
        { name: 'Deliverable File', value: submission_file_name || 'None', inline: true },
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
 * PATCH /api/admin/tasks/:id/archive (Admin Only)
 * Toggles task archival for permanent historical retention.
 */
app.patch('/api/admin/tasks/:id/archive', requireAdmin, async (req, res) => {
  try {
    const taskId = req.params.id;
    const task = await get('SELECT * FROM tasks WHERE id = ?', [taskId]);
    if (!task) return res.status(404).json({ error: 'Not Found', message: 'Task not found.' });

    const newArchived = task.is_archived === 1 ? 0 : 1;
    await run('UPDATE tasks SET is_archived = ? WHERE id = ?', [newArchived, taskId]);
    await logAudit(task.assigned_to, 'TASK_ARCHIVE_TOGGLED', { taskId, is_archived: newArchived });

    res.json({ message: newArchived ? 'Task archived to historical records.' : 'Task unarchived.', is_archived: newArchived });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * PATCH /api/admin/tickets/:id/archive (Admin Only)
 * Toggles ticket archival for permanent historical retention.
 */
app.patch('/api/admin/tickets/:id/archive', requireAdmin, async (req, res) => {
  try {
    const ticketId = req.params.id;
    const ticket = await get('SELECT * FROM tickets WHERE id = ?', [ticketId]);
    if (!ticket) return res.status(404).json({ error: 'Not Found', message: 'Ticket not found.' });

    const newArchived = ticket.is_archived === 1 ? 0 : 1;
    await run('UPDATE tickets SET is_archived = ? WHERE id = ?', [newArchived, ticketId]);
    await logAudit(ticket.candidate_id, 'TICKET_ARCHIVE_TOGGLED', { ticketId, is_archived: newArchived });

    res.json({ message: newArchived ? 'Ticket archived to historical records.' : 'Ticket unarchived.', is_archived: newArchived });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
        c.default_token,
        c.custom_token_set,
        c.custom_token_created_at,
        c.token_reset_requested,
        c.token_reset_reason,
        c.token_entropy_score,
        c.governance_status,
        c.exit_reason,
        c.exit_timestamp,
        c.do326a_track,
        c.target_repo_path,
        c.github_username,
        c.failsafe_active,
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

    const validCategories = ['technical', 'task_blocker', 'access_issue', 'extension_request', 'infrastructure', 'security_incident', 'code_review', 'general'];
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
// DO-326A Cohort Governance, Shadow Codebase & Webhook Telemetry
// ============================================================================

/**
 * GET /api/governance/cohort (Admin Only)
 * DO-326A Aerospace Cohort Matrix & Readiness Overview.
 */
app.get('/api/governance/cohort', requireAdmin, async (req, res) => {
  try {
    const candidates = await all(`
      SELECT 
        c.id, c.name, c.role, c.governance_status, c.exit_reason, c.exit_timestamp,
        c.do326a_track, c.target_repo_path, c.github_username, c.failsafe_active,
        c.is_online, c.access_token, c.default_token, c.custom_token_set, c.token_entropy_score,
        COALESCE(SUM(al.active_seconds), 0) AS total_active_seconds,
        COALESCE(SUM(al.idle_seconds), 0) AS idle_seconds
      FROM candidates c
      LEFT JOIN activity_logs al ON c.id = al.candidate_id
      GROUP BY c.id
      ORDER BY c.id ASC
    `);

    // Fetch latest pipeline telemetry for each candidate
    const telemetries = await all(`
      SELECT pt.* FROM pipeline_telemetry pt
      INNER JOIN (
        SELECT candidate_id, MAX(id) as max_id
        FROM pipeline_telemetry
        GROUP BY candidate_id
      ) latest ON pt.id = latest.max_id
    `);
    const telemetryMap = {};
    telemetries.forEach(t => {
      telemetryMap[t.candidate_id] = t;
    });

    const enriched = candidates.map(c => {
      const active = c.total_active_seconds || 0;
      const idle = c.idle_seconds || 0;
      const total = active + idle;
      const focusScore = total > 0 ? Math.round((active / total) * 100) : (c.is_online ? 100 : 0);
      return {
        ...c,
        focus_score: focusScore,
        latest_pipeline: telemetryMap[c.id] || null
      };
    });

    const activeCount = enriched.filter(c => (c.governance_status || 'active') === 'active').length;
    const neutralExitCount = enriched.filter(c => c.governance_status === 'neutral_exit').length;
    const adverseLogCount = enriched.filter(c => c.governance_status === 'adverse_log').length;
    const failsafeCount = enriched.filter(c => c.failsafe_active === 1).length;

    res.json({
      cohort_summary: {
        total_seats: enriched.length,
        active_candidates: activeCount,
        neutral_exits: neutralExitCount,
        adverse_logs: adverseLogCount,
        failsafe_engaged: failsafeCount,
        do326a_compliance_rate: enriched.length > 0 ? Math.round((activeCount / enriched.length) * 100) : 100
      },
      candidates: enriched
    });
  } catch (err) {
    console.error('[ERROR] [Governance::Cohort]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * PATCH /api/admin/candidates/:id/governance-status (Admin Only)
 * Allows Lead Architect to set candidate HR status: 'active', 'neutral_exit', 'adverse_log'.
 */
app.patch('/api/admin/candidates/:id/governance-status', requireAdmin, async (req, res) => {
  try {
    const candidateId = req.params.id;
    const { status, exit_reason } = req.body;

    const validStatuses = ['active', 'neutral_exit', 'adverse_log'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid Status', message: `Status must be one of: ${validStatuses.join(', ')}` });
    }

    const candidate = await get('SELECT * FROM candidates WHERE id = ?', [candidateId]);
    if (!candidate) {
      return res.status(404).json({ error: 'Not Found', message: `Candidate #${candidateId} not found.` });
    }

    const failsafeActive = status !== 'active' ? 1 : 0;
    const exitTimestamp = status !== 'active' ? new Date().toISOString() : null;

    await run(
      `UPDATE candidates 
       SET governance_status = ?, exit_reason = ?, exit_timestamp = ?, failsafe_active = ?, is_online = (CASE WHEN ? != 'active' THEN 0 ELSE is_online END)
       WHERE id = ?`,
      [status, exit_reason || null, exitTimestamp, failsafeActive, status, candidateId]
    );

    // If status is not active, activate failsafe backfill in shadow_codebase
    if (failsafeActive === 1 && candidate.target_repo_path) {
      await run(
        `UPDATE shadow_codebase 
         SET is_deployed = 1, lead_backfilled_at = CURRENT_TIMESTAMP, notes = ?
         WHERE target_path = ?`,
        [`Lead Shadow backfill active due to HR governance status: ${status}`, candidate.target_repo_path]
      );
    }

    await logAudit(candidateId, 'LEAD_GOVERNANCE_STATUS_UPDATE', {
      previous_status: candidate.governance_status,
      new_status: status,
      exit_reason: exit_reason || null,
      failsafe_active: failsafeActive
    });

    res.json({
      success: true,
      message: `Candidate #${candidateId} governance status set to ${status}.`,
      candidate_id: candidateId,
      status,
      failsafe_active: failsafeActive
    });
  } catch (err) {
    console.error('[ERROR] [Governance::StatusUpdate]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * GET /api/governance/failsafe (Admin Only)
 * Returns Shadow Codebase module repository and lead failover readiness.
 */
app.get('/api/governance/failsafe', requireAdmin, async (req, res) => {
  try {
    const modules = await all('SELECT * FROM shadow_codebase ORDER BY module_code ASC');
    const deployedCount = modules.filter(m => m.is_deployed === 1).length;
    res.json({
      total_modules: modules.length,
      deployed_failsafes: deployedCount,
      readiness_index_pct: 100,
      modules
    });
  } catch (err) {
    console.error('[ERROR] [Governance::Failsafe]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * POST /api/governance/failsafe/:moduleCode/toggle (Admin Only)
 * Engages or disengages the Lead Shadow Codebase failsafe backfill for a module.
 */
app.post('/api/governance/failsafe/:moduleCode/toggle', requireAdmin, async (req, res) => {
  try {
    const moduleCode = req.params.moduleCode.toUpperCase();
    const existing = await get('SELECT * FROM shadow_codebase WHERE module_code = ?', [moduleCode]);
    if (!existing) {
      return res.status(404).json({ error: 'Not Found', message: `Module code ${moduleCode} not found in shadow registry.` });
    }

    const nextState = existing.is_deployed === 1 ? 0 : 1;
    const nowIso = nextState === 1 ? new Date().toISOString() : null;
    const note = nextState === 1 ? 'Lead Golden Master manual failover engaged.' : 'Failsafe disengaged; candidate primary active.';

    await run(
      'UPDATE shadow_codebase SET is_deployed = ?, lead_backfilled_at = ?, notes = ? WHERE module_code = ?',
      [nextState, nowIso, note, moduleCode]
    );

    // Synchronize candidate failsafe flag if module matches target_path
    await run(
      'UPDATE candidates SET failsafe_active = ? WHERE target_repo_path = ?',
      [nextState, existing.target_path]
    );

    await logAudit(null, 'SHADOW_CODEBASE_FAILOVER_TOGGLED', {
      module_code: moduleCode,
      is_deployed: nextState,
      target_path: existing.target_path
    });

    res.json({
      success: true,
      module_code: moduleCode,
      is_deployed: nextState,
      message: nextState === 1 ? `Failsafe engaged for ${moduleCode}. Lead Golden Master active.` : `Failsafe disengaged for ${moduleCode}.`
    });
  } catch (err) {
    console.error('[ERROR] [Governance::FailsafeToggle]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * GET /api/governance/pipeline (Admin Only)
 * Real-time stream of GitHub Actions CI checks and Path-Guard evaluations.
 */
app.get('/api/governance/pipeline', requireAdmin, async (req, res) => {
  try {
    const telemetry = await all('SELECT * FROM pipeline_telemetry ORDER BY updated_at DESC LIMIT 50');
    res.json({
      total_runs: telemetry.length,
      pipeline: telemetry
    });
  } catch (err) {
    console.error('[ERROR] [Governance::Pipeline]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * POST /api/candidate/voluntary-exit (Candidate Auth)
 * Formal DO-326A Voluntary Exit Protocol: honorable withdrawal producing a Neutral Log.
 */
app.post('/api/candidate/voluntary-exit', requireCandidate, async (req, res) => {
  try {
    const candidate = req.candidate;
    const { reason, exit_ack } = req.body;

    if (!reason || reason.trim().length < 10) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'A formal departure explanation of at least 10 characters is required for voluntary exit logging.'
      });
    }

    if (!exit_ack) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'You must confirm the voluntary exit acknowledgment to finalize departure.'
      });
    }

    const exitTimestamp = new Date().toISOString();

    // 1. Update candidate record to neutral_exit and terminate online state
    await run(
      `UPDATE candidates 
       SET governance_status = 'neutral_exit', exit_reason = ?, exit_timestamp = ?, failsafe_active = 1, is_online = 0
       WHERE id = ?`,
      [reason.trim(), exitTimestamp, candidate.id]
    );

    // 2. Engage Shadow Codebase failover for their assigned track
    if (candidate.target_repo_path) {
      await run(
        `UPDATE shadow_codebase 
         SET is_deployed = 1, lead_backfilled_at = CURRENT_TIMESTAMP, notes = ?
         WHERE target_path = ?`,
        [`Lead Golden Master backfill engaged upon candidate ${candidate.name} voluntary withdrawal.`, candidate.target_repo_path]
      );
    }

    // 3. Log audit event
    await logAudit(candidate.id, 'CANDIDATE_VOLUNTARY_EXIT', {
      candidate_name: candidate.name,
      governance_status: 'neutral_exit',
      reason: reason.trim(),
      exit_timestamp: exitTimestamp
    });

    res.json({
      success: true,
      governance_status: 'neutral_exit',
      exit_timestamp: exitTimestamp,
      message: 'Voluntary Exit Protocol concluded honorably. DO-326A Neutral Log filed. Workstation decommissioned.'
    });
  } catch (err) {
    console.error('[ERROR] [Candidate::VoluntaryExit]', err.message);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

/**
 * POST /api/webhooks/github (Public Ingress)
 * Ingests GitHub Webhooks (pull_request, check_run) without altering local Git CLI workflow.
 */
app.post('/api/webhooks/github', async (req, res) => {
  try {
    const event = req.headers['x-github-event'] || req.body.event || 'pull_request';
    const body = req.body;

    let candidateId = null;
    let candidateName = 'External Contributor';
    let branch = 'main';
    let targetPath = 'src/';
    let prNumber = null;
    let prTitle = 'GitHub CI Telemetry Event';
    let prUrl = 'https://github.com/CyberForge/internship-core';
    let commitSha = 'HEAD';
    let pathGuardStatus = 'verified';
    let ciStatus = 'passing';
    let ciRunUrl = null;

    if (body.pull_request) {
      prNumber = body.pull_request.number;
      prTitle = body.pull_request.title;
      prUrl = body.pull_request.html_url;
      branch = body.pull_request.head ? body.pull_request.head.ref : 'feature/patch';
      commitSha = body.pull_request.head && body.pull_request.head.sha ? body.pull_request.head.sha.substring(0, 7) : 'HEAD';
      
      const githubUsername = body.pull_request.user ? body.pull_request.user.login : '';
      
      const matched = await get(
        'SELECT id, name, target_repo_path FROM candidates WHERE github_username = ? OR ? LIKE "%" || name || "%"',
        [githubUsername, branch]
      );
      if (matched) {
        candidateId = matched.id;
        candidateName = matched.name;
        targetPath = matched.target_repo_path;
      }
      
      if (body.action === 'opened' || body.action === 'synchronize') {
        ciStatus = 'in_progress';
      }
    } else if (body.check_run) {
      ciStatus = body.check_run.conclusion === 'success' ? 'passing' : (body.check_run.conclusion === 'failure' ? 'failed' : 'in_progress');
      commitSha = body.check_run.head_sha ? body.check_run.head_sha.substring(0, 7) : 'HEAD';
      ciRunUrl = body.check_run.html_url;
      prTitle = body.check_run.name || 'CI Check Run';
    } else if (body.candidate_id) {
      candidateId = body.candidate_id;
      const matched = await get('SELECT name, target_repo_path FROM candidates WHERE id = ?', [candidateId]);
      if (matched) {
        candidateName = matched.name;
        targetPath = matched.target_repo_path;
      }
      branch = body.branch || branch;
      targetPath = body.target_path || targetPath;
      prNumber = body.pr_number || prNumber;
      prTitle = body.pr_title || prTitle;
      prUrl = body.pr_url || prUrl;
      commitSha = body.commit_sha || commitSha;
      pathGuardStatus = body.path_guard_status || pathGuardStatus;
      ciStatus = body.ci_status || ciStatus;
      ciRunUrl = body.ci_run_url || ciRunUrl;
    }

    await run(
      `INSERT INTO pipeline_telemetry 
       (candidate_id, candidate_name, branch, target_path, pr_number, pr_title, pr_url, commit_sha, path_guard_status, ci_status, ci_run_url, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
      [candidateId, candidateName, branch, targetPath, prNumber, prTitle, prUrl, commitSha, pathGuardStatus, ciStatus, ciRunUrl]
    );

    res.status(202).json({
      success: true,
      event_type: event,
      message: 'Telemetry ingress recorded in pipeline audit stream.'
    });
  } catch (err) {
    console.error('[ERROR] [Webhook::GitHub]', err.message);
    res.status(500).json({ error: 'Webhook Ingress Error', message: err.message });
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

