/**
 * CyberForge Governance Engine - Automated Background Governance Worker
 *
 * Runs scheduled sweep tasks:
 * 1. Active Session Timeout Sweeper (Detects dropped heartbeats > 180s)
 * 2. Task Deadline Expiration Sweeper (Transitions overdue tasks and alerts leads)
 */

const { run, all, logAudit } = require('../database');
const { sendAlert } = require('../notifier');

const SWEEP_INTERVAL_MS = 60 * 1000; // 60 seconds
let sweepTimer = null;

async function runSessionSweep() {
  try {
    // Find active sessions with last heartbeat older than 180 seconds
    const staleSessions = await all(`
      SELECT 
        al.id AS session_id,
        al.candidate_id,
        c.name AS candidate_name,
        CAST(strftime('%s', 'now') - strftime('%s', al.last_heartbeat) AS INTEGER) AS elapsed_seconds
      FROM activity_logs al
      JOIN candidates c ON al.candidate_id = c.id
      WHERE al.status = 'active'
        AND (strftime('%s', 'now') - strftime('%s', al.last_heartbeat)) > 180;
    `);

    for (const session of staleSessions) {
      // Mark session as idle
      await run("UPDATE activity_logs SET status = 'idle' WHERE id = ?", [session.session_id]);
      // Mark candidate as offline
      await run("UPDATE candidates SET is_online = 0 WHERE id = ?", [session.candidate_id]);

      // Record DevSecOps audit trail
      await logAudit(session.candidate_id, 'SESSION_SWEEP_IDLE', {
        sessionId: session.session_id,
        elapsedSeconds: session.elapsed_seconds
      });

      // Broadcast alert to Discord
      await sendAlert(
        'Candidate Idle Detected',
        `${session.candidate_name} went idle / disconnected (No heartbeat for ${session.elapsed_seconds}s)`,
        'warning',
        [
          { name: 'Candidate', value: session.candidate_name, inline: true },
          { name: 'Status', value: 'idle', inline: true },
          { name: 'Elapsed', value: `${session.elapsed_seconds}s`, inline: true }
        ]
      );

      console.log(`[INFO] [Sweeper] Marked candidate ${session.candidate_name} (ID: ${session.candidate_id}) as idle. Dispatched alert.`);
    }
  } catch (err) {
    console.error('[ERROR] [Sweeper] Session sweep failed:', err.message);
  }
}

async function runTaskSweep() {
  try {
    // Find tasks that missed their deadline and are not yet submitted/completed
    const overdueTasks = await all(`
      SELECT 
        t.id AS task_id,
        t.title,
        t.assigned_to,
        c.name AS candidate_name,
        t.deadline
      FROM tasks t
      LEFT JOIN candidates c ON t.assigned_to = c.id
      WHERE t.status IN ('pending', 'in_progress')
        AND datetime(t.deadline) < datetime('now');
    `);

    for (const task of overdueTasks) {
      // Transition status to overdue
      await run("UPDATE tasks SET status = 'overdue' WHERE id = ?", [task.task_id]);

      // Record DevSecOps audit trail
      await logAudit(task.assigned_to, 'TASK_SWEEP_OVERDUE', {
        taskId: task.task_id,
        title: task.title,
        deadline: task.deadline
      });

      // Broadcast critical alert to Discord
      await sendAlert(
        'Task Overdue Alert',
        `Task "${task.title}" assigned to ${task.candidate_name || 'Unassigned'} has exceeded its deadline (${task.deadline}).`,
        'danger',
        [
          { name: 'Task ID', value: String(task.task_id), inline: true },
          { name: 'Candidate', value: task.candidate_name || 'Unassigned', inline: true },
          { name: 'Deadline', value: String(task.deadline), inline: true }
        ]
      );

      console.log(`[WARN] [Sweeper] Task #${task.task_id} ("${task.title}") marked as overdue.`);
    }
  } catch (err) {
    console.error('[ERROR] [Sweeper] Task sweep failed:', err.message);
  }
}

async function runGovernanceSweep() {
  await runSessionSweep();
  await runTaskSweep();
}

function startSweeper() {
  if (sweepTimer) return;
  console.log('[INFO] [DevSecOps] Initializing Automated Background Governance Sweeper (Interval: 60s)...');
  sweepTimer = setInterval(runGovernanceSweep, SWEEP_INTERVAL_MS);
}

function stopSweeper() {
  if (sweepTimer) {
    clearInterval(sweepTimer);
    sweepTimer = null;
    console.log('[INFO] [DevSecOps] Stopped Automated Background Governance Sweeper.');
  }
}

module.exports = {
  startSweeper,
  stopSweeper,
  runGovernanceSweep,
  runSessionSweep,
  runTaskSweep
};

