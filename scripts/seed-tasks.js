/**
 * CyberForge Cohort Task Seeder
 *
 * Populates interdependent security governance tasks for cohort candidates:
 * - Kaif Pathan (core)
 * - Nadir Murudkar (core)
 * - Tejal Puthran (core)
 * - Khot Maaz (junior)
 *
 * Features:
 * - Dynamic ID resolution by candidate name
 * - Idempotency guard (prevents duplicate tasks on repeated executions)
 * - Automatic DevSecOps audit trail logging
 */

const { get, run, logAudit, close } = require('../database');

const COHORT_TASKS = [
  {
    candidateName: 'Kaif Pathan',
    title: 'Ingress HMAC-SHA256 Signature Middleware',
    description: 'Implement an Express middleware function validating x-signature headers against request bodies using a shared secret. Drop unverified traffic with HTTP 403.',
    deadline: '2026-11-11T18:00:00Z'
  },
  {
    candidateName: 'Nadir Murudkar',
    title: 'Resilient Heartbeat Telemetry Client',
    description: 'Build a fault-tolerant client-side script that sends telemetry heartbeats every 60s, queues failed attempts during disconnections, and reconnects seamlessly.',
    deadline: '2026-11-11T18:00:00Z'
  },
  {
    candidateName: 'Tejal Puthran',
    title: 'Immutable Audit Log Streamer',
    description: 'Design an append-only logging pipeline for security events that records timestamp, actor ID, and action hash to prevent log tampering.',
    deadline: '2026-11-12T12:00:00Z'
  },
  {
    candidateName: 'Khot Maaz',
    title: 'API Payload Sanitization & Schema Guard',
    description: 'Create regex and boundary validation for all POST/PATCH endpoints to strip script tags and enforce max string lengths (prevent XSS/CWE-79).',
    deadline: '2026-11-12T12:00:00Z'
  }
];

async function seedTasks() {
  console.log('\n' + '='.repeat(80));
  console.log('[DevSecOps] SEEDING INITIAL COHORT GOVERNANCE TASKS');
  console.log('='.repeat(80));

  const results = [];

  for (const item of COHORT_TASKS) {
    // 1. Resolve candidate by name
    const candidate = await get('SELECT id, name, role FROM candidates WHERE name = ?', [item.candidateName]);

    if (!candidate) {
      console.warn(`[WARN] Candidate "${item.candidateName}" not found in database. Skipping task.`);
      continue;
    }

    // 2. Check for duplicate task by title
    const existingTask = await get('SELECT id, title, status FROM tasks WHERE title = ?', [item.title]);

    if (existingTask) {
      console.log(`[SKIP] Task "${item.title}" already exists (Task #${existingTask.id}, Status: ${existingTask.status}).`);
      results.push({
        taskId: existingTask.id,
        candidate: candidate.name,
        role: candidate.role,
        title: item.title,
        deadline: item.deadline,
        status: existingTask.status,
        action: 'EXISTING'
      });
      continue;
    }

    // 3. Insert task into tasks table
    const insertRes = await run(`
      INSERT INTO tasks (title, description, assigned_to, deadline, status)
      VALUES (?, ?, ?, ?, 'pending')
    `, [item.title, item.description, candidate.id, item.deadline]);

    const taskId = insertRes.lastID;

    // 4. Log DevSecOps audit trail
    await logAudit(candidate.id, 'SEED_TASK_CREATED', {
      taskId,
      title: item.title,
      deadline: item.deadline
    });

    results.push({
      taskId,
      candidate: candidate.name,
      role: candidate.role,
      title: item.title,
      deadline: item.deadline,
      status: 'pending',
      action: 'INSERTED'
    });
  }

  console.log('\nSeeded Task Matrix:');
  console.table(results);
  console.log('='.repeat(80) + '\n');

  await close();
  process.exit(0);
}

seedTasks().catch(async (err) => {
  console.error('[CRITICAL] [TaskSeeder] Seeding failed:', err.message);
  try { await close(); } catch (_) {}
  process.exit(1);
});

