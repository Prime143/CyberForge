/**
 * CyberForge Cohort Initial Seeder
 *
 * Automatically provisions initial candidates and baseline governance tasks
 * if the registry is empty (ensures cloud deployments like Render auto-initialize).
 */

const crypto = require('crypto');
const { get, run, all, logAudit } = require('../database');

const INITIAL_COHORT = [
  { name: 'Kaif Pathan', role: 'core', token: '04521968ccdc2d5bc71066dd3aed7f82' },
  { name: 'Nadir Murudkar', role: 'core', token: '1f4297bf57f572146c5281df4db52c6d' },
  { name: 'Tejal Puthran', role: 'core', token: 'e79155d935fb61ae6e5c4ac0f299aa28' },
  { name: 'Khot Maaz', role: 'junior', token: '2e16602939e3e77a4ea4e9b263ce6885' }
];

const INITIAL_TASKS = [
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

async function seedInitialCandidates() {
  try {
    // 1. Seed Candidates if empty
    const existing = await get('SELECT COUNT(*) AS count FROM candidates');
    if (!existing || existing.count === 0) {
      console.log('\n' + '='.repeat(80));
      console.log('[DevSecOps] INITIALIZING COHORT CANDIDATE REGISTRY');
      console.log('='.repeat(80));

      const seededList = [];

      for (const member of INITIAL_COHORT) {
        const token = member.token || crypto.randomBytes(16).toString('hex');
        const result = await run(
          'INSERT INTO candidates (name, role, access_token, is_online) VALUES (?, ?, ?, 0)',
          [member.name, member.role, token]
        );

        await logAudit(result.lastID, 'COHORT_AUTO_SEEDED', {
          name: member.name,
          role: member.role
        });

        seededList.push({
          id: result.lastID,
          name: member.name,
          role: member.role,
          access_token: token
        });
      }

      console.table(seededList);
      console.log('[IMPORTANT] Cohort credentials provisioned successfully.');
      console.log('='.repeat(80) + '\n');
    }

    // 2. Seed Baseline Governance Tasks if empty
    const existingTasks = await get('SELECT COUNT(*) AS count FROM tasks');
    if (!existingTasks || existingTasks.count === 0) {
      console.log('[DevSecOps] Initializing baseline cohort governance tasks...');
      for (const task of INITIAL_TASKS) {
        const candidate = await get('SELECT id FROM candidates WHERE name = ?', [task.candidateName]);
        if (candidate) {
          const insertRes = await run(`
            INSERT INTO tasks (title, description, assigned_to, deadline, status)
            VALUES (?, ?, ?, ?, 'pending')
          `, [task.title, task.description, candidate.id, task.deadline]);

          await logAudit(candidate.id, 'SEED_TASK_CREATED', {
            taskId: insertRes.lastID,
            title: task.title,
            deadline: task.deadline
          });
        }
      }
      console.log('[DevSecOps] Baseline tasks auto-seeded successfully.');
    }
  } catch (err) {
    console.error('[ERROR] [Seeder] Failed to seed initial cohort / tasks:', err.message);
  }
}

module.exports = {
  seedInitialCandidates
};
