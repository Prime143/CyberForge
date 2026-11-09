/**
 * CyberForge Production Database Cleanup & Hardening Sweep
 *
 * DevSecOps Sanitization:
 * 1. Purges mock/test candidate records, leaving only the authentic cohort members.
 * 2. Purges synthetic tasks from previous test runs, leaving strictly Tasks #5 to #8.
 * 3. Clears synthetic activity logs so active time begins at 0.
 * 4. Cleans audit trail, preserving authentic seed events.
 * 5. Resets is_online to 0 for all candidates.
 */

const { run, all, close } = require('../database');

async function cleanProductionDatabase() {
  console.log('\n' + '='.repeat(80));
  console.log('[DevSecOps] STARTING PRODUCTION DATABASE PURGE & HARDENING');
  console.log('='.repeat(80));

  // 1. Delete synthetic mock candidates (e.g. 'Zara DevSec')
  const validCohortNames = ['Kaif Pathan', 'Nadir Murudkar', 'Tejal Puthran', 'Khot Maaz'];
  const deletedCandidates = await run(`
    DELETE FROM candidates 
    WHERE name NOT IN (?, ?, ?, ?)
  `, validCohortNames);
  console.log(`[CLEANUP] Deleted ${deletedCandidates.changes} mock/temporary candidate account(s).`);

  // Reset online status
  await run('UPDATE candidates SET is_online = 0');
  console.log('[CLEANUP] Reset all cohort candidate statuses to offline (is_online = 0).');

  // 2. Delete test tasks, preserving only Tasks #5, #6, #7, #8
  const validTaskTitles = [
    'Ingress HMAC-SHA256 Signature Middleware',
    'Resilient Heartbeat Telemetry Client',
    'Immutable Audit Log Streamer',
    'API Payload Sanitization & Schema Guard'
  ];
  const deletedTasks = await run(`
    DELETE FROM tasks 
    WHERE title NOT IN (?, ?, ?, ?)
  `, validTaskTitles);
  console.log(`[CLEANUP] Deleted ${deletedTasks.changes} mock/test task(s).`);

  // 3. Clear synthetic activity logs
  const deletedLogs = await run('DELETE FROM activity_logs');
  console.log(`[CLEANUP] Cleared ${deletedLogs.changes} synthetic activity log session(s).`);

  // 4. Purge mock audit trail events, keeping authentic seed events
  const deletedAudits = await run(`
    DELETE FROM audit_trail 
    WHERE event_type NOT IN ('COHORT_AUTO_SEEDED', 'SEED_TASK_CREATED')
  `);
  console.log(`[CLEANUP] Purged ${deletedAudits.changes} mock audit event(s). Preserved authentic seeds.`);

  // 5. Run SQLite vacuum to reclaim space and optimize WAL
  await run('VACUUM');
  console.log('[CLEANUP] Executed SQLite VACUUM optimization.');

  console.log('\n--- SANITIZED COHORT REGISTRY ---');
  console.table(await all('SELECT id, name, role, access_token, is_online FROM candidates ORDER BY id ASC'));

  console.log('--- SANITIZED GOVERNANCE TASKS ---');
  console.table(await all('SELECT id, title, assigned_to, deadline, status FROM tasks ORDER BY id ASC'));

  console.log('--- SANITIZED AUDIT TRAIL ---');
  console.table(await all('SELECT id, candidate_id, event_type, details, timestamp FROM audit_trail ORDER BY id ASC'));

  console.log('='.repeat(80));
  console.log('[DevSecOps] PRODUCTION SWEEP COMPLETED SUCCESSFULLY.');
  console.log('='.repeat(80) + '\n');

  await close();
  process.exit(0);
}

cleanProductionDatabase().catch(async (err) => {
  console.error('[CRITICAL] [Cleanup] Database sanitization failed:', err.message);
  try { await close(); } catch (_) {}
  process.exit(1);
});

