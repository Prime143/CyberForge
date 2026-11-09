/**
 * CyberForge Cohort Initial Seeder
 *
 * Automatically provisions initial candidates if the candidates registry is empty.
 */

const crypto = require('crypto');
const { get, run, logAudit } = require('../database');

const INITIAL_COHORT = [
  { name: 'Kaif Pathan', role: 'core' },
  { name: 'Nadir Murudkar', role: 'core' },
  { name: 'Tejal Puthran', role: 'core' },
  { name: 'Khot Maaz', role: 'junior' }
];

async function seedInitialCandidates() {
  try {
    const existing = await get('SELECT COUNT(*) AS count FROM candidates');
    if (existing && existing.count > 0) {
      return;
    }

    console.log('\n' + '='.repeat(80));
    console.log('[DevSecOps] INITIALIZING COHORT CANDIDATE REGISTRY');
    console.log('='.repeat(80));

    const seededList = [];

    for (const member of INITIAL_COHORT) {
      const token = crypto.randomBytes(16).toString('hex');
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
    console.log('[IMPORTANT] Securely distribute the access tokens above to each candidate.');
    console.log('='.repeat(80) + '\n');
  } catch (err) {
    console.error('[ERROR] [Seeder] Failed to seed initial cohort:', err.message);
  }
}

module.exports = {
  seedInitialCandidates
};

