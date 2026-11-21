/**
 * CyberForge Cohort Initial Seeder & Repository Sync
 *
 * Automatically provisions 5-candidate CyberForge Swarm-Sec cohort,
 * Golden Master Shadow Codebase records, and verifies clean PR telemetry baseline.
 */

const crypto = require('crypto');
const { get, run, all, logAudit } = require('../database');

const INITIAL_COHORT = [
  {
    id: 1,
    name: 'Kaif Pathan',
    role: 'junior',
    default_token: '04521968ccdc2d5bc71066dd3aed7f82',
    do326a_track: 'Distroless Docker Infrastructure',
    target_repo_path: 'infra/docker/Dockerfile.gateway',
    github_username: 'kaif-pathan'
  },
  {
    id: 2,
    name: 'Nadir Murudkar',
    role: 'junior',
    default_token: '1f4297bf57f572146c5281df4db52c6d',
    do326a_track: 'Ed25519 Cryptographic Verifier',
    target_repo_path: 'services/ingress_gateway/crypto/verifier.py',
    github_username: 'nadir-m'
  },
  {
    id: 3,
    name: 'Tejal Puthran',
    role: 'junior',
    default_token: 'e79155d935fb61ae6e5c4ac0f299aa28',
    do326a_track: 'Kinematics Anomaly Filter',
    target_repo_path: 'services/ingress_gateway/filters/kinematics.py',
    github_username: 'tejal-p'
  },
  {
    id: 4,
    name: 'Khot Maaz',
    role: 'junior',
    default_token: '2e16602939e3e77a4ea4e9b263ce6885',
    do326a_track: 'Adversary MITM Proxy',
    target_repo_path: 'services/adversary_harness/mitm_proxy.py',
    github_username: 'khot-maaz'
  },
  {
    id: 5,
    name: 'Prarthana Shah',
    role: 'junior',
    default_token: '80766c0ceb1b07039a7ffccce3ddbaa4',
    do326a_track: 'Anti-Replay Guard',
    target_repo_path: 'services/ingress_gateway/filters/replay_guard.py',
    github_username: 'prarthana-s'
  }
];

const INITIAL_SHADOW_MODULES = [
  {
    module_code: 'MOD-01',
    module_name: 'Distroless Docker Infrastructure',
    do326a_track: 'Minimal Container Hardening & Ingress Gateway',
    target_path: 'infra/docker/Dockerfile.gateway',
    readiness_pct: 100,
    notes: 'Golden Master distroless multi-stage hardened build with non-root runtime.'
  },
  {
    module_code: 'MOD-02',
    module_name: 'Ed25519 Cryptographic Verifier',
    do326a_track: 'Zero-Trust Ingress & Signature Verification',
    target_path: 'services/ingress_gateway/crypto/verifier.py',
    readiness_pct: 100,
    notes: 'Constant-time Ed25519 signature verification engine with memory zeroization.'
  },
  {
    module_code: 'MOD-03',
    module_name: 'Kinematics Anomaly Filter',
    do326a_track: 'Flight Kinematics & Attitude Estimation',
    target_path: 'services/ingress_gateway/filters/kinematics.py',
    readiness_pct: 100,
    notes: 'State-space covariance boundary checking and trajectory rate-of-climb anomaly rejection.'
  },
  {
    module_code: 'MOD-04',
    module_name: 'Adversary MITM Proxy',
    do326a_track: 'Offensive Adversary Emulation & Proxy',
    target_path: 'services/adversary_harness/mitm_proxy.py',
    readiness_pct: 100,
    notes: 'Simulated packet alteration and adversary MITM injection harness.'
  },
  {
    module_code: 'MOD-05',
    module_name: 'Anti-Replay Guard',
    do326a_track: 'Deterministic Timestamp Window & Nonce Verification',
    target_path: 'services/ingress_gateway/filters/replay_guard.py',
    readiness_pct: 100,
    notes: 'Sliding window nonce cache preventing replay attacks within 60s flight windows.'
  }
];

async function seedInitialCandidates() {
  try {
    // 1. Sync / Re-align candidates table to exact 5 CyberForge Swarm-Sec candidates with IDs 1-5
    for (const member of INITIAL_COHORT) {
      const existingByName = await get('SELECT * FROM candidates WHERE name = ? OR id = ?', [member.name, member.id]);
      if (existingByName) {
        // Guarantee default_token is always set to canonical credential
        // Keep custom token if set, otherwise restore canonical default token
        await run(
          `UPDATE candidates 
           SET role = 'junior',
               default_token = ?,
               access_token = CASE WHEN custom_token_set = 1 AND access_token IS NOT NULL AND access_token != '' THEN access_token ELSE ? END,
               do326a_track = ?,
               target_repo_path = ?,
               github_username = ?,
               governance_status = COALESCE(governance_status, 'active')
           WHERE id = ?`,
          [member.default_token, member.default_token, member.do326a_track, member.target_repo_path, member.github_username, existingByName.id]
        );
      } else {
        await run(
          `INSERT INTO candidates (id, name, role, access_token, default_token, custom_token_set, do326a_track, target_repo_path, github_username, governance_status, is_online)
           VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, 'active', 0)`,
          [member.id, member.name, member.role, member.default_token, member.default_token, member.do326a_track, member.target_repo_path, member.github_username]
        );
      }
    }

    // Ensure IDs 1-5 alignment
    // Check if Kaif Pathan has ID 2 and need to align to 1:
    const kaif = await get("SELECT * FROM candidates WHERE name = 'Kaif Pathan'");
    if (kaif && kaif.id !== 1) {
      const slot1 = await get('SELECT id FROM candidates WHERE id = 1');
      if (!slot1) {
        await run('UPDATE candidates SET id = 1 WHERE name = ?', ['Kaif Pathan']);
        await run('UPDATE activity_logs SET candidate_id = 1 WHERE candidate_id = ?', [kaif.id]);
        await run('UPDATE work_logs SET candidate_id = 1 WHERE candidate_id = ?', [kaif.id]);
        await run('UPDATE tickets SET candidate_id = 1 WHERE candidate_id = ?', [kaif.id]);
        await run('UPDATE notifications SET candidate_id = 1 WHERE candidate_id = ?', [kaif.id]);
        await run('UPDATE audit_trail SET candidate_id = 1 WHERE candidate_id = ?', [kaif.id]);
      }
    }

    // 2. Sync Shadow Codebase entries to match the 5 real Swarm-Sec modules
    await run('DELETE FROM shadow_codebase WHERE module_code NOT IN ("MOD-01", "MOD-02", "MOD-03", "MOD-04", "MOD-05")');
    for (const mod of INITIAL_SHADOW_MODULES) {
      const existing = await get('SELECT id FROM shadow_codebase WHERE module_code = ?', [mod.module_code]);
      if (existing) {
        await run(
          `UPDATE shadow_codebase 
           SET module_name = ?, do326a_track = ?, target_path = ?, readiness_pct = ?, notes = ?
           WHERE module_code = ?`,
          [mod.module_name, mod.do326a_track, mod.target_path, mod.readiness_pct, mod.notes, mod.module_code]
        );
      } else {
        await run(
          `INSERT INTO shadow_codebase (module_code, module_name, do326a_track, target_path, readiness_pct, is_deployed, notes)
           VALUES (?, ?, ?, ?, ?, 0, ?)`,
          [mod.module_code, mod.module_name, mod.do326a_track, mod.target_path, mod.readiness_pct, mod.notes]
        );
      }
    }

    // 3. Clear all fake/mock PR telemetry so every candidate starts with NO PR DISPATCHED
    await run('DELETE FROM pipeline_telemetry WHERE pr_number IN (101, 102, 103, 104) OR pr_url LIKE "%CyberForge/core%"');

    console.log('[DevSecOps] CyberForge Swarm-Sec Cohort Matrix and Shadow Codebase synchronized.');
  } catch (err) {
    console.error('[ERROR] [Seeder] Failed to seed Swarm-Sec cohort / failsafe:', err.message);
  }
}

module.exports = {
  INITIAL_COHORT,
  INITIAL_SHADOW_MODULES,
  seedInitialCandidates
};
