/**
 * CyberForge Cohort Initial Seeder
 *
 * Automatically provisions 6-candidate DO-326A aerospace flight cohort,
 * Golden Master Shadow Codebase records, and baseline pipeline telemetry.
 */

const crypto = require('crypto');
const { get, run, all, logAudit } = require('../database');

const INITIAL_COHORT = [
  {
    name: 'Kaif Pathan',
    role: 'devsecops',
    token: '04521968ccdc2d5bc71066dd3aed7f82',
    do326a_track: 'Ed25519 Cryptographic Verifier',
    target_repo_path: 'src/crypto/ed25519_verifier.rs',
    github_username: 'kaif-pathan'
  },
  {
    name: 'Nadir Murudkar',
    role: 'core',
    token: '1f4297bf57f572146c5281df4db52c6d',
    do326a_track: 'Kinematics Kalman State Filter',
    target_repo_path: 'src/filters/kinematics.rs',
    github_username: 'nadir-m'
  },
  {
    name: 'Tejal Puthran',
    role: 'core',
    token: 'e79155d935fb61ae6e5c4ac0f299aa28',
    do326a_track: 'Ingress HMAC-SHA256 Guard',
    target_repo_path: 'src/middleware/hmac_guard.js',
    github_username: 'tejal-p'
  },
  {
    name: 'Khot Maaz',
    role: 'junior',
    token: '2e16602939e3e77a4ea4e9b263ce6885',
    do326a_track: 'Avionics High-Rate Telemetry Streamer',
    target_repo_path: 'src/telemetry/streamer.rs',
    github_username: 'khot-maaz'
  },
  {
    name: 'Aarav Sharma',
    role: 'core',
    token: '3a7b9c1d5e7f8a9b0c1d2e3f4a5b6c7d',
    do326a_track: 'DO-326A Memory Boundary Sanitizer',
    target_repo_path: 'src/security/boundary_sanitizer.c',
    github_username: 'aarav-sharma'
  },
  {
    name: 'Zoya Ansari',
    role: 'core',
    token: '5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c',
    do326a_track: 'Fault-Tolerant Sweeper Daemon',
    target_repo_path: 'src/daemons/sweeper.js',
    github_username: 'zoya-ansari'
  }
];

const INITIAL_SHADOW_MODULES = [
  {
    module_code: 'MOD-01',
    module_name: 'Kinematics Kalman State Filter',
    do326a_track: 'Flight Kinematics & Attitude Estimation',
    target_path: 'src/filters/kinematics.rs',
    readiness_pct: 100,
    notes: 'Golden Master v2.4 validated under RTCA DO-326A Tier 1 fault matrix.'
  },
  {
    module_code: 'MOD-02',
    module_name: 'Ed25519 Cryptographic Verifier',
    do326a_track: 'Zero-Trust Ingress & Signature Verification',
    target_path: 'src/crypto/ed25519_verifier.rs',
    readiness_pct: 100,
    notes: 'Rust-based constant-time signature verification engine with memory zeroization.'
  },
  {
    module_code: 'MOD-03',
    module_name: 'Ingress HMAC-SHA256 Guard',
    do326a_track: 'Ingress Signature Verification & Rate-Limiting',
    target_path: 'src/middleware/hmac_guard.js',
    readiness_pct: 100,
    notes: 'Deterministic payload canonicalization with replay-attack timestamp window.'
  },
  {
    module_code: 'MOD-04',
    module_name: 'Avionics High-Rate Telemetry Streamer',
    do326a_track: 'UDP/TCP Low-Latency Telemetry Link',
    target_path: 'src/telemetry/streamer.rs',
    readiness_pct: 100,
    notes: 'Asynchronous buffered ring-buffer with automated drop-detection and backpressure.'
  },
  {
    module_code: 'MOD-05',
    module_name: 'DO-326A Memory Boundary Sanitizer',
    do326a_track: 'Memory Safety & Buffer Overflow Elimination',
    target_path: 'src/security/boundary_sanitizer.c',
    readiness_pct: 100,
    notes: 'Hardware-enforced bounds checking for DMA buffers and serial packets.'
  },
  {
    module_code: 'MOD-06',
    module_name: 'Fault-Tolerant Sweeper Daemon',
    do326a_track: 'Autonomous System Health & Deadman Sweeper',
    target_path: 'src/daemons/sweeper.js',
    readiness_pct: 100,
    notes: 'Isolated background worker enforcing 60s dead-man switches and memory garbage collection.'
  }
];

async function seedInitialCandidates() {
  try {
    // 1. Provision or update candidates with DO-326A tracks
    for (const member of INITIAL_COHORT) {
      const existingCand = await get('SELECT * FROM candidates WHERE name = ?', [member.name]);
      if (!existingCand) {
        const token = member.token || crypto.randomBytes(16).toString('hex');
        const res = await run(
          `INSERT INTO candidates (name, role, access_token, default_token, do326a_track, target_repo_path, github_username, governance_status, is_online)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'active', 0)`,
          [member.name, member.role, token, token, member.do326a_track, member.target_repo_path, member.github_username]
        );
        await logAudit(res.lastID, 'COHORT_AEROSPACE_PROVISIONED', {
          track: member.do326a_track,
          path: member.target_repo_path
        });
      } else {
        // Update track and repo path if missing
        await run(
          `UPDATE candidates 
           SET do326a_track = COALESCE(do326a_track, ?),
               target_repo_path = COALESCE(target_repo_path, ?),
               github_username = COALESCE(github_username, ?),
               governance_status = COALESCE(governance_status, 'active')
           WHERE id = ?`,
          [member.do326a_track, member.target_repo_path, member.github_username, existingCand.id]
        );
      }
    }

    // 2. Provision Shadow Codebase entries if empty
    const existingShadow = await get('SELECT COUNT(*) AS count FROM shadow_codebase');
    if (!existingShadow || existingShadow.count === 0) {
      for (const mod of INITIAL_SHADOW_MODULES) {
        await run(
          `INSERT INTO shadow_codebase (module_code, module_name, do326a_track, target_path, readiness_pct, is_deployed, notes)
           VALUES (?, ?, ?, ?, ?, 0, ?)`,
          [mod.module_code, mod.module_name, mod.do326a_track, mod.target_path, mod.readiness_pct, mod.notes]
        );
      }
      console.log('[DevSecOps] Shadow Codebase Failsafe Golden Master modules initialized (6/6 Standby).');
    }

    // 3. Provision baseline pipeline telemetry if empty
    const existingTelemetry = await get('SELECT COUNT(*) AS count FROM pipeline_telemetry');
    if (!existingTelemetry || existingTelemetry.count === 0) {
      const candidates = await all('SELECT id, name, target_repo_path, github_username FROM candidates LIMIT 6');
      const sampleEvents = [
        {
          candIdx: 0,
          pr_number: 101,
          branch: 'feature/ed25519-core-verification',
          pr_title: 'feat(crypto): implement constant-time ed25519 point verification',
          commit_sha: 'a8f190c',
          path_guard: 'passed',
          ci_status: 'passed'
        },
        {
          candIdx: 1,
          pr_number: 102,
          branch: 'feature/kinematics-state-filter',
          pr_title: 'feat(filters): add Kalman state covariance matrix bounds',
          commit_sha: '7b203ef',
          path_guard: 'passed',
          ci_status: 'passed'
        },
        {
          candIdx: 2,
          pr_number: 103,
          branch: 'feature/hmac-ingress-guard',
          pr_title: 'feat(middleware): enforce sha256 signature timestamp window',
          commit_sha: '4d119ca',
          path_guard: 'passed',
          ci_status: 'passed'
        },
        {
          candIdx: 3,
          pr_number: 104,
          branch: 'feature/telemetry-udp-streamer',
          pr_title: 'feat(streamer): asynchronous ring-buffer frame serialization',
          commit_sha: '9c5812b',
          path_guard: 'passed',
          ci_status: 'running'
        }
      ];

      for (const ev of sampleEvents) {
        const cand = candidates[ev.candIdx];
        if (cand) {
          await run(
            `INSERT INTO pipeline_telemetry (candidate_id, candidate_name, branch, target_path, pr_number, pr_title, pr_url, commit_sha, path_guard_status, ci_status, ci_run_url)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              cand.id,
              cand.name,
              ev.branch,
              cand.target_repo_path,
              ev.pr_number,
              ev.pr_title,
              `https://github.com/CyberForge/core/pull/${ev.pr_number}`,
              ev.commit_sha,
              ev.path_guard,
              ev.ci_status,
              `https://github.com/CyberForge/core/actions/runs/${5000 + ev.pr_number}`
            ]
          );
        }
      }
      console.log('[DevSecOps] Initialized baseline GitHub Actions CI path-guard pipeline telemetry.');
    }

    console.log('[DevSecOps] DO-326A Cohort Matrix and Failsafe registry verified successfully.');
  } catch (err) {
    console.error('[ERROR] [Seeder] Failed to seed DO-326A cohort / failsafe:', err.message);
  }
}

module.exports = {
  seedInitialCandidates
};

module.exports = {
  seedInitialCandidates
};
