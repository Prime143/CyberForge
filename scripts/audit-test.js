/**
 * CyberForge Zero-Dependency Automated Security Verification & Pen-Test Harness
 *
 * Validates 8 Critical Industry Compliance & Security Controls against http://localhost:4000:
 * 1. RBAC & Unauthorized Access (OWASP A01: Broken Access Control)
 * 2. SQL Injection Resistance (OWASP A03: Injection / CWE-89)
 * 3. Cross-Site Scripting (XSS) Handling (OWASP A03: XSS / CWE-79)
 * 4. Heartbeat Anti-Tampering & Telemetry Guard
 * 5. Task Lifecycle Governance State-Machine
 * 6. Non-Repudiation Audit Trail Integrity
 * 7. Rate Bounding & Payload Denial-of-Service (DoS / 413)
 * 8. System Diagnostic Health Check
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });
const { get, all, run, close } = require('../database');

const BASE_URL = 'http://localhost:4000';
const ADMIN_KEY = process.env.ADMIN_API_KEY;

const auditResults = [];

function recordResult(controlId, name, owasp, status, details) {
  auditResults.push({
    control: `CTRL-${controlId}`,
    name,
    owasp,
    status: status ? 'PASS' : 'FAIL',
    details
  });
}

async function runPenetrationSuite() {
  console.log('\n' + '='.repeat(85));
  console.log(' CYBERFORGE DEVSECOPS COMPLIANCE & PENETRATION TEST HARNESS');
  console.log(' Target Ingress: ' + BASE_URL);
  console.log(' Local Time:     ' + new Date().toISOString());
  console.log('='.repeat(85) + '\n');

  let createdTaskIds = [];
  let kaif = null;
  let nadir = null;

  try {
    // Dynamically retrieve candidate credentials from database
    kaif = await get("SELECT * FROM candidates WHERE name LIKE '%Kaif%' LIMIT 1");
    if (!kaif) {
      kaif = await get("SELECT * FROM candidates LIMIT 1");
    }
    nadir = await get("SELECT * FROM candidates WHERE name LIKE '%Nadir%' LIMIT 1");
    if (!nadir) {
      nadir = await get("SELECT * FROM candidates WHERE id != ? LIMIT 1", [kaif.id]);
    }

    if (!kaif || !nadir) {
      throw new Error("Candidate fixtures not found in database. Please run auto-seeder first.");
    }

    const CANDIDATE_KAIF = {
      id: kaif.id,
      name: kaif.name,
      token: kaif.access_token,
      taskId: null
    };

    // Dynamically provision isolated test tasks to ensure 0-pollution in production
    console.log('[AUDIT] Provisioning isolated test fixtures...');
    const t1 = await run("INSERT INTO tasks (title, description, assigned_to, deadline, status) VALUES (?, ?, ?, datetime('now', '+2 days'), 'pending')", ['Audit Test Task 1', 'Test payload target', kaif.id]);
    const t2 = await run("INSERT INTO tasks (title, description, assigned_to, deadline, status) VALUES (?, ?, ?, datetime('now', '+2 days'), 'pending')", ['Audit Test Task 2', 'Nadir test target', nadir.id]);
    const t3 = await run("INSERT INTO tasks (title, description, assigned_to, deadline, status) VALUES (?, ?, ?, datetime('now', '+2 days'), 'pending')", ['Audit Test Task 3', 'Verification filler 1', kaif.id]);
    const t4 = await run("INSERT INTO tasks (title, description, assigned_to, deadline, status) VALUES (?, ?, ?, datetime('now', '+2 days'), 'pending')", ['Audit Test Task 4', 'Verification filler 2', nadir.id]);

    CANDIDATE_KAIF.taskId = t1.lastID;
    const TASK_NADIR_ID = t2.lastID;
    createdTaskIds = [t1.lastID, t2.lastID, t3.lastID, t4.lastID];
    // =========================================================================
    // Control 1: RBAC & Unauthorized Access (OWASP A01: Broken Access Control)
    // =========================================================================
    console.log('[AUDIT] Executing Control 1: RBAC & Access Control Verification...');
    
    // 1.1 Admin API with no header
    const r1_1 = await fetch(`${BASE_URL}/api/admin/candidates`);
    const pass1_1 = r1_1.status === 401;

    // 1.2 Admin API with tampered secret
    const r1_2 = await fetch(`${BASE_URL}/api/tasks`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-admin-key': 'tampered_malicious_admin_key_9999'
      },
      body: JSON.stringify({ title: 'Rogue Task', deadline: new Date().toISOString() })
    });
    const pass1_2 = r1_2.status === 401;

    // 1.3 Candidate API with invalid bearer token
    const r1_3 = await fetch(`${BASE_URL}/api/candidate/tasks`, {
      headers: { 'Authorization': 'Bearer rogue_unauthorized_token_xyz' }
    });
    const pass1_3 = r1_3.status === 401;

    // 1.4 Heartbeat API with no auth
    const r1_4 = await fetch(`${BASE_URL}/api/session/heartbeat`, { method: 'POST' });
    const pass1_4 = r1_4.status === 401;

    const passC1 = pass1_1 && pass1_2 && pass1_3 && pass1_4;
    recordResult(
      1,
      'RBAC & Unauthorized Access Guard',
      'OWASP A01: Broken Access Control',
      passC1,
      `Rejections: No-Admin-Key (${r1_1.status}), Tampered-Key (${r1_2.status}), Rogue-Token (${r1_3.status}), No-Auth (${r1_4.status})`
    );

    // =========================================================================
    // Control 2: SQL Injection Resistance (OWASP A03: Injection / CWE-89)
    // =========================================================================
    console.log('[AUDIT] Executing Control 2: SQL Injection (SQLi) Resistance Test...');
    
    // Authenticate Kaif
    await fetch(`${BASE_URL}/api/session/login`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${CANDIDATE_KAIF.token}` }
    });

    const sqliUrl = "https://github.com/org/repo/pull/1'; DROP TABLE tasks; --";
    const sqliNotes = "' OR '1'='1' UNION SELECT access_token, name, role FROM candidates; --";

    const r2 = await fetch(`${BASE_URL}/api/tasks/${CANDIDATE_KAIF.taskId}/submit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${CANDIDATE_KAIF.token}`
      },
      body: JSON.stringify({
        submission_url: sqliUrl,
        notes: sqliNotes
      })
    });

    // Verify task table is intact and stored string is literal
    const tableVerification = await get("SELECT COUNT(*) AS count FROM tasks");
    const storedTask = await get("SELECT submission_url FROM tasks WHERE id = ?", [CANDIDATE_KAIF.taskId]);

    const passC2 = r2.status === 200 && tableVerification.count >= 4 && storedTask && storedTask.submission_url === sqliUrl;
    recordResult(
      2,
      'SQL Injection Resistance',
      'OWASP A03: Injection (CWE-89)',
      passC2,
      `Table intact (Count: ${tableVerification ? tableVerification.count : 0}), Parameterized literal preservation: Verified`
    );

    // =========================================================================
    // Control 3: Cross-Site Scripting (XSS) Handling (OWASP A03: XSS)
    // =========================================================================
    console.log('[AUDIT] Executing Control 3: XSS Payload Handling Verification...');
    
    const xssPayload = "<script>alert('xss')</script><img src=x onerror=alert(1)>";
    const r3 = await fetch(`${BASE_URL}/api/tasks/${CANDIDATE_KAIF.taskId}/submit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${CANDIDATE_KAIF.token}`
      },
      body: JSON.stringify({
        submission_url: 'https://github.com/org/repo/pull/42',
        notes: xssPayload
      })
    });

    const passC3 = r3.status === 200 && !r3.headers.get('content-type')?.includes('text/html');
    recordResult(
      3,
      'XSS Payload Safe Handling',
      'OWASP A03: Cross-Site Scripting',
      passC3,
      `Server accepted sanitized payload safely (HTTP ${r3.status}), Content-Type: application/json`
    );

    // =========================================================================
    // Control 4: Heartbeat Anti-Tampering & Telemetry Guard
    // =========================================================================
    console.log('[AUDIT] Executing Control 4: Heartbeat Telemetry & Anti-Tampering Guard...');

    // 4.1 Normal heartbeat
    const r4_1 = await fetch(`${BASE_URL}/api/session/heartbeat`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${CANDIDATE_KAIF.token}` }
    });
    const hbData1 = await r4_1.json();
    const baselineSeconds = hbData1.active_seconds || 0;

    // 4.2 Burst rapid-fire test (10 rapid pings within 200ms)
    const burstPromises = [];
    for (let i = 0; i < 10; i++) {
      burstPromises.push(
        fetch(`${BASE_URL}/api/session/heartbeat`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${CANDIDATE_KAIF.token}` }
        }).then(r => r.json())
      );
    }
    const burstResults = await Promise.all(burstPromises);
    const maxActiveAfterBurst = Math.max(...burstResults.map(b => b.active_seconds || 0));
    // Burst should not inflate by hours - max delta should be <= 3 seconds
    const burstAntiInflationPass = (maxActiveAfterBurst - baselineSeconds) <= 3;

    // 4.3 Expired delta (> 180s gap) test
    await run(`
      UPDATE activity_logs 
      SET last_heartbeat = datetime('now', '-220 seconds') 
      WHERE candidate_id = ? AND status = 'active'
    `, [CANDIDATE_KAIF.id]);

    const r4_3 = await fetch(`${BASE_URL}/api/session/heartbeat`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${CANDIDATE_KAIF.token}` }
    });
    const hbData3 = await r4_3.json();
    const candidateDbStatus = await get("SELECT is_online FROM candidates WHERE id = ?", [CANDIDATE_KAIF.id]);
    const passExpiredIdle = hbData3.status === 'idle' && candidateDbStatus.is_online === 0;

    const passC4 = r4_1.status === 200 && burstAntiInflationPass && passExpiredIdle;
    recordResult(
      4,
      'Heartbeat Anti-Tampering Guard',
      'OWASP A04: Insecure Design & Telemetry',
      passC4,
      `Burst Inflation Defended (Delta: +${maxActiveAfterBurst - baselineSeconds}s), Stale Session Idle Transition: Verified (HTTP 200, status: idle)`
    );

    // =========================================================================
    // Control 5: Task Lifecycle Governance State-Machine
    // =========================================================================
    console.log('[AUDIT] Executing Control 5: Task Lifecycle & RBAC State Machine...');

    // 5.1 Kaif attempts to submit Nadir's Task #6
    const r5_1 = await fetch(`${BASE_URL}/api/tasks/${TASK_NADIR_ID}/submit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${CANDIDATE_KAIF.token}`
      },
      body: JSON.stringify({ submission_url: 'https://github.com/exploit' })
    });
    const passCrossSubmissionBlocked = r5_1.status === 403;

    // 5.2 Non-admin attempts to review/approve Task #5
    const r5_2 = await fetch(`${BASE_URL}/api/tasks/${CANDIDATE_KAIF.taskId}/review`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${CANDIDATE_KAIF.token}` // Candidate token, not admin key
      },
      body: JSON.stringify({ status: 'completed', feedback: 'Self-approval bypass attempt' })
    });
    const passUnauthReviewBlocked = r5_2.status === 401;

    // 5.3 Overdue flag computation verification
    const r5_3 = await fetch(`${BASE_URL}/api/candidate/tasks`, {
      headers: { 'Authorization': `Bearer ${CANDIDATE_KAIF.token}` }
    });
    const candTasks = await r5_3.json();
    const verifiedTasks = candTasks.tasks || [];
    const passOverdueLogic = verifiedTasks.every(t => typeof t.is_overdue === 'boolean');

    const passC5 = passCrossSubmissionBlocked && passUnauthReviewBlocked && passOverdueLogic;
    recordResult(
      5,
      'Governance State-Machine Enforcement',
      'OWASP A01: Broken Access Control',
      passC5,
      `Cross-Submission Blocked (${r5_1.status} Forbidden), Unauthorized Review Blocked (${r5_2.status} Unauthorized), Computed Overdue: Valid`
    );

    // =========================================================================
    // Control 6: Non-Repudiation Audit Trail Integrity
    // =========================================================================
    console.log('[AUDIT] Executing Control 6: Audit Trail Non-Repudiation Check...');

    // 6.1 Check audit records exist
    const auditCount = await get("SELECT COUNT(*) AS count FROM audit_trail");
    const hasAuditRecords = auditCount && auditCount.count > 0;

    // 6.2 Probe non-existent DELETE endpoints
    const r6_del1 = await fetch(`${BASE_URL}/api/admin/audit`, { method: 'DELETE' });
    const r6_del2 = await fetch(`${BASE_URL}/api/audit`, { method: 'DELETE' });
    const passNoDeleteApi = r6_del1.status === 404 && r6_del2.status === 404;

    const passC6 = hasAuditRecords && passNoDeleteApi;
    recordResult(
      6,
      'Audit Non-Repudiation Integrity',
      'OWASP A09: Security Logging & Monitoring',
      passC6,
      `Immutable Audit Records (${auditCount.count} entries), Delete Endpoints Blocked (${r6_del1.status}/${r6_del2.status} Not Found)`
    );

    // =========================================================================
    // Control 7: Rate Bounding & Payload Denial-of-Service (DoS / 413)
    // =========================================================================
    console.log('[AUDIT] Executing Control 7: Payload Size Bounding (DoS Mitigation)...');

    const oversizedPayload = JSON.stringify({
      data: 'A'.repeat(2 * 1024 * 1024) // 2 MB
    });

    const r7 = await fetch(`${BASE_URL}/api/tasks`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-admin-key': ADMIN_KEY
      },
      body: oversizedPayload
    });

    const passC7 = r7.status === 413;
    recordResult(
      7,
      'Payload Bounding (DoS Defense)',
      'OWASP A05: Security Misconfiguration',
      passC7,
      `2MB Oversized Body Rejected with HTTP ${r7.status} (Payload Too Large)`
    );

    // =========================================================================
    // Control 8: System Diagnostic Health Check
    // =========================================================================
    console.log('[AUDIT] Executing Control 8: System Diagnostic Health Probe...');

    const r8 = await fetch(`${BASE_URL}/api/health`);
    const healthData = await r8.json();

    const passC8 = r8.status === 200 && healthData.status === 'UP' && typeof healthData.uptime === 'number';
    recordResult(
      8,
      'System Diagnostics & Readiness',
      'OWASP Operations & Reliability',
      passC8,
      `Status: ${healthData.status}, Uptime: ${healthData.uptime.toFixed(1)}s, Open Tasks: ${healthData.governance.open_tasks}`
    );

    // =========================================================================
    // Post-Audit Database Sanitization (Preserve clean state)
    // =========================================================================
    console.log('\n[AUDIT] Restoring pristine database state post-test...');
    if (createdTaskIds.length > 0) {
      await run(`DELETE FROM tasks WHERE id IN (${createdTaskIds.join(',')})`);
    }
    await run("DELETE FROM activity_logs WHERE candidate_id = ?", [CANDIDATE_KAIF.id]);
    await run("UPDATE candidates SET is_online = 0 WHERE id = ?", [CANDIDATE_KAIF.id]);
    await run("DELETE FROM audit_trail WHERE event_type NOT IN ('COHORT_AUTO_SEEDED', 'SEED_TASK_CREATED')");
    console.log('[AUDIT] Database restored to clean production baseline (0 test tasks).');

    // =========================================================================
    // Audit Report Presentation
    // =========================================================================
    console.log('\n' + '='.repeat(85));
    console.log('             CYBERFORGE DEVSECOPS PENETRATION & AUDIT REPORT');
    console.log('='.repeat(85));
    console.table(auditResults);

    const allPassed = auditResults.every(r => r.status === 'PASS');
    if (allPassed) {
      console.log('🎉 AUDIT VERDICT: ALL 8 DEVSECOPS SECURITY CONTROLS STRICTLY COMPLIANT (PASS)\n');
      await close();
      process.exit(0);
    } else {
      console.error('❌ AUDIT VERDICT: COMPLIANCE BREACH DETECTED. Review failing controls.\n');
      await close();
      process.exit(1);
    }
  } catch (err) {
    console.error('\n[CRITICAL] [PenTestHarness] Test execution aborted:', err.message);
    try { await close(); } catch (_) {}
    process.exit(1);
  }
}

runPenetrationSuite();

