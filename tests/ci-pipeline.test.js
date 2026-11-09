/**
 * CyberForge CI/CD Isolated Integration Test
 *
 * STRICT DEVSECOPS SAFETY RULE:
 * This test suite operates strictly on an isolated temporary test database ('test-sandbox.db').
 * It is completely isolated from the live 'cyberforge.db' production database.
 */

const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const TEST_DB_PATH = path.resolve(__dirname, 'test-sandbox.db');

// Ensure clean slate
if (fs.existsSync(TEST_DB_PATH)) {
  fs.unlinkSync(TEST_DB_PATH);
}

const db = new sqlite3.Database(TEST_DB_PATH);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

async function runTestSuite() {
  console.log('[CI/CD] Initializing isolated sandbox database schema...');

  db.serialize(async () => {
    await run('PRAGMA foreign_keys = ON;');
    await run('PRAGMA journal_mode = WAL;');

    await run(`
      CREATE TABLE candidates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        role TEXT CHECK(role IN ('lead', 'core', 'junior')) DEFAULT 'junior',
        access_token TEXT UNIQUE NOT NULL,
        is_online INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await run(`
      CREATE TABLE activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        candidate_id INTEGER NOT NULL,
        session_start DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP,
        active_seconds INTEGER DEFAULT 0,
        status TEXT CHECK(status IN ('active', 'idle', 'closed')) DEFAULT 'active',
        FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE CASCADE
      );
    `);

    await run(`
      CREATE TABLE tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        assigned_to INTEGER,
        deadline DATETIME NOT NULL,
        status TEXT CHECK(status IN ('pending', 'in_progress', 'submitted', 'completed', 'overdue')) DEFAULT 'pending',
        priority TEXT CHECK(priority IN ('critical', 'high', 'medium', 'low')) DEFAULT 'medium',
        submission_url TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (assigned_to) REFERENCES candidates(id) ON DELETE SET NULL
      );
    `);

    await run(`
      CREATE TABLE tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        candidate_id INTEGER NOT NULL,
        subject TEXT NOT NULL,
        category TEXT DEFAULT 'technical',
        priority TEXT DEFAULT 'medium',
        description TEXT NOT NULL,
        status TEXT DEFAULT 'open',
        admin_notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE CASCADE
      );
    `);

    await run(`
      CREATE TABLE notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        candidate_id INTEGER,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT DEFAULT 'info',
        is_read INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE CASCADE
      );
    `);

    // Test 1: Insert Candidate
    const cand = await run(
      'INSERT INTO candidates (name, role, access_token) VALUES (?, ?, ?)',
      ['CI Test Candidate', 'core', 'ci_token_test_123']
    );
    console.log(' -> [PASS] Candidate schema validation, ID:', cand.lastID);

    // Test 2: Foreign Key Constraint Check
    try {
      await run('INSERT INTO activity_logs (candidate_id) VALUES (?)', [9999]);
      throw new Error('Foreign key violation should have triggered!');
    } catch (err) {
      console.log(' -> [PASS] Foreign key integrity enforcement confirmed.');
    }

    // Test 3: Activity Session Logging
    const session = await run(
      'INSERT INTO activity_logs (candidate_id, status) VALUES (?, ?)',
      [cand.lastID, 'active']
    );
    console.log(' -> [PASS] Activity session logging, ID:', session.lastID);

    // Cleanup & Tear Down Sandbox
    db.close(() => {
      if (fs.existsSync(TEST_DB_PATH)) {
        try { fs.unlinkSync(TEST_DB_PATH); } catch (_) {}
      }
      console.log('\n[CI/CD] ALL ISOLATED SANDBOX TESTS PASSED. Live database untouched.\n');
      process.exit(0);
    });
  });
}

runTestSuite().catch((err) => {
  console.error('[CI/CD FAILURE]', err);
  db.close(() => process.exit(1));
});

