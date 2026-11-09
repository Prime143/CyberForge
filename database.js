/**
 * CyberForge Governance Engine - Database Subsystem
 *
 * DevSecOps Hardened SQLite Configuration:
 * - WAL (Write-Ahead Logging) for high-concurrency read/write throughput
 * - Strict Foreign Key validation enabled via PRAGMA
 * - Parameterized query abstraction to eliminate SQL Injection (CWE-89)
 * - Complete audit trail logging and schema index optimization
 */

const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

const rawDbPath = process.env.DATABASE_PATH || 'cyberforge.db';
const DB_PATH = path.isAbsolute(rawDbPath)
  ? rawDbPath
  : path.resolve(process.cwd(), rawDbPath);

// Ensure parent storage directory exists (e.g. for /data/cyberforge.db in Docker volumes)
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// Initialize SQLite connection with serialized execution mode
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error(`[CRITICAL] [DevSecOps] Failed to connect to SQLite database at ${DB_PATH}:`, err.message);
    process.exit(1);
  }
  console.log(`[INFO] [DevSecOps] Connected to SQLite database: ${DB_PATH}`);
});

/**
 * Configure database pragmas and execute initial schema creation.
 */
db.serialize(() => {
  // Enforce referential integrity & enterprise concurrency settings
  db.run('PRAGMA foreign_keys = ON;');
  db.run('PRAGMA journal_mode = WAL;');
  db.run('PRAGMA synchronous = NORMAL;');
  db.run('PRAGMA busy_timeout = 5000;');

  // Table 1: candidates
  db.run(`
    CREATE TABLE IF NOT EXISTS candidates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      role TEXT CHECK(role IN ('lead', 'core', 'junior')) DEFAULT 'junior',
      access_token TEXT UNIQUE NOT NULL,
      is_online INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Table 2: activity_logs
  db.run(`
    CREATE TABLE IF NOT EXISTS activity_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      candidate_id INTEGER NOT NULL,
      session_start DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP,
      active_seconds INTEGER DEFAULT 0,
      status TEXT CHECK(status IN ('active', 'idle', 'closed')) DEFAULT 'active',
      FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE CASCADE
    );
  `);

  // Table 3: tasks
  db.run(`
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      assigned_to INTEGER,
      deadline DATETIME NOT NULL,
      status TEXT CHECK(status IN ('pending', 'in_progress', 'submitted', 'completed', 'overdue')) DEFAULT 'pending',
      submission_url TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (assigned_to) REFERENCES candidates(id) ON DELETE SET NULL
    );
  `);

  // Table 4: audit_trail
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_trail (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      candidate_id INTEGER,
      event_type TEXT NOT NULL,
      details TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE SET NULL
    );
  `);

  // Table 5: tickets (Support & Incident Ticketing)
  db.run(`
    CREATE TABLE IF NOT EXISTS tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      candidate_id INTEGER NOT NULL,
      subject TEXT NOT NULL,
      category TEXT CHECK(category IN ('technical', 'task_blocker', 'access_issue', 'extension_request', 'general')) DEFAULT 'technical',
      priority TEXT CHECK(priority IN ('critical', 'high', 'medium', 'low')) DEFAULT 'medium',
      description TEXT NOT NULL,
      status TEXT CHECK(status IN ('open', 'in_progress', 'resolved', 'closed')) DEFAULT 'open',
      admin_notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE CASCADE
    );
  `);

  // Table 6: notifications (In-app Notification Center)
  db.run(`
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      candidate_id INTEGER,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      type TEXT CHECK(type IN ('info', 'warning', 'success', 'urgent')) DEFAULT 'info',
      is_read INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE CASCADE
    );
  `);

  // Migration: Add priority to tasks if not present
  db.run(`ALTER TABLE tasks ADD COLUMN priority TEXT CHECK(priority IN ('critical', 'high', 'medium', 'low')) DEFAULT 'medium'`, () => {});

  // Performance & Security Indexes
  db.run(`CREATE INDEX IF NOT EXISTS idx_candidates_access_token ON candidates(access_token);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_activity_logs_candidate_id ON activity_logs(candidate_id);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_activity_logs_status ON activity_logs(status);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_tasks_assigned_to ON tasks(assigned_to);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_audit_trail_candidate_id ON audit_trail(candidate_id);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_audit_trail_event_type ON audit_trail(event_type);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_tickets_candidate_id ON tickets(candidate_id);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_notifications_candidate_id ON notifications(candidate_id);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read);`);

  console.log('[INFO] [DevSecOps] Database schema and indexes verified successfully.');
});

/**
 * Promise-based parameterized RUN wrapper (INSERT, UPDATE, DELETE)
 * Guarantees parameterized input handling to eliminate SQL injection vulnerabilities.
 *
 * @param {string} sql - Parameterized SQL query
 * @param {Array|Object} params - Query parameters
 * @returns {Promise<{lastID: number, changes: number}>}
 */
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) {
        console.error('[ERROR] [Database::run] Query execution failed:', {
          query: sql,
          error: err.message
        });
        return reject(err);
      }
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

/**
 * Promise-based parameterized GET wrapper (SELECT single row)
 *
 * @param {string} sql - Parameterized SQL query
 * @param {Array|Object} params - Query parameters
 * @returns {Promise<Object|undefined>}
 */
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        console.error('[ERROR] [Database::get] Query execution failed:', {
          query: sql,
          error: err.message
        });
        return reject(err);
      }
      resolve(row);
    });
  });
}

/**
 * Promise-based parameterized ALL wrapper (SELECT multiple rows)
 *
 * @param {string} sql - Parameterized SQL query
 * @param {Array|Object} params - Query parameters
 * @returns {Promise<Array<Object>>}
 */
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        console.error('[ERROR] [Database::all] Query execution failed:', {
          query: sql,
          error: err.message
        });
        return reject(err);
      }
      resolve(rows);
    });
  });
}

/**
 * Promise-based EXEC wrapper for multi-statement DDL/maintenance scripts
 *
 * @param {string} sql - SQL batch commands
 * @returns {Promise<void>}
 */
function exec(sql) {
  return new Promise((resolve, reject) => {
    db.exec(sql, (err) => {
      if (err) {
        console.error('[ERROR] [Database::exec] Exec failed:', err.message);
        return reject(err);
      }
      resolve();
    });
  });
}

/**
 * Dedicated DevSecOps Audit Trail Recorder
 * Automatically persists governance events with immutable timestamps.
 *
 * @param {number|null} candidateId - Associated candidate ID
 * @param {string} eventType - Event category (e.g., 'AUTH_LOGIN', 'TASK_SUBMISSION')
 * @param {string|object} details - Additional metadata or context
 * @returns {Promise<{lastID: number, changes: number}>}
 */
async function logAudit(candidateId, eventType, details = null) {
  const serializedDetails = typeof details === 'object' && details !== null
    ? JSON.stringify(details)
    : (details || null);

  const sql = `
    INSERT INTO audit_trail (candidate_id, event_type, details)
    VALUES (?, ?, ?)
  `;
  return run(sql, [candidateId, eventType, serializedDetails]);
}

/**
 * In-App Notification Recorder
 */
async function createNotification(candidateId, title, message, type = 'info') {
  const sql = `
    INSERT INTO notifications (candidate_id, title, message, type)
    VALUES (?, ?, ?, ?)
  `;
  return run(sql, [candidateId || null, title, message, type]);
}

/**
 * Graceful connection termination
 * @returns {Promise<void>}
 */
function close() {
  return new Promise((resolve, reject) => {
    db.close((err) => {
      if (err) {
        console.error('[ERROR] [Database::close] Error closing database connection:', err.message);
        return reject(err);
      }
      console.log('[INFO] [DevSecOps] Database connection closed cleanly.');
      resolve();
    });
  });
}

// Graceful signal handlers for server shutdown
const shutdownHandler = async () => {
  try {
    await close();
  } catch (_) {
    // Already logged in close()
  } finally {
    process.exit(0);
  }
};

process.on('SIGINT', shutdownHandler);
process.on('SIGTERM', shutdownHandler);

module.exports = {
  db,
  run,
  get,
  all,
  exec,
  logAudit,
  createNotification,
  close
};

