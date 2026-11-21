/**
 * CyberForge DevSecOps - Authentication & Governance Middlewares
 * 
 * Security hardening per OWASP ASVS & CIS Benchmark controls:
 * - CWE-208: Timing-safe credential comparison (crypto.timingSafeEqual)
 * - CWE-307: Account lockout on repeated failures
 * - CWE-287: Parameterized token lookup (zero SQLi)
 * - CWE-532: No credential exposure in logs (token prefix only)
 */

const crypto = require('crypto');
const { get, run, logAudit } = require('../database');
require('dotenv').config();

/**
 * Constant-time string comparison to prevent timing-based token oracle attacks.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aBuf = Buffer.from(a, 'utf8');
  const bBuf = Buffer.from(b, 'utf8');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

/**
 * Admin Authentication Middleware
 * Validates 'x-admin-key' against ADMIN_API_KEY environment variable.
 * Uses timing-safe comparison to prevent oracle attacks.
 */
async function requireAdmin(req, res, next) {
  const adminKey = req.headers['x-admin-key'];
  const configuredKey = process.env.ADMIN_API_KEY;

  if (!adminKey || !configuredKey || !safeCompare(adminKey, configuredKey)) {
    try {
      await logAudit(null, 'UNAUTHORIZED_ADMIN_ACCESS_ATTEMPT', {
        ip: req.ip || req.socket.remoteAddress,
        path: req.originalUrl,
        method: req.method
      });
    } catch (_) {}

    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Missing or invalid administrator API key.'
    });
  }

  req.isAdmin = true;
  next();
}

/**
 * Candidate Authentication Middleware
 * Validates 'Authorization: Bearer <access_token>' against the candidates table.
 * Enforces account lockout, attaches candidate record to req.candidate.
 */
async function requireCandidate(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Candidate access token required. Header format: Authorization: Bearer <access_token>'
    });
  }

  const token = authHeader.substring(7).trim();

  if (!token) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Empty candidate access token provided.'
    });
  }

  try {
    const candidate = await get(
      `SELECT id, name, role, access_token, default_token, custom_token_set, 
              custom_token_created_at, token_reset_requested, token_reset_reason, 
              token_entropy_score, governance_status, exit_reason, exit_timestamp, 
              do326a_track, target_repo_path, github_username, failsafe_active, 
              is_online, created_at, failed_attempts, locked_until, must_change_token,
              last_login_at, last_login_ip
       FROM candidates WHERE access_token = ? OR default_token = ?`,
      [token, token]
    );

    if (!candidate) {
      await logAudit(null, 'INVALID_CANDIDATE_TOKEN_ATTEMPT', {
        ip: req.ip || req.socket.remoteAddress,
        tokenExcerpt: token.substring(0, 6) + '...'
      });

      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid candidate access token.'
      });
    }

    // CWE-307: Account lockout enforcement
    if (candidate.locked_until) {
      const lockExpiry = new Date(candidate.locked_until);
      if (lockExpiry > new Date()) {
        const remainingMs = lockExpiry - new Date();
        const remainingMin = Math.ceil(remainingMs / 60000);
        await logAudit(candidate.id, 'AUTH_ATTEMPT_WHILE_LOCKED', {
          ip: req.ip || req.socket.remoteAddress,
          remainingMinutes: remainingMin
        });
        return res.status(423).json({
          error: 'Account Locked',
          message: `Account temporarily locked due to repeated failed authentication attempts. Try again in ${remainingMin} minute(s).`
        });
      }
      // Lock expired — clear it
      run('UPDATE candidates SET locked_until = NULL, failed_attempts = 0 WHERE id = ?', [candidate.id]).catch(() => {});
    }

    req.candidate = candidate;
    next();
  } catch (err) {
    console.error('[ERROR] [AuthMiddleware] Verification error:', err.message);
    res.status(500).json({ error: 'Internal server error during authentication' });
  }
}

module.exports = {
  safeCompare,
  requireAdmin,
  requireCandidate
};
