/**
 * CyberForge DevSecOps - Authentication & Governance Middlewares
 */

const { get, logAudit } = require('../database');
require('dotenv').config();

/**
 * Admin Authentication Middleware
 * Validates 'x-admin-key' against ADMIN_API_KEY environment variable.
 */
async function requireAdmin(req, res, next) {
  const adminKey = req.headers['x-admin-key'];
  const configuredKey = process.env.ADMIN_API_KEY;

  if (!adminKey || !configuredKey || adminKey !== configuredKey) {
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
 * Attaches the candidate record to req.candidate.
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
      'SELECT id, name, role, access_token, default_token, custom_token_set, custom_token_created_at, token_reset_requested, token_reset_reason, token_entropy_score, governance_status, exit_reason, exit_timestamp, do326a_track, target_repo_path, github_username, failsafe_active, is_online, created_at FROM candidates WHERE access_token = ?',
      [token]
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

    req.candidate = candidate;
    next();
  } catch (err) {
    console.error('[ERROR] [AuthMiddleware] Verification error:', err.message);
    res.status(500).json({ error: 'Internal server error during authentication' });
  }
}

module.exports = {
  requireAdmin,
  requireCandidate
};
