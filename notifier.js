/**
 * CyberForge Governance Engine - Discord Webhook Notifier
 *
 * Real-time DevSecOps Alerting Channel:
 * - Emits security, candidate activity, and governance alerts to designated lead Discord channels
 * - Non-blocking architecture with timeout protection (never halts transaction workflows)
 * - Flexible color mapping (hex strings, integer codes, or semantic presets)
 * - Rate-limit (HTTP 429) awareness and secure payload truncation
 */

const axios = require('axios');
require('dotenv').config();

// Standard DevSecOps Severity Palette
const COLOR_PALETTE = {
  success: 0x2ECC71,  // Green (e.g., candidate login, task completed)
  info: 0x3498DB,     // Blue (e.g., heartbeat resumed, candidate online)
  warning: 0xF39C12,  // Amber (e.g., candidate went idle, deadline approaching)
  danger: 0xE74C3C,   // Red (e.g., task overdue, unauthorized access attempt)
  lead: 0x9B59B6,     // Purple (e.g., lead promotion, critical governance event)
  default: 0x5865F2   // Discord Blurple
};

/**
 * Normalizes input color to Discord's required decimal integer format.
 *
 * @param {string|number} color - Preset name, hex string, or decimal integer
 * @returns {number}
 */
function resolveColor(color) {
  if (typeof color === 'number' && Number.isInteger(color)) {
    return color;
  }

  if (typeof color === 'string') {
    const normalized = color.trim().toLowerCase();
    if (COLOR_PALETTE[normalized]) {
      return COLOR_PALETTE[normalized];
    }
    // Handle hex strings like "#2ECC71" or "2ECC71"
    const hex = normalized.replace(/^#/, '');
    if (/^[0-9a-f]{6}$/.test(hex)) {
      return parseInt(hex, 16);
    }
  }

  return COLOR_PALETTE.default;
}

/**
 * Broadcasts real-time events to the configured Discord channel via webhook.
 * Designed to be fail-safe: failures are logged without crashing the calling process.
 *
 * @param {string} title - Brief headline of the event
 * @param {string} message - Detailed event description or markdown-formatted summary
 * @param {string|number} [color='info'] - Semantic preset ('success'|'info'|'warning'|'danger'|'lead') or hex code
 * @param {Array<{name: string, value: string, inline?: boolean}>} [fields=[]] - Optional structured metadata fields
 * @returns {Promise<{success: boolean, error?: string}>}
 */
async function sendAlert(title, message, color = 'info', fields = []) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;

  // Silent fallback when Discord webhook is unconfigured or not in use
  if (!webhookUrl || webhookUrl.includes('webhooks/...')) {
    return { success: false, reason: 'DISCORD_NOT_CONFIGURED' };
  }

  // Ensure title and description fit within Discord limits
  const safeTitle = (title || 'CyberForge Governance Alert').substring(0, 256);
  const safeMessage = (message || '').substring(0, 4000);

  const payload = {
    username: 'CyberForge Lead Bot',
    avatar_url: 'https://cdn-icons-png.flaticon.com/512/9440/9440539.png',
    embeds: [
      {
        title: safeTitle,
        description: safeMessage,
        color: resolveColor(color),
        fields: Array.isArray(fields) ? fields.slice(0, 25) : [],
        timestamp: new Date().toISOString(),
        footer: {
          text: 'CyberForge Candidate Governance & Activity Engine'
        }
      }
    ]
  };

  try {
    await axios.post(webhookUrl, payload, {
      headers: {
        'Content-Type': 'application/json'
      },
      timeout: 5000 // 5-second timeout to prevent blocking worker threads
    });

    console.log(`[INFO] [Notifier] Successfully dispatched Discord alert: "${safeTitle}"`);
    return { success: true };
  } catch (err) {
    const errorDetails = err.response
      ? `HTTP ${err.response.status} - ${JSON.stringify(err.response.data)}`
      : err.message;

    console.error(`[ERROR] [Notifier] Failed to dispatch Discord alert: ${errorDetails}`);
    return { success: false, error: errorDetails };
  }
}

module.exports = {
  sendAlert,
  COLOR_PALETTE
};

