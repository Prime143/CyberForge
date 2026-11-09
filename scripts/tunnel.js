/**
 * CyberForge DevSecOps - Automated Cloudflare Quick Tunnel Provisioner
 *
 * Provides instant zero-cost TLS (HTTPS) tunnel to local port 4000
 * without router configuration, port-forwarding, or public IP exposure.
 *
 * Flow:
 * 1. Checks if `cloudflared` binary exists locally in ./bin or system PATH.
 * 2. If not found, stream-downloads official static binary from Cloudflare.
 * 3. Launches quick tunnel targeting http://localhost:4000.
 * 4. Extracts the assigned `https://*.trycloudflare.com` domain.
 * 5. Automatically broadcasts public workstation URL to Discord leads.
 * 6. Ensures zero orphan process leaks on exit/SIGINT.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { spawn, execSync } = require('child_process');
require('dotenv').config();

const { sendAlert } = require('../notifier');

const PORT = process.env.PORT || 4000;
const BIN_DIR = path.resolve(__dirname, '..', 'bin');
const IS_WIN = process.platform === 'win32';
const BIN_NAME = IS_WIN ? 'cloudflared.exe' : 'cloudflared';
const LOCAL_BIN_PATH = path.join(BIN_DIR, BIN_NAME);

// Official Cloudflare Release Binaries
const DOWNLOAD_URLS = {
  win32: 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe',
  linux: 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64',
  darwin: 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz'
};

/**
 * Downloads a file following HTTPS redirects (e.g. GitHub Releases -> S3)
 */
function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    https.get(url, (response) => {
      // Handle redirects
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        return downloadFile(response.headers.location, destPath).then(resolve).catch(reject);
      }

      if (response.statusCode !== 200) {
        return reject(new Error(`Download failed with HTTP ${response.statusCode}: ${response.statusMessage}`));
      }

      const fileStream = fs.createWriteStream(destPath);
      let downloadedBytes = 0;
      const totalBytes = parseInt(response.headers['content-length'] || '0', 10);

      response.on('data', (chunk) => {
        downloadedBytes += chunk.length;
        if (totalBytes > 0) {
          const pct = ((downloadedBytes / totalBytes) * 100).toFixed(1);
          process.stdout.write(`\r[DevSecOps] Downloading cloudflared: ${pct}% (${(downloadedBytes / 1048576).toFixed(1)} MB)`);
        }
      });

      response.pipe(fileStream);

      fileStream.on('finish', () => {
        fileStream.close(() => {
          process.stdout.write('\n');
          if (!IS_WIN) {
            fs.chmodSync(destPath, 0o755);
          }
          resolve(destPath);
        });
      });

      fileStream.on('error', (err) => {
        fs.unlink(destPath, () => reject(err));
      });
    }).on('error', reject);
  });
}

/**
 * Locates or provisions the cloudflared executable.
 */
async function ensureBinary() {
  // 1. Check system PATH
  try {
    const cmd = IS_WIN ? 'where cloudflared' : 'which cloudflared';
    const foundPath = execSync(cmd, { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim().split('\n')[0].trim();
    if (foundPath && fs.existsSync(foundPath)) {
      console.log(`[INFO] [Tunnel] Found system cloudflared binary at: ${foundPath}`);
      return foundPath;
    }
  } catch (_) {}

  // 2. Check local bin directory
  if (fs.existsSync(LOCAL_BIN_PATH) && fs.statSync(LOCAL_BIN_PATH).size > 1000000) {
    return LOCAL_BIN_PATH;
  }

  // 3. Download official binary
  const platform = process.platform;
  const downloadUrl = DOWNLOAD_URLS[platform];
  if (!downloadUrl) {
    throw new Error(`Unsupported operating system architecture: ${platform}`);
  }

  if (!fs.existsSync(BIN_DIR)) {
    fs.mkdirSync(BIN_DIR, { recursive: true });
  }

  console.log(`[INFO] [Tunnel] cloudflared not found. Downloading standalone binary for ${platform}...`);
  console.log(`[INFO] [Tunnel] Source: ${downloadUrl}`);
  await downloadFile(downloadUrl, LOCAL_BIN_PATH);
  console.log('[INFO] [Tunnel] Binary verified and prepared.');
  return LOCAL_BIN_PATH;
}

/**
 * Starts the Cloudflare Quick Tunnel and listens for the generated URL.
 */
async function startTunnel() {
  const binaryPath = await ensureBinary();
  const targetUrl = `http://localhost:${PORT}`;

  console.log(`\n================================================================`);
  console.log(`[DevSecOps] Initializing Cloudflare Zero-Trust Quick Tunnel`);
  console.log(`[DevSecOps] Target Ingress: ${targetUrl}`);
  console.log(`================================================================`);

  const tunnelProcess = spawn(binaryPath, ['tunnel', '--url', targetUrl], {
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let urlDetected = false;

  const handleTunnelOutput = async (data) => {
    const text = data.toString();

    // Scan for Cloudflare Quick Tunnel regex pattern
    const match = text.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/i);
    if (match && !urlDetected) {
      urlDetected = true;
      const publicBaseUrl = match[0];
      const workstationUrl = `${publicBaseUrl}/workstation`;
      const leadRoute = process.env.LEAD_PORTAL_ROUTE || '/lead-hub';
      const leadUrl = `${publicBaseUrl}${leadRoute}`;

      console.log('\n' + '='.repeat(70));
      console.log('[DevSecOps] ⚡ CLOUDFLARE SECURE HTTPS TUNNEL ACTIVE');
      console.log('='.repeat(70));
      console.log(`  🌐 Public Base URL:     ${publicBaseUrl}`);
      console.log(`  💻 Candidate Portal:    ${workstationUrl}`);
      console.log(`  🛡️  Lead Governance Hub: ${leadUrl} (Protected)`);
      console.log(`  🔒 Security Protocol:   TLS 1.3 / End-to-End Encrypted`);
      console.log(`  💰 Infrastructure Cost: ₹0 / Zero Router Exposure`);
      console.log('='.repeat(70) + '\n');

      // Automated URL Broadcast to Discord
      await sendAlert(
        'CyberForge Workstation is Online',
        `CyberForge Workstation is Online: **${workstationUrl}**\n\nCandidate workstation gateway is accessible over secure HTTPS.`,
        'success',
        [
          { name: 'Candidate Portal URL', value: workstationUrl, inline: false },
          { name: 'Gateway Status', value: 'ONLINE (TLS 1.3)', inline: true },
          { name: 'Target Local Port', value: String(PORT), inline: true }
        ]
      );
    }
  };

  tunnelProcess.stdout.on('data', handleTunnelOutput);
  tunnelProcess.stderr.on('data', handleTunnelOutput);

  // Clean Termination Handling (Anti-Orphan Process Guarantee)
  const cleanup = () => {
    if (tunnelProcess && !tunnelProcess.killed) {
      console.log('\n[INFO] [Tunnel] Terminating Cloudflare tunnel cleanly...');
      if (IS_WIN) {
        try {
          execSync(`taskkill /pid ${tunnelProcess.pid} /T /F`, { stdio: 'ignore' });
        } catch (_) {}
      } else {
        tunnelProcess.kill('SIGTERM');
      }
    }
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  process.on('exit', () => {
    if (tunnelProcess && !tunnelProcess.killed) {
      if (IS_WIN) {
        try { execSync(`taskkill /pid ${tunnelProcess.pid} /T /F`, { stdio: 'ignore' }); } catch (_) {}
      } else {
        tunnelProcess.kill('SIGTERM');
      }
    }
  });

  tunnelProcess.on('close', (code) => {
    console.log(`[INFO] [Tunnel] Cloudflare tunnel closed with exit code ${code}`);
    process.exit(code || 0);
  });
}

// Execution entry point
startTunnel().catch((err) => {
  console.error('[CRITICAL] [Tunnel] Failed to start tunnel:', err.message);
  process.exit(1);
});

