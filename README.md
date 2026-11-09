# 🛡️ CyberForge — DevSecOps Candidate Governance & Telemetry Engine

CyberForge is a corporate-grade candidate activity tracking, session heartbeat monitoring, and task governance platform built with **Node.js, Express, SQLite (WAL mode), Cloudflare Quick Tunnels, and real-time Discord lead alerts**.

---

## 🌐 Secure Public Ingress & Web Portals

### 1. Cloudflare Quick Tunnel (Zero Router Exposure, TLS 1.3)
- **Candidate Public Workstation**: [`https://coupons-asthma-increases-three.trycloudflare.com/workstation`](https://coupons-asthma-increases-three.trycloudflare.com/workstation)
- **Local Ingress**: `http://localhost:4000/workstation`

### 2. Lead Governance Console (Hardened & Obscured)
- **Local Route**: `http://localhost:4000/lead-hub`
- **Reconnaissance Guard**: Common administrative paths (`/admin`, `/administrator`, `/admin-panel`) return strict `404 Not Found`.
- **In-Memory Credential Security**: Master API Key (`ADMIN_API_KEY`) is stored strictly in ephemeral session memory. It is never logged, exposed in URLs, or rendered in plain text.

---

## 👥 Verified Cohort Registry

The database has been cleaned and hardened to preserve only the 4 authentic cohort members:

| ID | Candidate Name | Role | Status | Access Token |
|:--:|:---------------|:----:|:------:|:-------------|
| `2` | **Kaif Pathan** | `core` | `OFFLINE` | `04521968ccdc2d5bc71066dd3aed7f82` |
| `3` | **Nadir Murudkar** | `core` | `OFFLINE` | `1f4297bf57f572146c5281df4db52c6d` |
| `4` | **Tejal Puthran** | `core` | `OFFLINE` | `e79155d935fb61ae6e5c4ac0f299aa28` |
| `5` | **Khot Maaz** | `junior` | `OFFLINE` | `2e16602939e3e77a4ea4e9b263ce6885` |

---

## 📋 Active Governance Tasks

| Task ID | Assigned To | Task Title | Deadline | Status |
|:---:|:---|:---|:---:|:---:|
| **#5** | Kaif Pathan | **Ingress HMAC-SHA256 Signature Middleware** | 2026-11-11 18:00 UTC | `pending` |
| **#6** | Nadir Murudkar | **Resilient Heartbeat Telemetry Client** | 2026-11-11 18:00 UTC | `pending` |
| **#7** | Tejal Puthran | **Immutable Audit Log Streamer** | 2026-11-12 12:00 UTC | `pending` |
| **#8** | Khot Maaz | **API Payload Sanitization & Schema Guard** | 2026-11-12 12:00 UTC | `pending` |

---

## 🚀 DevSecOps Commands

```bash
# 1. Start CyberForge server locally
npm start

# 2. Expose secure Cloudflare Quick Tunnel (₹0, TLS 1.3, auto-broadcast to Discord)
npm run tunnel

# 3. Seed / Sync governance tasks
npm run seed:tasks

# 4. Run automated production sanitization sweep
npm run clean:db

# 5. Run zero-dependency security & penetration verification harness
npm run audit:security

# 6. Run isolated sandbox tests (zero live database contamination)
npm test

# 7. Production Container Deployment (Docker Compose)
docker compose -f docker-compose.prod.yml up -d --build
```

---

## 🔒 Security Hardening Highlights

- **Zero SQL Injection (CWE-89)**: All SQLite queries executed via strictly parameterized wrappers.
- **Anti-Tampering Heartbeat**: Rejects gaps $> 180$ seconds, sets session to `idle`, flags candidate offline.
- **Payload Bounding (CWE-400)**: Express strictly enforces 1MB body limit (`413 Payload Too Large`).
- **Fail-Safe Alerting**: Asynchronous Discord webhooks with 5-second timeout protection.
- **Automated Sweeper**: 60-second periodic audit sweep for idle heartbeats and task expirations.
- **Automated Pen-Test Suite**: Zero-dependency automated security verification harness validating all 8 OWASP/CWE controls.
