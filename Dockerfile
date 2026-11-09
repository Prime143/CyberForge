# ==============================================================================
# CyberForge Production Multi-Stage Hardened Dockerfile
# Base: node:20-alpine (Minimal attack surface, zero extraneous tools)
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Builder (Compile native addons & production dependencies)
# ------------------------------------------------------------------------------
FROM node:20-alpine AS builder

# Install compilation toolchain required for sqlite3 native bindings
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy dependency manifests
COPY package*.json ./

# Install production-only dependencies strictly
RUN npm ci --omit=dev

# ------------------------------------------------------------------------------
# Stage 2: Runtime (Minimal unprivileged production container)
# ------------------------------------------------------------------------------
FROM node:20-alpine AS runner

# Install dumb-init for PID 1 signal forwarding & zombie reaping
RUN apk add --no-cache dumb-init

# Prepare persistent data directory with non-root ownership
RUN mkdir -p /data && chown -R node:node /data

WORKDIR /app

# Copy production node_modules from builder with strict non-root ownership
COPY --from=builder --chown=node:node /app/node_modules ./node_modules

# Copy application source code
COPY --chown=node:node . .

# Set container production defaults
ENV NODE_ENV=production \
    PORT=4000 \
    DATABASE_PATH=/data/cyberforge.db

# Switch to unprivileged system user
USER node

# Expose server ingress port
EXPOSE 4000

# Container healthcheck probe against system health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:4000/api/health || exit 1

# Forward OS signals cleanly to Node runtime
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

CMD ["node", "server.js"]

