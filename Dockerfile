# Vigilant — single image for both the ingest service and the collector worker.
# One manifest builds one image; docker-compose runs it as two services with
# different start commands (see docker-compose.yml). Matches the CommonJS / stdlib-http
# Node service style of provisioner/server.js — no build step, no TypeScript.

FROM node:22-alpine

# Run as the unprivileged 'node' user that the base image ships.
WORKDIR /app

# Install production dependencies first so the layer is cached unless the manifest
# changes. We copy only the manifest(s) before the source for better layer reuse.
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Now the application source. .dockerignore keeps node_modules / .env / .git out.
COPY . .

# Build the offline OUI database (full IEEE registry) so MAC→vendor resolves without the
# rate-limited public API. Best-effort: if IEEE is unreachable at build time, the ingest
# falls back to the small hand-curated seed (oui.js tolerates a missing oui-db.json).
RUN npm run build:oui || echo "build-oui: skipped (no network at build) — using seed fallback"

# Drop privileges. The 'node' user exists in the official image.
USER node

# The ingest API listens on $PORT (default 9100 from config.js). Compose / Coolify set it.
ENV PORT=9100
EXPOSE 9100

# Default command = the ingest HTTP service. The worker runs the SAME image with a
# different command (overridden in docker-compose.yml):
#     command: node src/worker/worker.js
# Keeping both in one image means one build, one tag, one deploy.
CMD ["node", "src/ingest/server.js"]
