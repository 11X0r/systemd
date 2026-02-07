#!/usr/bin/env bash
# FuzzForge AI — Bootstrap Script
# Sets up the complete FuzzForge infrastructure for fuzzing systemd
#
# Usage: ./bootstrap.sh [fuzzforge_repo_path]
# Example: ./bootstrap.sh /home/user/fuzzforge_ai

set -euo pipefail

FUZZFORGE_DIR="${1:-/home/user/fuzzforge_ai}"
SYSTEMD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[bootstrap]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*" >&2; }

# ---- Pre-flight checks ----
log "Checking prerequisites..."

if ! command -v docker &>/dev/null; then
    err "Docker is not installed. Install Docker first."
    exit 1
fi

if ! docker info &>/dev/null 2>&1; then
    err "Docker daemon is not running. Start it with: sudo systemctl start docker"
    exit 1
fi

if ! command -v docker compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
    err "Docker Compose is not available."
    exit 1
fi

if [[ ! -d "$FUZZFORGE_DIR" ]]; then
    log "Cloning FuzzForge AI..."
    git clone https://github.com/FuzzingLabs/fuzzforge_ai.git "$FUZZFORGE_DIR"
fi

ok "Prerequisites satisfied"

# ---- Environment setup ----
log "Configuring environment..."

ENV_FILE="${FUZZFORGE_DIR}/volumes/env/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    cp "${FUZZFORGE_DIR}/volumes/env/.env.template" "$ENV_FILE"
    warn "Created .env from template. Edit ${ENV_FILE} to add API keys for LLM workflows."
    warn "Required for sections G (LLM Analysis) and H (Secret Detection):"
    warn "  LITELLM_OPENAI_API_KEY=sk-..."
    warn "  LITELLM_ANTHROPIC_API_KEY=sk-ant-..."
fi

ok "Environment configured"

# ---- Start core services ----
log "Starting FuzzForge core services (Temporal, MinIO, PostgreSQL)..."
cd "$FUZZFORGE_DIR"
docker compose up -d temporal temporal-ui postgresql minio minio-setup 2>&1

log "Waiting for services to be healthy..."
sleep 15

# Check Temporal is up
for i in {1..30}; do
    if curl -sf http://localhost:7233/health 2>/dev/null || docker compose logs temporal 2>&1 | grep -q "started"; then
        ok "Temporal is running on :7233"
        break
    fi
    sleep 2
done

# Check MinIO is up
for i in {1..20}; do
    if curl -sf http://localhost:9000/minio/health/live 2>/dev/null; then
        ok "MinIO is running on :9000"
        break
    fi
    sleep 2
done

# ---- Start OSS-Fuzz worker ----
log "Starting OSS-Fuzz worker (this may take a while on first run)..."
docker compose up -d worker-ossfuzz 2>&1

log "Waiting for worker to register..."
sleep 30

ok "OSS-Fuzz worker started"

# ---- Start secrets worker (for Section H) ----
log "Starting secrets worker..."
docker compose up -d worker-secrets 2>&1
ok "Secrets worker started"

# ---- Install CLI if needed ----
if ! command -v ff &>/dev/null; then
    log "Installing FuzzForge CLI..."
    pip3 install --upgrade setuptools 2>/dev/null
    pip3 install langdetect --no-build-isolation 2>/dev/null
    pip3 install -e ./sdk -e ./ai -e ./cli --ignore-installed pyyaml 2>&1
fi

ok "FuzzForge CLI available: $(ff version 2>/dev/null | head -1)"

# ---- Initialize project ----
log "Initializing FuzzForge project in systemd..."
cd "$SYSTEMD_DIR"
ff init --name systemd --force 2>/dev/null || true

# Ensure config exists
mkdir -p .fuzzforge
cat > .fuzzforge/config.yaml << EOF
project_name: systemd
api_url: http://localhost:8000

workers:
  auto_start_workers: true
  auto_stop_workers: false
  worker_startup_timeout: 120
EOF

ok "Project initialized"

# ---- Start backend API ----
log "Starting FuzzForge backend API..."
cd "$FUZZFORGE_DIR"
docker compose up -d backend 2>&1 || warn "Backend may need manual start"

# ---- Verify ----
log ""
log "============================================"
log "  FuzzForge Infrastructure Ready"
log "============================================"
log ""
log "Services:"
log "  Temporal UI:  http://localhost:8080"
log "  MinIO Console: http://localhost:9001 (fuzzforge/fuzzforge123)"
log "  Backend API:   http://localhost:8000"
log ""
log "Available workflows:"
log "  ff workflows"
log ""
log "Quick test:"
log "  ff workflow run ossfuzz_campaign . project_name=systemd campaign_duration_hours=1 --wait"
log ""
log "Run full task list:"
log "  cd ${SYSTEMD_DIR}"
log "  .fuzzforge/run_all.sh ossfuzz --dry-run   # Preview"
log "  .fuzzforge/run_all.sh security             # Run security assessment"
log "  .fuzzforge/run_all.sh all                   # Run everything (~250h)"
log ""
ok "Bootstrap complete!"
