#!/usr/bin/env bash
# update.sh — Idempotent update script for the Bastion service
# Run as root. Safe to run multiple times.
set -euo pipefail

BASTION_ROOT="/opt/bastion"
BASTION_USER="bastion"
BASTION_GROUP="bastion"

log()  { echo "[bastion-update] $*"; }
die()  { echo "[bastion-update] ERROR: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "This script must be run as root."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="$(dirname "$SCRIPT_DIR")"

# ── Stop services ─────────────────────────────────────────────────────────────
log "Stopping Bastion services..."
systemctl stop bastion-api bastion-admin bastion-worker bastion-beat || true

# ── Update application code ───────────────────────────────────────────────────
log "Updating application code..."
rsync -a --delete \
    --exclude='.git' \
    --exclude='.amazonq' \
    --exclude='*.pyc' \
    --exclude='__pycache__' \
    --exclude='.env' \
    --exclude='*.db' \
    --exclude='recordings/' \
    --exclude='logs/' \
    "$APP_SRC/" "$BASTION_ROOT/app/"

chown -R "$BASTION_USER:$BASTION_GROUP" "$BASTION_ROOT/app"

# ── Update Python dependencies ────────────────────────────────────────────────
log "Updating Python dependencies..."
sudo -u "$BASTION_USER" "$BASTION_ROOT/venv/bin/pip" install --quiet --upgrade pip
sudo -u "$BASTION_USER" "$BASTION_ROOT/venv/bin/pip" install --quiet -r "$BASTION_ROOT/app/requirements.txt"

# ── Run database migrations ───────────────────────────────────────────────────
log "Running database migrations..."
cd "$BASTION_ROOT/app"
sudo -u "$BASTION_USER" PYTHONPATH="$BASTION_ROOT/app" \
    "$BASTION_ROOT/venv/bin/alembic" upgrade head || \
    log "WARNING: Alembic migration failed or no migrations directory found — skipping."

# ── Reload systemd units (in case they changed) ───────────────────────────────
log "Reloading systemd configuration..."
systemctl daemon-reload

# ── Restart services ──────────────────────────────────────────────────────────
log "Starting Bastion services..."
systemctl start bastion-api bastion-admin bastion-worker bastion-beat

# ── Verify services started ───────────────────────────────────────────────────
sleep 2
for svc in bastion-api bastion-admin bastion-worker bastion-beat; do
    if systemctl is-active --quiet "$svc"; then
        log "  ✓ $svc is running"
    else
        log "  ✗ $svc failed to start — check: journalctl -u $svc -n 50"
    fi
done

log ""
log "Update complete."
