#!/usr/bin/env bash
# =============================================================
#  Certificate DApp  - One-command setup for a new machine
#
#  Run once on a fresh Ubuntu/Debian VM (Debian based):
#      bash setup.sh
#
#  This will:
#    1. Install Node.js 20 + npm + pm2
#    2. Create .env from .env.example if missing (edit it!)
#    3. Install dependencies
#    4. Build the React frontend
#    5. Start the app with PM2
#    6. Enable auto-start on boot (pm2 startup)
# =============================================================
set -e

APP_NAME="cert-app"
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

say()  { printf "\n\033[1;32m[setup]\033[0m %s\n" "$1"; }
warn() { printf "\033[1;33m[!!] %s\033[0m\n" "$1"; }

# ---------- 1. Node.js 20 ----------
if ! command -v node >/dev/null 2>&1; then
  say "Node.js not found. Installing Node 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
else
  ver="$(node -p 'process.versions.node' | cut -d. -f1)"
  if [ "$ver" -lt 20 ]; then
    warn "Node.js v$ver found; 20+ recommended. Continuing anyway."
  fi
fi

# ---------- 2. pm2 ----------
if ! command -v pm2 >/dev/null 2>&1; then
  say "Installing pm2 globally..."
  sudo npm install -g pm2
fi

# ---------- 3. .env ----------
if [ ! -f .env ]; then
  say "Creating .env from .env.example..."
  cp .env.example .env
  warn ">>> EDIT .env and set ADMIN_PRIVATE_KEY + CONTRACT_ADDRESS before using!"
fi

# ---------- 4. dependencies ----------
if [ ! -d node_modules ]; then
  say "Installing npm dependencies..."
  npm install
else
  say "node_modules present; skipping install."
fi

# ---------- 5. build frontend ----------
say "Building React frontend..."
npm run build

# ---------- 6. start with PM2 ----------
if pm2 describe "$APP_NAME" >/dev/null 2>&1; then
  say "$APP_NAME already exists; restarting with latest code..."
  pm2 restart "$APP_NAME" --update-env
else
  say "Starting $APP_NAME with PM2..."
  pm2 start server.js --name "$APP_NAME" --update-env
fi
pm2 save

# ---------- 7. auto-start on boot ----------
if systemctl list-unit-files 2>/dev/null | grep -q "pm2-$(whoami)"; then
  say "pm2 boot service already enabled."
else
  say "Enabling pm2 to start on boot..."
  CMD=$(pm2 startup 2>&1 | grep -oE "sudo env PATH=[^ ]* pm2 startup systemd[^\"]*")
  if [ -n "$CMD" ]; then
    warn "Running (needs sudo): $CMD"
    eval "$CMD"
    pm2 save
  else
    say "Run 'pm2 startup' manually and execute the printed sudo command."
  fi
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
say "DONE! Your app is running at:  http://${IP:-<this-machine>}:5000"
say "On a new deploy:  bash setup.sh   (re-runs are safe/idempotent)"