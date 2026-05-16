#!/usr/bin/env bash
#
# tilde installer — https://github.com/kiedanski/tilde
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/kiedanski/tilde/main/install.sh | bash
#
# What it does:
#   1. Downloads the latest tilde binary from GitHub Releases
#   2. Detects or prompts for data directory (separate volume)
#   3. If data exists → starts serving immediately
#   4. If no data → prompts to restore from backup or start fresh
#   5. Prompts for domain, verifies DNS points to this server
#   6. Sets up systemd with ACME TLS on port 443
#   7. Creates first app password
#
# Requirements: Linux (x86_64 or aarch64), systemd, curl
#
set -euo pipefail

REPO="kiedanski/tilde"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/tilde"
DEFAULT_DATA_DIR="/data/tilde"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}→${NC} $*"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}!${NC} $*"; }
err()   { echo -e "${RED}✗${NC} $*" >&2; }

# ── Preflight checks ──────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (or with sudo)"
    exit 1
fi

if ! command -v curl &>/dev/null; then
    err "curl is required. Install it with: apt install curl"
    exit 1
fi

if ! command -v systemctl &>/dev/null; then
    err "systemd is required"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ASSET="tilde-linux-x86_64" ;;
    aarch64) ASSET="tilde-linux-aarch64" ;;
    *)
        err "Unsupported architecture: $ARCH (need x86_64 or aarch64)"
        exit 1
        ;;
esac

echo ""
echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}   tilde — Personal Cloud Server      ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}   Installer                          ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Download binary ───────────────────────────────────────────────────

info "Detecting latest release..."
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
if [ -z "$LATEST" ]; then
    err "Could not determine latest release"
    exit 1
fi
ok "Latest version: $LATEST"

info "Downloading tilde ($ASSET)..."
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET}"
curl -fsSL "$DOWNLOAD_URL" -o /tmp/tilde-download
chmod +x /tmp/tilde-download

# Verify it runs
if ! /tmp/tilde-download --help &>/dev/null; then
    err "Downloaded binary failed to execute"
    exit 1
fi

mv /tmp/tilde-download "${INSTALL_DIR}/tilde"
ok "Installed tilde to ${INSTALL_DIR}/tilde"

# ── Step 2: Data directory ────────────────────────────────────────────────────

echo ""
info "Where should tilde store data (photos, files, database)?"
info "Use a separate volume/disk so data survives if you rebuild the server."
echo ""

# Check for common volume mount points
DETECTED=""
for candidate in /data /mnt/data /mnt/volume /vol; do
    if mountpoint -q "$candidate" 2>/dev/null; then
        DETECTED="$candidate/tilde"
        break
    fi
done

if [ -n "$DETECTED" ]; then
    info "Detected mounted volume at $(dirname "$DETECTED")"
fi

read -rp "Data directory [${DETECTED:-$DEFAULT_DATA_DIR}]: " DATA_DIR
DATA_DIR="${DATA_DIR:-${DETECTED:-$DEFAULT_DATA_DIR}}"

mkdir -p "$DATA_DIR"
ok "Data directory: $DATA_DIR"

# ── Step 3: Check for existing data or restore ────────────────────────────────

DB_PATH="$DATA_DIR/tilde.db"

if [ -f "$DB_PATH" ]; then
    ok "Existing database found — will use existing data"
    FRESH=false
else
    echo ""
    warn "No existing data found at $DATA_DIR"
    echo ""
    echo "  1) Restore from restic backup (Backblaze B2)"
    echo "  2) Restore from local backup file (.tar.gz)"
    echo "  3) Start fresh"
    echo ""
    read -rp "Choose [1/2/3]: " RESTORE_CHOICE

    if [ "$RESTORE_CHOICE" = "1" ]; then
        # Install restic if needed
        if ! command -v restic &>/dev/null; then
            info "Installing restic..."
            if command -v apt-get &>/dev/null; then
                apt-get install -y -qq restic 2>/dev/null
                restic self-update 2>/dev/null || true
            fi
        fi

        if ! command -v restic &>/dev/null; then
            err "restic is required for backup restore. Install it manually."
            exit 1
        fi

        echo ""
        read -rp "Restic repository (e.g., b2:bucket-name:tilde-backups): " RESTIC_REPO
        read -rp "B2 account ID: " RESTORE_B2_KEY_ID
        read -rsp "B2 application key: " RESTORE_B2_KEY
        echo ""
        read -rsp "Restic password: " RESTIC_PW
        echo ""

        info "Listing snapshots..."
        RESTIC_REPOSITORY="$RESTIC_REPO" \
        RESTIC_PASSWORD="$RESTIC_PW" \
        B2_ACCOUNT_ID="$RESTORE_B2_KEY_ID" \
        B2_ACCOUNT_KEY="$RESTORE_B2_KEY" \
        restic snapshots --last --compact

        echo ""
        info "Restoring latest snapshot to $DATA_DIR (this may take a while)..."
        RESTIC_REPOSITORY="$RESTIC_REPO" \
        RESTIC_PASSWORD="$RESTIC_PW" \
        B2_ACCOUNT_ID="$RESTORE_B2_KEY_ID" \
        B2_ACCOUNT_KEY="$RESTORE_B2_KEY" \
        restic restore latest --target /

        # Rename DB snapshot
        if [ -f "$DATA_DIR/.tilde-backup.db" ]; then
            mv "$DATA_DIR/.tilde-backup.db" "$DATA_DIR/tilde.db"
            ok "Restored database"
        fi

        ok "Backup restored from restic"

        # Save B2 creds for ongoing backups
        RESTORED_RESTIC_REPO="$RESTIC_REPO"
        RESTORED_B2_KEY_ID="$RESTORE_B2_KEY_ID"
        RESTORED_B2_KEY="$RESTORE_B2_KEY"
        RESTORED_RESTIC_PW="$RESTIC_PW"
        FRESH=false

    elif [ "$RESTORE_CHOICE" = "2" ]; then
        read -rp "Path to backup archive: " BACKUP_PATH
        if [ ! -f "$BACKUP_PATH" ]; then
            err "File not found: $BACKUP_PATH"
            exit 1
        fi
        info "Restoring from $BACKUP_PATH..."
        tilde restore --from "$BACKUP_PATH" --at "" --to "$DATA_DIR"
        ok "Backup restored"
        FRESH=false
    else
        FRESH=true
    fi
fi

# ── Step 4: Domain and DNS ───────────────────────────────────────────────────

echo ""
MY_IP=$(curl -fsSL https://ifconfig.me 2>/dev/null || curl -fsSL https://api.ipify.org 2>/dev/null || echo "")

if [ -n "$MY_IP" ]; then
    ok "This server's public IP: $MY_IP"
else
    warn "Could not detect public IP"
fi

# Check if config already has a hostname (restored from backup)
EXISTING_HOSTNAME=""
if [ -f "$CONFIG_DIR/config.toml" ]; then
    EXISTING_HOSTNAME=$(grep '^hostname' "$CONFIG_DIR/config.toml" 2>/dev/null | head -1 | sed 's/.*= *"\(.*\)"/\1/' || true)
fi

echo ""
read -rp "Domain name (e.g., cloud.example.com)${EXISTING_HOSTNAME:+ [$EXISTING_HOSTNAME]}: " HOSTNAME
HOSTNAME="${HOSTNAME:-$EXISTING_HOSTNAME}"

if [ -z "$HOSTNAME" ]; then
    err "A domain name is required for TLS certificates"
    exit 1
fi

# Verify DNS points to this server
info "Checking DNS for $HOSTNAME..."
DNS_IP=""
if command -v dig &>/dev/null; then
    DNS_IP=$(dig +short "$HOSTNAME" A 2>/dev/null | head -1)
elif command -v host &>/dev/null; then
    DNS_IP=$(host "$HOSTNAME" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}')
elif command -v getent &>/dev/null; then
    DNS_IP=$(getent hosts "$HOSTNAME" 2>/dev/null | awk '{print $1}' | head -1)
fi

if [ -z "$DNS_IP" ]; then
    echo ""
    warn "Could not resolve $HOSTNAME"
    echo ""
    echo "  Create a DNS A record:"
    echo ""
    echo "    ${YELLOW}$HOSTNAME  →  A  →  $MY_IP${NC}"
    echo ""
    echo "  Then re-run this installer, or wait here for propagation."
    echo ""
    read -rp "Wait for DNS to propagate? [Y/n]: " WAIT_DNS
    if [ "${WAIT_DNS,,}" != "n" ]; then
        info "Waiting for $HOSTNAME to resolve to $MY_IP..."
        for i in $(seq 1 60); do
            DNS_IP=$(dig +short "$HOSTNAME" A 2>/dev/null | head -1 || true)
            if [ "$DNS_IP" = "$MY_IP" ]; then
                break
            fi
            printf "\r  Attempt %d/60 (got: %s, need: %s)" "$i" "${DNS_IP:-nothing}" "$MY_IP"
            sleep 10
        done
        echo ""
    fi
fi

if [ "$DNS_IP" = "$MY_IP" ]; then
    ok "DNS verified: $HOSTNAME → $MY_IP"
elif [ -n "$DNS_IP" ]; then
    warn "$HOSTNAME resolves to $DNS_IP but this server is $MY_IP"
    warn "TLS certificate provisioning will fail until DNS is correct"
    read -rp "Continue anyway? [y/N]: " CONTINUE
    if [ "${CONTINUE,,}" != "y" ]; then
        echo ""
        echo "  Create or update the DNS A record:"
        echo ""
        echo "    ${YELLOW}$HOSTNAME  →  A  →  $MY_IP${NC}"
        echo ""
        echo "  Then re-run this installer."
        exit 1
    fi
else
    warn "Could not verify DNS — TLS may fail on first start"
    warn "Make sure $HOSTNAME points to $MY_IP"
fi

# Check port 443 is not already in use
if ss -tlnp 2>/dev/null | grep -q ':443 '; then
    err "Port 443 is already in use:"
    ss -tlnp 2>/dev/null | grep ':443 '
    err "Stop the other service or configure it as a reverse proxy"
    exit 1
fi

# ── Step 5: Configuration ───────────────────────────────────────────────────

mkdir -p "$CONFIG_DIR"

if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    cat > "$CONFIG_DIR/config.toml" << TOML
data_dir_override = "$DATA_DIR"

[server]
hostname = "$HOSTNAME"
listen_addr = "0.0.0.0"
listen_port = 443

[tls]
mode = "acme"

[photos]
enabled = true
organization_pattern = "{year}/{month:02}"

[backup]
enabled = true
schedule = "daily@04:00"
password_file = "${CONFIG_DIR}/restic-password"
keep_daily = 7
keep_weekly = 4
keep_monthly = 12
TOML
    ok "Config written to $CONFIG_DIR/config.toml"
else
    # Update hostname in existing config if changed
    if [ -n "$EXISTING_HOSTNAME" ] && [ "$EXISTING_HOSTNAME" != "$HOSTNAME" ]; then
        sed -i "s/hostname = \"$EXISTING_HOSTNAME\"/hostname = \"$HOSTNAME\"/" "$CONFIG_DIR/config.toml"
        ok "Updated hostname to $HOSTNAME in existing config"
    else
        ok "Using existing config at $CONFIG_DIR/config.toml"
    fi
fi

# Create .env if missing
if [ ! -f "$CONFIG_DIR/.env" ]; then
    cat > "$CONFIG_DIR/.env" << 'ENV'
# Notifications (optional): create a topic at https://ntfy.sh
# TILDE_NTFY_TOPIC=https://ntfy.sh/your-private-topic
ENV
    chmod 600 "$CONFIG_DIR/.env"
fi

# ── Step 6: Firewall ────────────────────────────────────────────────────────

# Only allow port 443 (HTTPS) — block everything else
if command -v ufw &>/dev/null; then
    info "Configuring firewall (ufw)..."
    ufw --force reset >/dev/null 2>&1
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    ufw allow ssh >/dev/null 2>&1
    ufw allow 443/tcp >/dev/null 2>&1
    ufw --force enable >/dev/null 2>&1
    ok "Firewall: only SSH and 443/tcp open"
elif command -v firewall-cmd &>/dev/null; then
    info "Configuring firewall (firewalld)..."
    firewall-cmd --permanent --add-service=https >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1
    ok "Firewall: HTTPS enabled"
else
    warn "No firewall detected — consider installing ufw: apt install ufw"
fi

# ── Step 7: Create system user ───────────────────────────────────────────────

if ! id tilde &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin tilde
    ok "Created system user: tilde"
fi

chown -R tilde:tilde "$DATA_DIR"
chown -R tilde:tilde "$CONFIG_DIR"

# ── Step 8: systemd service ─────────────────────────────────────────────────

cat > /etc/systemd/system/tilde.service << SERVICE
[Unit]
Description=tilde personal cloud server
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=tilde
ExecStart=${INSTALL_DIR}/tilde --config ${CONFIG_DIR}/config.toml serve
EnvironmentFile=${CONFIG_DIR}/.env
Environment=TILDE_DATA_DIR=${DATA_DIR}
Environment=TILDE_CONFIG_DIR=${CONFIG_DIR}

Restart=always
RestartSec=5
TimeoutStartSec=300
TimeoutStopSec=30

# Security hardening
ProtectSystem=strict
ReadWritePaths=${DATA_DIR} ${CONFIG_DIR}
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true

# Allow binding to port 443
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
ok "systemd service installed"

# ── Step 9: Initialize if fresh ──────────────────────────────────────────────

if [ "$FRESH" = true ]; then
    info "Initializing database..."
    TILDE_DATA_DIR="$DATA_DIR" TILDE_HOSTNAME="$HOSTNAME" TILDE_TLS_MODE="acme" \
        sudo -u tilde tilde --config "$CONFIG_DIR/config.toml" init
    ok "Database initialized"
fi

# ── Step 10: Install optional dependencies ───────────────────────────────────

echo ""
info "Installing optional dependencies..."
if command -v apt-get &>/dev/null; then
    apt-get install -y -qq ffmpeg 2>/dev/null && ok "ffmpeg installed (video thumbnails)" || warn "ffmpeg not available (video thumbnails disabled)"
    apt-get install -y -qq restic 2>/dev/null && ok "restic installed (incremental backups)" || warn "restic not available (install manually for backup support)"
    restic self-update 2>/dev/null || true
fi

# ── Step 10b: Set up restic backup ────────────────────────────────────────────

if command -v restic &>/dev/null; then
    # If we restored from restic, reuse those creds
    if [ -n "${RESTORED_RESTIC_PW:-}" ]; then
        echo "$RESTORED_RESTIC_PW" > "$CONFIG_DIR/restic-password"
        chmod 400 "$CONFIG_DIR/restic-password"
        ok "Restic password file created (from restore)"

        if ! grep -q "RESTIC_REPOSITORY" "$CONFIG_DIR/.env" 2>/dev/null; then
            {
                echo ""
                echo "# Restic backup to Backblaze B2"
                echo "RESTIC_REPOSITORY=${RESTORED_RESTIC_REPO}"
                echo "B2_ACCOUNT_ID=${RESTORED_B2_KEY_ID}"
                echo "B2_ACCOUNT_KEY=${RESTORED_B2_KEY}"
            } >> "$CONFIG_DIR/.env"
            chmod 600 "$CONFIG_DIR/.env"
            ok "B2 credentials saved to .env (from restore)"
        fi
    else
        # Create restic password file if it doesn't exist
        if [ ! -f "$CONFIG_DIR/restic-password" ]; then
            head -c 32 /dev/urandom | base64 > "$CONFIG_DIR/restic-password"
            chmod 400 "$CONFIG_DIR/restic-password"
            ok "Created restic password file"
            echo ""
            warn "IMPORTANT: Back up $CONFIG_DIR/restic-password somewhere safe!"
            warn "If lost, your backup repository becomes unrecoverable."
            echo ""
        fi

        # Prompt for B2 backup setup
        echo ""
        echo "  Set up Backblaze B2 backup? (recommended)"
        echo ""
        read -rp "Configure B2 backup? [Y/n]: " SETUP_B2

        if [ "${SETUP_B2,,}" != "n" ]; then
            read -rp "B2 bucket name: " B2_BUCKET
            read -rp "B2 key ID: " B2_KEY_ID
            read -rsp "B2 application key: " B2_KEY
            echo ""

            # Add B2 credentials to .env
            {
                echo ""
                echo "# Restic backup to Backblaze B2"
                echo "RESTIC_REPOSITORY=b2:${B2_BUCKET}:tilde-backups"
                echo "B2_ACCOUNT_ID=${B2_KEY_ID}"
                echo "B2_ACCOUNT_KEY=${B2_KEY}"
            } >> "$CONFIG_DIR/.env"
            chmod 600 "$CONFIG_DIR/.env"
            ok "B2 credentials saved to .env"

            # Initialize the restic repo
            info "Initializing restic backup repository..."
            RESTIC_REPOSITORY="b2:${B2_BUCKET}:tilde-backups" \
            RESTIC_PASSWORD_FILE="$CONFIG_DIR/restic-password" \
            B2_ACCOUNT_ID="$B2_KEY_ID" \
            B2_ACCOUNT_KEY="$B2_KEY" \
            restic init 2>/dev/null && ok "Restic repo initialized" || ok "Restic repo already exists"
        fi
    fi
fi

# ── Step 11: Start ───────────────────────────────────────────────────────────

systemctl enable tilde
systemctl start tilde
sleep 3

if systemctl is-active --quiet tilde; then
    ok "tilde is running!"
else
    err "tilde failed to start. Check: journalctl -u tilde -n 50"
    exit 1
fi

# Wait for TLS cert
info "Waiting for TLS certificate (Let's Encrypt)..."
for i in $(seq 1 30); do
    if curl -fsSk "https://127.0.0.1/health" -H "Host: $HOSTNAME" &>/dev/null 2>&1; then
        ok "TLS certificate provisioned!"
        break
    fi
    sleep 2
done

# ── Step 12: Create app password ─────────────────────────────────────────────

echo ""
info "Creating your first app password..."
APP_PW=$(TILDE_DATA_DIR="$DATA_DIR" sudo -u tilde tilde --config "$CONFIG_DIR/config.toml" auth app-password create --name "default" --scope "*" 2>/dev/null | grep -o 'tilde_app_[a-zA-Z0-9]*')

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}   tilde is ready!                    ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo "  URL:          https://$HOSTNAME"
echo "  Data:         $DATA_DIR"
echo "  Config:       $CONFIG_DIR/config.toml"
echo "  Logs:         journalctl -u tilde -f"
echo ""
if [ -n "${APP_PW:-}" ]; then
    echo -e "  ${YELLOW}App password:   $APP_PW${NC}"
    echo -e "  ${YELLOW}Save this — it cannot be retrieved later!${NC}"
fi
echo ""
echo "  Connect clients:"
echo "    CalDAV/CardDAV (iOS): https://$HOSTNAME/apple-mobileconfig"
echo "    DAVx5 (Android):      https://$HOSTNAME"
echo "    WebDAV files:         https://$HOSTNAME/dav/files/"
echo ""
echo "  Manage:"
echo "    tilde status"
echo "    tilde usage"
echo "    tilde auth app-password create --name phone --scope '/dav/*'"
echo ""
