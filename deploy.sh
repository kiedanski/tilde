#!/usr/bin/env bash
#
# tilde deploy — deploy tilde to any VPS via SSH
#
# Usage:
#   ./deploy.sh root@203.0.113.5                    # fresh install
#   ./deploy.sh root@203.0.113.5 --restore          # install + restore from B2
#   ./deploy.sh --provision hetzner --restore       # provision + install + restore
#
# Providers (--provision):
#   hetzner   — Hetzner Cloud (requires HCLOUD_TOKEN env var)
#   (more coming: digitalocean, vultr, aws-lightsail)
#
# Without --provision, give it any server with:
#   - Ubuntu/Debian (or any Linux with systemd + apt)
#   - Root SSH access
#   - Port 443 available
#
set -euo pipefail

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

# ── Parse arguments ───────────────────────────────────────────────────────────

SSH_TARGET=""
RESTORE=false
PROVIDER=""
DOMAIN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --restore) RESTORE=true; shift ;;
        --provision) PROVIDER="$2"; shift 2 ;;
        --domain) DOMAIN="$2"; shift 2 ;;
        -*) err "Unknown option: $1"; exit 1 ;;
        *) SSH_TARGET="$1"; shift ;;
    esac
done

echo ""
echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}   tilde — Deploy                      ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"
echo ""

# ── Provision (optional) ──────────────────────────────────────────────────────

provision_hetzner() {
    local HCLOUD_API="https://api.hetzner.cloud/v1"

    if [ -z "${HCLOUD_TOKEN:-}" ]; then
        echo "  Get a token at: https://console.hetzner.cloud → Security → API Tokens"
        echo ""
        read -rsp "Hetzner API token: " HCLOUD_TOKEN
        echo ""
    fi

    if ! curl -fsSL -H "Authorization: Bearer $HCLOUD_TOKEN" "$HCLOUD_API/servers" >/dev/null 2>&1; then
        err "Invalid Hetzner API token"
        exit 1
    fi
    ok "API token verified"

    local SERVER_NAME
    read -rp "Server name [tilde]: " SERVER_NAME
    SERVER_NAME="${SERVER_NAME:-tilde}"

    echo ""
    echo "  Locations:"
    echo "    1) nbg1 — Nuremberg, DE"
    echo "    2) fsn1 — Falkenstein, DE"
    echo "    3) hel1 — Helsinki, FI"
    echo "    4) ash  — Ashburn, US  (x86 only, no ARM)"
    echo ""
    local LOCATION_CHOICE LOCATION
    read -rp "Choose [1]: " LOCATION_CHOICE
    case "${LOCATION_CHOICE:-1}" in
        2) LOCATION="fsn1" ;;
        3) LOCATION="hel1" ;;
        4) LOCATION="ash" ;;
        *) LOCATION="nbg1" ;;
    esac

    echo ""
    if [ "$LOCATION" = "ash" ]; then
        echo "  Server types (x86 only in US):"
        echo "    1) CPX11 — AMD, 2 vCPU, 2 GB, 40 GB   (~€5/mo)"
        echo "    2) CPX21 — AMD, 3 vCPU, 4 GB, 80 GB   (~€9/mo)"
        echo "    3) CPX31 — AMD, 4 vCPU, 8 GB, 160 GB  (~€17/mo)"
        echo ""
        local SERVER_TYPE_CHOICE SERVER_TYPE
        read -rp "Choose [2]: " SERVER_TYPE_CHOICE
        case "${SERVER_TYPE_CHOICE:-2}" in
            1) SERVER_TYPE="cpx11" ;;
            3) SERVER_TYPE="cpx31" ;;
            *) SERVER_TYPE="cpx21" ;;
        esac
    else
        echo "  Server types:"
        echo "    1) CAX11 — ARM, 2 vCPU, 4 GB, 40 GB   (~€4/mo)"
        echo "    2) CAX21 — ARM, 4 vCPU, 8 GB, 80 GB   (~€8/mo)"
        echo "    3) CX23  — x86, 2 vCPU, 4 GB, 40 GB   (~€4/mo)"
        echo "    4) CX33  — x86, 4 vCPU, 8 GB, 80 GB   (~€7/mo)"
        echo ""
        local SERVER_TYPE_CHOICE SERVER_TYPE
        read -rp "Choose [1]: " SERVER_TYPE_CHOICE
        case "${SERVER_TYPE_CHOICE:-1}" in
            2) SERVER_TYPE="cax21" ;;
            3) SERVER_TYPE="cx23" ;;
            4) SERVER_TYPE="cx33" ;;
            *) SERVER_TYPE="cax11" ;;
        esac
    fi

    # Volume size
    echo ""
    echo "  Data volume (separate disk, survives server rebuilds):"
    echo "  €0.052/GB/month — 50 GB = ~€2.60/mo, 100 GB = ~€5.20/mo"
    echo ""
    local VOLUME_SIZE
    read -rp "Volume size in GB [50]: " VOLUME_SIZE
    VOLUME_SIZE="${VOLUME_SIZE:-50}"

    # SSH key
    local SSH_KEY_PATH="${HOME}/.ssh/id_ed25519"
    if [ ! -f "$SSH_KEY_PATH" ] && [ ! -f "${HOME}/.ssh/id_rsa" ]; then
        info "No SSH key found. Generating..."
        ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -C "tilde-deploy"
    elif [ ! -f "$SSH_KEY_PATH" ]; then
        SSH_KEY_PATH="${HOME}/.ssh/id_rsa"
    fi

    local SSH_PUB_KEY
    SSH_PUB_KEY=$(cat "${SSH_KEY_PATH}.pub")

    # Upload key
    local SSH_KEY_NAME="tilde-$(hostname -s 2>/dev/null || echo local)"
    local SSH_KEY_ID
    SSH_KEY_ID=$(curl -fsSL -X POST -H "Authorization: Bearer $HCLOUD_TOKEN" \
        -H "Content-Type: application/json" \
        "$HCLOUD_API/ssh_keys" \
        -d "{\"name\":\"$SSH_KEY_NAME\",\"public_key\":\"$SSH_PUB_KEY\"}" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('ssh_key',{}).get('id',''))" 2>/dev/null || echo "")

    if [ -z "$SSH_KEY_ID" ]; then
        # Key might already exist
        SSH_KEY_ID=$(curl -fsSL -H "Authorization: Bearer $HCLOUD_TOKEN" \
            "$HCLOUD_API/ssh_keys" 2>/dev/null \
            | python3 -c "import sys,json; keys=json.load(sys.stdin)['ssh_keys']; print(next((k['id'] for k in keys if k['name']=='$SSH_KEY_NAME'),''))" 2>/dev/null || echo "")
    fi

    if [ -z "$SSH_KEY_ID" ]; then
        err "Failed to upload SSH key"
        exit 1
    fi

    # Create volume first (in the same location)
    info "Creating ${VOLUME_SIZE} GB volume in $LOCATION..."
    local VOL_RESPONSE VOLUME_ID
    VOL_RESPONSE=$(curl -fsSL -X POST -H "Authorization: Bearer $HCLOUD_TOKEN" \
        -H "Content-Type: application/json" \
        "$HCLOUD_API/volumes" \
        -d "{
            \"name\": \"${SERVER_NAME}-data\",
            \"size\": $VOLUME_SIZE,
            \"location\": \"$LOCATION\",
            \"format\": \"ext4\",
            \"automount\": false
        }")

    VOLUME_ID=$(echo "$VOL_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['volume']['id'])" 2>/dev/null || echo "")

    if [ -z "$VOLUME_ID" ] || [ "$VOLUME_ID" = "None" ]; then
        err "Failed to create volume"
        echo "$VOL_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$VOL_RESPONSE"
        exit 1
    fi
    ok "Volume created: ${SERVER_NAME}-data (${VOLUME_SIZE} GB, ID: $VOLUME_ID)"

    # Create server with volume attached
    info "Creating $SERVER_TYPE in $LOCATION..."
    local CREATE_RESPONSE SERVER_IP SERVER_ID
    CREATE_RESPONSE=$(curl -fsSL -X POST -H "Authorization: Bearer $HCLOUD_TOKEN" \
        -H "Content-Type: application/json" \
        "$HCLOUD_API/servers" \
        -d "{
            \"name\": \"$SERVER_NAME\",
            \"server_type\": \"$SERVER_TYPE\",
            \"location\": \"$LOCATION\",
            \"image\": \"ubuntu-24.04\",
            \"ssh_keys\": [$SSH_KEY_ID],
            \"volumes\": [$VOLUME_ID],
            \"public_net\": {\"enable_ipv4\": true, \"enable_ipv6\": true}
        }")

    SERVER_ID=$(echo "$CREATE_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['server']['id'])" 2>/dev/null || echo "")
    SERVER_IP=$(echo "$CREATE_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['server']['public_net']['ipv4']['ip'])" 2>/dev/null || echo "")

    if [ -z "$SERVER_IP" ] || [ "$SERVER_IP" = "None" ]; then
        err "Failed to create server"
        echo "$CREATE_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$CREATE_RESPONSE"
        warn "Cleaning up volume..."
        curl -fsSL -X DELETE -H "Authorization: Bearer $HCLOUD_TOKEN" \
            "$HCLOUD_API/volumes/$VOLUME_ID" >/dev/null 2>&1 && ok "Volume deleted" || true
        exit 1
    fi

    ok "Server created: $SERVER_NAME → $SERVER_IP (volume attached)"

    # Return values via globals
    PROVISIONED_IP="$SERVER_IP"
    PROVISIONED_SSH_KEY="$SSH_KEY_PATH"
    PROVISIONED_VOLUME=true
}

if [ -n "$PROVIDER" ]; then
    case "$PROVIDER" in
        hetzner) provision_hetzner ;;
        *)
            err "Unknown provider: $PROVIDER"
            err "Supported: hetzner"
            exit 1
            ;;
    esac
    SSH_TARGET="root@$PROVISIONED_IP"
fi

# ── Validate SSH target ───────────────────────────────────────────────────────

if [ -z "$SSH_TARGET" ]; then
    echo "  Deploy tilde to a VPS via SSH."
    echo ""
    echo "  Usage:"
    echo "    ./deploy.sh root@1.2.3.4"
    echo "    ./deploy.sh root@1.2.3.4 --restore"
    echo "    ./deploy.sh --provision hetzner"
    echo ""
    read -rp "SSH target (e.g., root@1.2.3.4): " SSH_TARGET
    if [ -z "$SSH_TARGET" ]; then
        err "SSH target required"
        exit 1
    fi
fi

# Build SSH options
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
if [ -n "${PROVISIONED_SSH_KEY:-}" ]; then
    SSH_OPTS="$SSH_OPTS -i $PROVISIONED_SSH_KEY"
fi

# Extract IP from target for DNS instructions
SERVER_IP="${SSH_TARGET#*@}"

# ── Wait for SSH ──────────────────────────────────────────────────────────────

info "Connecting to $SSH_TARGET..."
for i in $(seq 1 60); do
    if ssh $SSH_OPTS -o BatchMode=yes "$SSH_TARGET" "true" 2>/dev/null; then
        break
    fi
    if [ "$i" -eq 60 ]; then
        err "Could not connect via SSH after 5 minutes"
        exit 1
    fi
    printf "\r  Waiting for SSH... (%d/60)" "$i"
    sleep 5
done
echo ""
ok "SSH connected"

# ── Mount volume (if provisioned) ─────────────────────────────────────────────

if [ "${PROVISIONED_VOLUME:-}" = true ]; then
    info "Mounting data volume..."
    ssh $SSH_OPTS "$SSH_TARGET" bash <<'MOUNT_SCRIPT'
set -euo pipefail

# Find the attached volume (Hetzner attaches as /dev/sdb or /dev/disk/by-id/scsi-0HC_Volume_*)
VOLUME_DEV=""
for dev in /dev/disk/by-id/scsi-0HC_Volume_*; do
    if [ -e "$dev" ]; then
        VOLUME_DEV=$(readlink -f "$dev")
        break
    fi
done

if [ -z "$VOLUME_DEV" ]; then
    # Fallback: look for unpartitioned disks
    for dev in /dev/sdb /dev/vdb /dev/xvdb; do
        if [ -b "$dev" ]; then
            VOLUME_DEV="$dev"
            break
        fi
    done
fi

if [ -z "$VOLUME_DEV" ]; then
    echo "WARNING: No attached volume found, using /data on root disk"
    mkdir -p /data
    exit 0
fi

echo "Found volume at $VOLUME_DEV"

# Format if not already formatted
if ! blkid "$VOLUME_DEV" | grep -q ext4; then
    echo "Formatting $VOLUME_DEV as ext4..."
    mkfs.ext4 -q "$VOLUME_DEV"
fi

# Mount at /data
mkdir -p /data
if ! mountpoint -q /data; then
    mount "$VOLUME_DEV" /data
fi

# Add to fstab for persistence
if ! grep -q "$VOLUME_DEV" /etc/fstab; then
    echo "$VOLUME_DEV /data ext4 defaults,nofail 0 2" >> /etc/fstab
fi

echo "Volume mounted at /data"
df -h /data
MOUNT_SCRIPT
    ok "Volume mounted at /data"
fi

# ── Domain ────────────────────────────────────────────────────────────────────

if [ -z "$DOMAIN" ]; then
    echo ""
    read -rp "Domain (e.g., cloud.example.com): " DOMAIN
fi

if [ -z "$DOMAIN" ]; then
    err "A domain is required for TLS"
    exit 1
fi

echo ""
echo -e "  ${YELLOW}Point your DNS to this server:${NC}"
echo ""
echo -e "    ${GREEN}$DOMAIN  →  A  →  $SERVER_IP${NC}"
echo ""
read -rp "Press Enter once DNS is configured (or Enter to skip verification)..."

# ── Restore from B2 ──────────────────────────────────────────────────────────

if [ "$RESTORE" = true ]; then
    echo ""
    echo -e "  ${BLUE}── Restore from Backblaze B2 ──${NC}"
    echo ""

    read -rp "Restic repository (e.g., b2:bucket:tilde-backups): " RESTIC_REPO
    read -rp "B2 account ID: " B2_ACCOUNT_ID
    read -rsp "B2 application key: " B2_ACCOUNT_KEY
    echo ""
    read -rsp "Restic password: " RESTIC_PASSWORD
    echo ""

    info "Installing restic on server..."
    ssh $SSH_OPTS "$SSH_TARGET" "apt-get update -qq && apt-get install -y -qq restic >/dev/null 2>&1 && restic self-update 2>/dev/null || true"
    ok "restic installed"

    info "Restoring latest snapshot (this may take a while)..."
    ssh $SSH_OPTS "$SSH_TARGET" bash <<RESTORE_SCRIPT
set -euo pipefail
export RESTIC_REPOSITORY="$RESTIC_REPO"
export RESTIC_PASSWORD="$RESTIC_PASSWORD"
export B2_ACCOUNT_ID="$B2_ACCOUNT_ID"
export B2_ACCOUNT_KEY="$B2_ACCOUNT_KEY"

echo "Finding latest snapshot..."
restic snapshots --last --compact

echo ""
echo "Restoring..."
restic restore latest --target /

# Rename DB snapshot
DATA_DIR=\$(find / -name ".tilde-backup.db" 2>/dev/null | head -1 | xargs dirname 2>/dev/null || echo "")
if [ -n "\$DATA_DIR" ] && [ -f "\$DATA_DIR/.tilde-backup.db" ]; then
    mv "\$DATA_DIR/.tilde-backup.db" "\$DATA_DIR/tilde.db"
    echo "Renamed .tilde-backup.db → tilde.db"
fi
RESTORE_SCRIPT
    ok "Restore complete"
fi

# ── Run install.sh ────────────────────────────────────────────────────────────

echo ""
info "Running tilde installer..."

# The install script is interactive — pipe answers if we have them
ssh $SSH_OPTS -t "$SSH_TARGET" bash <<INSTALL_CMD
set -euo pipefail
curl -fsSL https://raw.githubusercontent.com/kiedanski/tilde/main/install.sh -o /tmp/tilde-install.sh
chmod +x /tmp/tilde-install.sh
/tmp/tilde-install.sh
INSTALL_CMD

# ── Post-install: configure B2 backup ─────────────────────────────────────────

if [ "$RESTORE" = true ] && [ -n "${RESTIC_REPO:-}" ]; then
    echo ""
    info "Configuring ongoing B2 backups..."
    ssh $SSH_OPTS "$SSH_TARGET" bash <<B2_SETUP
# Write restic password file
echo "$RESTIC_PASSWORD" > /etc/tilde/restic-password
chmod 400 /etc/tilde/restic-password
chown tilde:tilde /etc/tilde/restic-password

# Add B2 creds to .env (if not already there)
if ! grep -q "RESTIC_REPOSITORY" /etc/tilde/.env 2>/dev/null; then
    cat >> /etc/tilde/.env << 'ENVEOF'

# Restic backup to Backblaze B2
RESTIC_REPOSITORY=$RESTIC_REPO
B2_ACCOUNT_ID=$B2_ACCOUNT_ID
B2_ACCOUNT_KEY=$B2_ACCOUNT_KEY
ENVEOF
fi
chmod 600 /etc/tilde/.env

# Update config to enable backup
if ! grep -q "password_file" /etc/tilde/config.toml 2>/dev/null; then
    sed -i '/^\[backup\]/,/^\[/{
        s/enabled = false/enabled = true/
    }' /etc/tilde/config.toml
    # Add password_file if missing
    sed -i '/^\[backup\]/a password_file = "/etc/tilde/restic-password"' /etc/tilde/config.toml
fi

systemctl restart tilde
B2_SETUP
    ok "B2 backup configured — daily at 04:00"
fi

# ── Create admin user (don't run as root) ─────────────────────────────────────

echo ""
read -rp "Create an admin user? (replaces root SSH) [Y/n]: " CREATE_USER
if [ "${CREATE_USER,,}" != "n" ]; then
    read -rp "Username: " ADMIN_USER
    if [ -n "$ADMIN_USER" ]; then
        info "Creating user '$ADMIN_USER'..."
        ssh $SSH_OPTS "$SSH_TARGET" bash <<USER_SETUP
set -euo pipefail

# Create user with sudo
adduser --disabled-password --gecos "" "$ADMIN_USER"
usermod -aG sudo "$ADMIN_USER"

# Copy SSH key from root
mkdir -p /home/$ADMIN_USER/.ssh
cp /root/.ssh/authorized_keys /home/$ADMIN_USER/.ssh/
chown -R $ADMIN_USER:$ADMIN_USER /home/$ADMIN_USER/.ssh
chmod 700 /home/$ADMIN_USER/.ssh
chmod 600 /home/$ADMIN_USER/.ssh/authorized_keys

# Add to tilde group for CLI access
usermod -aG tilde $ADMIN_USER

# Group-readable data dirs
chmod -R g+rw /data/tilde
chmod g+r /etc/tilde/config.toml
find /data/tilde -type d -exec chmod g+s {} \;

# Passwordless sudo
echo "$ADMIN_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$ADMIN_USER

# Disable root SSH
sed -i '/^PermitRootLogin/d' /etc/ssh/sshd_config.d/99-harden.conf 2>/dev/null || true
echo "PermitRootLogin no" >> /etc/ssh/sshd_config.d/99-harden.conf
systemctl restart ssh
USER_SETUP
        ok "User '$ADMIN_USER' created, root SSH disabled"
        SSH_USER_TARGET="$ADMIN_USER@$SERVER_IP"
    fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}   tilde deployed!                                    ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  URL:      https://$DOMAIN"
echo "  SSH:      ssh ${SSH_USER_TARGET:-$SSH_TARGET}"
echo "  Logs:     ssh ${SSH_USER_TARGET:-$SSH_TARGET} journalctl -u tilde -f"
echo ""
if [ "$RESTORE" = true ]; then
    echo "  Restored from: ${RESTIC_REPO}"
    echo "  Backups: daily at 04:00 → B2"
fi
echo ""
