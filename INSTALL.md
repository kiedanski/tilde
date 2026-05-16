# Installing tilde

## Quick Install (any VPS)

SSH into a fresh Ubuntu 24.04 server and run:

```bash
curl -fsSL https://raw.githubusercontent.com/kiedanski/tilde/main/install.sh | sudo bash
```

The installer will:
1. Download the latest binary
2. Ask for your data directory and domain
3. Set up systemd, firewall, and restic backups
4. Create your first app password

**Requirements:** Linux (x86_64 or aarch64), systemd, port 443 available.

After the installer finishes, set up nginx as a reverse proxy for TLS (see below).

---

## Step-by-Step Manual Install

### 1. Download the binary

```bash
ARCH=$(uname -m)  # x86_64 or aarch64
curl -fsSL "https://github.com/kiedanski/tilde/releases/latest/download/tilde-linux-${ARCH}" \
  -o /usr/local/bin/tilde
chmod +x /usr/local/bin/tilde
```

### 2. Create system user and directories

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin tilde
mkdir -p /data/tilde /etc/tilde /home/tilde/.cache/tilde
chown -R tilde:tilde /data/tilde /etc/tilde /home/tilde
```

Use a separate volume for `/data` so your data survives server rebuilds.

### 3. Write config

**/etc/tilde/config.toml:**

```toml
[server]
hostname = "cloud.example.com"
listen_addr = "0.0.0.0"
listen_port = 8080

[tls]
mode = "upstream"   # nginx handles TLS

data_dir_override = "/data/tilde"

[photos]
enabled = true
organization_pattern = "{year}/{month:02}"

[calendar]
enabled = true

[contacts]
enabled = true

[notes]
root_path = "notes"

[mcp]
enabled = true
tool_allowlist = ["*"]

[backup]
enabled = true
schedule = "daily@04:00"
password_file = "/etc/tilde/restic-password"
keep_daily = 7
keep_weekly = 4
keep_monthly = 12

[logging]
level = "info"
format = "json"
```

**/etc/tilde/.env:**

```bash
# Restic backup to Backblaze B2
RESTIC_REPOSITORY=b2:your-bucket:tilde-backups
B2_ACCOUNT_ID=your-key-id
B2_ACCOUNT_KEY=your-key

# Email archive (optional)
# TILDE_EMAIL_USERNAME=you@example.com
# TILDE_EMAIL_PASSWORD=your-imap-password

# Notifications (optional)
# TILDE_NTFY_TOPIC=https://ntfy.sh/your-topic
```

```bash
chmod 600 /etc/tilde/.env
```

### 4. Set up restic backup

```bash
# Generate a password (save this somewhere safe!)
head -c 32 /dev/urandom | base64 > /etc/tilde/restic-password
chmod 400 /etc/tilde/restic-password
chown tilde:tilde /etc/tilde/restic-password

# Initialize the repo
source /etc/tilde/.env
RESTIC_PASSWORD_FILE=/etc/tilde/restic-password restic init
```

### 5. Install systemd service

**/etc/systemd/system/tilde.service:**

```ini
[Unit]
Description=tilde personal cloud server
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=tilde
ExecStart=/usr/local/bin/tilde --config /etc/tilde/config.toml serve
EnvironmentFile=/etc/tilde/.env
Environment=TILDE_DATA_DIR=/data/tilde
Environment=TILDE_CONFIG_DIR=/etc/tilde

Restart=always
RestartSec=5
TimeoutStartSec=300
TimeoutStopSec=30

ProtectSystem=strict
ReadWritePaths=/data/tilde /etc/tilde /home/tilde
ProtectHome=false
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now tilde
```

### 6. Install nginx + TLS

```bash
apt install -y nginx certbot python3-certbot-nginx
```

**/etc/nginx/sites-available/tilde:**

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name cloud.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebDAV/CalDAV/CardDAV need large bodies
        client_max_body_size 10G;

        # WebSocket/streaming support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Stream responses (don't buffer)
        proxy_buffering off;
        proxy_request_buffering off;
    }
}
```

```bash
ln -sf /etc/nginx/sites-available/tilde /etc/nginx/sites-enabled/tilde
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx

# Get TLS certificate
certbot --nginx -d cloud.example.com --non-interactive --agree-tos -m you@example.com
```

Certbot auto-renews via a systemd timer. To keep port 80 closed except during renewal:

```bash
# Close port 80
ufw delete allow 80/tcp

# Add hooks to open/close during renewal
cat > /etc/letsencrypt/renewal-hooks/pre/open-80.sh << 'EOF'
#!/bin/bash
ufw allow 80/tcp >/dev/null 2>&1
EOF

cat > /etc/letsencrypt/renewal-hooks/post/close-80.sh << 'EOF'
#!/bin/bash
ufw delete allow 80/tcp >/dev/null 2>&1
EOF

chmod +x /etc/letsencrypt/renewal-hooks/pre/open-80.sh
chmod +x /etc/letsencrypt/renewal-hooks/post/close-80.sh
```

### 7. Firewall

```bash
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 443/tcp
ufw --force enable
```

### 8. Harden SSH

```bash
cat > /etc/ssh/sshd_config.d/99-harden.conf << 'EOF'
PasswordAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin prohibit-password
EOF
systemctl restart ssh
```

Install fail2ban:

```bash
apt install -y fail2ban
systemctl enable --now fail2ban
```

### 9. Create app passwords

```bash
sudo -u tilde tilde --config /etc/tilde/config.toml auth app-password create \
  --name "phone" --scope "/dav/*"

sudo -u tilde tilde --config /etc/tilde/config.toml auth app-password create \
  --name "desktop" --scope "*"
```

Save each token — they cannot be retrieved later.

### 10. Install optional dependencies

```bash
apt install -y ffmpeg    # Video thumbnails
apt install -y restic    # Backups (already installed if using install.sh)
restic self-update       # Get latest version
```

---

## Connect Clients

### iOS/macOS (Calendar + Contacts)

Open in Safari to auto-configure:
```
https://cloud.example.com/apple-mobileconfig
```

### Android (DAVx5)

- Base URL: `https://cloud.example.com`
- Use app password with `/dav/*` scope

### Files (rclone, Roundsync, any WebDAV client)

- WebDAV URL: `https://cloud.example.com/dav/files/`

### Notes (any WebDAV-capable app)

- WebDAV URL: `https://cloud.example.com/dav/notes/`

---

## Backups

tilde uses [restic](https://restic.net) for incremental, encrypted, deduplicated backups to Backblaze B2.

```bash
# Check status
sudo -u tilde tilde --config /etc/tilde/config.toml backup status

# Run a backup now
sudo -u tilde tilde --config /etc/tilde/config.toml backup now

# List snapshots
sudo -u tilde tilde --config /etc/tilde/config.toml backup list

# Verify repository integrity
sudo -u tilde tilde --config /etc/tilde/config.toml backup verify
```

### Restore from backup

On a new server, install tilde and restic, then:

```bash
export RESTIC_REPOSITORY=b2:your-bucket:tilde-backups
export RESTIC_PASSWORD_FILE=/etc/tilde/restic-password
export B2_ACCOUNT_ID=your-key-id
export B2_ACCOUNT_KEY=your-key

# List available snapshots
restic snapshots --last

# Restore latest
restic restore latest --target /

# Rename the database snapshot
mv /data/tilde/.tilde-backup.db /data/tilde/tilde.db
```

Then start tilde normally.

---

## Updating

```bash
sudo -u tilde tilde --config /etc/tilde/config.toml update apply
```

This downloads the latest release from GitHub and performs a zero-downtime restart.

---

## Data Locations

| What | Path |
|------|------|
| Config | `/etc/tilde/config.toml` |
| Secrets | `/etc/tilde/.env` |
| Database | `/data/tilde/tilde.db` |
| Files | `/data/tilde/files/` |
| Photos | `/data/tilde/photos/` |
| Notes | `/data/tilde/notes/` |
| Calendars | `/data/tilde/calendars/` |
| Contacts | `/data/tilde/contacts/` |
| Thumbnails | `~tilde/.cache/tilde/thumbnails/` |
| Logs | `journalctl -u tilde` |

---

## Security Checklist

- [ ] SSH: password auth disabled, key-only
- [ ] Firewall: only 22 and 443 open
- [ ] TLS: valid cert, auto-renewing
- [ ] fail2ban installed
- [ ] unattended-upgrades enabled
- [ ] Secrets: `.env` is 600, `restic-password` is 400
- [ ] tilde runs as unprivileged user
- [ ] Backup password stored in password manager
