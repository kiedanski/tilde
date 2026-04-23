# Installing tilde on a Proxmox LXC Container

This guide covers deploying tilde as a Nextcloud replacement on a Proxmox server, running in an unprivileged LXC container with systemd.

## Requirements

- Proxmox VE host with a Debian/Ubuntu LXC template
- A domain name pointing to your server (e.g., `cloud.example.com`)
- Port 443 open and forwarded to the container
- ~1 GB disk minimum (more for photos/files)
- 256-512 MB RAM

## 1. Create the LXC Container

On the Proxmox host:

```bash
# Create a Debian 12 container (adjust storage/ID as needed)
pct create 110 local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
  --hostname tilde \
  --memory 512 \
  --swap 512 \
  --cores 2 \
  --rootfs local-lvm:8 \
  --net0 name=eth0,bridge=vmbr0,ip=192.168.0.110/24,gw=192.168.0.1 \
  --unprivileged 1 \
  --onboot 1
```

If you want to share a ZFS volume for photos/files storage, add a mount point:

```bash
# Optional: mount existing ZFS subvolume for data
# mp0: data:subvol-100-disk-1,mp=/data,backup=0,ro=0
```

## 2. Start and Enter the Container

```bash
pct start 110
pct enter 110
```

## 3. Install tilde Binary

**Option A: Copy pre-built binary (recommended)**

From your build machine (the one with the cross-compiled binary):

```bash
# From the machine where you built tilde:
scp target/x86_64-unknown-linux-musl/release/tilde root@proxmox-ip:/tmp/

# On the Proxmox host, copy into the container:
pct push 110 /tmp/tilde /usr/bin/tilde
pct exec 110 -- chmod +x /usr/bin/tilde
```

**Option B: Build on the container itself**

```bash
apt update && apt install -y curl build-essential pkg-config libheif-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
# Clone and build
git clone <your-repo-url> /tmp/tilde-src
cd /tmp/tilde-src
cargo build --release
cp target/release/tilde /usr/bin/tilde
```

## 4. Configure

### Create config directory and environment file

```bash
mkdir -p /etc/tilde
```

### Write `/etc/tilde/config.toml`

```toml
[server]
hostname = "cloud.example.com"   # YOUR DOMAIN HERE
listen_addr = "0.0.0.0"
listen_port = 443

[tls]
mode = "acme"
# For reverse proxy setups, use mode = "upstream" and listen_port = 8080

[auth]
session_ttl_hours = 24
webauthn_enabled = true
webauthn_rp_id = "cloud.example.com"   # Must match hostname

[photos]
enabled = true
organization_pattern = "{year}/{month:02}"

[calendar]
enabled = true

[contacts]
enabled = true

[notes]
root_path = "notes"

[email]
enabled = false
# Uncomment to enable email archival:
# enabled = true
# [[email.accounts]]
# name = "personal"
# imap_host = "imap.yourprovider.com"

[mcp]
enabled = true
tool_allowlist = ["*"]

[backup]
enabled = true
schedule = "hourly"

# Optional: offsite backup to Backblaze B2
# [[backup.offsite]]
# name = "b2"
# type = "s3"
# endpoint = "https://s3.us-east-005.backblazeb2.com"  # Check your B2 region!
# bucket_env = "TILDE_BACKUP_B2_BUCKET"
# key_id_env = "TILDE_BACKUP_B2_KEY_ID"
# key_env = "TILDE_BACKUP_B2_KEY"
# schedule = "hourly"
```

### Write `/etc/tilde/.env`

```bash
cat > /etc/tilde/.env << 'EOF'
# REQUIRED
TILDE_ADMIN_PASSWORD=CHANGE_ME_TO_A_STRONG_PASSWORD
TILDE_HOSTNAME=cloud.example.com
TILDE_ACME_EMAIL=you@example.com
TILDE_BACKUP_PASSWORD=CHANGE_ME_RANDOM_STRING

# OFFSITE BACKUP (optional)
# TILDE_BACKUP_B2_KEY_ID=
# TILDE_BACKUP_B2_KEY=
# TILDE_BACKUP_B2_BUCKET=tilde-backups

# EMAIL (optional)
# TILDE_EMAIL_IMAP_HOST=imap.purelymail.com
# TILDE_EMAIL_IMAP_PORT=993
# TILDE_EMAIL_USERNAME=you@example.com
# TILDE_EMAIL_PASSWORD=
EOF
chmod 600 /etc/tilde/.env
```

## 5. Install systemd Service

```bash
tilde install
```

This creates a `tilde` system user, writes the systemd unit file, and reloads systemd.

### Load environment variables

Edit the systemd override to load the env file:

```bash
mkdir -p /etc/systemd/system/tilde.service.d
cat > /etc/systemd/system/tilde.service.d/env.conf << 'EOF'
[Service]
EnvironmentFile=/etc/tilde/.env
EOF
systemctl daemon-reload
```

## 6. Start the Service

```bash
systemctl enable --now tilde
systemctl status tilde
journalctl -u tilde -f   # Watch logs
```

## 7. Verify

```bash
# Check health endpoint
curl -s http://localhost:443/health | python3 -m json.tool

# Check Nextcloud-compatible status
curl -s http://localhost:443/status.php

# Run built-in diagnostics
tilde diagnose
```

## 8. Connect Clients

### Nextcloud Desktop/Mobile

1. Open Nextcloud client
2. Enter your server URL: `https://cloud.example.com`
3. It will open a browser for Login Flow v2
4. Log in with username `admin` and your `TILDE_ADMIN_PASSWORD`
5. The client will sync your files

### iOS/macOS Calendar & Contacts

Use the auto-config profile:

1. Open `https://cloud.example.com/apple-mobileconfig` in Safari
2. Install the profile — it pre-configures CalDAV and CardDAV

Or manually:
- CalDAV server: `https://cloud.example.com/caldav/`
- CardDAV server: `https://cloud.example.com/carddav/`
- Username: `admin`, Password: your admin password

### DAVx5 (Android)

- Base URL: `https://cloud.example.com`
- Use CalDAV/CardDAV auto-discovery

### Notes (Joplin, iA Writer, etc.)

Any WebDAV-capable notes app:
- URL: `https://cloud.example.com/dav/notes/`
- Username: `admin`, Password: your admin password

### MCP (AI Integration)

Generate an MCP token:

```bash
tilde mcp create-token --name "my-ai" --tools "*"
```

Use the returned token as a Bearer token with endpoint:
`https://cloud.example.com/mcp`

## 9. Backups

### Local backup status

```bash
tilde backup status
tilde backup list
```

### Manual backup with offsite upload

```bash
tilde backup now --offsite b2
```

### Restore from backup

```bash
tilde backup list
tilde backup restore <snapshot-id>
```

## 10. Updating

```bash
# Copy new binary
scp tilde root@proxmox-ip:/tmp/
pct push 110 /tmp/tilde /usr/bin/tilde

# Restart
pct exec 110 -- systemctl restart tilde
```

Or use the built-in self-update (if configured):

```bash
tilde self-update
```

## Reverse Proxy Setup (Alternative to ACME)

If you already have a reverse proxy (nginx, Caddy, Traefik) handling TLS:

```toml
# In config.toml:
[server]
listen_port = 8080
trusted_proxies = ["10.0.0.1/32"]  # Your proxy IP

[tls]
mode = "upstream"
```

Then proxy `https://cloud.example.com` to `http://<container-ip>:8080`.

## Data Locations

When running as a systemd service:

| What | Path |
|------|------|
| Config | `/etc/tilde/config.toml` |
| Secrets | `/etc/tilde/.env` |
| Database | `/var/lib/tilde/tilde.db` |
| Files | `/var/lib/tilde/files/` |
| Photos | `/var/lib/tilde/photos/` |
| Notes | `/var/lib/tilde/files/notes/` |
| Backups | `/var/lib/tilde/backup/` |
| Thumbnails | `/var/cache/tilde/thumbnails/` |
| ACME certs | `/var/lib/tilde/acme/` |
| Logs | `journalctl -u tilde` |

## Migrating from Nextcloud

1. **Files:** Copy your Nextcloud data directory contents into `/var/lib/tilde/files/`
2. **Calendar:** Export `.ics` files from Nextcloud, import via CalDAV client
3. **Contacts:** Export `.vcf` files from Nextcloud, import via CardDAV client
4. **Photos:** Copy into `/var/lib/tilde/photos/_inbox/` — tilde auto-organizes them
5. **Notes:** Copy markdown files into `/var/lib/tilde/files/notes/`

After copying files, let tilde index them:

```bash
systemctl restart tilde   # Triggers re-scan
```

## Troubleshooting

### ACME certificate not provisioning

- Ensure port 443 is reachable from the internet
- Check DNS resolves to your server: `dig cloud.example.com`
- Check logs: `journalctl -u tilde | grep -i acme`
- The first request may take 10-30 seconds while the cert is provisioned

### Nextcloud client can't connect

- Verify `status.php` works: `curl https://cloud.example.com/status.php`
- Check the client is using your server URL (not `localhost`)
- Try the Login Flow v2 URL in a browser: `https://cloud.example.com/login/v2`

### Out of memory

tilde is configured with `MemoryMax=512M` in systemd. If you're processing many large HEIC photos simultaneously, you may need to increase this:

```bash
systemctl edit tilde
# Add: [Service]
#      MemoryMax=1G
```

### Database locked

Only one instance of tilde should run at a time. Check for stale processes:

```bash
ps aux | grep tilde
```
