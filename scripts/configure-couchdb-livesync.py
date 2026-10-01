#!/usr/bin/env python3
"""Configure Tilde's native CouchDB, restricted LiveSync user, and HTTPS route."""

import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import tomllib
import urllib.error
import urllib.parse
import urllib.request


if os.geteuid() != 0:
    raise SystemExit("Run as root")

admin_password = Path("/etc/tilde/couchdb-admin-password").read_text().strip()
sync_secret = Path("/etc/tilde/couchdb-sync-password")
if not sync_secret.exists():
    sync_secret.write_text(secrets.token_hex(24) + "\n")
    sync_secret.chmod(0o600)
sync_password = sync_secret.read_text().strip()


def couch(method, path, body=None, user="admin", password=None):
    if password is None:
        password = admin_password
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    payload = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:5984" + path,
        data=payload,
        method=method,
        headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


status, _ = couch("PUT", "/tilde_notes")
if status not in (201, 202, 412):
    raise SystemExit(f"Create tilde_notes database failed: HTTP {status}")

user_id = urllib.parse.quote("org.couchdb.user:tilde_sync", safe=":")
status, _ = couch(
    "PUT",
    "/_users/" + user_id,
    {"name": "tilde_sync", "password": sync_password, "roles": [], "type": "user"},
)
if status not in (201, 202, 409):
    raise SystemExit(f"Create CouchDB sync user failed: HTTP {status}")

status, _ = couch(
    "PUT",
    "/tilde_notes/_security",
    {"admins": {"names": [], "roles": []}, "members": {"names": ["tilde_sync"], "roles": []}},
)
if status not in (200, 201, 202):
    raise SystemExit(f"Secure tilde_notes database failed: HTTP {status}")

status, _ = couch("GET", "/tilde_notes", user="tilde_sync", password=sync_password)
if status != 200:
    raise SystemExit(f"Restricted sync user cannot read tilde_notes: HTTP {status}")

version_path = "/tilde_notes/obsydian_livesync_version"
status, body = couch("GET", version_path)
if status == 404:
    status, _ = couch(
        "PUT", version_path,
        {"_id": "obsydian_livesync_version", "type": "versioninfo", "version": 12},
    )
    if status not in (201, 202):
        raise SystemExit(f"Create LiveSync version document failed: HTTP {status}")
elif status == 200:
    version = json.loads(body)
    if version.get("type") != "versioninfo" or version.get("version") != 12:
        raise SystemExit("Existing LiveSync database version is incompatible")
else:
    raise SystemExit(f"Read LiveSync version document failed: HTTP {status}")

config = Path("/etc/tilde/config.toml")
config_text = config.read_text()
hostname = tomllib.loads(config_text).get("server", {}).get("hostname", "")
public_url = os.environ.get("TILDE_COUCHDB_PUBLIC_URL") or (
    f"https://{hostname}/couchdb/" if hostname else ""
)
if not public_url:
    raise SystemExit("Set TILDE_COUCHDB_PUBLIC_URL or [server].hostname")
if "[notes.livesync]" not in config_text:
    config_text += (
        "\n[notes.livesync]\n"
        'server_url = "http://127.0.0.1:5984"\n'
        f"public_url = {json.dumps(public_url)}\n"
        'database = "tilde_notes"\n'
        'username = "tilde_sync"\n'
    )
    config.write_text(config_text)
else:
    section = config_text.split("[notes.livesync]", 1)[1].split("\n[", 1)[0]
    if "public_url" not in section:
        config_text = config_text.replace(
            "[notes.livesync]\n",
            f"[notes.livesync]\npublic_url = {json.dumps(public_url)}\n",
            1,
        )
        config.write_text(config_text)

env_file = Path("/etc/tilde/.env")
env_text = env_file.read_text()
key = "TILDE_NOTES__LIVESYNC__PASSWORD="
env_lines = [line for line in env_text.splitlines() if not line.startswith(key)]
env_lines.append(key + sync_password)
env_file.write_text("\n".join(env_lines) + "\n")
env_file.chmod(0o600)

nginx_site = Path("/etc/nginx/sites-available/tilde")
site_text = nginx_site.read_text()
if "location ^~ /couchdb/" not in site_text:
    backup = nginx_site.with_name("tilde.before-couchdb")
    if not backup.exists():
        backup.write_text(site_text)
    route = """    location = /couchdb { return 308 /couchdb/; }

    location ^~ /couchdb/ {
        rewrite ^/couchdb/(.*) /$1 break;
        proxy_pass http://127.0.0.1:5984;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_request_buffering off;
        client_max_body_size 50M;
        proxy_read_timeout 3600s;
    }

"""
    if "    location / {" not in site_text:
        raise SystemExit("Expected Nginx location / was not found")
    nginx_site.write_text(site_text.replace("    location / {", route + "    location / {", 1))
    subprocess.run(["nginx", "-t"], check=True)
    subprocess.run(["systemctl", "reload", "nginx"], check=True)

for path in ("/var/lib/couchdb", "/opt/couchdb/etc"):
    subprocess.run(["setfacl", "-R", "-m", "u:tilde:rX", path], check=True)
    subprocess.run(
        ["find", path, "-type", "d", "-exec", "setfacl", "-m", "d:u:tilde:rX", "{}", "+"],
        check=True,
    )

if "additional_paths" not in config_text:
    config_text = config.read_text()
    config_text = config_text.replace(
        "[backup]\n",
        '[backup]\nadditional_paths = ["/var/lib/couchdb", "/opt/couchdb/etc", "/etc/tilde/config.toml", "/etc/tilde/.env"]\n',
        1,
    )
    config.write_text(config_text)

print("LiveSync database, restricted user, HTTPS route, backup paths, and Tilde config ready")
