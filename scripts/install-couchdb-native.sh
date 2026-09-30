#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root" >&2
    exit 1
fi

admin_secret=/etc/tilde/couchdb-admin-password
if [[ ! -e $admin_secret ]]; then
    umask 077
    openssl rand -hex 24 > "$admin_secret"
fi
admin_password=$(cat "$admin_secret")
cookie_secret=/etc/tilde/couchdb-cookie
if [[ ! -e $cookie_secret ]]; then
    umask 077
    openssl rand -hex 24 > "$cookie_secret"
fi
cookie=$(cat "$cookie_secret")
{
    printf 'couchdb couchdb/mode select standalone\n'
    printf 'couchdb couchdb/bindaddress string 127.0.0.1\n'
    printf 'couchdb couchdb/cookie string %s\n' "$cookie"
    printf 'couchdb couchdb/adminpass password %s\n' "$admin_password"
    printf 'couchdb couchdb/adminpass_again password %s\n' "$admin_password"
} | debconf-set-selections

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates gnupg
curl -fsS https://couchdb.apache.org/repo/keys.asc \
    | gpg --dearmor > /usr/share/keyrings/couchdb-archive-keyring.gpg
chmod 0644 /usr/share/keyrings/couchdb-archive-keyring.gpg
. /etc/os-release
printf 'deb [signed-by=/usr/share/keyrings/couchdb-archive-keyring.gpg] https://apache.jfrog.io/artifactory/couchdb-deb/ %s main\n' "$VERSION_CODENAME" \
    > /etc/apt/sources.list.d/couchdb.list

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y couchdb

cat > /opt/couchdb/etc/local.d/20-tilde-livesync.ini <<'INI'
[couchdb]
max_document_size = 50000000

[chttpd]
bind_address = 127.0.0.1
max_http_request_size = 4294967296
require_valid_user = true

[httpd]
WWW-Authenticate = Basic realm="couchdb"
enable_cors = true
require_valid_user = true

[cors]
credentials = true
origins = app://obsidian.md,capacitor://localhost,http://localhost
INI
chmod 0644 /opt/couchdb/etc/local.d/20-tilde-livesync.ini
systemctl restart couchdb
systemctl is-active --quiet couchdb
for attempt in $(seq 1 30); do
    if curl -fsS --user "admin:$admin_password" http://127.0.0.1:5984/_up > /dev/null 2>&1; then
        echo "Native CouchDB installed and healthy on localhost"
        exit 0
    fi
    sleep 2
done
echo "CouchDB did not become healthy" >&2
exit 1
