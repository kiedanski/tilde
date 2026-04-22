# tilde — English locale (default)

app-name = tilde
app-description = Personal Cloud Server

# Init wizard
init-welcome = Welcome to tilde setup
init-hostname-prompt = Enter your public hostname (e.g., cloud.example.com)
init-password-prompt = Set your admin password
init-tls-prompt = Choose TLS mode (acme/manual/upstream)
init-complete = Setup complete! Run `systemctl enable --now tilde` to start.

# Status
status-running = Server is running
status-stopped = Server is stopped
status-disk-usage = Disk usage: { $used } / { $total }
status-last-backup = Last backup: { $time }
status-cert-expiry = Certificate expires: { $date }

# Errors
error-config-missing = Configuration file not found at { $path }
error-config-invalid = Invalid configuration: { $details }
error-auth-failed = Authentication failed
error-not-found = Resource not found: { $path }
error-conflict = Conflict: { $details }
