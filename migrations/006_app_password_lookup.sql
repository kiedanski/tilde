-- Add lookup_hash column for O(1) app-password lookup (avoids iterating all Argon2 hashes)
-- Stores SHA-256 of the raw password for fast matching before expensive Argon2 verification.
ALTER TABLE app_passwords ADD COLUMN lookup_hash TEXT;
CREATE INDEX IF NOT EXISTS idx_app_passwords_lookup ON app_passwords(lookup_hash);
