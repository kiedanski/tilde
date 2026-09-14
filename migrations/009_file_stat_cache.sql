-- Stat cache for ETag resolution.
--
-- The `files` table is no longer the authority for ETags — disk is. These
-- columns let PROPFIND/GET decide whether the cached `etag` still describes
-- what is on disk without re-hashing the file on every request.
--
-- Existing rows get NULL mtime_nanos, which reads as a cache miss and forces
-- one rehash per file on first access. That is intended.
ALTER TABLE files ADD COLUMN mtime_nanos INTEGER;
ALTER TABLE files ADD COLUMN inode INTEGER;
