-- Set a sentinel taken_at for photos with no EXIF date so they appear in
-- date-filtered queries (e.g. `tilde photos list --since ...`).
UPDATE photos SET taken_at = '1800-01-01T00:00:00+00:00' WHERE taken_at IS NULL;
