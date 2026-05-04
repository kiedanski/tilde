-- Remove unused FTS5 virtual tables (search uses grep instead)
DROP TABLE IF EXISTS notes_fts;
DROP TABLE IF EXISTS email_fts;
