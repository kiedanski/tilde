"""Build a populated pre-009 tilde instance, as a 4-month-old deployment would have."""
import hashlib, os, sqlite3, sys, pathlib, random

data = pathlib.Path(sys.argv[1])
migrations = pathlib.Path(sys.argv[2])

for d in ["notes", "files/documents", "photos/2026/05", "photos/2026/06",
          "calendars", "contacts", "mail", "collections", "uploads", "backup"]:
    (data / d).mkdir(parents=True, exist_ok=True)

db = sqlite3.connect(data / "tilde.db")
db.executescript("""CREATE TABLE IF NOT EXISTS migrations (
  version INTEGER PRIMARY KEY, name TEXT NOT NULL,
  applied_at TEXT NOT NULL, checksum TEXT NOT NULL);""")

applied = []
for f in sorted(migrations.glob("*.sql")):
    v = int(f.name.split("_")[0])
    if v > 8:
        continue
    sql = f.read_text()
    db.executescript(sql)
    db.execute("INSERT INTO migrations (version,name,applied_at,checksum) VALUES (?,?,?,?)",
               (v, f.stem, "2026-05-01T00:00:00+00:00",
                hashlib.sha256(sql.encode()).hexdigest()))
    applied.append(v)
db.commit()
print(f"legacy schema built: migrations {min(applied)}..{max(applied)}")

random.seed(7)
now = "2026-05-01T00:00:00+00:00"

def add_file(disk_rel, db_path, content, *, stale=False):
    """Index a file. `disk_rel` is relative to the data dir; `db_path` is what the
    server stores, which is the path relative to that MOUNT's root prefixed by the
    mount's db_path_prefix ("" for files, "notes/" for notes).

    `stale` writes an etag that does not match disk — what the pre-fix server left
    behind for any write that bypassed DAV."""
    disk = data / disk_rel
    disk.parent.mkdir(parents=True, exist_ok=True)
    disk.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    etag = "0" * 16 if stale else sha[:16]
    parent = str(pathlib.PurePath(db_path).parent)
    db.execute("""INSERT INTO files (id,path,parent_path,name,size_bytes,content_type,
                    etag,sha256,is_directory,created_at,modified_at,hlc)
                  VALUES (?,?,?,?,?,?,?,?,0,?,?,?)""",
               (f"id-{db_path}", db_path, "" if parent == "." else parent,
                pathlib.PurePath(db_path).name, len(content),
                "text/markdown" if db_path.endswith(".md") else "application/octet-stream",
                etag, sha, now, now, now))

# 120 notes; a third carry stale etags, as agent/CLI writes would have left them
stale_count = 0
for i in range(120):
    stale = (i % 3 == 0)
    stale_count += stale
    body = f"# Note {i}\n\n" + "\n".join(f"line {j}" for j in range(20)) + "\n"
    add_file(f"notes/note-{i:03}.md", f"notes/note-{i:03}.md", body.encode(), stale=stale)

for i in range(40):
    # files mount: db_path_prefix is "", so the stored path drops the "files/" dir
    add_file(f"files/documents/doc-{i:02}.txt", f"documents/doc-{i:02}.txt", (f"document {i}\n" * 50).encode())

db.execute("INSERT INTO collections (id,name,schema_json,created_at,updated_at) VALUES ('c1','weight','{}',?,?)", (now, now))
for i in range(200):
    db.execute("INSERT INTO records (id,collection_id,data_json,created_at,updated_at,hlc) VALUES (?,?,?,?,?,?)",
               (f"r{i}", "c1", f'{{"kg": {80 + i % 5}}}', now, now, now))

db.commit()
n_files = db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
n_rec = db.execute("SELECT COUNT(*) FROM records").fetchone()[0]
print(f"seeded: {n_files} indexed files ({stale_count} with stale etags), {n_rec} records")
db.close()
