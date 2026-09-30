#!/usr/bin/env python3
"""Compare Tilde's Rust CLI with output from the upstream TypeScript bridge.

Usage: python3 compare.py /path/to/oracle.log /path/to/tilde
The oracle log must contain one ORACLE_RESULT= line from oracle.ts.
"""

import hashlib
import json
import os
import subprocess
import sys


def main() -> None:
    oracle_log, tilde = sys.argv[1:3]
    with open(oracle_log, encoding="utf-8") as file:
        lines = [line.removeprefix("ORACLE_RESULT=") for line in file if line.startswith("ORACLE_RESULT=")]
    if len(lines) != 1:
        raise RuntimeError(f"Expected one ORACLE_RESULT in {oracle_log}, found {len(lines)}")
    expected = json.loads(lines[0])

    env = os.environ.copy()
    env.update({
        "TILDE_NOTES__LIVESYNC__SERVER_URL": os.environ.get("ORACLE_HOST_URL", "http://127.0.0.1:15989"),
        "TILDE_NOTES__LIVESYNC__DATABASE": os.environ.get("ORACLE_DATABASE", "tilde_livesync_oracle"),
        "TILDE_NOTES__LIVESYNC__USERNAME": "admin",
        "TILDE_NOTES__LIVESYNC__PASSWORD": "testpassword",
    })

    def tilde_command(*args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [tilde, "--config", os.environ.get("ORACLE_EMPTY_CONFIG", "/private/tmp/tilde-livesync-oracle-no-config-20260930"), "notes", "live-sync", *args],
            env=env,
            capture_output=True,
            check=False,
        )

    listed = tilde_command("list")
    if listed.returncode:
        raise AssertionError(listed.stderr.decode())
    actual_paths = listed.stdout.decode().splitlines()
    expected_paths = sorted(note["path"] for note in expected if note["exists"])
    assert actual_paths == expected_paths, (actual_paths, expected_paths)

    for note in expected:
        actual = tilde_command("read", note["path"])
        if not note["exists"]:
            assert actual.returncode != 0 and b"note not found" in actual.stderr, (
                note["path"], actual.returncode, actual.stderr
            )
            continue
        if actual.returncode:
            raise AssertionError((note["path"], actual.stderr.decode()))
        assert len(actual.stdout) == note["size"], note["path"]
        assert hashlib.sha256(actual.stdout).hexdigest() == note["sha256"], note["path"]
        snapshot = tilde_command("read", note["path"], "--json")
        if snapshot.returncode:
            raise AssertionError((note["path"], snapshot.stderr.decode()))
        parsed = json.loads(snapshot.stdout)
        assert parsed["path"] == note["path"]
        assert parsed["content"].encode() == actual.stdout
        assert isinstance(parsed["revision"], str) and parsed["revision"]

    print(f"Matched bridge output for {len(expected)} paths and {len(expected_paths)} listed notes")


if __name__ == "__main__":
    main()
