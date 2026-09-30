// Run inside the pinned upstream livesync-bridge image. This is the TypeScript
// oracle for the Rust reader; it deliberately uses the bridge's public peer.
import { PeerCouchDB } from "/app/PeerCouchDB.ts";
import type { FileData, PeerCouchDBConf } from "/app/types.ts";
import type { FilePathWithPrefix } from "@vrtmrz/livesync-commonlib/compat/common/types";

const database = Deno.env.get("ORACLE_DATABASE") ?? "tilde_livesync_oracle";
const config: PeerCouchDBConf = {
    type: "couchdb",
    name: "tilde-oracle",
    database,
    username: "admin",
    password: "testpassword",
    url: Deno.env.get("ORACLE_COUCH_URL") ?? "http://tilde-livesync-couchdb-20260930:5984",
    passphrase: "",
    obfuscatePassphrase: "",
    baseDir: "",
    customChunkSize: 100,
    minimumChunkSize: 20,
};
const peer = new PeerCouchDB(config, async () => {});

const original = [
    { path: "simple.md", content: "# Hello\n\nA note.\n" },
    { path: "folder/café 雪.md", content: "Unicode: café, 雪, 🦊\n" },
    { path: "empty.md", content: "" },
    { path: "long.md", content: "chunk-🦊-".repeat(1000) },
];
const rustPath = "rust/folder 🦊.md";
const mcpPath = "mcp/shared.md";
const rustInitial = "# From Tilde\n\n" + "mixed 🦊 data\n".repeat(2000);
const rustUpdated = "# Tilde resolved\n\nObsidian edit\nTilde edit\n";

function fileData(content: string, mtime: number): FileData {
    return {
        ctime: 1_700_000_000_000,
        mtime,
        size: new TextEncoder().encode(content).length,
        data: [content],
    };
}

try {
    await peer.start();
    const mode = Deno.args[0] ?? "seed";
    if (mode === "seed") {
        for (const note of original) {
            if (!await peer.put(note.path, fileData(note.content, 1_700_000_000_000))) {
                throw new Error(`Could not write ${note.path}`);
            }
        }
    } else if (mode === "update") {
        if (!await peer.put("simple.md", fileData("# Updated\n", 1_700_000_010_000))) {
            throw new Error("Could not update simple.md");
        }
    } else if (mode === "delete") {
        if (!await peer.delete("empty.md")) {
            throw new Error("Could not delete empty.md");
        }
    } else if (mode === "bridge-edit-rust") {
        const before = await peer.get(rustPath as FilePathWithPrefix);
        if (before === false || before.data.join("") !== rustInitial) {
            throw new Error("The bridge did not read Tilde's original note content");
        }
        if (!await peer.put(rustPath, fileData("# Obsidian edit\n", 1_700_000_020_000))) {
            throw new Error("The bridge could not update Tilde's note");
        }
    } else if (mode === "verify-mcp") {
        const value = await peer.get(mcpPath as FilePathWithPrefix);
        if (value === false || value.data.join("") !== "# MCP\n\nFrom Tilde\nfrom agent") {
            throw new Error("The bridge did not read Tilde's MCP note content");
        }
    } else if (mode === "verify-rust" || mode === "verify-rust-updated" || mode === "verify-rust-deleted") {
        const value = await peer.get(rustPath as FilePathWithPrefix);
        const expected = mode === "verify-rust" ? rustInitial : mode === "verify-rust-updated" ? rustUpdated : null;
        const actual = value === false ? null : value.data.join("");
        if (actual !== expected) {
            throw new Error(`The bridge saw unexpected content for ${rustPath}`);
        }
        if (mode === "verify-rust") {
            const raw = await peer.man.rawGet(await peer.man.path2id(rustPath));
            if (!raw || !Array.isArray(raw.children) || raw.children.length < 2) {
                throw new Error("Tilde did not create a chunked LiveSync note");
            }
            for (const id of raw.children) {
                const chunk = await peer.man.rawGet(id);
                if (!chunk || chunk.type !== "leaf" || typeof chunk.data !== "string") {
                    throw new Error(`Tilde produced an unreadable chunk: ${id}`);
                }
                const expectedId = `h:${await peer.man.liveSyncLocalDB.managers.hashManager.computeHash(chunk.data)}`;
                if (id !== expectedId) {
                    throw new Error(`Tilde produced a chunk with a non-LiveSync hash: ${id}`);
                }
            }
        }
    } else if (mode !== "read") {
        throw new Error(`Unknown oracle mode: ${mode}`);
    }
    const paths = [...original.map((note) => note.path), rustPath, mcpPath];
    const result = [];
    for (const path of paths) {
        const value = await peer.get(path as FilePathWithPrefix);
        if (value === false) {
            result.push({ path, exists: false });
        } else {
            const content = value.data.join("");
            const bytes = new TextEncoder().encode(content);
            const hash = await crypto.subtle.digest("SHA-256", bytes);
            const sha256 = Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("");
            result.push({ path, exists: true, size: bytes.length, sha256 });
        }
    }
    console.log(`ORACLE_RESULT=${JSON.stringify(result)}`);
} finally {
    await peer.stop();
    await peer.man?.close();
}
Deno.exit(0);
