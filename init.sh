#!/usr/bin/env bash
set -euo pipefail

# tilde — Personal Cloud Server
# Development environment setup script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ─── Load environment variables ─────────────────────────────────────────────
if [ -f "$SCRIPT_DIR/.env" ]; then
    info "Loading environment variables from .env"
    set -a
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
    set +a
elif [ -f "$SCRIPT_DIR/.env.example" ]; then
    error ".env file not found!"
    echo "  Create it from the template:"
    echo "    cp .env.example .env"
    echo "  Then fill in your values and re-run this script."
    exit 1
else
    warn "No .env or .env.example found. Proceeding without environment variables."
fi

# ─── Check system dependencies ──────────────────────────────────────────────
info "Checking system dependencies..."

check_dep() {
    if command -v "$1" &>/dev/null; then
        info "  ✓ $1 found: $(command -v "$1")"
        return 0
    else
        warn "  ✗ $1 not found (required for: $2)"
        return 1
    fi
}

MISSING=0
check_dep "rustc"    "building tilde"         || MISSING=1
check_dep "cargo"    "building tilde"         || MISSING=1
check_dep "sqlite3"  "database operations"    || MISSING=1
check_dep "exiftool" "photo metadata"         || { MISSING=0; warn "    (optional: needed for photo features)"; }
check_dep "ffmpeg"   "video thumbnails"       || { MISSING=0; warn "    (optional: needed for video thumbnails)"; }

if [ "$MISSING" -eq 1 ]; then
    error "Required dependencies missing. Install them and re-run."
    exit 1
fi

# Check Rust toolchain version
RUST_VERSION=$(rustc --version | awk '{print $2}')
info "  Rust version: $RUST_VERSION"

# ─── Install Rust dependencies ──────────────────────────────────────────────
info "Building project (this may take a few minutes on first run)..."

if cargo build 2>&1; then
    info "Build successful!"
else
    error "Build failed. Check error output above."
    exit 1
fi

# ─── Create data directories for development ────────────────────────────────
DEV_DATA_DIR="${TILDE_DATA_DIR:-$SCRIPT_DIR/.dev-data}"
DEV_CACHE_DIR="${TILDE_CACHE_DIR:-$SCRIPT_DIR/.dev-cache}"

info "Creating development data directories at $DEV_DATA_DIR"

mkdir -p "$DEV_DATA_DIR"/{files/notes,files/documents}
mkdir -p "$DEV_DATA_DIR"/photos/{_inbox,_library-drop,_untriaged,_errors}
mkdir -p "$DEV_DATA_DIR"/{calendars,contacts,mail,collections,uploads,backup}
mkdir -p "$DEV_DATA_DIR"/blobs/by-id
mkdir -p "$DEV_CACHE_DIR"/{thumbnails,fts}

info "Data directories created."

# ─── Print summary ──────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  tilde development environment ready"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Binary:     target/debug/tilde"
echo "  Data dir:   $DEV_DATA_DIR"
echo "  Cache dir:  $DEV_CACHE_DIR"
echo ""
echo "  Quick start:"
echo "    cargo run -- init          # Run setup wizard"
echo "    cargo run -- serve         # Start the server"
echo "    cargo run -- status        # Check server status"
echo "    cargo run -- --help        # See all commands"
echo ""
echo "  Run tests:"
echo "    cargo test                 # All tests"
echo "    cargo test -p tilde-core   # Single crate"
echo "    cargo clippy -D warnings   # Lint check"
echo ""
if [ -n "${TILDE_HOSTNAME:-}" ]; then
    echo "  Hostname:   $TILDE_HOSTNAME"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
