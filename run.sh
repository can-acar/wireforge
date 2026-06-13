#!/usr/bin/env bash
# Wireforge — local development runner.
#
# Builds (if needed), prepares ./wireforge.toml + ./data, then launches the
# server in the foreground. Designed for the repo working tree.
#
# Usage:
#     ./run.sh                     # build (debug) + run on :8080
#     ./run.sh --release           # build & run release binary
#     ./run.sh --port 8088         # override bind port
#     ./run.sh --no-build          # use existing binary
#     ./run.sh --reset             # wipe ./data + ./wireforge.toml first
#     ./run.sh --dry-run-wg=0      # force real WireGuard adapter (Linux only)
#     ./run.sh --open              # open browser after start (Linux/macOS)
#     ./run.sh --help

set -euo pipefail

# ───────── defaults ─────────
PROFILE="debug"          # debug | release
PORT=8080
HOST="127.0.0.1"
BUILD=1
RESET=0
OPEN=0
# On macOS / Windows hosts WireGuard kernel module isn't available — default
# to dry-run unless explicitly overridden. On Linux we try the real adapter.
DEFAULT_DRY_RUN=1
if [[ "$(uname -s)" == "Linux" ]]; then
    DEFAULT_DRY_RUN=0
fi
DRY_RUN_WG="$DEFAULT_DRY_RUN"

# ───────── colours ─────────
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
    C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m';   C_BLUE=$'\033[34m'
else
    C_RESET=""; C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_BLUE=""
fi
log()  { printf '%s==>%s %s\n'  "${C_GREEN}${C_BOLD}" "${C_RESET}" "$*"; }
info() { printf '%s—%s %s\n'    "${C_BLUE}"           "${C_RESET}" "$*"; }
warn() { printf '%s!!%s %s\n'   "${C_YELLOW}${C_BOLD}" "${C_RESET}" "$*" >&2; }
die()  { printf '%sERR%s %s\n'  "${C_RED}${C_BOLD}"   "${C_RESET}" "$*" >&2; exit 1; }

usage() {
    sed -n '2,15p' "$0" | sed 's/^# \?//'
    exit "${1:-0}"
}

# ───────── arg parsing ─────────
while (( $# > 0 )); do
    case "$1" in
        --release)         PROFILE="release"; shift ;;
        --port)            PORT="$2"; shift 2 ;;
        --host)            HOST="$2"; shift 2 ;;
        --no-build)        BUILD=0; shift ;;
        --reset)           RESET=1; shift ;;
        --open)            OPEN=1; shift ;;
        --dry-run-wg=*)    DRY_RUN_WG="${1#*=}"; shift ;;
        --dry-run-wg)      DRY_RUN_WG="$2"; shift 2 ;;
        -h|--help)         usage 0 ;;
        *)                 warn "unknown arg: $1"; usage 1 ;;
    esac
done

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd "$REPO_ROOT"

CONFIG_FILE="$REPO_ROOT/wireforge.toml"
DATA_DIR="$REPO_ROOT/data"

# ───────── preflight ─────────
command -v cargo >/dev/null || die "cargo not found — install Rust via https://rustup.rs"

# Bail if the port is already busy.
port_busy() {
    if command -v lsof &>/dev/null; then
        lsof -i ":$1" -sTCP:LISTEN -P -n 2>/dev/null | grep -q .
    elif command -v ss &>/dev/null; then
        ss -tln "sport = :$1" 2>/dev/null | tail -n +2 | grep -q .
    else
        return 1
    fi
}
if port_busy "$PORT"; then
    die "port $PORT is already in use (try --port 8088 or kill the listener)"
fi

# ───────── reset (optional) ─────────
if (( RESET )); then
    log "Resetting local state"
    rm -rf "$DATA_DIR" "$CONFIG_FILE"
fi

# ───────── config ─────────
if [[ ! -f "$CONFIG_FILE" ]]; then
    log "Generating $CONFIG_FILE"
    cp "$REPO_ROOT/config/wireforge.sample.toml" "$CONFIG_FILE"

    if command -v openssl &>/dev/null; then
        MASTER_KEY="$(openssl rand -base64 48)"
    else
        MASTER_KEY="$(head -c 36 /dev/urandom | base64)"
    fi
    ESCAPED_KEY="$(printf '%s' "$MASTER_KEY" | sed 's/[&/\]/\\&/g')"

    # GNU vs BSD sed in-place flag.
    SED_INPLACE=(-i)
    if sed --version &>/dev/null; then :; else SED_INPLACE=(-i ''); fi

    sed "${SED_INPLACE[@]}" \
        -e "s|^master_key = .*|master_key = \"${ESCAPED_KEY}\"|" \
        -e "s|^bind = .*|bind = \"${HOST}:${PORT}\"|" \
        -e "s|^path = \".*wireforge.sqlite\"|path = \"./data/wireforge.sqlite\"|" \
        "$CONFIG_FILE"
    info "Generated master_key (saved inside $CONFIG_FILE)"
else
    info "Reusing existing $CONFIG_FILE"
fi

mkdir -p "$DATA_DIR"

# ───────── build ─────────
if (( BUILD )); then
    log "Building wireforge-server + wireforge ($PROFILE)"
    if [[ "$PROFILE" == "release" ]]; then
        cargo build --release -p wireforge-bin -p wireforge-cli
    else
        cargo build -p wireforge-bin -p wireforge-cli
    fi
fi

if [[ "$PROFILE" == "release" ]]; then
    BIN="$REPO_ROOT/target/release/wireforge-server"
else
    BIN="$REPO_ROOT/target/debug/wireforge-server"
fi
[[ -x "$BIN" ]] || die "missing $BIN — re-run without --no-build"

# ───────── trap for graceful shutdown ─────────
SERVER_PID=""
cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        info "Stopping server (pid $SERVER_PID)"
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# ───────── env ─────────
export WIREFORGE_CONFIG="$CONFIG_FILE"
export RUST_LOG="${RUST_LOG:-info,sqlx=warn,hyper=warn}"
if [[ "$DRY_RUN_WG" == "1" ]]; then
    export WIREFORGE_WG_DRY_RUN=1
    info "WireGuard adapter: ${C_YELLOW}DRY-RUN${C_RESET} (no kernel I/O)"
else
    unset WIREFORGE_WG_DRY_RUN
    info "WireGuard adapter: ${C_GREEN}live${C_RESET} (requires CAP_NET_ADMIN / kernel wg)"
fi

# ───────── browser (optional) ─────────
launch_browser_when_ready() {
    local url="$1"
    for _ in $(seq 1 30); do
        if curl -fsS "$url/healthz" >/dev/null 2>&1; then
            case "$(uname -s)" in
                Darwin) open "$url" ;;
                Linux)  command -v xdg-open >/dev/null && xdg-open "$url" || true ;;
            esac
            return 0
        fi
        sleep 0.3
    done
    warn "server did not respond within 9 seconds; not opening browser"
}

# ───────── run ─────────
URL="http://$HOST:$PORT"
log "Starting Wireforge"
info "URL:    ${C_BOLD}$URL${C_RESET}"
info "Config: $CONFIG_FILE"
info "Data:   $DATA_DIR"
info "Press Ctrl-C to stop."

if (( OPEN )); then
    launch_browser_when_ready "$URL" &
fi

# exec replaces the shell so signals go straight to wireforge-server.
exec "$BIN" --config "$CONFIG_FILE"
