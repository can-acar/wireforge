#!/usr/bin/env bash
# Wireforge — Linux installation script (systemd).
#
# Usage:
#     sudo ./install.sh                       # build + install + enable
#     sudo ./install.sh --no-build            # skip cargo build (use prebuilt)
#     sudo ./install.sh --no-start            # install but don't enable/start
#     sudo ./install.sh --prefix /opt/wireforge
#     sudo ./install.sh --uninstall           # remove service + binaries + user
#     sudo ./install.sh --help

set -euo pipefail

# ───────── defaults ─────────
PREFIX="/usr/local"
ETC_DIR="/etc/wireforge"
DATA_DIR="/var/lib/wireforge"
SERVICE_USER="wireforge"
SERVICE_GROUP="wireforge"
SERVICE_NAME="wireforge.service"
BUILD=1
START=1
UNINSTALL=0

# ───────── colours ─────────
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m'
    C_BLUE=$'\033[34m'
else
    C_RESET="" C_BOLD="" C_GREEN="" C_YELLOW="" C_RED="" C_BLUE=""
fi

log()  { printf '%s==>%s %s\n'   "${C_GREEN}${C_BOLD}" "${C_RESET}" "$*"; }
info() { printf '%s—%s %s\n'     "${C_BLUE}"           "${C_RESET}" "$*"; }
warn() { printf '%s!!%s %s\n'    "${C_YELLOW}${C_BOLD}" "${C_RESET}" "$*" >&2; }
err()  { printf '%sERR%s %s\n'   "${C_RED}${C_BOLD}"   "${C_RESET}" "$*" >&2; }
die()  { err "$*"; exit 1; }

# ───────── arg parsing ─────────
usage() {
    sed -n '2,9p' "$0" | sed 's/^# \?//'
    exit "${1:-0}"
}

while (( $# > 0 )); do
    case "$1" in
        --prefix)     PREFIX="$2"; shift 2 ;;
        --etc-dir)    ETC_DIR="$2"; shift 2 ;;
        --data-dir)   DATA_DIR="$2"; shift 2 ;;
        --user)       SERVICE_USER="$2"; SERVICE_GROUP="$2"; shift 2 ;;
        --no-build)   BUILD=0; shift ;;
        --no-start)   START=0; shift ;;
        --uninstall)  UNINSTALL=1; shift ;;
        -h|--help)    usage 0 ;;
        *)            err "unknown argument: $1"; usage 1 ;;
    esac
done

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd "$REPO_ROOT"

# ───────── preflight ─────────
require_root() {
    if [[ $EUID -ne 0 ]]; then
        die "this script must run as root (try: sudo $0 $*)"
    fi
}

require_linux() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        die "install.sh targets Linux (systemd). On macOS use ./run.sh for local development."
    fi
}

require_systemd() {
    if ! command -v systemctl &>/dev/null; then
        die "systemctl not found — this script requires systemd"
    fi
}

# ───────── uninstall ─────────
if (( UNINSTALL )); then
    require_root "$@"
    require_linux
    log "Uninstalling Wireforge"
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        info "Stopping $SERVICE_NAME"
        systemctl stop "$SERVICE_NAME" || true
    fi
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Disabling $SERVICE_NAME"
        systemctl disable "$SERVICE_NAME" || true
    fi
    rm -f "/etc/systemd/system/$SERVICE_NAME"
    systemctl daemon-reload
    rm -f "$PREFIX/bin/wireforge-server" "$PREFIX/bin/wireforge"
    warn "Kept config + data: $ETC_DIR  $DATA_DIR  (remove manually if no longer needed)"
    warn "Kept system user: $SERVICE_USER (remove with: userdel $SERVICE_USER)"
    log "Done."
    exit 0
fi

require_root "$@"
require_linux
require_systemd

log "Wireforge installer"
info "prefix=$PREFIX  etc=$ETC_DIR  data=$DATA_DIR  user=$SERVICE_USER"

# ───────── build (optional) ─────────
SERVER_BIN="$REPO_ROOT/target/release/wireforge-server"
CLI_BIN="$REPO_ROOT/target/release/wireforge"

if (( BUILD )); then
    log "Building release binaries"
    if ! command -v cargo &>/dev/null; then
        die "cargo not found — install Rust via https://rustup.rs"
    fi
    su - "$SUDO_USER" -c "cd '$REPO_ROOT' && cargo build --release -p wireforge-bin -p wireforge-cli" \
        2>/dev/null \
        || cargo build --release -p wireforge-bin -p wireforge-cli
fi

[[ -x "$SERVER_BIN" ]] || die "missing $SERVER_BIN — run without --no-build"
[[ -x "$CLI_BIN" ]]    || die "missing $CLI_BIN — run without --no-build"

# ───────── runtime dependencies ─────────
check_wg_tools() {
    if ! command -v wg &>/dev/null; then
        warn "wireguard-tools not installed (the 'wg' command is missing)."
        warn "On Debian/Ubuntu:  apt install wireguard-tools"
        warn "On RHEL/Fedora:    dnf install wireguard-tools"
        warn "Wireforge will still start, but interfaces cannot be brought up."
    fi
}
check_wg_tools

# ───────── service user ─────────
if ! id -u "$SERVICE_USER" &>/dev/null; then
    log "Creating system user $SERVICE_USER"
    useradd --system \
            --home "$DATA_DIR" \
            --shell /usr/sbin/nologin \
            --no-create-home \
            "$SERVICE_USER"
fi

# ───────── directories ─────────
log "Preparing directories"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 750 "$DATA_DIR"
install -d                                          -m 755 "$ETC_DIR"

# ───────── binaries ─────────
log "Installing binaries to $PREFIX/bin"
install -Dm755 "$SERVER_BIN" "$PREFIX/bin/wireforge-server"
install -Dm755 "$CLI_BIN"    "$PREFIX/bin/wireforge"

# Grant the server binary CAP_NET_ADMIN so it can manage WireGuard
# interfaces without sudo. If setcap is unavailable, fall back to the
# AmbientCapabilities directive in the systemd unit.
if command -v setcap &>/dev/null; then
    info "Granting CAP_NET_ADMIN to wireforge-server"
    setcap cap_net_admin+ep "$PREFIX/bin/wireforge-server"
fi

# ───────── config ─────────
CONFIG_FILE="$ETC_DIR/wireforge.toml"
if [[ -f "$CONFIG_FILE" ]]; then
    info "Config already exists: $CONFIG_FILE (kept)"
else
    log "Creating default config at $CONFIG_FILE"
    install -m 640 -o "$SERVICE_USER" -g "$SERVICE_GROUP" \
        "$REPO_ROOT/config/wireforge.sample.toml" "$CONFIG_FILE"

    # Auto-generate a strong master_key.
    if command -v openssl &>/dev/null; then
        MASTER_KEY="$(openssl rand -base64 48)"
    else
        MASTER_KEY="$(head -c 36 /dev/urandom | base64)"
    fi
    # Escape & for sed (BSD/GNU compatible).
    ESCAPED_KEY="$(printf '%s' "$MASTER_KEY" | sed 's/[&/\]/\\&/g')"
    sed -i.bak "s|^master_key = .*|master_key = \"${ESCAPED_KEY}\"|" "$CONFIG_FILE"
    rm -f "${CONFIG_FILE}.bak"
    # Lock down DB path to /var/lib/wireforge.
    sed -i.bak "s|^path = \".*wireforge.sqlite\"|path = \"$DATA_DIR/wireforge.sqlite\"|" "$CONFIG_FILE"
    rm -f "${CONFIG_FILE}.bak"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"
    info "Generated master_key (kept inside $CONFIG_FILE — back it up!)"
fi

# ───────── systemd unit ─────────
log "Installing systemd unit"
UNIT_SRC="$REPO_ROOT/deploy/systemd/wireforge.service"
UNIT_DST="/etc/systemd/system/$SERVICE_NAME"

# Patch ExecStart + paths into a fresh copy so the operator can override
# --prefix / --etc-dir without editing the unit file by hand.
sed \
    -e "s|^User=.*|User=$SERVICE_USER|" \
    -e "s|^Group=.*|Group=$SERVICE_GROUP|" \
    -e "s|^WorkingDirectory=.*|WorkingDirectory=$DATA_DIR|" \
    -e "s|^ExecStart=.*|ExecStart=$PREFIX/bin/wireforge-server --config $CONFIG_FILE|" \
    -e "s|^ReadWritePaths=.*|ReadWritePaths=$DATA_DIR|" \
    "$UNIT_SRC" > "$UNIT_DST"
chmod 644 "$UNIT_DST"

systemctl daemon-reload

# ───────── start ─────────
if (( START )); then
    log "Enabling and starting $SERVICE_NAME"
    systemctl enable --now "$SERVICE_NAME"
    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        info "Service is active."
    else
        warn "Service failed to start — inspect with: journalctl -u $SERVICE_NAME -e"
    fi
else
    info "Service installed but not started (use: systemctl enable --now $SERVICE_NAME)"
fi

# ───────── next steps ─────────
cat <<EOF

${C_GREEN}${C_BOLD}✓ Wireforge installed.${C_RESET}

  Config:    ${C_BOLD}$CONFIG_FILE${C_RESET}
  Data dir:  ${C_BOLD}$DATA_DIR${C_RESET}
  Binaries:  ${C_BOLD}$PREFIX/bin/wireforge-server${C_RESET}
             ${C_BOLD}$PREFIX/bin/wireforge${C_RESET}
  Service:   ${C_BOLD}$SERVICE_NAME${C_RESET}

Next steps:
  1. Edit $CONFIG_FILE — set [wireguard].endpoint and adjust [server].bind
  2. Open http://<host>:8080 and create the first admin account
  3. Tail logs:        ${C_BOLD}journalctl -u $SERVICE_NAME -f${C_RESET}
  4. Manage:           ${C_BOLD}wireforge --config $CONFIG_FILE user list${C_RESET}
  5. Backup:           ${C_BOLD}wireforge --config $CONFIG_FILE backup create --output /backups/wf.age${C_RESET}

Uninstall any time with:  ${C_BOLD}sudo $0 --uninstall${C_RESET}
EOF
