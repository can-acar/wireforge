#!/usr/bin/env bash
# Wireforge — build helper.
#
# Targets Linux (kernel WireGuard) for production; development happens on
# macOS. Cross-platform Linux artifacts are produced via Docker buildx so no
# host cross-toolchain is required.
#
# Usage:
#     ./build.sh native                       # cargo release build (this host)
#     ./build.sh linux-bin [amd64|arm64|both] # extract Linux binaries → dist/
#     ./build.sh image [--push <ref>]         # multi-arch image (push or local)
#     ./build.sh --help
#
# Examples:
#     ./build.sh linux-bin both
#     ./build.sh image --push ghcr.io/can-acar/wireforge:latest
#     ./build.sh image                         # local single-arch test images

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKERFILE="$ROOT/deploy/docker/Dockerfile"
DIST="$ROOT/dist"
IMAGE_BASENAME="wireforge"

# ───────── colours ─────────
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
    C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m';   C_BLUE=$'\033[34m'
else
    C_RESET=""; C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_BLUE=""
fi
info()  { printf '%s==>%s %s\n' "$C_BLUE$C_BOLD" "$C_RESET" "$*"; }
note()  { printf '%s—%s %s\n'   "$C_YELLOW" "$C_RESET" "$*"; }
ok()    { printf '%s✓%s %s\n'   "$C_GREEN" "$C_RESET" "$*"; }
die()   { printf '%s✗ %s%s\n'   "$C_RED$C_BOLD" "$*" "$C_RESET" >&2; exit 1; }

usage() { sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# ───────── helpers ─────────
need_docker_buildx() {
    command -v docker >/dev/null 2>&1 || die "docker not found — install Docker Desktop."
    docker buildx version >/dev/null 2>&1 || \
        die "docker buildx unavailable — update Docker Desktop or run 'docker buildx install'."
    # Ensure a builder capable of multi-platform exists.
    if ! docker buildx inspect --bootstrap >/dev/null 2>&1; then
        info "Creating buildx builder 'wireforge-builder'…"
        docker buildx create --use --name wireforge-builder >/dev/null
        docker buildx inspect --bootstrap >/dev/null
    fi
}

# Map our short arch name → docker platform + expected `file` ELF token.
docker_platform() { case "$1" in amd64) echo "linux/amd64";; arm64) echo "linux/arm64";; *) die "unknown arch: $1";; esac; }

# ───────── commands ─────────
cmd_native() {
    info "Building release binaries on $(uname -sm)…"
    ( cd "$ROOT" && cargo build --release --locked --bin wireforge-server --bin wireforge )
    ok "Built target/release/wireforge-server and target/release/wireforge"
}

extract_one() {
    local arch="$1" platform tag cid out
    platform="$(docker_platform "$arch")"
    tag="$IMAGE_BASENAME:build-$arch"
    out="$DIST/linux-$arch"
    info "Building $platform image (cross-compiled via cargo-zigbuild, no QEMU)…"
    docker buildx build --platform "$platform" -f "$DOCKERFILE" -t "$tag" --load "$ROOT"
    mkdir -p "$out"
    cid="$(docker create "$tag")"
    docker cp "$cid:/usr/local/bin/wireforge-server" "$out/wireforge-server"
    docker cp "$cid:/usr/local/bin/wireforge"        "$out/wireforge"
    docker rm -f "$cid" >/dev/null 2>&1 || true
    chmod +x "$out/wireforge-server" "$out/wireforge"
    ok "Extracted → $out/"
    if command -v file >/dev/null 2>&1; then
        note "$(file -b "$out/wireforge-server")"
    fi
}

cmd_linux_bin() {
    need_docker_buildx
    local which="${1:-both}"
    case "$which" in
        amd64) extract_one amd64 ;;
        arm64) extract_one arm64 ;;
        both)  extract_one amd64; extract_one arm64 ;;
        *)     die "linux-bin expects: amd64 | arm64 | both" ;;
    esac
    ok "Linux binaries in $DIST/. Deploy: scp to host + 'sudo ./install.sh --no-build'."
}

cmd_image() {
    need_docker_buildx
    local push_ref=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --push) push_ref="${2:?--push needs a registry/repo:tag}"; shift 2 ;;
            *) die "unknown image option: $1" ;;
        esac
    done
    if [[ -n "$push_ref" ]]; then
        info "Building multi-arch image (amd64+arm64) and pushing → $push_ref"
        docker buildx build --platform linux/amd64,linux/arm64 \
            -f "$DOCKERFILE" -t "$push_ref" --push "$ROOT"
        ok "Pushed multi-arch manifest: $push_ref"
    else
        note "No --push given: multi-arch manifests can't be --load'ed locally."
        note "Building single-arch local test images instead."
        local arch
        for arch in amd64 arm64; do
            info "Building $IMAGE_BASENAME:local-$arch …"
            docker buildx build --platform "$(docker_platform "$arch")" \
                -f "$DOCKERFILE" -t "$IMAGE_BASENAME:local-$arch" --load "$ROOT"
        done
        ok "Local images: $IMAGE_BASENAME:local-amd64, $IMAGE_BASENAME:local-arm64"
        note "Run: docker run --rm -p 8080:8080 -e WIREFORGE_WG_DRY_RUN=1 $IMAGE_BASENAME:local-amd64"
    fi
}

# ───────── dispatch ─────────
[[ $# -eq 0 ]] && { usage; exit 0; }
case "$1" in
    -h|--help) usage ;;
    native)    shift; cmd_native "$@" ;;
    linux-bin) shift; cmd_linux_bin "$@" ;;
    image)     shift; cmd_image "$@" ;;
    *)         die "unknown command: $1  (try ./build.sh --help)" ;;
esac
