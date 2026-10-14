#!/bin/bash
# vpngw, installed with one command.
#
#   curl -fsSL https://raw.githubusercontent.com/vovanero/VPN-Gateway/main/get.sh | bash
#   wget -qO- https://raw.githubusercontent.com/vovanero/VPN-Gateway/main/get.sh | bash
#
# Run as root, on the machine that is to become the gateway: Debian 13 with two
# network adapters. It downloads the newest release and runs its install.sh,
# whose questions are asked on your terminal even though this script arrived
# through a pipe. Nothing else is fetched, and nothing runs in the background.
#
# For a machine that is not a gateway yet. One that is updates with
# `vpngw-update`, which fetches through one of its tunnels; this script fetches
# over the uplink, which on a fresh machine is the only way there is.
#
#   VPNGW_VERSION=v2.8.4    a specific release instead of the newest
#   VPNGW_NONINTERACTIVE=1  no questions; see install.sh for the variables
#
# Everything lives in functions and main runs on the last line, so a download
# cut short never runs half a script.

set -euo pipefail

REPO="${VPNGW_REPO:-vovanero/VPN-Gateway}"

BOLD=$'\e[1m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; OFF=$'\e[0m'
say()  { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*"; }
ok()   { printf '    %sok%s   %s\n' "$GREEN" "$OFF" "$*"; }
warn() { printf '    %swarn%s %s\n' "$YELLOW" "$OFF" "$*"; }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

# One download, with whichever of curl and wget is here: a fresh Debian has
# wget but not curl, and this script arrived through one of the two.
fetch() {
    local url="$1" out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 -o "$out" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --tries=3 --timeout=30 -O "$out" "$url"
    else
        die "neither curl nor wget is installed"
    fi
}

check_host() {
    [[ $EUID -eq 0 ]] || die "run this as root: put sudo before bash, or become root with su - first"
    [[ -r /etc/os-release ]] || die "cannot tell which system this is (no /etc/os-release)"
    # shellcheck disable=SC1091
    . /etc/os-release
    local major="${VERSION_ID%%.*}"
    case "${ID:-}" in
        debian)
            [[ "${major:-0}" -ge 13 ]] 2>/dev/null \
                || die "this is Debian ${VERSION_ID:-?}; vpngw needs Debian 13 (trixie) or newer"
            ok "${PRETTY_NAME:-Debian}"
            ;;
        ubuntu)
            # Ubuntu configures its network with netplan, which the installer
            # does not handle yet: its own files would lose to netplan's, and
            # on a machine you reach over the network that is a lockout.
            [[ -n "${VPNGW_ALLOW_UBUNTU:-}" ]] || die "Ubuntu is not supported yet: the installer does not handle netplan, and getting the network wrong locks you out of the machine. Debian 13 is the supported system. To try it anyway on a VM you can reach from its console, set VPNGW_ALLOW_UBUNTU=1."
            warn "${PRETTY_NAME:-Ubuntu}: not supported; trying anyway because VPNGW_ALLOW_UBUNTU is set"
            ;;
        *)
            die "this is ${PRETTY_NAME:-an unknown system}; vpngw installs on Debian 13"
            ;;
    esac
    if [[ -f /opt/vpngw/vpngw/__init__.py ]]; then
        die "vpngw is already installed here. Update it with:  vpngw-update
       It fetches the new release through one of your tunnels; this script
       would fetch it over the uplink, in plain view of your ISP."
    fi
}

# The newest vX.Y.Z tag - the same rule vpngw-update uses, so release
# candidates (v2.8.0-rc1) are never picked by accident.
resolve_tag() {
    local tmp="$1"
    if [[ -n "${VPNGW_VERSION:-}" ]]; then
        TAG="$VPNGW_VERSION"
        return
    fi
    fetch "https://api.github.com/repos/$REPO/tags?per_page=100" "$tmp/tags.json" \
        || die "could not ask GitHub for the newest release"
    TAG="$(grep -o '"name": *"v[0-9]*\.[0-9]*\.[0-9]*"' "$tmp/tags.json" \
             | grep -o 'v[0-9.]*' | sort -V | tail -1)"
    [[ -n "$TAG" ]] || die "no release found in $REPO"
}

# The release's own tree; prints where install.sh is.
download_release() {
    local tag="$1" tmp="$2"
    fetch "https://codeload.github.com/$REPO/tar.gz/refs/tags/$tag" "$tmp/release.tar.gz" \
        || die "could not download $tag"
    tar -xzf "$tmp/release.tar.gz" -C "$tmp" || die "the download of $tag is damaged"
    SRC="$(dirname "$(find "$tmp" -mindepth 2 -maxdepth 2 -name install.sh | head -1)")"
    [[ -f "$SRC/install.sh" ]] || die "$tag has no install.sh"
}

# install.sh asks its questions on stdin - which, under curl | bash, is this
# script. So it reads from the terminal instead.
run_installer() {
    cd "$SRC"
    if [[ -n "${VPNGW_NONINTERACTIVE:-}" || -t 0 ]]; then
        bash ./install.sh
    elif { : </dev/tty; } 2>/dev/null; then
        bash ./install.sh </dev/tty
    else
        die "there is no terminal to ask the setup questions on. Run it from
       an interactive shell, or answer them up front: VPNGW_NONINTERACTIVE=1
       with VPNGW_WAN and VPNGW_LAN (see install.sh)."
    fi
}

main() {
    say "checking this machine"
    check_host
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    say "finding the newest release"
    resolve_tag "$tmp"
    ok "$REPO $TAG"
    say "downloading $TAG"
    download_release "$TAG" "$tmp"
    ok "unpacked"
    say "running its installer"
    run_installer
}

[[ -n "${VPNGW_GET_SOURCED:-}" ]] || main "$@"
