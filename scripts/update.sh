#!/bin/bash
# Update vpngw in place, through a tunnel, with a way back.
#
# Three things shape this script.
#
# It fetches through a VPN tunnel, never over the uplink. Asking GitHub for a
# new version of *this* software tells whoever is watching that this address
# runs a VPN gateway and which version - which is the sort of thing the box
# exists to prevent. Both the name lookup and the download go through a
# tunnel's own resolver and interface, so the only address GitHub sees is the
# VPN exit. If no tunnel is up, this refuses to run rather than leaking; the
# gateway fails closed everywhere else and there is no reason to make its own
# updates the exception.
#
# It needs no firewall change. The output chain already permits
# `oifname @tun_ifaces accept` - traffic leaving through a tunnel is safe by
# construction because it is encrypted - so nothing here punches a hole, and
# a gateway that has never been updated has no hole waiting to be used.
#
# It can be undone. The running tree is copied aside and a timer is armed
# before anything is replaced. If the new daemon does not come up healthy the
# old one comes back by itself, the same way an uplink change does. A failed
# update on a box you cannot reach is otherwise a trip to the console.
#
#   update.sh --check      what is installed, what is available, no changes
#   update.sh              fetch the newest tag and install it, with a prompt
#   update.sh --to v2.2.0  a specific tag
#   update.sh --rollback   put the previous tree back now

set -euo pipefail

# Every tool here lives in /usr/sbin or /sbin, and `su` without a dash keeps
# the calling user's PATH, which has neither. Set our own rather than depend
# on how the operator became root.
PATH="/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
export PATH

REPO="${VPNGW_REPO:-vovanero/VPN-Gateway}"
PREFIX=/opt/vpngw
STATE=/var/lib/vpngw
BACKUP="$STATE/update-backup"
WORK="$STATE/update-work"
ROLLBACK_UNIT=vpngw-updaterollback
ROLLBACK_MINUTES="${VPNGW_ROLLBACK_MINUTES:-5}"

BOLD=$'\e[1m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; DIM=$'\e[2m'; OFF=$'\e[0m'
say()  { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*"; }
ok()   { printf '    %sok%s   %s\n' "$GREEN" "$OFF" "$*"; }
warn() { printf '    %swarn%s %s\n' "$YELLOW" "$OFF" "$*"; }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"

MODE=install
WANT_TAG=""
ASSUME_YES=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)    MODE=check ;;
        --rollback) MODE=rollback ;;
        --to)       WANT_TAG="${2:-}"; shift ;;
        -y|--yes)   ASSUME_YES=1 ;;
        -h|--help)  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)          die "unknown argument $1" ;;
    esac
    shift
done

installed_version() {
    PYTHONPATH="$PREFIX" python3 -c \
        'import vpngw; print(vpngw.__version__)' 2>/dev/null || echo "unknown"
}

# ---------------------------------------------------------------------------
# rollback
# ---------------------------------------------------------------------------

cancel_rollback() {
    systemctl stop "$ROLLBACK_UNIT.timer" >/dev/null 2>&1 || true
    systemctl reset-failed "$ROLLBACK_UNIT.service" "$ROLLBACK_UNIT.timer" \
        >/dev/null 2>&1 || true
}

restore_backup() {
    [[ -d "$BACKUP/vpngw" ]] || die "no backup at $BACKUP to restore"
    rm -rf "$PREFIX/vpngw"
    cp -a "$BACKUP/vpngw" "$PREFIX/vpngw"
    [[ -d "$BACKUP/tests" ]] && { rm -rf "$PREFIX/tests"; cp -a "$BACKUP/tests" "$PREFIX/tests"; }
    find "$PREFIX" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
    systemctl restart vpngw || true
}

if [[ "$MODE" == rollback ]]; then
    say "restoring the previous version"
    cancel_rollback
    restore_backup
    sleep 6
    ok "back to $(installed_version)"
    exit 0
fi

# ---------------------------------------------------------------------------
# pick a tunnel to fetch through
# ---------------------------------------------------------------------------

say "choosing a tunnel to fetch through"

read -r TUN_IFACE TUN_SLUG RESOLVER <<<"$(
    PYTHONPATH="$PREFIX" python3 - <<'PY'
import sys
from vpngw import config
from vpngw.db import Database
from vpngw.net import ifaces

settings = config.Settings.load()
db = Database()
try:
    for t in db.tunnels(enabled_only=True):
        # Up means the interface exists and the kernel has a real default
        # route in its table - the same test the panel shows as "routed".
        if ifaces.exists(t.iface):
            print(t.iface, t.slug, settings.dns.resolver_ip(t.esid))
            break
    else:
        print("", "", "")
finally:
    db.close()
PY
)" || true

[[ -n "${TUN_IFACE:-}" ]] || die "no tunnel is up.
       This fetches through a tunnel on purpose: asking GitHub for a new
       version of this software over the uplink would tell your ISP - and
       GitHub - that this address runs a VPN gateway. Bring a tunnel up and
       run this again, or update the machine from a copy you carried over."

ok "fetching through $TUN_SLUG ($TUN_IFACE), resolver $RESOLVER"

# ---------------------------------------------------------------------------
# what is available
# ---------------------------------------------------------------------------

# Resolve inside the tunnel too. Doing the lookup over the uplink would still
# tell the ISP which host we are about to talk to, which is half the leak.
resolve_via_tunnel() {
    dig +short +time=4 +tries=2 "$1" "@$RESOLVER" 2>/dev/null \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1
}

fetch() {
    # fetch <host> <url> <output|-->
    local host="$1" url="$2" out="$3" ip
    ip="$(resolve_via_tunnel "$host")"
    [[ -n "$ip" ]] || return 1
    curl -sS --fail --max-time 60 \
        --interface "$TUN_IFACE" --resolve "$host:443:$ip" \
        ${out:+-o "$out"} "$url"
}

say "checking $REPO"

CURRENT="$(installed_version)"
TAGS_JSON="$(fetch api.github.com \
    "https://api.github.com/repos/$REPO/tags?per_page=20" "" || true)"
[[ -n "$TAGS_JSON" ]] || die "could not reach GitHub through $TUN_SLUG.
       The tunnel is up but the request failed. Check 'vpngwctl status'."

# The JSON goes in on stdin, so the parser cannot be a heredoc: a heredoc
# *is* stdin, and would silently replace the pipe with an empty document.
LATEST="$(printf '%s' "$TAGS_JSON" | python3 -c '
import json, re, sys

def key(tag):
    parts = [int(p) for p in re.findall(r"\d+", tag)[:3]]
    return tuple(parts) + (0,) * (3 - len(parts))

try:
    tags = [t["name"] for t in json.load(sys.stdin)
            if re.fullmatch(r"v?\d+\.\d+\.\d+", t.get("name", ""))]
except Exception:
    tags = []
print(max(tags, key=key) if tags else "")
')"

[[ -n "$LATEST" ]] || die "no version tags found in $REPO"

TARGET="${WANT_TAG:-$LATEST}"
printf '    installed  %s\n' "$CURRENT"
printf '    latest     %s\n' "$LATEST"
[[ -n "$WANT_TAG" ]] && printf '    requested  %s\n' "$WANT_TAG"

if [[ "v$CURRENT" == "$LATEST" || "$CURRENT" == "$LATEST" ]] && [[ -z "$WANT_TAG" ]]; then
    ok "already up to date"
    [[ "$MODE" == check ]] && exit 0
    exit 0
fi

if [[ "$MODE" == check ]]; then
    printf '\n    %s%s is available.%s Run this script without --check to install it.\n\n' \
        "$BOLD" "$TARGET" "$OFF"
    exit 0
fi

# ---------------------------------------------------------------------------
# download and unpack
# ---------------------------------------------------------------------------

say "downloading $TARGET"

rm -rf "$WORK"
mkdir -p "$WORK"
fetch codeload.github.com \
    "https://codeload.github.com/$REPO/tar.gz/refs/tags/$TARGET" \
    "$WORK/src.tar.gz" \
    || die "download failed - is $TARGET a tag in $REPO?"

SIZE=$(stat -c %s "$WORK/src.tar.gz")
(( SIZE > 20000 )) || die "the download is only $SIZE bytes; refusing to install it"
ok "$SIZE bytes"

tar -xzf "$WORK/src.tar.gz" -C "$WORK"
# -mindepth 1 matters: find lists the starting directory first, and
# "update-work" matches '*-*' too - without it SRC became the work directory
# itself, which of course has no installer in it.
SRC="$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -1)"
[[ -n "$SRC" && -x "$SRC/install.sh" ]]     || die "the archive has no executable install.sh; refusing to install it"
ok "unpacked to $SRC"

# What is actually changing, from the tree we just fetched.
if [[ -f "$SRC/CHANGELOG.md" ]]; then
    echo
    sed -n '/^## /,$p' "$SRC/CHANGELOG.md" | awk '
        /^## / { if (++n > 1) exit } { print "    " $0 }' | head -24
    echo
fi

if [[ -z "$ASSUME_YES" ]]; then
    printf '  Install %s over %s? Clients lose the internet for a few seconds\n' \
        "$TARGET" "$CURRENT"
    printf '  while the daemon restarts; the kill switch stays armed throughout.\n'
    read -r -p "  Continue? [y/N] " answer
    [[ "${answer,,}" == y* ]] || { echo "  nothing was changed"; exit 1; }
fi

# ---------------------------------------------------------------------------
# back up, arm the rollback, install
# ---------------------------------------------------------------------------

say "saving the current version"
rm -rf "$BACKUP"
mkdir -p "$BACKUP"
cp -a "$PREFIX/vpngw" "$BACKUP/vpngw"
[[ -d "$PREFIX/tests" ]] && cp -a "$PREFIX/tests" "$BACKUP/tests"
printf '%s\n' "$CURRENT" > "$BACKUP/version"
ok "$CURRENT saved to $BACKUP"

say "arming the rollback"
cancel_rollback
# Plain shell in the timer, no interpreter: this has to run when the thing
# that is broken is the Python package it would otherwise import.
systemd-run --on-active="${ROLLBACK_MINUTES}min" --unit="$ROLLBACK_UNIT" \
    /bin/sh -c "
        rm -rf $PREFIX/vpngw;
        cp -a $BACKUP/vpngw $PREFIX/vpngw;
        [ -d $BACKUP/tests ] && { rm -rf $PREFIX/tests; cp -a $BACKUP/tests $PREFIX/tests; };
        find $PREFIX -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null;
        systemctl restart vpngw
    " >/dev/null
ok "$CURRENT returns in $ROLLBACK_MINUTES minutes unless this run confirms"

say "installing $TARGET"
# The installer keeps /etc/vpngw/vpngw.toml and never touches the database,
# so an update preserves tunnels, clients and the panel password.
if VPNGW_NONINTERACTIVE=1 "$SRC/install.sh"; then
    ok "installer finished"
else
    warn "the installer failed - restoring $CURRENT now rather than waiting"
    cancel_rollback
    restore_backup
    die "update aborted; $CURRENT is back"
fi

# ---------------------------------------------------------------------------
# prove it works before keeping it
# ---------------------------------------------------------------------------

say "checking the new version came up"
systemctl restart vpngw || true
HEALTHY=""
for _ in $(seq 1 12); do
    sleep 3
    systemctl is-active --quiet vpngw || continue
    # The panel answering is the test that matters: a daemon that starts and
    # then throws on its first request is not an update anybody wants kept.
    if vpngwctl status >/dev/null 2>&1; then HEALTHY=1; break; fi
done

if [[ -z "$HEALTHY" ]]; then
    warn "the new version is not answering - restoring $CURRENT"
    cancel_rollback
    restore_backup
    die "update rolled back; $CURRENT is running again"
fi

cancel_rollback
rm -rf "$WORK"

NEW="$(installed_version)"
say "updated"
cat <<EOF

    $CURRENT  ->  $NEW

    Tunnels, clients and settings were kept. The kill switch was armed
    throughout; the only interruption was the daemon restart.

    If something looks wrong, the previous version is still in
    $BACKUP and comes back with:

      $0 --rollback

EOF
