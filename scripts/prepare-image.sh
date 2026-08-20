#!/bin/bash
# Turn this working gateway into a disk image that is safe to hand to someone
# else.
#
# An image made by shutting a VM down and exporting the disk carries everything
# the VM knew: your VPN private keys, your provider account, the admin password
# hash, and - most dangerously - the SSH host keys. Host keys are the one that
# is easy to miss and impossible to undo afterwards: every machine created from
# that image answers with the same key, so none of them can tell an impostor
# from the real thing, and the warning that would have caught it is one their
# users have already trained themselves to click through.
#
# This removes all of it and arms a first-boot service that regenerates what
# has to be unique. Run it as the last thing before shutting down for export.
#
#   sudo scripts/prepare-image.sh --dry-run   # show what would go, change nothing
#   sudo scripts/prepare-image.sh
#   sudo poweroff
#
# The result boots as a fresh gateway: new host keys, new machine ID, no
# tunnels, no clients, no password - the panel asks for one on first open.

set -euo pipefail

BOLD=$'\e[1m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; OFF=$'\e[0m'

DRY=0
[ "${1-}" = "--dry-run" ] && DRY=1

[ "$(id -u)" -eq 0 ] || { echo "run this as root" >&2; exit 1; }

step() { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$1"; }
note() { printf '    %s%-9s%s %s\n' "$2" "$1" "$OFF" "$3"; }

# Every destructive action goes through one of these two, so the dry run
# describes the same list the real run performs. A separate description of what
# the script does would be a second thing to keep in step, and the one that
# drifts is always the description.
gone() {
    # gone <what it is> <path>...
    local what="$1"; shift
    local existing=""
    for path in "$@"; do
        [ -e "$path" ] && existing="$existing $path"
    done
    if [ "$DRY" = 1 ]; then
        if [ -n "$existing" ]; then
            note "would go" "$YELLOW" "$what -$existing"
        else
            note "absent" "$YELLOW" "$what"
        fi
        return
    fi
    rm -rf "$@" 2>/dev/null || true
    note "removed" "$GREEN" "$what"
}

does() {
    # does <description> <command...>
    local what="$1"; shift
    if [ "$DRY" = 1 ]; then
        note "would run" "$YELLOW" "$*"
        return
    fi
    "$@" >/dev/null 2>&1 || true
    note "done" "$GREEN" "$what"
}

# Removing /tmp or /var/lib/apt/lists outright breaks the running system and
# the next apt run; what has to go is what is inside them.
emptied() {
    # emptied <description> <directory>...
    local what="$1"; shift
    if [ "$DRY" = 1 ]; then
        note "would empty" "$YELLOW" "$what - $*"
        return
    fi
    for dir in "$@"; do
        [ -d "$dir" ] || continue
        find "$dir" -mindepth 1 -delete 2>/dev/null || true
    done
    note "emptied" "$GREEN" "$what"
}

kept() { note "kept" "$YELLOW" "$1"; }

if [ "$DRY" = 1 ]; then
    printf '%s==>%s dry run - nothing will be changed\n' "$BOLD" "$OFF"
elif [ "${VPNGW_IMAGE_YES-}" != "1" ]; then
    printf '\n%s%sThis destroys the state of this machine.%s\n\n' "$RED" "$BOLD" "$OFF"
    cat <<'WARN'
Every tunnel, pool, client, provider credential and the admin password will be
deleted, along with the SSH host keys and the shell history. The machine is
meant to be powered off immediately afterwards and exported as an image.

Do not run this on a gateway you are still using.

WARN
    read -r -p "Type ERASE to continue: " answer
    [ "$answer" = "ERASE" ] || { echo "nothing was changed"; exit 1; }
fi

step "stopping services"
does "stopped the daemon"    systemctl stop vpngw
does "stopped the resolvers" systemctl stop 'vpngw-dns@*'
does "stopped openvpn"       systemctl stop 'openvpn@*'
if [ "$DRY" = 0 ]; then
    for iface in $(wg show interfaces 2>/dev/null); do
        ip link del "$iface" 2>/dev/null || true
    done
fi

step "vpngw state"
# The database holds tunnels with their private keys, clients, pools, provider
# account numbers, the admin password hash and any live panel sessions.
gone "the database (tunnels, clients, pools, password, sessions)" \
     /var/lib/vpngw/vpngw.db /var/lib/vpngw/vpngw.db-wal /var/lib/vpngw/vpngw.db-shm
gone "secrets (WireGuard keys, provider credentials, CLI token)" \
     /etc/vpngw/secrets
gone "network backups and test state" \
     /var/lib/vpngw/netbackup /var/lib/vpngw/reboottest
gone "runtime files" /run/vpngw
kept "/etc/vpngw/vpngw.toml - interfaces and addressing, which a new operator will edit"

step "identity"
# Host keys first: this is the one that turns a privacy problem into a security
# one, because every machine from the image would answer with the same key.
# By glob rather than by name: a key type nobody thought to list is exactly
# the one that would survive into the image.
gone "SSH host keys (regenerated on first boot)" /etc/ssh/ssh_host_*
gone "the D-Bus machine ID" /var/lib/dbus/machine-id
does "emptied /etc/machine-id (identical images share a DHCP lease otherwise)" \
     truncate -s 0 /etc/machine-id
gone "persistent NIC naming rules" /etc/udev/rules.d/70-persistent-net.rules

step "credentials and history"
gone "root's authorized_keys and known_hosts" \
     /root/.ssh/authorized_keys /root/.ssh/known_hosts
for home in /home/*; do
    [ -d "$home" ] || continue
    gone "$(basename "$home")'s ssh files and history" \
         "$home/.ssh/authorized_keys" "$home/.ssh/known_hosts" "$home/.bash_history"
done
gone "root's shell history" /root/.bash_history
# Tunnel configs get left in a home directory during setup more often than not.
if [ "$DRY" = 0 ]; then
    rm -f /etc/wireguard/*.conf /root/*.conf /root/*.ovpn 2>/dev/null || true
fi
note "checked" "$GREEN" "stray .conf/.ovpn files in /root and /etc/wireguard"

step "logs and caches"
does "rotated and vacuumed the journal" journalctl --vacuum-time=1s
emptied "archived logs" /var/log/journal
if [ "$DRY" = 0 ]; then
    find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null || true
fi
does "cleaned the package cache" apt-get clean
emptied "package lists and temporary files" /var/lib/apt/lists /tmp /var/tmp

step "first-boot regeneration"
if [ "$DRY" = 1 ]; then
    note "would arm" "$YELLOW" "vpngw-firstboot.service - new host keys, new machine ID"
else
    cat > /etc/systemd/system/vpngw-firstboot.service <<'UNIT'
[Unit]
Description=Regenerate the identity this image was stripped of
# Before anything that would try to use an identity that does not exist yet.
Before=ssh.service systemd-networkd.service networking.service vpngw.service
DefaultDependencies=no
After=local-fs.target
ConditionPathExists=!/var/lib/vpngw/.firstboot-done

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/vpngw-firstboot
StandardOutput=journal+console

[Install]
WantedBy=sysinit.target
UNIT

    cat > /usr/local/sbin/vpngw-firstboot <<'BOOT'
#!/bin/sh
# Everything here has to be unique per machine. Booting from an image without
# it means every deployment shares one identity.
set -e
echo "vpngw: first boot, generating this machine's identity"

[ -s /etc/machine-id ] || systemd-machine-id-setup
ssh-keygen -A
systemd-tmpfiles --create >/dev/null 2>&1 || true

mkdir -p /var/lib/vpngw
: > /var/lib/vpngw/.firstboot-done
echo "vpngw: done - the panel will ask for an admin password on first open"
BOOT
    chmod 0755 /usr/local/sbin/vpngw-firstboot
    systemctl enable vpngw-firstboot.service >/dev/null 2>&1
    note "armed" "$GREEN" "vpngw-firstboot.service - new host keys, new machine ID"
fi

step "zeroing free space so the image compresses"
# A deleted file is only unlinked; its contents stay on the disk, end up in the
# image as bulk, and can be recovered from it.
if [ "$DRY" = 1 ]; then
    for fs in $(findmnt -rno TARGET -t ext4,xfs,btrfs 2>/dev/null); do
        note "would fill" "$YELLOW" "$fs with zeroes, then delete the file"
    done
else
    for fs in $(findmnt -rno TARGET -t ext4,xfs,btrfs 2>/dev/null); do
        printf '    %s ... ' "$fs"
        dd if=/dev/zero of="$fs/.zerofill" bs=4M status=none 2>/dev/null || true
        sync
        rm -f "$fs/.zerofill"
        echo done
    done
    fstrim -av >/dev/null 2>&1 || true
fi

if [ "$DRY" = 1 ]; then
    printf '\n%s==>%s nothing was changed. Run without --dry-run to do it.\n\n' \
        "$BOLD" "$OFF"
    exit 0
fi

cat <<'DONE'

==> Ready to export.

    Power off now - do not let it boot again before you export it:

      poweroff

    Then, on the Windows host, compact the disk:

      Optimize-VHD -Path .\vpngw.vhdx -Mode Full

    Anyone who boots the result gets new SSH host keys, a new machine ID, and
    a panel that asks them to choose an admin password. No tunnel, client or
    credential of yours travels with it.

DONE
