#!/bin/bash
# Turn this working gateway into a disk image that is safe to hand to someone
# else.
#
# An image made by shutting a VM down and exporting the disk carries everything
# the VM knew: your VPN private keys, your provider account, the admin password
# hash, and - most dangerously - the SSH host keys. Host keys are the one that
# is easy to miss and hard to undo: every machine created from that image
# answers with the same key, so none of them can tell an impostor from the real
# thing, and every warning that would have caught it has already been accepted
# by everyone who used the image before.
#
# This removes all of it and arms a first-boot service that regenerates what
# has to be unique. Run it as the last thing before shutting down for export.
#
#   sudo scripts/prepare-image.sh
#   sudo poweroff
#
# The result boots as a fresh gateway: new host keys, new machine ID, no
# tunnels, no clients, no password - the panel asks for one on first open.

set -euo pipefail

BOLD=$'\e[1m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; OFF=$'\e[0m'
step() { printf "${BOLD}==>${OFF} %s\n" "$1"; }
did()  { printf "    ${GREEN}removed${OFF}  %s\n" "$1"; }
kept() { printf "    ${YELLOW}kept${OFF}     %s\n" "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "run this as root" >&2; exit 1; }

if [ "${VPNGW_IMAGE_YES-}" != "1" ]; then
    cat <<WARN

${RED}${BOLD}This destroys the state of this machine.${OFF}

Every tunnel, pool, client, provider credential and the admin password will be
deleted, along with the SSH host keys and the shell history. The machine is
meant to be powered off immediately afterwards and exported as an image.

Do not run this on a gateway you are still using.

WARN
    read -r -p "Type ERASE to continue: " answer
    [ "$answer" = "ERASE" ] || { echo "nothing was changed"; exit 1; }
fi

step "stopping services"
systemctl stop vpngw 2>/dev/null || true
systemctl stop 'vpngw-dns@*' 2>/dev/null || true
systemctl stop 'openvpn@*' 2>/dev/null || true
for iface in $(wg show interfaces 2>/dev/null); do ip link del "$iface" 2>/dev/null || true; done

step "vpngw state"
# The database holds tunnels with their private keys, clients, pools, provider
# account numbers, the admin password hash and any live panel sessions.
rm -f  /var/lib/vpngw/vpngw.db /var/lib/vpngw/vpngw.db-wal /var/lib/vpngw/vpngw.db-shm
did "the database (tunnels, clients, pools, password, sessions)"
rm -rf /etc/vpngw/secrets
did "/etc/vpngw/secrets (WireGuard keys, provider credentials, CLI token)"
rm -rf /var/lib/vpngw/netbackup /var/lib/vpngw/reboottest
did "network backups and test state"
rm -rf /run/vpngw
did "runtime files"
kept "/etc/vpngw/vpngw.toml - interfaces and addressing, which a new operator will edit"

step "identity"
# Host keys first: an image whose users all share a host key cannot detect a
# man in the middle, and every one of them has been trained to click through
# the warning that would have shown it.
rm -f /etc/ssh/ssh_host_*
did "SSH host keys (regenerated on first boot)"
: > /etc/machine-id
rm -f /var/lib/dbus/machine-id
did "machine ID (DHCP hands identical images the same lease otherwise)"
rm -f /etc/udev/rules.d/70-persistent-net.rules
did "persistent NIC naming rules"

step "credentials and history"
rm -f /root/.ssh/authorized_keys /root/.ssh/known_hosts
for home in /home/*; do
    [ -d "$home" ] || continue
    rm -f "$home/.ssh/authorized_keys" "$home/.ssh/known_hosts"
done
did "authorized_keys and known_hosts"
rm -f /root/.bash_history
for home in /home/*; do rm -f "$home/.bash_history" 2>/dev/null || true; done
did "shell history"
rm -f /etc/wireguard/*.conf /root/*.conf /root/*.ovpn 2>/dev/null || true
did "stray tunnel configs in root's home"

step "logs and caches"
journalctl --rotate >/dev/null 2>&1 || true
journalctl --vacuum-time=1s >/dev/null 2>&1 || true
rm -rf /var/log/journal/* /var/log/*.gz /var/log/*.1
find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null || true
did "system logs"
apt-get clean 2>/dev/null || true
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
did "package cache and temporary files"

step "first-boot regeneration"
cat > /etc/systemd/system/vpngw-firstboot.service <<'UNIT'
[Unit]
Description=Regenerate the identity this image was stripped of
# Before anything that would use an identity that does not exist yet.
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
# Everything here has to be unique per machine. Running from one image without
# it means every deployment shares an identity.
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
printf "    ${GREEN}armed${OFF}    vpngw-firstboot.service (new host keys and machine ID)\n"

step "zeroing free space so the image compresses"
# A deleted file is only unlinked; its contents stay on the disk and end up in
# the image, both as bulk and as data somebody can recover.
for fs in $(findmnt -rno TARGET -t ext4,xfs,btrfs 2>/dev/null); do
    printf "    %s ... " "$fs"
    dd if=/dev/zero of="$fs/.zerofill" bs=4M status=none 2>/dev/null || true
    sync
    rm -f "$fs/.zerofill"
    echo done
done
fstrim -av 2>/dev/null || true

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
