# Changelog

## 1.0.0

First release. Verified end to end on Debian 13 under Hyper-V, with a Windows
client browsing through a commercial WireGuard provider and every suite green:
139 unit tests, 15 release checks, 14 leak checks, 9 pool-failover checks and
15 cold-boot checks.

### The gateway

- **Fail-closed by construction.** `forward` policy `drop`, forwarded traffic
  admitted only out `@tun_ifaces`, and a `blackhole default metric 1000` in
  every policy table so clients stop reaching the internet even when the daemon
  is dead, stopped, or was never started.
- **Per-client exits.** Each client is pinned to one tunnel or to a pool, by
  fwmark and its own routing table.
- **Pools with failover and stickiness.** Health is measured with hysteresis so
  a single lost probe does not move anyone; recovery does not immediately move
  them back.
- **WireGuard and OpenVPN side by side.** WireGuard is driven without
  `wg-quick`, and provider `.ovpn` directives that would rewrite the routing
  table or `/etc/resolv.conf` are stripped before use.
- **DNS that cannot escape its tunnel.** Every `:53` query is redirected to a
  per-egress resolver bound to that egress's source address, so a client
  hard-coding `8.8.8.8` is answered by the gateway rather than obeyed.
- **Providers.** Mullvad, NordVPN, IVPN and Surfshark, plus any WireGuard or
  OpenVPN config file.

### Panel

- Router-style Settings: live interface status, WAN with `Automatic (DHCP)` or
  `Static IP`, dotted subnet masks, a LAN card that shows the resulting network
  as you type, DHCP, and per-interface access control.
- **Commit-confirm for the uplink.** Applying a new WAN address arms a rollback
  first; the change becomes permanent only when someone reaches the panel on
  the new address and confirms. Nothing about it requires console access to
  undo.
- Password-protected, with sessions that survive a restart.
- Unregistered machines seen on a client interface are surfaced with a
  one-click Register button, because a blocked machine and a switched-off one
  look identical otherwise.

### Fixed during release testing

Each of these was found by running the thing rather than reading it.

- **ICMP redirects were being sent on every interface.** The kernel ORs
  `send_redirects` across `conf.all` and `conf.<iface>` rather than ANDing it,
  so setting only `conf.all = 0` left it on. Where clients share a segment with
  the real router — the common Hyper-V lab layout — the gateway was telling
  unregistered clients to route around it. Those clients then never reached the
  box again, so no rule saw them, no counter moved, and the leak test could not
  detect it. Now cleared per interface, shipped in the boot-time sysctls, and
  covered by a leak-test check.
- **`[wan]` and `[dhcp]` were written but never read.** `Settings.load()` was
  missing both sections, so uplink and DHCP settings saved from the panel
  reverted to their defaults on the next read — silently, and for the uplink
  the default is "use DHCP". Every section now round-trips, with a test that
  fails if a new one is added and forgotten.
- **The uplink was defined twice under ifupdown.** Debian's own
  `/etc/network/interfaces` defines the interface *and* sources
  `interfaces.d/*`, so the generated drop-in became a second definition that
  ifupdown ignored: every step reported success and the address never moved.
  The original stanza is now disabled reversibly.
- **`/etc/resolv.conf` was nobody's job.** With no `resolvconf` installed,
  `dns-nameservers` does nothing, and a DHCP run replaces the file with an
  empty template — after which the gateway cannot resolve the hostname of the
  next endpoint it is asked to connect to. The daemon now owns the file and
  points it at the bootstrap servers, which are the only ones the firewall
  lets it reach.
- **Panel sessions died on every restart.** They lived in memory, so an
  upgrade, a settings change, or a crash signed the operator out. They are now
  stored as hashes in the database and survive a cold boot.
- **`vpngwctl` locked itself out.** Once a panel password existed the CLI got
  401 — including `vpngwctl passwd`, the documented way back in after
  forgetting it. It now authenticates with a root-only token.
- **The panel polled from behind the sign-in card**, producing a console full
  of 401s and a "cannot reach the daemon" toast that blamed the wrong thing.
- **Empty required fields were outlined red before anyone typed in them**
  (`:invalid` → `:user-invalid`).
- **The LAN preview counted the gateway's own address as assignable**, so
  `10.10.0.1/24` advertised `10.10.0.1 – 10.10.0.254` as client range.
