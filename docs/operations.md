# Operating vpngw

## Tunnels

### Importing

```bash
vpngwctl tunnel import nl01 ~/mullvad-nl-ams.conf --name "Mullvad Amsterdam"
vpngwctl tunnel import us01 ~/proton-us.ovpn --auth ~/proton.auth
```

The slug becomes the interface name (`wg-nl01`, `tun-us01`), so it is capped at
ten characters. The type is detected from the file; pass `--kind` if it guesses
wrong.

For OpenVPN configs that need credentials, the auth file is two lines —
username, then password — and is stored `0600` under `/etc/vpngw/secrets/`.
Without `--auth`, a config containing a bare `auth-user-pass` will import but
cannot connect, and the CLI says so.

### What the importer changes

WireGuard configs are parsed into their components; `Table`, `PostUp` and
`PreDown` are **ignored on purpose** — those are how `wg-quick` installs its own
routing and firewall rules, and honouring them would let an imported file
reconfigure the kill switch.

OpenVPN configs are filtered rather than trusted. `redirect-gateway`, `route`,
`up`, `down`, `persist-tun` and about twenty others are commented out and
reissued in a block vpngw controls. Inline `<ca>`/`<cert>`/`<tls-auth>` blocks
pass through verbatim. To see exactly what happened:

```bash
journalctl -u vpngw | grep neutralised
```

### Endpoints and strict egress

With `strict_host_egress = true` the gateway may only dial addresses in
`@vpn_endpoints`, taken from the imported configs. Providers move hostnames to
new addresses, so vpngw re-resolves them every fifteen minutes.

If a tunnel imports with no resolved endpoint, it cannot connect, and the drop
will be in `host_egress_drop` rather than anywhere obvious. Check with:

```bash
vpngwctl check
```

## Providers

Two ways to get tunnels in, and the second one works for every provider that
exists.

### Bulk import — the universal path

Every provider hands you a zip or a folder of configs. Import the whole thing:

```bash
vpngwctl tunnel import-bundle ~/mullvad-configs.zip --prefix nl --dry-run
vpngwctl tunnel import-bundle ~/mullvad-configs.zip --prefix nl
```

Always `--dry-run` first: it parses everything, shows the slugs it would
assign, and lists what it would skip and why. Nothing is written.

Slugs are generated (`nl01`, `nl02`, …) rather than derived from filenames,
because provider filenames are routinely longer than the ten characters an
interface name allows and often differ only past that limit. The original name
becomes the tunnel's display name.

Useful flags: `--filter berlin` to take only matching files, `--limit 5` to cap
it, `--auth ~/creds.txt` to apply one OpenVPN credential file to all of them,
`--disabled` to import without switching anything on.

Files that cannot be used are reported, not silently dropped — an .ovpn that
needs a username and password without `--auth` is listed as skipped with the
reason.

### Provider integrations

```bash
vpngwctl provider list
vpngwctl provider login mullvad
vpngwctl provider locations mullvad --country nl
vpngwctl provider add mullvad nl-ams-wg-001 --prefix nl
```

Four providers ship, in two shapes:

| Provider | How credentials work | Catalogue |
|---|---|---|
| **Mullvad** | Account number; the API issues tunnel credentials | 546 relays, public |
| **NordVPN** | Paste a NordLynx key once | ~8000 servers, public |
| **IVPN** | Paste key + address from the account area | 88 servers, public |
| **Surfshark** | Paste key + address from Manual setup | 142 servers, public |

**Mullvad** is the only one whose API provisions tunnels end to end. `add`
generates a WireGuard keypair *on this machine*, registers only the public
half as a device, and builds the tunnel from the address Mullvad assigns. The
private key never leaves the gateway. Five devices per account:
`provider devices mullvad` lists them, `provider device-rm mullvad <id>` frees
one.

**The other three** publish their full server catalogue without
authentication, but none documents a way to fetch *your* private key. So the
plugin supplies the catalogue and you paste the key once. The alternative
would be reverse-engineering an undocumented endpoint and shipping code that
breaks silently the first time they change it — worse than an honest manual
step, because a plugin that quietly stops provisioning looks exactly like one
that was never configured.

Every catalogue is public, so `locations` works before you have an account —
browse first, sign up second.

`--country` takes a two-letter code or a name fragment. A two-letter needle is
matched against the country *code* only: a plain substring search matches "nl"
inside "Finland", and quietly exiting through the wrong country is precisely
what this gateway exists to prevent.

### Adding another provider

Most of the market fits the second shape, and it is one class and one method.
Subclass `CatalogueProvider`, declare the API host, and turn their JSON into
`Location` objects — see `providers/surfshark.py`, which is about forty lines.

Providers checked and deliberately not included:

* **ProtonVPN** — `/vpn/logicals` was closed to public access; anything built
  on it now would break.
* **AirVPN** — the status API publishes servers but no WireGuard public keys,
  so a tunnel cannot be assembled from it. Config generation needs an API key
  through an undocumented endpoint.

For both, and for anyone else, use bulk import.

### Credentials

You type them; nothing here invents or transcribes one. `provider login`
prompts, or `--from-file` reads a file you wrote, or you type them into the
panel. They are stored under `/etc/vpngw/secrets/` created mode 0600 — with
`os.open`, not written and then chmod-ed, because that gap is long enough to
matter for a private key.

Access tokens are cached in `/run` (tmpfs), so they never touch the disk and
do not survive a reboot.

### The firewall has to be told first

Under strict host egress this gateway may only reach the VPN endpoints it was
configured with. A provider's API host is not one of them, so the first
request would be dropped by our own output chain, landing in
`host_egress_drop` with nothing obvious to point at.

So asking for a catalogue, or connecting an account, opens that hole first:
the provider's declared API hosts are resolved and added to the
`@provider_api` nftables set, limited to HTTPS. The set is **empty until you
ask** — a default install has no hole for an API it never calls — and
`provider logout` closes it again.

A plugin may only contact hosts it declared in `api_hosts`. Trying to fetch
anything else raises rather than silently hitting the firewall, so the code
and the allow-list cannot drift apart.

### Providers without an API

hide.me, AirVPN, ProtonVPN and others either have no public API
documentation or require reverse-engineering their client. Rather than ship
code written against a guessed API — which fails silently and is worse than
nothing — use `import-bundle` with the config archive from their website. The
resulting tunnels are identical; only the provisioning step differs.

## Pools

A pool is an egress like a tunnel is, with its own routing table and mark. It
picks one healthy member and points its table at it.

```bash
vpngwctl pool create eu --strategy priority --members nl01 de01 se01
vpngwctl client assign 10.10.0.12 pool:eu
```

| Strategy | Behaviour |
|---|---|
| `priority` | the healthy member with the lowest priority number |
| `latency` | the healthy member with the lowest measured RTT |
| `round_robin` | rotates every `rotate_seconds` |
| `random` | random, but stays put while the current member is healthy |

Failover costs one `ip route replace` no matter how many clients are on the
pool, so there is no window where some clients have moved and others have not.
Conntrack entries for the pool's mark are flushed on every switch, so clients
see a clean reconnect rather than a hung socket.

`sticky_seconds` (default 60) stops a flapping tunnel from dragging every
client through a reconnect each time it bounces: once failed over, vpngw does
not switch back until the preferred member has been continuously healthy for
that long.

**When every member is down, the pool blackholes.** Its clients lose the
internet. They do not fall back to the uplink — that is the whole point.

## Clients

```bash
vpngwctl client add pc01 10.10.0.11 --egress tunnel:nl01
vpngwctl client assign 10.10.0.11 pool:eu
vpngwctl client assign 10.10.0.11 none          # blocked
vpngwctl client list
```

Reassignment takes effect on the next packet — classification is stateless, by
source address, so it does not wait for existing flows to expire.

In the web UI it is the dropdown in the client table.

## Health

Two signals, in order: a protocol hint (WireGuard handshake age, OpenVPN unit
state) which is instant and decisive, then an ICMP probe bound to the interface
with `SO_BINDTODEVICE` — which tests the tunnel itself rather than testing
whether the routing happens to point at it.

Hysteresis: three consecutive failures to go down, two successes to come back
(`[health]` in `vpngw.toml`). A single lost packet does not trigger a failover.

## Maintenance windows

With strict host egress on, `apt upgrade` on the gateway will not work — by
design. To open the gateway's *own* egress temporarily:

```bash
vpngwctl maintenance on --minutes 30
apt update && apt upgrade
vpngwctl maintenance off
```

This does not touch the forward chain. Client traffic is unaffected; a
maintenance window cannot let a client out unencrypted.

## Troubleshooting

**A client has no internet.**

```bash
vpngwctl status
```

Look at its egress state. `unassigned` means no tunnel is set — blocked by
design. `down` means the tunnel is unhealthy, so it is blackholed, also by
design. If the tunnel says `up` but the client still cannot browse, check that
the client's default gateway really is `10.10.0.1` and that it has exactly one
network adapter.

**A tunnel will not come up.**

```bash
vpngwctl events
journalctl -u vpngw-ovpn@us01 -n 50
nft list counter inet vpngw host_egress_drop
```

A rising `host_egress_drop` with a tunnel that never connects almost always
means the endpoint address is not in the allowlist. `vpngwctl check` names it.

**Everything looks right but traffic stalls on large transfers.** MTU. Try
`vpngwctl tunnel set nl01 --mtu 1380`. WireGuard defaults to 1420, which is
often too large once Hyper-V and a provider's own encapsulation are stacked.

**The web UI is unreachable.** It is bound to the management interface only.
From the Windows host, confirm `10.20.0.2` is on `vEthernet (vpngw-mgmt)` and
that `ping 10.20.0.1` answers.

**Something is deeply wrong and you want to see the actual rules.**

```bash
nft list table inet vpngw
ip rule show
ip route show table 101
vpngwctl render          # what vpngw thinks the ruleset should be
```

`vpngwctl render` works with the daemon stopped, which is useful when it will
not start.

**Starting over.**

```bash
vpngwctl teardown        # removes the firewall and routes; asks for confirmation
systemctl restart vpngw-killswitch vpngw
```

## Backup

Everything is in two places:

```
/etc/vpngw/vpngw.toml     settings
/etc/vpngw/secrets/       imported configs and keys (0600)
/var/lib/vpngw/vpngw.db   tunnels, pools, clients
```

Copy those three and the gateway can be rebuilt with `install.sh` on a fresh VM.

## After any change worth trusting

```bash
vpngwctl selftest --disrupt
```

Run it after adding tunnels, after changing `vpngw.toml`, and after every
upgrade. The suite takes about a minute and is the only thing that turns
"should be fine" into "measured".
