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

## Proxies

A SOCKS5 or HTTP proxy - a residential proxy, typically - can be an exit, the
way a tunnel is. It is always reached through one of your WireGuard or OpenVPN
tunnels, its **entry**: dialled directly, the proxy's provider would see this
gateway's real address, and the login would cross the ISP's wire in the clear.
There is no option to do that, in the panel or the CLI.

```bash
vpngwctl tunnel add-proxy res-de1 socks5://customer-7f3a@gate.example.net:7000 \
    --via nl01 --name "Residential Germany"
vpngwctl tunnel test res-de1
vpngwctl client assign 10.10.0.11 tunnel:res-de1
```

The password is asked for, or read with `--password-file`; one in the URL is
refused, because a command line is readable by every local account. In the
panel it is **Add tunnel › Proxy**: paste the address the provider gives you -
`socks5://user:pass@host:port` and `host:port:user:pass` both work - and the
password moves to its masked field at once. **Add proxy** saves it, tests it
through the chain, and keeps it only if the test passes; otherwise it is
deleted again and the form says which link broke.

The proxy server's name is looked up through the entry tunnel, never over the
uplink. `https://` proxies (TLS to the proxy itself) are not supported yet; if
the provider also offers `http://`, use that - what you reach through it is
still HTTPS end to end.

**TCP only.** A proxy carries TCP. UDP from its clients - QUIC, video calls,
games, VoIP - is refused with an ICMP error, so browsers fall back to TCP at
once and nothing is sent around the proxy. The panel says so wherever a proxy
can be picked. Proxies cannot join pools: failing over between a VPN and a
proxy would silently change what works for a client.

**Changing one.** In its drawer: Change login (an empty password keeps the
current one), Change entry, and Change address. The relay restarts with the
change and is tested straight away. From the CLI:

```bash
vpngwctl tunnel login res-de1 --user customer-7f3a-session-92
```

**Cost.** Residential proxies are usually billed by the byte. A healthy proxy
is probed every 30 seconds with one small HTTPS request through the chain; a
proxy whose state is changing is probed every pass until it settles.

**When it breaks**, the message names the link:

| Message | Means | Do |
|---|---|---|
| `<entry> is down, so <proxy> can't reach its proxy.` | the entry tunnel is down | fix the entry, or Change entry |
| `<host> couldn't be resolved through <entry>.` | the name does not resolve where the entry exits | Change address |
| `The proxy at <host>:<port> didn't answer through <entry>.` | nothing answers at that address and port | check the address; some providers admit only allow-listed callers |
| `The proxy rejected the username or password.` | the login is wrong | Change login |
| `The proxy wants a username and password, and none is set.` | it needs a login | Change login |
| `The proxy does not take a username and password...` | it admits by caller address instead | clear the login; see below |
| `The proxy accepted the login but would not connect onward...` | the proxy refuses the destination | the provider's own rules |
| `The proxy relay stopped...` | redsocks exited | it restarts by itself; see `journalctl -u vpngw-proxy@<slug>` |

Prefer a proxy that asks for a username and password. One that admits callers
by address would have to admit the entry tunnel's exit - which every other
customer of that VPN provider shares.

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

**The panel is unreachable.** It listens on every address; the firewall
decides who may reach it. `admin_ifaces` in `[net]` is the list of interfaces
whose traffic is let through to port 8080 and 22 - a property of which side of
the box you are on, not of your source address.

```bash
grep admin_ifaces /etc/vpngw/vpngw.toml
nft list chain inet vpngw input | grep 8080
ss -tlnp | grep 8080
```

The default is the client bridge alone. `install.sh` adds the uplink as well
when the uplink is on a private network, which is the usual lab case and is
almost always where you are during setup - so on a machine reached over its
uplink, expect to see both:

```
iifname "br-lan" tcp dport { 22, 8080 } accept
iifname "eth0"   tcp dport { 22, 8080 } accept
```

If the uplink is missing from that list, add it to `admin_ifaces` and restart.
Nothing here exposes the panel to the internet on its own: on a routable
uplink, `install.sh` leaves the uplink out.

**Something on the gateway itself hangs reaching the internet - `apt`, most
often.** This is the kill switch, working. The gateway's *own* egress is
dropped by default: it may reach VPN endpoints, the bootstrap resolvers,
provider APIs on 443, NTP and ICMP, and nothing else. A dropped SYN is not a
refusal - it is retried until it times out - so being blocked looks exactly
like being slow, which is why this one costs people an afternoon.

```bash
nft list counter inet vpngw host_egress_drop
```

A counter climbing while the command sits there is the answer. If you
genuinely need the box to fetch something, open a window rather than editing
rules by hand:

```bash
vpngwctl maintenance on --minutes 10
```

Updating does not need one. `install.sh` calls apt only when a package is
actually absent, and on a provisioned gateway nothing is.

**Updating a gateway that has no tunnel of its own.** `vpngw-update` refuses
to fetch over the uplink, by design, so a gateway with no tunnel cannot use
it. Carry the tree over and run the installer instead - that is the same
update, minus the automatic rollback:

```bash
scp -r VPN-Gateway root@<gateway>:/root/
ssh root@<gateway> VPNGW_NONINTERACTIVE=1 bash /root/VPN-Gateway/install.sh
```

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
