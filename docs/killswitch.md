# The kill switch

The requirement is absolute: a client VM using this gateway must never send a
single byte to the internet outside a VPN tunnel. Not while a tunnel is
reconnecting, not during a config reload, not in the seconds after a reboot,
not if the management daemon crashes.

Meeting that means not relying on any single mechanism. What follows is every
layer, what each one catches, and — at the end — the things none of them can.

---

## Layer 1 — the forward chain drops by default

```nft
chain forward {
    type filter hook forward priority filter; policy drop;
    ...
}
```

The chain's *policy* is `drop`. Every packet the gateway would forward is
discarded unless a rule explicitly accepts it. Adding a tunnel adds an
exception; there is no rule that opens things up in general and none that can
be reached by accident.

## Layer 2 — the uplink is named and refused

```nft
oifname $WAN counter name "wan_leak_drop" drop
```

Forwarded traffic aimed at the uplink is dropped before any accept rule is
considered. This is redundant with layer 3, and that is the point: it is the
rule whose counter names the exact failure we care about, so
`vpngwctl selftest` has something unambiguous to assert on.

## Layer 3 — egress is an allow-list, not a deny-list

```nft
oifname != @tun_ifaces counter name "nontunnel_drop" drop
```

Traffic may leave only through an interface that is a member of `@tun_ifaces` —
the WireGuard and OpenVPN interfaces belonging to enabled tunnels. A second
uplink added later, a bridge created by hand, an interface that did not exist
when this was written: all refused, without anyone having to remember to add a
rule for them.

## Layer 4 — the blackhole route

This is the layer that matters most, because it is the only one that works with
vpngw dead.

Every per-egress routing table holds two default routes:

```
default dev wg-nl01    metric 100
blackhole default      metric 1000
```

The kernel prefers the lower metric, so traffic normally rides the tunnel. When
the tunnel interface goes down **the kernel itself withdraws every route
pointing at it**, and the blackhole is what remains. Packets are discarded in
the routing layer, before the firewall is even consulted.

Nothing in userspace has to notice, react, or still be running. Compare with
the usual arrangement, where a tunnel's default route lives in the *main* table
and its disappearance means traffic silently falls through to the uplink's
default route — that is the standard leak, and it is a routing bug rather than
a firewall one, which is why firewall-only kill switches keep missing it.

A pool works the same way: its table's default route is repointed as members
come and go, and when every member is down the real default is removed and the
blackhole takes over. Clients on that pool lose the internet. **They do not
fall back to the uplink**, which is the entire difference between a pool here
and a pool on a normal router.

## Layer 5 — boot ordering

`vpngw-killswitch.service` loads a minimal drop-everything ruleset and is
ordered:

```ini
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target
```

`network-pre.target` is reached before systemd-networkd configures a single
interface. So the firewall exists before the network does, and the window
between "NICs are up" and "vpngw finished its first reconcile" is not a
permissive one.

The unit has **no `ExecStop`**. Stopping a firewall unit must not flush the
firewall — `systemctl stop` should cost you management, not protection.
Removing the rules is `vpngwctl teardown`, which requires typing the word.

Alongside it, `/etc/sysctl.d/99-vpngw.conf` ships `net.ipv4.ip_forward = 0`.
vpngw raises it to 1 only after a complete ruleset has loaded. A boot in which
the daemon never starts — masked unit, corrupt database, Python broken by a bad
upgrade — forwards nothing at all, for two independent reasons.

## Layer 6 — IPv6 is not carried

IPv6 is the most common leak in home-made VPN routers, and it is invisible:
everything looks correct, but every v6-capable site is reached outside the
tunnel.

Three things prevent it. `net.ipv6.conf.all.forwarding = 0`; `accept_ra = 0` on
the client side so a rogue advertisement from one client VM cannot hand the
others a working v6 path; and the firewall table being `inet` family, so the
`forward` chain's `drop` policy covers v6 exactly as it covers v4.

`vpngwctl selftest` pings a v6 address from the test client and fails if it
gets an answer.

## Layer 7 — the gateway does not tell clients to route around it

Every layer above assumes the client's packets arrive here. An ICMP redirect
breaks that assumption at the source: it is the router saying "for this
destination, stop sending to me and use that other router instead". The client
installs the route and complies. From then on its traffic never touches this
box at all — no rule is consulted, no counter moves, and `selftest` finds
nothing wrong, because there is nothing here to find. The machine is simply on
the internet with its own address.

This is not a remote possibility in the layout this project targets. Clients
usually share a segment with the real router, which is exactly the condition a
redirect is generated for: a packet that arrives on an interface and leaves by
the same one, toward a next hop the sender could have reached directly. An
unregistered client — one whose packets carry no mark and therefore use the
main table — meets it on the first packet it sends.

The fix is one sysctl, with one trap in it:

```
net.ipv4.conf.all.send_redirects = 0        # not sufficient on its own
net.ipv4.conf.<iface>.send_redirects = 0    # this is the one that counts
```

The kernel combines this setting with **or**, not **and** (`IN_DEV_ORCONF`).
Setting `conf.all` alone leaves it enabled on every interface that already has
it set, which on Debian is all of them. `harden_sysctls()` therefore walks
`/proc/sys/net/ipv4/conf/*` and clears each one by name, including interfaces
created later, and `/etc/sysctl.d/99-vpngw.conf` carries `conf.default` so new
ones start correct.

Note also where the redirect is emitted: `ip_forward()` sends it *before* the
netfilter `FORWARD` hook runs. Dropping the packet in the firewall does not
suppress the redirect that was already generated for it. The firewall cannot
close this one; only the sysctl can.

`vpngwctl selftest` fails if any interface still has it on.

## Layer 8 — DNS is taken, not offered

The clients are statically addressed, so nothing hands them a resolver, and any
of them could be pointed at `8.8.8.8` by hand. So the gateway does not offer a
resolver — it takes every query:

```nft
iifname $LAN udp dport 53 dnat ip to ip saddr map @cli2dns
```

Every `:53` packet from the client bridge is redirected to the resolver
belonging to *that client's* egress, regardless of the address it was sent to.
There is one dnsmasq per tunnel and per pool, each bound to its own address in
`10.99.0.0/21`.

The part that makes it leak-proof is how those resolvers reach upstream:

```
server=1.1.1.1@10.99.0.1
```

The `@source` suffix binds dnsmasq's *outgoing* query socket to the resolver's
own address, which an `ip rule from 10.99.0.1 lookup 101` then steers into that
tunnel's routing table — the same table with the same blackhole. Without the
`@source` the kernel would choose a source address only *after* choosing a
route, the policy rule would never match, and lookups would leave via the
uplink. On a box whose whole purpose is not to leak, that would be the leak.

When the tunnel is down, name resolution for its clients fails immediately
rather than resolving over the uplink.

> DNS-over-HTTPS is not intercepted, and does not need to be: it is ordinary
> HTTPS, so it travels the tunnel like everything else. It is invisible to the
> gateway's resolver, which is a filtering limitation, not a leak. Set
> `block_dot = true` if you also want plain DNS-over-TLS (port 853) refused so
> clients fall back to the resolver you control.

---

## Proxy exits

A SOCKS5 or HTTP proxy can be an exit (see
[operations.md](operations.md#proxies)). Every layer above applies to it
unchanged: to the host, a proxy exit is a tunnel whose interface is
`px-<slug>`, one end of a veth pair into a network namespace of its own. What
is new is a third way to fail. A tunnel either carries a packet or blackholes
it; a proxy exit can also be **gone around** - traffic leaving through the
entry tunnel without passing the proxy. That is no leak to the ISP, but it
shows the destination the entry tunnel's address instead of the proxy's, the
one thing the proxy was chosen to change.

**The relay is not on the host.** redsocks runs inside the namespace, whose
only interfaces are `lo` and the veth, and whose own ruleset admits nothing but
connections to the relay and lets nothing out but TCP to the proxy server. A
client's connection and the relay's connection to its server both cross the
host's forward chain, so a maintenance window - which opens only the host's own
output - cannot reach a proxied byte. The host does not take the namespace's
word for any of it:

* `px_upstream` lets a proxy interface reach one address and port, through a
  tunnel interface, and nothing else; `proxy_upstream_drop` counts the rest.
* `px_entry` gives the relay's traffic its entry tunnel's mark, so it is routed
  by the entry's table - and, when the entry is down, by its blackhole. The
  proxy server never appears on the uplink, and forward rule 2,
  `oifname $WAN drop`, would stop it if it tried.
* Client UDP to a proxy exit is refused with an ICMP error
  (`proxy_nontcp_drop`), so QUIC falls back to TCP at once. None of it is sent
  around the proxy.
* DNS is asked over UDP into the namespace, where `pxdns` turns it into TCP
  through the relay: lookups leave where the traffic leaves.

There is no way to dial a proxy directly. The model refuses a proxy without an
entry, the API refuses to unchain one, and the panel offers no such choice:
dialled directly, the proxy's provider would see this gateway's real address,
and the login would cross the ISP's wire in the clear.

## Proving it

```bash
vpngwctl selftest --disrupt
```

A network namespace is attached to `br-lan` with a veth pair. As far as the
kernel is concerned it is a LAN client: same bridge, same forward chain, same
rules as a Hyper-V VM. Traffic from it is real forwarded traffic.

Each leak assertion is checked by two mechanisms that do not share a failure
mode:

* **nftables counters** — authoritative and in-kernel, but they only prove that
  the rule we *think* is matching is matching.
* **`tcpdump` on the uplink**, filtered to a port used by nothing else, so a
  single packet is unambiguous. This does not trust our ruleset at all.

If they ever disagree, believe tcpdump.

`--disrupt` takes the tunnel down for real and measures the window. Clients on
that tunnel lose connectivity for roughly twenty seconds. Without the flag the
destructive checks are skipped and the report says so.

With a proxy as the test's exit (`vpngwctl selftest --egress tunnel:<slug>`, or
**Through** on the panel's Security page), four checks are added. Each is
watched at three points - the uplink, inside the entry tunnel, and on the veth
into the proxy's namespace:

| Check | Fails when |
|---|---|
| the exit is the proxy's | the client exits with the entry tunnel's own address |
| the proxy is dialled only through its entry | a packet to the proxy server appears on the uplink |
| client UDP is refused | the canary appears anywhere, or `proxy_nontcp_drop` does not move |
| DNS goes through the proxy | a lookup's name appears as plain DNS on the uplink or inside the entry |

A capture that saw nothing at all - not even the traffic it was there to see -
is reported as a warning, not a pass: it proves nothing either way.

`--disrupt` on a proxy exit tests its own two failures. Its relay is stopped,
and nothing may reach the internet through the entry tunnel instead. Then its
entry tunnel is taken down, and the relay must not reach for the proxy server
over the uplink. The proxy's route is kept in place for both, so what refuses
the client is the namespace and the relay, not the routing blackhole the other
checks already cover. Clients on the entry and on the proxy lose connectivity
for roughly half a minute.

## Reading the counters

```bash
nft list counters table inet vpngw
```

| Counter | Meaning |
|---|---|
| `wan_leak_drop` | forwarded traffic aimed at the uplink — **the kill switch firing** |
| `nontunnel_drop` | forwarded traffic aimed at anything that is not a tunnel |
| `unclassified_drop` | a client with no egress assigned, or assigned to a disabled one |
| `forwarded_new` | new client flows admitted into a tunnel |
| `dns_hijacked` | client DNS queries redirected |
| `host_egress_drop` | the gateway's own traffic, blocked by strict egress |
| `proxy_nontcp_drop` | client UDP refused on a proxy exit, which carries TCP only |
| `proxy_upstream_drop` | a proxy's relay sending anywhere but its one server — **should stay at zero** |
| `proxy_upstream_new` | new connections from relays to their proxy servers |

A rising `wan_leak_drop` is **not** a leak. It is the record of attempts that
were stopped — usually a client retrying while its tunnel reconnects. A leak
would be that counter staying at zero while traffic appears on `wan0`.

---

## Deliberately not supported: split tunnelling

Most VPN routers offer a per-destination bypass — "send my bank and Windows
Update straight out the uplink, everything else through the tunnel". It is a
popular feature and it is **not going to be added here.**

The reason is that it does not survive contact with this design. The guarantee
this gateway makes is not "traffic usually goes through a tunnel"; it is that a
client packet reaching the uplink is impossible. Every layer above is built on
that being absolute:

* `oifname != @tun_ifaces drop` is an allow-list. A bypass would have to punch a
  destination-based hole through it, and the moment such a hole exists the
  claim becomes "no leak except through the hole" — which is a claim nobody can
  audit at a glance, and which changes every time somebody edits the list.
* The blackhole route is what protects clients when the daemon is dead. A
  bypass route would have to live in the same policy tables and would keep
  working when everything else fails — meaning the failure mode inverts: the
  situation where the kill switch matters most is exactly when the bypass is
  the only route left.
* `vpngwctl selftest` asserts on "zero packets on the uplink". With split
  tunnelling that assertion cannot be written, only weakened to "zero packets
  other than the expected ones" — and a test that has to be told what to ignore
  stops being evidence.

A destination that genuinely must not go through a VPN belongs on a machine
that is not behind this gateway. That is a topology decision, and topology is
something you can actually verify.

**If you find yourself wanting this feature, the honest options are:** give that
VM a second adapter on a different switch (accepting that it is then outside
this gateway entirely, and documenting it), or run a second gateway without a
kill switch for that traffic. Both are visible. A bypass rule buried in a
firewall is not.

### A note on the optional DoT chain

`block_dot = true` adds a second base chain on the forward hook at
`priority filter - 10`, whose policy is `accept`. That is not a bypass. In
netfilter, several base chains on one hook run in priority order and an
`accept` verdict ends only *that* chain — the main forward chain still runs
afterwards and still drops by default. Only `drop` is terminal. The DoT chain
can therefore reject port 853 early, but it cannot let anything past the kill
switch.

## What this does not protect against

Being honest about the boundary matters more than the list of things it does
cover.

**A client VM with a second network adapter.** If a client VM is attached to
both the Private client switch *and* an External switch, it has its own route
to the internet and this gateway is not in the path at all. No firewall on the
gateway can see that traffic, let alone stop it. Keep client VMs on one
adapter, on the Private switch. `hyperv/Set-VpnGwClientVm.ps1` checks for this
and refuses to configure a VM that has extra adapters.

**The Hyper-V host itself.** The Windows host is not behind this gateway and
never was. It is on the management segment so you can reach the UI. Its own
traffic goes wherever Windows sends it.

**A compromised client.** A client with root can do anything a host on a LAN
can do — spoof another client's IP and inherit that client's tunnel, for
instance. Assignment is by source address, so it is an identity claim, not a
security control. Use `Private` switches and per-VM isolation if the client VMs
are not trusted.

**The VPN provider.** Traffic is confined to the tunnel; what the provider does
with it at the other end is outside this system entirely.

**Traffic before the tunnel is imported.** A client added while no tunnel exists
has no egress, so it is blocked — correct, but if you expected internet, that
is why.

**Correlation.** Ten clients on ten tunnels still share one uplink, one clock
and one traffic pattern. This provides separation of exits, not anonymity.
