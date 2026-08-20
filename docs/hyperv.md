# The Hyper-V side

## Switch topology

| Switch | Type | Carries | Why this type |
|---|---|---|---|
| `vpngw-wan` | External | the gateway's uplink | needs the physical NIC |
| `vpngw-lan` | **Private** | the ten client VMs | Private means the Windows host has **no leg** on the client segment |
| `vpngw-mgmt` | Internal | host ↔ gateway web UI and SSH | Internal gives the host an address, which is what we want here and only here |

The LAN switch being **Private** rather than Internal is a deliberate choice.
An Internal switch would give the Windows host an interface on `10.10.0.0/24`,
and a client could then reach the host — which has an unfiltered internet
connection of its own. That is a second, unpoliced route out, and a firewall on
the gateway cannot do anything about traffic that never reaches it.

## The three defaults that break a routing VM

Hyper-V's defaults assume a VM speaks only for itself. A gateway does not, and
all three defaults have to be changed. `New-VpnGwLab.ps1` does it, but if you
build the VM by hand:

**MAC address spoofing — must be ON.** The virtual switch drops any frame whose
source MAC is not the one it assigned to that adapter. A VM forwarding traffic
on behalf of other machines sends exactly such frames. The failure is silent:
no error, no log, packets just vanish. Symptoms look like a routing problem and
are usually debugged for hours as one.

```powershell
Set-VMNetworkAdapter -VMName vpngw -Name lan -MacAddressSpoofing On
```

**Router guard — must be OFF** on the gateway's adapters. It drops router
advertisements and ICMP redirects coming *from* the VM, which is what a gateway
legitimately sends.

**DHCP guard — OFF on the gateway**, ON for the clients. Reversed from the
usual advice, and correct here: the gateway is the only machine on that segment
allowed to behave like infrastructure.

## Interface naming

Hyper-V does not guarantee adapter order across boots, so `eth0` is not
reliably the uplink. On a kill-switch gateway that is not a cosmetic problem —
`$WAN` in the firewall would be pointing at the client segment, and `@tun_ifaces`
at nothing useful.

`New-VpnGwLab.ps1` pins a static MAC per adapter and writes matching systemd
`.link` files:

```ini
[Match]
MACAddress=00:15:5d:0a:f0:01

[Link]
Name=wan0
```

Copy `debian/systemd-network/*.link` to `/etc/systemd/network/` on the VM, run
`update-initramfs -u`, and reboot. After that `wan0`, `lan0` and `mgmt0` are
stable forever.

Verify with:

```bash
ip -br link show
```

## Generation 2 and Secure Boot

Debian will not boot as a Gen 2 VM under the default Windows secure boot
template:

```powershell
Set-VMFirmware -VMName vpngw -SecureBootTemplate MicrosoftUEFICertificateAuthority
```

## Offloads

Hyper-V's synthetic adapter offloads corrupt checksums on forwarded, NAT-ed
traffic often enough to matter on a router. The symptom is maddening — most
traffic works, some TCP streams stall partway. vpngw turns them off on `wan0`
and `lan0` at startup (`net/ifaces.py: disable_offloads`).

## Host address on the management segment

`New-VpnGwLab.ps1` assigns `10.20.0.2/24` to the host's `vEthernet (vpngw-mgmt)`
adapter. If it could not (some setups have the adapter appear late), do it by
hand:

```powershell
New-NetIPAddress -InterfaceAlias "vEthernet (vpngw-mgmt)" -IPAddress 10.20.0.2 -PrefixLength 24
```

The web UI is then at `http://10.20.0.1:8080`.

## Client VMs

```powershell
.\hyperv\Set-VpnGwClientVm.ps1 -VMName pc01 -IPAddress 10.10.0.11
```

That script's main job is refusing to configure a VM that has more than one
network adapter — see
[killswitch.md](killswitch.md#what-this-does-not-protect-against) for why that
is the one hole the gateway genuinely cannot close.

Inside each client, static configuration:

```
address  10.10.0.11/24
gateway  10.10.0.1
DNS      10.10.0.1     (any value works; queries are intercepted regardless)
```

Then register it:

```bash
vpngwctl client add pc01 10.10.0.11 --egress tunnel:nl01
```

An unregistered client has no egress and its traffic is dropped. Unknown means
blocked — that is the intended default, not a misconfiguration.

## Checkpoints

Automatic checkpoints are disabled on the gateway VM. Restoring a gateway to an
older state would restore an older tunnel database and an older ruleset while
the clients carry on as if nothing happened, and a paused VM's clock skew makes
OpenVPN's TLS handshake fail outright on resume.
