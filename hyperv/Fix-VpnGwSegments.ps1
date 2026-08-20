<#
.SYNOPSIS
    Separates the gateway's client segment from its uplink.

.DESCRIPTION
    A gateway can only protect clients that have no other way out. If the
    client adapter and the uplink adapter sit on the same virtual switch, they
    share one broadcast domain: a client can ARP for the real router and leave
    without the gateway ever seeing the packet. No firewall rule can prevent
    that, because the traffic never arrives.

    This script creates a Private switch for the client segment and moves the
    gateway's second adapter onto it.

    The adapter is identified by MAC address, not by name or index. Moving the
    wrong one disconnects the uplink - and with it any SSH session you are
    running this to fix - so the match is exact and the script refuses rather
    than guesses.

.PARAMETER VMName
    The gateway VM.

.PARAMETER LanMac
    MAC address of the adapter that should face the clients. Read it off the
    gateway itself:  ip -br link show eth1

.PARAMETER WanMac
    MAC address of the uplink adapter. Given so the script can prove it is not
    about to move the interface you are connected over.

.EXAMPLE
    .\Fix-VpnGwSegments.ps1 -VMName vpn -LanMac 00:15:5d:6f:b1:12 -WanMac 00:15:5d:6f:b1:11
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $VMName,
    [Parameter(Mandatory = $true)] [string] $LanMac,
    [Parameter(Mandatory = $true)] [string] $WanMac,
    [string] $LanSwitch = "vpngw-lan",
    [switch] $MoveClients
)

$ErrorActionPreference = "Stop"

function Norm([string] $Mac) { ($Mac -replace '[^0-9A-Fa-f]', '').ToUpper() }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this in an elevated PowerShell."
}

$vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
if (-not $vm) { throw "No VM named '$VMName'." }

$lan = Norm $LanMac
$wan = Norm $WanMac
if ($lan -eq $wan) { throw "-LanMac and -WanMac are the same address." }

$adapters = @(Get-VMNetworkAdapter -VMName $VMName)
$lanAdapter = $adapters | Where-Object { (Norm $_.MacAddress) -eq $lan }
$wanAdapter = $adapters | Where-Object { (Norm $_.MacAddress) -eq $wan }

if (-not $lanAdapter) {
    Write-Host "Adapters on '$VMName':" -ForegroundColor Yellow
    $adapters | Select-Object Name, MacAddress, SwitchName | Format-Table -AutoSize | Out-String | Write-Host
    throw "No adapter with MAC $LanMac. Check 'ip -br link show' on the gateway."
}
if (-not $wanAdapter) { throw "No adapter with MAC $WanMac - refusing to act without knowing which one is the uplink." }

Write-Host "=== current layout ===" -ForegroundColor Cyan
$adapters | ForEach-Object {
    $role = ""
    if ((Norm $_.MacAddress) -eq $lan) { $role = "  <- will move (client side)" }
    if ((Norm $_.MacAddress) -eq $wan) { $role = "  <- uplink, NOT touched" }
    Write-Host ("  {0,-10} {1}  switch '{2}'{3}" -f $_.Name, $_.MacAddress, $_.SwitchName, $role)
}

if ($lanAdapter.SwitchName -eq $wanAdapter.SwitchName) {
    Write-Host ""
    Write-Host "Both adapters are on '$($wanAdapter.SwitchName)'. That is the problem:" -ForegroundColor Yellow
    Write-Host "clients on that switch can reach the real router directly and bypass" -ForegroundColor Yellow
    Write-Host "the gateway entirely." -ForegroundColor Yellow
}

# --- the Private switch ------------------------------------------------------
Write-Host ""
Write-Host "=== client switch ===" -ForegroundColor Cyan
if (-not (Get-VMSwitch -Name $LanSwitch -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $LanSwitch -SwitchType Private | Out-Null
    Write-Host "  created Private switch '$LanSwitch'" -ForegroundColor Green
    Write-Host "  Private, not Internal: the Hyper-V host must not have a leg on" -ForegroundColor DarkGray
    Write-Host "  the client segment either, or it becomes the bypass." -ForegroundColor DarkGray
} else {
    $existing = Get-VMSwitch -Name $LanSwitch
    if ($existing.SwitchType -ne 'Private') {
        throw "'$LanSwitch' exists but is $($existing.SwitchType), not Private. Remove it or pass -LanSwitch with another name."
    }
    Write-Host "  '$LanSwitch' already exists" -ForegroundColor DarkGray
}

# --- move the client adapter -------------------------------------------------
Connect-VMNetworkAdapter -VMNetworkAdapter $lanAdapter -SwitchName $LanSwitch
Set-VMNetworkAdapter -VMNetworkAdapter $lanAdapter `
    -MacAddressSpoofing On -DhcpGuard Off -RouterGuard Off
Write-Host "  moved $($lanAdapter.MacAddress) to '$LanSwitch'" -ForegroundColor Green
Write-Host "  MAC spoofing ON, guards OFF - a routing VM forwards frames whose" -ForegroundColor DarkGray
Write-Host "  source MAC is not its own, and the switch drops those otherwise." -ForegroundColor DarkGray

# --- optionally move the clients --------------------------------------------
if ($MoveClients) {
    Write-Host ""
    Write-Host "=== client VMs ===" -ForegroundColor Cyan
    $others = Get-VM | Where-Object { $_.Name -ne $VMName }
    foreach ($other in $others) {
        $nics = @(Get-VMNetworkAdapter -VMName $other.Name)
        if ($nics.Count -gt 1) {
            Write-Host ("  {0}: {1} adapters - skipped. A client with a second" -f $other.Name, $nics.Count) -ForegroundColor Yellow
            Write-Host "     adapter has its own way out and cannot be protected." -ForegroundColor Yellow
            continue
        }
        if ($nics.Count -eq 1 -and $nics[0].SwitchName -ne $LanSwitch) {
            Connect-VMNetworkAdapter -VMNetworkAdapter $nics[0] -SwitchName $LanSwitch
            Set-VMNetworkAdapter -VMNetworkAdapter $nics[0] -DhcpGuard On -RouterGuard On
            Write-Host "  $($other.Name) -> '$LanSwitch'" -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "=== done ===" -ForegroundColor Cyan
Get-VMNetworkAdapter -VMName $VMName | Select-Object Name, MacAddress, SwitchName |
    Format-Table -AutoSize | Out-String | Write-Host

Write-Host @"
Next, on the gateway:

    systemctl restart vpngw

Then give each client VM an address on the client network with the gateway's
LAN address as its default route, and register it in the panel. Until a machine
is registered it has no exit assigned and its traffic is dropped - unknown
means blocked, by design.
"@ -ForegroundColor Gray
