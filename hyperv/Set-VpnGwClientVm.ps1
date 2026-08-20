<#
.SYNOPSIS
    Attaches a VM to the vpngw client segment and verifies it has no way around
    the gateway.

.DESCRIPTION
    The gateway's kill switch covers every packet that passes through it. What
    it cannot cover is a client VM with a second adapter on an External switch:
    that VM has its own route to the internet and vpngw is not in the path at
    all. No firewall rule on the gateway can see that traffic.

    So the check this script performs matters more than the change it makes. It
    refuses to configure a VM that has extra adapters, and tells you which ones.

.PARAMETER VMName
    The client VM to configure.

.PARAMETER IPAddress
    The static address to assign it inside the guest. Not applied by this
    script - Hyper-V cannot set a guest's IP - but printed so you can copy it,
    and used to build the matching vpngwctl command.

.PARAMETER Force
    Remove extra network adapters instead of refusing. Destructive; the removed
    adapters are named before they go.

.EXAMPLE
    .\Set-VpnGwClientVm.ps1 -VMName pc01 -IPAddress 10.10.0.11

.EXAMPLE
    Get-VM pc0* | ForEach-Object { .\Set-VpnGwClientVm.ps1 -VMName $_.Name }
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $VMName,
    [string] $IPAddress   = "",
    [string] $LanSwitch   = "vpngw-lan",
    [string] $GatewayIP   = "10.10.0.1",
    [int]    $PrefixLength = 24,
    [switch] $Force
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this in an elevated PowerShell (Run as Administrator)."
    }
}

Assert-Admin

$vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
if (-not $vm) { throw "No VM named '$VMName'." }

if (-not (Get-VMSwitch -Name $LanSwitch -ErrorAction SilentlyContinue)) {
    throw "Switch '$LanSwitch' does not exist. Run New-VpnGwLab.ps1 first."
}

Write-Host "=== $VMName ===" -ForegroundColor Cyan

$adapters = @(Get-VMNetworkAdapter -VMName $VMName)
if ($adapters.Count -eq 0) {
    Add-VMNetworkAdapter -VMName $VMName -SwitchName $LanSwitch
    Write-Host "  added an adapter on '$LanSwitch'" -ForegroundColor Green
    $adapters = @(Get-VMNetworkAdapter -VMName $VMName)
}

# --- the check this script exists for ----------------------------------------
$primary = $adapters[0]
$extras  = @($adapters | Select-Object -Skip 1)

if ($extras.Count -gt 0) {
    Write-Host ""
    Write-Host "  This VM has $($extras.Count) adapter(s) besides the first:" -ForegroundColor Yellow
    foreach ($a in $extras) {
        $sw = $a.SwitchName
        if (-not $sw) { $sw = "<not connected>" }
        Write-Host "    - '$($a.Name)' on '$sw'" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  Any adapter on an External switch is a route to the internet" -ForegroundColor Yellow
    Write-Host "  that bypasses the gateway completely. vpngw cannot see that" -ForegroundColor Yellow
    Write-Host "  traffic, so its kill switch cannot stop it." -ForegroundColor Yellow
    Write-Host ""

    if (-not $Force) {
        throw "Refusing to configure '$VMName' while it has extra adapters. Remove them, or re-run with -Force."
    }
    foreach ($a in $extras) {
        Remove-VMNetworkAdapter -VMNetworkAdapter $a
        Write-Host "  removed '$($a.Name)'" -ForegroundColor Red
    }
}

# --- attach the remaining adapter to the client segment ----------------------
if ($primary.SwitchName -ne $LanSwitch) {
    Connect-VMNetworkAdapter -VMNetworkAdapter $primary -SwitchName $LanSwitch
    Write-Host "  connected to '$LanSwitch'" -ForegroundColor Green
} else {
    Write-Host "  already on '$LanSwitch'" -ForegroundColor DarkGray
}

# A client has no business advertising itself as a router or a DHCP server on a
# segment where the gateway is the only one of either.
Set-VMNetworkAdapter -VMNetworkAdapter $primary -DhcpGuard On -RouterGuard On `
                     -MacAddressSpoofing Off
Write-Host "  DHCP guard ON, router guard ON, MAC spoofing OFF" -ForegroundColor Green

$mac = (Get-VMNetworkAdapter -VMName $VMName)[0].MacAddress
if ($mac -and $mac -ne "000000000000") {
    $macFormatted = ($mac -replace '(..)(?!$)', '$1:').ToLower()
} else {
    $macFormatted = "(assigned when the VM starts)"
}

Write-Host ""
Write-Host "Inside the guest, set a static configuration:" -ForegroundColor Cyan
$addr = $IPAddress
if (-not $addr) { $addr = "10.10.0.<n>" }
Write-Host @"
    address  $addr/$PrefixLength
    gateway  $GatewayIP
    DNS      $GatewayIP    (any value works - queries are intercepted)
    MAC      $macFormatted
"@ -ForegroundColor Gray

if ($IPAddress) {
    Write-Host "Then register it on the gateway:" -ForegroundColor Cyan
    Write-Host "    vpngwctl client add $VMName $IPAddress --egress tunnel:<slug>" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Until you do, this VM has no egress assigned and its traffic is" -ForegroundColor Gray
    Write-Host "dropped. That is the intended default: unknown means blocked." -ForegroundColor Gray
}
