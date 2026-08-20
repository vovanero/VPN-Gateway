<#
.SYNOPSIS
    Provisions the Hyper-V side of a vpngw lab: three virtual switches and the
    gateway VM, with the adapter settings that a routing VM actually needs.

.DESCRIPTION
    Hyper-V has three defaults that silently break a Linux router, and all
    three are fixed here:

      * MAC address spoofing is OFF by default. The virtual switch drops any
        frame whose source MAC is not the one it assigned, so a VM that
        forwards traffic for other machines loses those frames with no error
        anywhere. Routing appears to work until it doesn't.

      * Router guard drops router advertisements and ICMP redirects from the
        VM, which is precisely what a gateway sends.

      * Adapter order is not stable across boots, so eth0 is not reliably the
        uplink. This script pins a static MAC per adapter and emits matching
        systemd .link files, so the interfaces come up as wan0/lan0/mgmt0
        every single time. Getting this wrong on a kill-switch box means the
        firewall's "$WAN" is pointed at the client bridge.

    The LAN switch is Private, not Internal: the Windows host must not have a
    leg on the client segment. If it did, a client could reach the host and use
    it as an unfiltered second route to the internet, and no firewall rule on
    the gateway could stop that.

.PARAMETER VMName
    Name of the gateway VM.

.PARAMETER UplinkAdapter
    Name of the physical NIC to bind the External switch to. Run
    Get-NetAdapter to list them. Omit to reuse an existing External switch.

.PARAMETER IsoPath
    Path to the Debian 13 netinst ISO.

.PARAMETER VMPath
    Where to store the VM and its disk.

.EXAMPLE
    .\New-VpnGwLab.ps1 -UplinkAdapter "Ethernet" -IsoPath D:\iso\debian-13-netinst.iso
#>

[CmdletBinding()]
param(
    [string] $VMName        = "vpngw",
    [string] $UplinkAdapter = "",
    [string] $IsoPath       = "",
    [string] $VMPath        = "C:\Hyper-V",
    [int]    $MemoryStartupMB = 2048,
    [int]    $MemoryMaxMB     = 4096,
    [int]    $CpuCount        = 2,
    [int]    $DiskGB          = 32,

    [string] $WanSwitch  = "vpngw-wan",
    [string] $LanSwitch  = "vpngw-lan",
    [string] $MgmtSwitch = "vpngw-mgmt",

    # Pinned so Linux can name the interfaces deterministically.
    [string] $WanMac  = "00155D0AF001",
    [string] $LanMac  = "00155D0AF002",
    [string] $MgmtMac = "00155D0AF003"
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this in an elevated PowerShell (Run as Administrator)."
    }
}

function Format-Mac([string] $Raw) {
    ($Raw -replace '[^0-9A-Fa-f]', '').ToUpper() -replace '(..)(?!$)', '$1:'
}

Assert-Admin

if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
    throw "The Hyper-V PowerShell module is not available. Enable the Hyper-V feature first."
}

Write-Host "=== virtual switches ===" -ForegroundColor Cyan

# --- WAN: External -----------------------------------------------------------
$wan = Get-VMSwitch -Name $WanSwitch -ErrorAction SilentlyContinue
if (-not $wan) {
    if ($UplinkAdapter) {
        $nic = Get-NetAdapter -Name $UplinkAdapter -ErrorAction SilentlyContinue
        if (-not $nic) {
            Write-Host "Available adapters:" -ForegroundColor Yellow
            Get-NetAdapter | Format-Table Name, Status, LinkSpeed -AutoSize | Out-String | Write-Host
            throw "No physical adapter named '$UplinkAdapter'."
        }
        New-VMSwitch -Name $WanSwitch -NetAdapterName $UplinkAdapter -AllowManagementOS $true | Out-Null
        Write-Host "  created External switch '$WanSwitch' on '$UplinkAdapter'" -ForegroundColor Green
    } else {
        $existing = Get-VMSwitch | Where-Object { $_.SwitchType -eq 'External' } | Select-Object -First 1
        if (-not $existing) {
            throw "No External switch exists and -UplinkAdapter was not given. Pass -UplinkAdapter <NIC name>."
        }
        $WanSwitch = $existing.Name
        Write-Host "  reusing existing External switch '$WanSwitch'" -ForegroundColor Green
    }
} else {
    Write-Host "  '$WanSwitch' already exists" -ForegroundColor DarkGray
}

# --- LAN: Private ------------------------------------------------------------
if (-not (Get-VMSwitch -Name $LanSwitch -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $LanSwitch -SwitchType Private | Out-Null
    Write-Host "  created Private switch '$LanSwitch' (client segment, host has no leg here)" -ForegroundColor Green
} else {
    Write-Host "  '$LanSwitch' already exists" -ForegroundColor DarkGray
}

# --- MGMT: Internal ----------------------------------------------------------
if (-not (Get-VMSwitch -Name $MgmtSwitch -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $MgmtSwitch -SwitchType Internal | Out-Null
    Write-Host "  created Internal switch '$MgmtSwitch' (host <-> web UI)" -ForegroundColor Green
} else {
    Write-Host "  '$MgmtSwitch' already exists" -ForegroundColor DarkGray
}

# Give the host its address on the management segment.
$mgmtIf = Get-NetAdapter | Where-Object { $_.Name -like "*$MgmtSwitch*" } | Select-Object -First 1
if ($mgmtIf) {
    $existingIp = Get-NetIPAddress -InterfaceIndex $mgmtIf.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                  Where-Object { $_.IPAddress -eq '10.20.0.2' }
    if (-not $existingIp) {
        try {
            New-NetIPAddress -InterfaceIndex $mgmtIf.ifIndex -IPAddress 10.20.0.2 `
                             -PrefixLength 24 -ErrorAction Stop | Out-Null
            Write-Host "  host management address 10.20.0.2/24 assigned" -ForegroundColor Green
        } catch {
            Write-Host "  could not assign 10.20.0.2/24 automatically: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  host already has 10.20.0.2/24" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "=== gateway VM ===" -ForegroundColor Cyan

if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
    throw "A VM named '$VMName' already exists. Remove it or pass -VMName."
}

$vhdDir  = Join-Path $VMPath "$VMName\Virtual Hard Disks"
$vhdPath = Join-Path $vhdDir "$VMName.vhdx"
New-Item -ItemType Directory -Force -Path $vhdDir | Out-Null

New-VM -Name $VMName -Generation 2 -MemoryStartupBytes ($MemoryStartupMB * 1MB) `
       -NewVHDPath $vhdPath -NewVHDSizeBytes ($DiskGB * 1GB) `
       -SwitchName $WanSwitch -Path $VMPath | Out-Null

Set-VM -Name $VMName -ProcessorCount $CpuCount -AutomaticCheckpointsEnabled $false `
       -AutomaticStartAction StartIfRunning -AutomaticStopAction ShutDown
Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $true `
             -MinimumBytes (1024MB) -MaximumBytes ($MemoryMaxMB * 1MB)

# Debian will not boot Gen2 under the default Windows secure boot template.
Set-VMFirmware -VMName $VMName -EnableSecureBoot On `
               -SecureBootTemplate MicrosoftUEFICertificateAuthority

# The first adapter came with New-VM; name it and pin its MAC.
$wanAdapter = Get-VMNetworkAdapter -VMName $VMName | Select-Object -First 1
Rename-VMNetworkAdapter -VMNetworkAdapter $wanAdapter -NewName "wan"
Set-VMNetworkAdapter -VMName $VMName -Name "wan" -StaticMacAddress $WanMac

Add-VMNetworkAdapter -VMName $VMName -Name "lan"  -SwitchName $LanSwitch  -StaticMacAddress $LanMac
Add-VMNetworkAdapter -VMName $VMName -Name "mgmt" -SwitchName $MgmtSwitch -StaticMacAddress $MgmtMac

# The settings this whole script exists for.
foreach ($n in @("wan", "lan", "mgmt")) {
    Set-VMNetworkAdapter -VMName $VMName -Name $n `
        -MacAddressSpoofing On -DhcpGuard Off -RouterGuard Off
}
Write-Host "  MAC spoofing ON, DHCP/router guard OFF on all three adapters" -ForegroundColor Green

if ($IsoPath) {
    if (-not (Test-Path $IsoPath)) { throw "ISO not found: $IsoPath" }
    Add-VMDvdDrive -VMName $VMName -Path $IsoPath
    $dvd = Get-VMDvdDrive -VMName $VMName
    Set-VMFirmware -VMName $VMName -FirstBootDevice $dvd
    Write-Host "  attached installer ISO and set it as first boot device" -ForegroundColor Green
} else {
    Write-Host "  no -IsoPath given; attach the Debian ISO before starting the VM" -ForegroundColor Yellow
}

Enable-VMIntegrationService -VMName $VMName -Name "Guest Service Interface" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== interface naming ===" -ForegroundColor Cyan
$linkDir = Join-Path $PSScriptRoot "..\debian\systemd-network"
$linkDir = [System.IO.Path]::GetFullPath($linkDir)
New-Item -ItemType Directory -Force -Path $linkDir | Out-Null

$pairs = @(
    @{ Name = "wan0";  Mac = $WanMac  },
    @{ Name = "lan0";  Mac = $LanMac  },
    @{ Name = "mgmt0"; Mac = $MgmtMac }
)
foreach ($p in $pairs) {
    $mac  = (Format-Mac $p.Mac).ToLower()
    $file = Join-Path $linkDir ("10-" + $p.Name + ".link")
    $body = @"
# Generated by New-VpnGwLab.ps1. Copy to /etc/systemd/network/ on the gateway.
#
# Without this, adapter order decides which interface is the uplink, and it is
# not stable. On a kill-switch gateway a swap between wan0 and lan0 points the
# firewall's uplink rules at the wrong segment.
[Match]
MACAddress=$mac

[Link]
Name=$($p.Name)
"@
    Set-Content -Path $file -Value $body -Encoding UTF8
    Write-Host ("  {0}  ->  {1}" -f $p.Name, $mac) -ForegroundColor Green
}
Write-Host "  .link files written to $linkDir" -ForegroundColor Green

Write-Host ""
Write-Host "=== done ===" -ForegroundColor Cyan
Write-Host @"
Next:
  1. Start-VM -Name $VMName ; vmconnect.exe localhost $VMName
  2. Install Debian 13. Choose only "SSH server" and "standard system utilities"
     in tasksel - no desktop.
  3. During install, configure the network on the FIRST interface (the uplink).
     The other two have no DHCP and will be configured by vpngw's installer.
  4. After first boot, copy debian/systemd-network/*.link to
     /etc/systemd/network/ on the VM, then run:  update-initramfs -u && reboot
  5. Run install.sh from this repository on the VM.

Client VMs: attach them to '$LanSwitch' with Set-VpnGwClientVm.ps1, give them
static addresses in 10.10.0.0/24, and gateway 10.10.0.1.
"@ -ForegroundColor Gray
