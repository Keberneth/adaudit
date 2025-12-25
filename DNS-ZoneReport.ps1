<#
DNS Audit Report (Read-only) - Auto-detect DNS server and run audit with NO arguments

Adds:
- Output subfolder: <OutputRoot>\<TargetDnsServer>\DNS-Reports\
- Recommendations report (HTML + TXT) generated alongside audit outputs

DISCLAIMER (shown at top of recommendations report):
Recommendations are based on Microsoft guidance and general DNS/AD best practices.
Technicians must validate and adapt recommendations to:
- local best practices and operational standards
- internal policies and compliance requirements
- risk assessments and threat models
- change management procedures and service impact

Outputs:
  <OutputRoot>\<TargetDnsServer>\DNS-Reports\DNSAudit-<timestamp>.(html|csv|json)
  <OutputRoot>\<TargetDnsServer>\DNS-Reports\DNSAudit-Errors-<timestamp>.json
  <OutputRoot>\<TargetDnsServer>\DNS-Reports\DNS-Recommendations-<timestamp>.(html|txt)

Run:
  .\DNS-ZoneReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = (Get-Location).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ----------------------------
# Config (no args)
# ----------------------------
$IncludeRecordCounts       = $true          # full audit
$PreferZoneStatistics      = $true          # safer/faster when available
$RecordCountMaxRecords     = 250000         # safety cap if enumeration is needed
$IncludeSystemZones        = $false
$FailSoft                 = $true
$WriteErrorReport          = $true

# ----------------------------
# Error bucket
# ----------------------------
$CollectionErrors = @()
$ZoneFailures     = @()

function Add-Err {
    param([string]$Context, [object]$Err)
    $script:CollectionErrors += [pscustomobject]@{
        Time    = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Context = $Context
        Error   = ($Err.Exception.Message)
        Type    = ($Err.Exception.GetType().FullName)
    }
}

function Safe-Get {
    param(
        [Parameter(Mandatory)] [scriptblock]$Script,
        [object]$Default = $null,
        [string]$Context = $null
    )
    try { & $Script }
    catch {
        if ($Context) { Add-Err -Context $Context -Err $_ }
        $Default
    }
}

function Get-Prop {
    param(
        [Parameter(Mandatory)] [object]$Obj,
        [Parameter(Mandatory)] [string]$Name,
        [object]$Default = $null
    )
    if (-not $Obj) { return $Default }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    $Default
}

function Format-TimeSpan {
    param([Nullable[TimeSpan]]$Ts)
    if (-not $Ts) { return $null }
    ("{0}d {1}h {2}m" -f $Ts.Days, $Ts.Hours, $Ts.Minutes)
}

function Convert-ServerListToString {
    param([object]$Value)
    if (-not $Value) { return $null }

    $items = @()
    foreach ($o in @($Value)) {
        if ($null -eq $o) { continue }

        $ipProp = $o.PSObject.Properties['IPAddressToString']
        if ($ipProp -and $ipProp.Value) { $items += [string]$ipProp.Value; continue }

        $found = $false
        foreach ($p in @('IPAddress','Address','ServerName','Name')) {
            $pp = $o.PSObject.Properties[$p]
            if ($pp -and $pp.Value) { $items += [string]$pp.Value; $found = $true; break }
        }
        if (-not $found) { $items += [string]$o }
    }

    $items = $items | Where-Object { $_ -and $_.Trim() } | Sort-Object -Unique
    if (-not $items) { return $null }
    ($items -join ', ')
}

function Ensure-Folder {
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) { New-Item -Path $Path -ItemType Directory | Out-Null }
    $Path
}

function New-ReportsFolder {
    param([string]$Root, [string]$ServerName)
    $safeServer = ($ServerName -replace '[\\/:*?"<>| ]','_')
    $base = Join-Path -Path $Root -ChildPath $safeServer
    Ensure-Folder $base | Out-Null
    $reports = Join-Path -Path $base -ChildPath 'DNS-Reports'
    Ensure-Folder $reports
}

# ----------------------------
# Detect target DNS server (no args)
# ----------------------------
function Get-TargetDnsServer {
    # Prefer local if DNS Server is present and query works
    $localOk = Safe-Get -Context "Detect: Get-DnsServer local" -Default $false -Script {
        Import-Module DnsServer -ErrorAction Stop
        $null = Get-DnsServer -ComputerName $env:COMPUTERNAME -ErrorAction Stop
        $true
    }
    if ($localOk) { return $env:COMPUTERNAME }

    # Otherwise pick the first configured DNS server on active NICs
    $dnsIps = Safe-Get -Context "Detect: Get-DnsClientServerAddress" -Default @() -Script {
        $addrs = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop
        $active = $addrs | Where-Object { $_.InterfaceAlias -and $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 }
        ($active | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
    }

    if (-not $dnsIps -or $dnsIps.Count -eq 0) {
        throw "Could not detect a DNS server from local NIC DNS settings, and local host does not appear to be a DNS server."
    }

    foreach ($ip in $dnsIps) {
        $ok = Safe-Get -Context "Detect: Test-NetConnection $ip:53" -Default $false -Script {
            (Test-NetConnection -ComputerName $ip -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue)
        }
        if ($ok) { return $ip }
    }

    $dnsIps[0]
}

# ----------------------------
# Preflight module
# ----------------------------
$dnsModule = Safe-Get -Context "Preflight: Get-Module DnsServer" -Default $null -Script {
    Get-Module -ListAvailable -Name DnsServer | Sort-Object Version -Descending | Select-Object -First 1
}
if (-not $dnsModule) { throw "DnsServer module not found. Install DNS role tools / RSAT DNS (DnsServer) on this host." }

Import-Module DnsServer -ErrorAction Stop

$ComputerName = Get-TargetDnsServer

$serverInfo = Safe-Get -Context "Preflight: Get-DnsServer -ComputerName $ComputerName" -Default $null -Script {
    Get-DnsServer -ComputerName $ComputerName -ErrorAction Stop
}
if (-not $serverInfo) {
    throw "Unable to query DNS server '$ComputerName'. Check connectivity, firewall/RPC, permissions, and that DNS Server role is present."
}

# ----------------------------
# Output paths (Reports subfolder)
# ----------------------------
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir    = New-ReportsFolder -Root $OutputRoot -ServerName $ComputerName

$csvPath     = Join-Path $outDir "DNSAudit-$timestamp.csv"
$jsonPath    = Join-Path $outDir "DNSAudit-$timestamp.json"
$htmlPath    = Join-Path $outDir "DNSAudit-$timestamp.html"
$errJsonPath = Join-Path $outDir "DNSAudit-Errors-$timestamp.json"
$recHtmlPath = Join-Path $outDir "DNS-Recommendations-$timestamp.html"
$recTxtPath  = Join-Path $outDir "DNS-Recommendations-$timestamp.txt"

# ----------------------------
# Server posture
# ----------------------------
$serverSettings = Safe-Get -Context "Server: Get-DnsServerSetting" -Default $null -Script {
    Get-DnsServerSetting -ComputerName $ComputerName -ErrorAction Stop
}
$serverScavenging = Safe-Get -Context "Server: Get-DnsServerScavenging" -Default $null -Script {
    Get-DnsServerScavenging -ComputerName $ComputerName -ErrorAction Stop
}
$serverForwarders = Safe-Get -Context "Server: Get-DnsServerForwarder" -Default $null -Script {
    Get-DnsServerForwarder -ComputerName $ComputerName -ErrorAction Stop
}
$serverDiagnostics = Safe-Get -Context "Server: Get-DnsServerDiagnostics" -Default $null -Script {
    Get-DnsServerDiagnostics -ComputerName $ComputerName -ErrorAction Stop
}
$serverCache = Safe-Get -Context "Server: Get-DnsServerCache" -Default $null -Script {
    Get-DnsServerCache -ComputerName $ComputerName -ErrorAction Stop
}

$serverPosture = [pscustomobject]@{
    TargetDnsServer        = $ComputerName
    Generated              = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    RunAs                  = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    PowerShellVersion      = $PSVersionTable.PSVersion.ToString()
    OSVersion              = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version -ErrorAction SilentlyContinue)
    DnsServerModuleVersion = $dnsModule.Version.ToString()

    IsDsAvailable          = Get-Prop $serverInfo 'DsAvailable' $null
    Recursion              = Get-Prop $serverSettings 'EnableRecursion' (Get-Prop $serverInfo 'EnableRecursion' $null)

    Forwarders             = Convert-ServerListToString (Get-Prop $serverForwarders 'IPAddress' (Get-Prop $serverForwarders 'IPAddresses' $null))
    ForwarderTimeoutSec    = Get-Prop $serverForwarders 'Timeout' $null
    ForwarderUseRootHints  = Get-Prop $serverForwarders 'UseRootHint' $null

    ScavengingEnabled      = Get-Prop $serverScavenging 'ScavengingState' $null
    ScavRefreshInterval    = Safe-Get -Context "Server: Scav RefreshInterval stringify" -Default $null -Script { [string](Get-Prop $serverScavenging 'RefreshInterval' $null) }
    ScavNoRefreshInterval  = Safe-Get -Context "Server: Scav NoRefreshInterval stringify" -Default $null -Script { [string](Get-Prop $serverScavenging 'NoRefreshInterval' $null) }

    CacheMaxTTL            = Safe-Get -Context "Server: Cache MaxTTL stringify" -Default $null -Script { [string](Get-Prop $serverCache 'MaxTTL' $null) }
    CacheMaxNegativeTTL    = Safe-Get -Context "Server: Cache MaxNegativeTTL stringify" -Default $null -Script { [string](Get-Prop $serverCache 'MaxNegativeTTL' $null) }

    Diagnostics            = if ($serverDiagnostics) { "Available" } else { "Not available" }
}

function Get-ServerIssuesAndRisk {
    param([pscustomobject]$Posture)

    $issues = @()
    $reco   = @()
    $riskScore = 0

    if ($Posture.Recursion -eq $true) {
        $issues += "Server recursion: enabled (review exposure)."
        $reco   += "Confirm the server is not exposed to untrusted networks. Restrict access via firewall/interface binding/allow-lists."
        $riskScore += 2
    }
    if (-not $Posture.Forwarders) {
        $issues += "Forwarders: none detected."
        $reco   += "If external resolution is required, configure forwarders to approved resolvers; otherwise document intent."
        $riskScore += 1
    }
    if ($Posture.ScavengingEnabled -ne $true) {
        $issues += "Server scavenging: disabled or unknown."
        $reco   += "If using dynamic zones, enable scavenging at server level and validate zone aging intervals."
        $riskScore += 1
    }

    $riskLevel = if ($riskScore -ge 5) { 'High' } elseif ($riskScore -ge 2) { 'Medium' } else { 'Low' }

    [pscustomobject]@{
        RiskScore       = $riskScore
        RiskLevel       = $riskLevel
        Issues          = $issues
        Recommendations = $reco
    }
}

# ----------------------------
# Zone helpers
# ----------------------------
function Get-ZoneAgingSummary {
    param([string]$ZoneName)

    $aging = Safe-Get -Context "Zone '$ZoneName': Get-DnsServerZoneAging" -Default $null -Script {
        Get-DnsServerZoneAging -ComputerName $ComputerName -ZoneName $ZoneName -ErrorAction Stop
    }

    if (-not $aging) {
        return [pscustomobject]@{
            AgingEnabled         = $null
            RefreshInterval      = $null
            NoRefreshInterval    = $null
            AvailForScavengeTime = $null
            ScavengeServers      = $null
            AgingNote            = "Aging/Scavenging info not available."
        }
    }

    [pscustomobject]@{
        AgingEnabled         = Get-Prop $aging 'AgingEnabled' $null
        RefreshInterval      = Format-TimeSpan (Get-Prop $aging 'RefreshInterval' $null)
        NoRefreshInterval    = Format-TimeSpan (Get-Prop $aging 'NoRefreshInterval' $null)
        AvailForScavengeTime = Safe-Get -Context "Zone '$ZoneName': AvailForScavengeTime stringify" -Default $null -Script { (Get-Prop $aging 'AvailForScavengeTime' $null).ToString() }
        ScavengeServers      = Convert-ServerListToString (Get-Prop $aging 'ScavengeServers' $null)
        AgingNote            = $null
    }
}

function Get-ZoneTransferEvidence {
    param([object]$ZoneDetails)

    [pscustomobject]@{
        ZoneTransferType  = Get-Prop $ZoneDetails 'ZoneTransferType' $null
        SecureSecondaries = Get-Prop $ZoneDetails 'SecureSecondaries' $null
        Notify            = Get-Prop $ZoneDetails 'Notify' $null
        NotifyServers     = Convert-ServerListToString (Get-Prop $ZoneDetails 'NotifyServers' $null)
        SecondaryServers  = Convert-ServerListToString (Get-Prop $ZoneDetails 'SecondaryServers' $null)
        MasterServers     = Convert-ServerListToString (Get-Prop $ZoneDetails 'MasterServers' $null)
        TransferNote      = $null
    }
}

function Get-ZoneRecordCounts {
    param([string]$ZoneName)

    if (-not $IncludeRecordCounts) {
        return [pscustomobject]@{
            TotalRecords    = $null
            A=$null; AAAA=$null; CNAME=$null; MX=$null; NS=$null; SRV=$null; TXT=$null; PTR=$null
            RecordCountNote = "Record counting disabled."
        }
    }

    if ($PreferZoneStatistics) {
        $zs = Safe-Get -Context "Zone '$ZoneName': Get-DnsServerZoneStatistics" -Default $null -Script {
            Get-DnsServerZoneStatistics -ComputerName $ComputerName -ZoneName $ZoneName -ErrorAction Stop
        }
        if ($zs) {
            return [pscustomobject]@{
                TotalRecords    = Get-Prop $zs 'TotalRecordCount' (Get-Prop $zs 'RecordCount' $null)
                A               = Get-Prop $zs 'ARecordCount' $null
                AAAA            = Get-Prop $zs 'AAAARecordCount' $null
                CNAME           = Get-Prop $zs 'CNAMERecordCount' $null
                MX              = Get-Prop $zs 'MXRecordCount' $null
                NS              = Get-Prop $zs 'NSRecordCount' $null
                SRV             = Get-Prop $zs 'SRVRecordCount' $null
                TXT             = Get-Prop $zs 'TXTRecordCount' $null
                PTR             = Get-Prop $zs 'PTRRecordCount' $null
                RecordCountNote = "Counts from Get-DnsServerZoneStatistics (best-effort)."
            }
        }
    }

    $recs = Safe-Get -Context "Zone '$ZoneName': Get-DnsServerResourceRecord (enumeration)" -Default $null -Script {
        Get-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName -ErrorAction Stop
    }
    if (-not $recs) {
        return [pscustomobject]@{
            TotalRecords    = $null
            A=$null; AAAA=$null; CNAME=$null; MX=$null; NS=$null; SRV=$null; TXT=$null; PTR=$null
            RecordCountNote = "Record counting failed (permissions/size/zone type)."
        }
    }

    $arr = @($recs)
    $truncated = $false
    if ($RecordCountMaxRecords -gt 0 -and $arr.Count -gt $RecordCountMaxRecords) {
        $arr = $arr[0..($RecordCountMaxRecords-1)]
        $truncated = $true
    }

    $byType = $arr | Group-Object -Property RecordType -NoElement

    function Count-Type([string]$t, $groups) {
        $g = $groups | Where-Object Name -eq $t | Select-Object -First 1
        if ($g) { return [int]$g.Count }
        return 0
    }

    [pscustomobject]@{
        TotalRecords    = ($arr | Measure-Object).Count
        A               = (Count-Type 'A' $byType)
        AAAA            = (Count-Type 'AAAA' $byType)
        CNAME           = (Count-Type 'CNAME' $byType)
        MX              = (Count-Type 'MX' $byType)
        NS              = (Count-Type 'NS' $byType)
        SRV             = (Count-Type 'SRV' $byType)
        TXT             = (Count-Type 'TXT' $byType)
        PTR             = (Count-Type 'PTR' $byType)
        RecordCountNote = if ($truncated) { "Counts truncated to first $RecordCountMaxRecords records (safety cap)." } else { $null }
    }
}

function Get-ZoneIssuesAndRisk {
    param([pscustomobject]$ZoneRow, [pscustomobject]$ServerPosture)

    $issues = @()
    $reco   = @()
    $riskScore = 0
    $factors = @()

    if ($null -eq $ZoneRow.DynamicUpdate) {
        $issues += "Dynamic updates: unknown (property not available)."
        $reco   += "Verify zone dynamic update setting in DNS Manager (Zone Properties -> General)."
        $riskScore += 1
        $factors += "DU=Unknown"
    } else {
        switch ([string]$ZoneRow.DynamicUpdate) {
            'Secure' { $factors += "DU=Secure" }
            'None'   {
                $issues += "Dynamic updates: disabled."
                $reco   += "If this zone must accept registrations, enable Secure dynamic updates (AD-integrated recommended)."
                $riskScore += 1
                $factors += "DU=None"
            }
            default  {
                $issues += "Dynamic updates: non-secure updates allowed."
                $reco   += "Set dynamic updates to Secure (especially on AD-integrated zones)."
                $riskScore += 5
                $factors += "DU=NonSecure"
            }
        }
    }

    if ($ZoneRow.IsDsIntegrated -ne $true) {
        $issues += "Zone is not AD-integrated."
        $reco   += "If this is an internal zone, consider AD-integrated for secure updates and replication benefits."
        $riskScore += 2
        $factors += "ADI=No"
    } else {
        $factors += "ADI=Yes"
    }

    if ($ZoneRow.ZoneTransferType -and ($ZoneRow.ZoneTransferType -match 'Any')) {
        $issues += "Zone transfers: allowed to any server."
        $reco   += "Restrict zone transfers to explicit authorized secondaries or IP allow-lists."
        $riskScore += 5
        $factors += "XFR=Any"
    } elseif ($ZoneRow.SecureSecondaries -ne $null -and $ZoneRow.SecureSecondaries -eq $false) {
        $issues += "Zone transfer security (SecureSecondaries) is disabled."
        $reco   += "Restrict zone transfers (secure secondaries / explicit allow-list)."
        $riskScore += 3
        $factors += "XFR=Insecure"
    }

    if ($ZoneRow.AgingEnabled -eq $false) {
        $issues += "Aging/Scavenging: disabled."
        $reco   += "Enable aging where appropriate and validate refresh/no-refresh intervals."
        $riskScore += 2
        $factors += "Aging=Off"
    } elseif ($ZoneRow.AgingEnabled -eq $true -and $ServerPosture.ScavengingEnabled -ne $true) {
        $issues += "Zone aging enabled but server scavenging appears disabled/unknown."
        $reco   += "Enable scavenging at server level or validate intended posture."
        $riskScore += 1
        $factors += "Scav=Mismatch"
    }

    $riskLevel = if ($riskScore -ge 7) { 'High' } elseif ($riskScore -ge 3) { 'Medium' } else { 'Low' }

    [pscustomobject]@{
        RiskScore       = $riskScore
        RiskLevel       = $riskLevel
        Issues          = $issues
        Recommendations = $reco
        RiskFactors     = $factors
    }
}

# ----------------------------
# Recommendations report generator
# ----------------------------
$RecommendationDisclaimer = @"
Recommendations disclaimer:
These recommendations are based on information from Microsoft and general DNS/AD best practices.
Technicians must take into consideration their own:
- best practices and operational standards
- internal policies and compliance requirements
- risk assessments and threat models
- change management procedures and service impact
before implementing any changes.
"@

function Build-Recommendations {
    param(
        [pscustomobject]$ServerPosture,
        [pscustomobject]$ServerRisk,
        [array]$Rows
    )

    $items = New-Object System.Collections.Generic.List[object]

    if ($ServerPosture.Recursion -eq $true) {
        $items.Add([pscustomobject]@{
            Priority = "Medium"
            Area = "Server"
            Topic = "Recursion exposure"
            Evidence = "Recursion enabled = $($ServerPosture.Recursion)"
            Recommendation = "Ensure the DNS server is not exposed to untrusted networks. Restrict client access via firewall/interface binding/allow-lists and document allowed resolvers."
        }) | Out-Null
    }

    if (-not $ServerPosture.Forwarders) {
        $items.Add([pscustomobject]@{
            Priority = "Low"
            Area = "Server"
            Topic = "Forwarders"
            Evidence = "Forwarders not detected"
            Recommendation = "If external resolution is required, configure forwarders to approved resolvers. If not required, document the design (e.g., root hints in controlled networks)."
        }) | Out-Null
    }

    if ($ServerPosture.ScavengingEnabled -ne $true) {
        $items.Add([pscustomobject]@{
            Priority = "Low"
            Area = "Server"
            Topic = "Scavenging"
            Evidence = "Server scavenging state = $($ServerPosture.ScavengingEnabled)"
            Recommendation = "If dynamic DNS is used, enable scavenging at server level and validate zone aging intervals to reduce stale records."
        }) | Out-Null
    }

    # Derived from findings (deduplicate by Topic)
    $hasNonSecureDU = ($Rows | Where-Object { $_.Issues -match 'non-secure updates' } | Select-Object -First 1)
    if ($hasNonSecureDU) {
        $items.Add([pscustomobject]@{
            Priority = "High"
            Area = "Zones"
            Topic = "Non-secure dynamic updates"
            Evidence = "At least one zone allows non-secure dynamic updates"
            Recommendation = "Set dynamic updates to Secure on AD-integrated zones. Avoid non-secure updates unless justified by a documented exception and compensating controls."
        }) | Out-Null
    }

    $hasAnyXfr = ($Rows | Where-Object { $_.Issues -match 'Zone transfers: allowed to any' } | Select-Object -First 1)
    if ($hasAnyXfr) {
        $items.Add([pscustomobject]@{
            Priority = "High"
            Area = "Zones"
            Topic = "Zone transfers to any"
            Evidence = "At least one zone appears to allow transfers to any server"
            Recommendation = "Restrict zone transfers to explicit authorized secondaries or IP allow-lists. Review Notify settings and validate secondaries."
        }) | Out-Null
    }

    $hasAgingOff = ($Rows | Where-Object { $_.Issues -match 'Aging/Scavenging: disabled' } | Select-Object -First 1)
    if ($hasAgingOff) {
        $items.Add([pscustomobject]@{
            Priority = "Medium"
            Area = "Zones"
            Topic = "Aging disabled"
            Evidence = "At least one zone has aging/scavenging disabled"
            Recommendation = "Enable aging where appropriate and ensure refresh/no-refresh intervals align with operational needs. Validate scavenging impact prior to enabling."
        }) | Out-Null
    }

    # Baseline always
    $items.Add([pscustomobject]@{
        Priority = "Medium"
        Area = "Baseline"
        Topic = "Least privilege and auditing"
        Evidence = "Administrative control of DNS is high impact"
        Recommendation = "Use least-privilege admin groups and enable auditing/monitoring for DNS changes. Separate duties where possible."
    }) | Out-Null

    $items.Add([pscustomobject]@{
        Priority = "Medium"
        Area = "Baseline"
        Topic = "Patch and hardening"
        Evidence = "DNS is critical infrastructure"
        Recommendation = "Keep DNS servers patched, restrict management access, and baseline configuration against Microsoft security guidance."
    }) | Out-Null

    $items
}

# ----------------------------
# Collect zones
# ----------------------------
$zones = Safe-Get -Context "Get-DnsServerZone -ComputerName $ComputerName" -Default @() -Script {
    @(Get-DnsServerZone -ComputerName $ComputerName -ErrorAction Stop)
}

if (-not $IncludeSystemZones) {
    $zones = @($zones | Where-Object { $_.IsAutoCreated -ne $true -and $_.ZoneName -notmatch '^TrustAnchors$' })
}

$serverRisk = Get-ServerIssuesAndRisk -Posture $serverPosture

$rows = @()
foreach ($z in $zones) {
    $zn = $z.ZoneName
    try {
        $zoneDetails = Safe-Get -Context "Zone '$zn': Get-DnsServerZone -Name" -Default $z -Script {
            Get-DnsServerZone -ComputerName $ComputerName -Name $zn -ErrorAction Stop
        }

        $aging  = Get-ZoneAgingSummary -ZoneName $zn
        $xfr    = Get-ZoneTransferEvidence -ZoneDetails $zoneDetails
        $counts = Get-ZoneRecordCounts -ZoneName $zn

        $baseRow = [pscustomobject]@{
            Server              = $ComputerName
            ZoneName            = Get-Prop $zoneDetails 'ZoneName' $zn
            ZoneType            = Get-Prop $zoneDetails 'ZoneType' $null
            IsDsIntegrated      = Get-Prop $zoneDetails 'IsDsIntegrated' $null
            ReplicationScope    = Get-Prop $zoneDetails 'ReplicationScope' $null
            IsReverseLookupZone = Get-Prop $zoneDetails 'IsReverseLookupZone' $null
            IsAutoCreated       = Get-Prop $zoneDetails 'IsAutoCreated' $null
            DynamicUpdate       = Get-Prop $zoneDetails 'DynamicUpdate' $null

            ZoneTransferType    = $xfr.ZoneTransferType
            SecureSecondaries   = $xfr.SecureSecondaries
            Notify              = $xfr.Notify
            NotifyServers       = $xfr.NotifyServers
            SecondaryServers    = $xfr.SecondaryServers
            MasterServers       = $xfr.MasterServers

            AgingEnabled        = $aging.AgingEnabled
            NoRefreshInterval   = $aging.NoRefreshInterval
            RefreshInterval     = $aging.RefreshInterval
            AvailForScavengeTime= $aging.AvailForScavengeTime
            ScavengeServers     = $aging.ScavengeServers

            TotalRecords        = $counts.TotalRecords
            A                   = $counts.A
            AAAA                = $counts.AAAA
            CNAME               = $counts.CNAME
            MX                  = $counts.MX
            NS                  = $counts.NS
            SRV                 = $counts.SRV
            TXT                 = $counts.TXT
            PTR                 = $counts.PTR

            Notes               = ((@($aging.AgingNote, $counts.RecordCountNote, $xfr.TransferNote) | Where-Object { $_ }) -join ' | ')
        }

        $risk = Get-ZoneIssuesAndRisk -ZoneRow $baseRow -ServerPosture $serverPosture

        $rows += [pscustomobject]@{
            Server              = $baseRow.Server
            ZoneName            = $baseRow.ZoneName
            ZoneType            = $baseRow.ZoneType
            IsDsIntegrated      = $baseRow.IsDsIntegrated
            ReplicationScope    = $baseRow.ReplicationScope
            IsReverseLookupZone = $baseRow.IsReverseLookupZone
            DynamicUpdate       = $baseRow.DynamicUpdate

            ZoneTransferType    = $baseRow.ZoneTransferType
            SecureSecondaries   = $baseRow.SecureSecondaries
            Notify              = $baseRow.Notify
            NotifyServers       = $baseRow.NotifyServers
            SecondaryServers    = $baseRow.SecondaryServers
            MasterServers       = $baseRow.MasterServers

            AgingEnabled        = $baseRow.AgingEnabled
            NoRefreshInterval   = $baseRow.NoRefreshInterval
            RefreshInterval     = $baseRow.RefreshInterval
            AvailForScavengeTime= $baseRow.AvailForScavengeTime
            ScavengeServers     = $baseRow.ScavengeServers

            TotalRecords        = $baseRow.TotalRecords
            A                   = $baseRow.A
            AAAA                = $baseRow.AAAA
            CNAME               = $baseRow.CNAME
            MX                  = $baseRow.MX
            NS                  = $baseRow.NS
            SRV                 = $baseRow.SRV
            TXT                 = $baseRow.TXT
            PTR                 = $baseRow.PTR

            RiskLevel           = $risk.RiskLevel
            RiskScore           = $risk.RiskScore
            RiskFactors         = ($risk.RiskFactors -join ';')
            Issues              = ($risk.Issues -join ' | ')
            Recommendations     = ($risk.Recommendations -join ' | ')
            Notes               = $baseRow.Notes

            _IssueList          = $risk.Issues
            _RecoList           = $risk.Recommendations
            _RiskFactorList     = $risk.RiskFactors
        }
    }
    catch {
        $script:ZoneFailures += [pscustomobject]@{
            ZoneName = $zn
            Error    = $_.Exception.Message
            Type     = $_.Exception.GetType().FullName
        }
        if (-not $FailSoft) { throw }
    }
}

# ----------------------------
# Summary + top findings
# ----------------------------
$totalZones = ($rows | Measure-Object).Count
$high   = ($rows | Where-Object RiskLevel -eq 'High'   | Measure-Object).Count
$medium = ($rows | Where-Object RiskLevel -eq 'Medium' | Measure-Object).Count
$low    = ($rows | Where-Object RiskLevel -eq 'Low'    | Measure-Object).Count

$topFindings = $rows |
    ForEach-Object { $_._IssueList } |
    Where-Object { $_ } |
    ForEach-Object { $_ } |
    Group-Object |
    Sort-Object Count -Descending |
    Select-Object -First 10

# ----------------------------
# Recommendations report
# ----------------------------
$recommendations = Build-Recommendations -ServerPosture $serverPosture -ServerRisk $serverRisk -Rows $rows

# TXT
$recTxt = @()
$recTxt += "DNS Recommendations Report"
$recTxt += "Target DNS server: $ComputerName"
$recTxt += "Generated: $($serverPosture.Generated)"
$recTxt += ""
$recTxt += $RecommendationDisclaimer.Trim()
$recTxt += ""
$recTxt += "Recommendations:"
$recTxt += ($recommendations | ForEach-Object {
    "- [$($_.Priority)] $($_.Area) - $($_.Topic)`r`n  Evidence: $($_.Evidence)`r`n  Recommendation: $($_.Recommendation)"
})
$recTxt -join "`r`n" | Set-Content -Encoding UTF8 -Path $recTxtPath

# HTML
$recCss = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 18px; }
.small { color: #555; font-size: 0.95em; }
table { border-collapse: collapse; width: 100%; margin-top: 8px; }
th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
th { background: #f3f3f3; }
.pri-high { background: #ffd6d6; }
.pri-medium { background: #fff2cc; }
.pri-low { background: #d9ead3; }
</style>
"@

$recRowsHtml = ($recommendations | ForEach-Object {
    $cls = switch ($_.Priority) { 'High' { 'pri-high' } 'Medium' { 'pri-medium' } default { 'pri-low' } }
    "<tr class='$cls'><td>$($_.Priority)</td><td>$($_.Area)</td><td>$($_.Topic)</td><td>$($_.Evidence)</td><td>$($_.Recommendation)</td></tr>"
}) -join "`r`n"

@"
$recCss
<h1>DNS Recommendations Report</h1>
<div class="small">
<b>Target DNS server:</b> $ComputerName<br/>
<b>Generated:</b> $($serverPosture.Generated)
</div>

<h2>Disclaimer</h2>
<div class="small">
$($RecommendationDisclaimer.Trim() -replace "`r?`n","<br/>")
</div>

<h2>Recommendations</h2>
<table>
<tr><th>Priority</th><th>Area</th><th>Topic</th><th>Evidence</th><th>Recommendation</th></tr>
$recRowsHtml
</table>
"@ | Set-Content -Encoding UTF8 -Path $recHtmlPath

# ----------------------------
# Write audit outputs
# ----------------------------
$rows |
    Sort-Object -Property @{Expression="RiskScore";Descending=$true}, @{Expression="ZoneName";Descending=$false} |
    Select-Object Server,ZoneName,ZoneType,IsDsIntegrated,ReplicationScope,IsReverseLookupZone,DynamicUpdate,
                  ZoneTransferType,SecureSecondaries,Notify,NotifyServers,SecondaryServers,MasterServers,
                  AgingEnabled,NoRefreshInterval,RefreshInterval,AvailForScavengeTime,ScavengeServers,
                  TotalRecords,A,AAAA,CNAME,MX,NS,SRV,TXT,PTR,
                  RiskLevel,RiskScore,RiskFactors,Issues,Recommendations,Notes |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath

$jsonObj = [pscustomobject]@{
    ServerPosture = $serverPosture
    ServerRisk    = $serverRisk
    Summary       = [pscustomobject]@{
        ZonesTotal      = $totalZones
        HighRiskZones   = $high
        MediumRiskZones = $medium
        LowRiskZones    = $low
        ZoneFailures    = ($ZoneFailures | Measure-Object).Count
    }
    TopFindings   = @($topFindings | Select-Object Name, Count)
    Zones         = @(
        $rows | ForEach-Object {
            [pscustomobject]@{
                Server              = $_.Server
                ZoneName            = $_.ZoneName
                ZoneType            = $_.ZoneType
                IsDsIntegrated      = $_.IsDsIntegrated
                ReplicationScope    = $_.ReplicationScope
                IsReverseLookupZone = $_.IsReverseLookupZone
                DynamicUpdate       = $_.DynamicUpdate
                ZoneTransferType    = $_.ZoneTransferType
                SecureSecondaries   = $_.SecureSecondaries
                Notify              = $_.Notify
                NotifyServers       = $_.NotifyServers
                SecondaryServers    = $_.SecondaryServers
                MasterServers       = $_.MasterServers
                AgingEnabled        = $_.AgingEnabled
                NoRefreshInterval   = $_.NoRefreshInterval
                RefreshInterval     = $_.RefreshInterval
                AvailForScavengeTime= $_.AvailForScavengeTime
                ScavengeServers     = $_.ScavengeServers
                TotalRecords        = $_.TotalRecords
                A                   = $_.A
                AAAA                = $_.AAAA
                CNAME               = $_.CNAME
                MX                  = $_.MX
                NS                  = $_.NS
                SRV                 = $_.SRV
                TXT                 = $_.TXT
                PTR                 = $_.PTR
                RiskLevel           = $_.RiskLevel
                RiskScore           = $_.RiskScore
                RiskFactors         = $_._RiskFactorList
                Issues              = $_._IssueList
                Recommendations     = $_._RecoList
                Notes               = $_.Notes
            }
        }
    )
    Recommendations = @($recommendations)
    Failures        = @($ZoneFailures)
    CollectionErrors= @($CollectionErrors)
}

$jsonObj | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 -Path $jsonPath

if ($WriteErrorReport) {
    [pscustomobject]@{
        ZoneFailures     = @($ZoneFailures)
        CollectionErrors = @($CollectionErrors)
    } | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path $errJsonPath
}

# ----------------------------
# HTML audit report
# ----------------------------
$css = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 18px; }
h1,h2 { margin-bottom: 6px; }
.small { color: #555; font-size: 0.95em; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.9em; }
.high { background: #ffd6d6; border: 1px solid #c40000; }
.medium { background: #fff2cc; border: 1px solid #b38f00; }
.low { background: #d9ead3; border: 1px solid #2d7d2d; }
table { border-collapse: collapse; width: 100%; margin-top: 8px; }
th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
th { background: #f3f3f3; position: sticky; top: 0; }
</style>
"@

$serverSummaryHtml = @"
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>TargetDnsServer</td><td>$($serverPosture.TargetDnsServer)</td></tr>
<tr><td>Generated</td><td>$($serverPosture.Generated)</td></tr>
<tr><td>RunAs</td><td>$($serverPosture.RunAs)</td></tr>
<tr><td>PowerShellVersion</td><td>$($serverPosture.PowerShellVersion)</td></tr>
<tr><td>OSVersion</td><td>$($serverPosture.OSVersion)</td></tr>
<tr><td>DnsServerModuleVersion</td><td>$($serverPosture.DnsServerModuleVersion)</td></tr>
<tr><td>Recursion</td><td>$($serverPosture.Recursion)</td></tr>
<tr><td>Forwarders</td><td>$($serverPosture.Forwarders)</td></tr>
<tr><td>ScavengingEnabled</td><td>$($serverPosture.ScavengingEnabled)</td></tr>
</table>
"@

$serverRiskHtml = @"
<div class="small">
<b>Server risk:</b>
<span class="badge $($serverRisk.RiskLevel.ToLower())">$($serverRisk.RiskLevel)</span>
Score=$($serverRisk.RiskScore)<br/>
<b>Issues:</b> $([string]::Join(' | ', $serverRisk.Issues))<br/>
<b>Recommendations:</b> $([string]::Join(' | ', $serverRisk.Recommendations))
</div>
"@

$zonesTable = $rows |
    Sort-Object -Property @{Expression="RiskScore";Descending=$true}, @{Expression="ZoneName";Descending=$false} |
    Select-Object ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate,
                  ZoneTransferType, SecureSecondaries, Notify, NotifyServers, SecondaryServers,
                  AgingEnabled, NoRefreshInterval, RefreshInterval,
                  TotalRecords, RiskLevel, RiskScore, RiskFactors, Issues, Recommendations, Notes

$zonesHtml = ($zonesTable | ConvertTo-Html -Fragment) `
    -replace '<td>High</td>','<td><span class="badge high">High</span></td>' `
    -replace '<td>Medium</td>','<td><span class="badge medium">Medium</span></td>' `
    -replace '<td>Low</td>','<td><span class="badge low">Low</span></td>'

$findingsHtml = (($topFindings | Select-Object Name, Count) | ConvertTo-Html -Fragment)

@"
$css
<h1>DNS Audit Report</h1>
<div class="small">
<b>Target DNS server:</b> $ComputerName<br/>
<b>Zones:</b> Total=$totalZones, High=$high, Medium=$medium, Low=$low<br/>
<b>Recommendations report:</b> DNS-Recommendations-$timestamp.html
</div>

<h2>Server posture</h2>
$serverSummaryHtml
$serverRiskHtml

<h2>Top findings</h2>
$findingsHtml

<h2>Zone details</h2>
$zonesHtml
"@ | Set-Content -Encoding UTF8 -Path $htmlPath

Write-Host "Report generated:"
Write-Host "  Target DNS: $ComputerName"
Write-Host "  Reports folder: $outDir"
Write-Host "  Audit HTML:  $htmlPath"
Write-Host "  Audit CSV:   $csvPath"
Write-Host "  Audit JSON:  $jsonPath"
Write-Host "  Reco HTML:   $recHtmlPath"
Write-Host "  Reco TXT:    $recTxtPath"
if ($WriteErrorReport) { Write-Host "  ERR JSON:    $errJsonPath" }
