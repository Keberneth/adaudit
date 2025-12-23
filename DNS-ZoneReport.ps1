<#
DNS Zone Posture Report (Read-only)
- Produces a manager-friendly HTML report + technician-friendly CSV/JSON.
- Focus: security + hygiene for Windows DNS zones (dynamic updates, transfers, scavenging, AD integration, etc.)
- Optional record counting (can be slow on large zones).

Run on a DNS server with the DNS PowerShell module.
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = (Get-Location).Path,

    # Record counting can be slow/heavy on big zones. Off by default.
    [switch]$IncludeRecordCounts,

    # Include auto-created/system zones (TrustAnchors, etc.). Off by default.
    [switch]$IncludeSystemZones
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ----------------------------
# Helpers
# ----------------------------
function New-OutputFolder {
    param([string]$Root)

    $serverName = $env:COMPUTERNAME
    $outDir = Join-Path -Path $Root -ChildPath $serverName
    if (-not (Test-Path -Path $outDir)) {
        New-Item -Path $outDir -ItemType Directory | Out-Null
    }
    return $outDir
}

function Safe-Get {
    param(
        [scriptblock]$Script,
        [object]$Default = $null
    )
    try { & $Script } catch { $Default }
}

function Format-TimeSpan {
    param([Nullable[TimeSpan]]$Ts)
    if (-not $Ts) { return $null }
    # friendly but still precise
    return ("{0}d {1}h {2}m" -f $Ts.Days, $Ts.Hours, $Ts.Minutes)
}

function Get-ZoneAgingSummary {
    param([string]$ZoneName)

    $aging = Safe-Get { Get-DnsServerZoneAging -ZoneName $ZoneName } $null
    if (-not $aging) {
        return [pscustomobject]@{
            AgingEnabled        = $null
            RefreshInterval     = $null
            NoRefreshInterval   = $null
            AvailForScavengeTime= $null
            ScavengeServers     = $null
            AgingNote           = "Aging/Scavenging info not available (cmdlet failed or zone type unsupported)."
        }
    }

    return [pscustomobject]@{
        AgingEnabled         = $aging.AgingEnabled
        RefreshInterval      = Format-TimeSpan $aging.RefreshInterval
        NoRefreshInterval    = Format-TimeSpan $aging.NoRefreshInterval
        AvailForScavengeTime = ($aging.AvailForScavengeTime.ToString())
        ScavengeServers      = (($aging.ScavengeServers | ForEach-Object { $_.IPAddressToString }) -join ', ')
        AgingNote            = $null
    }
}

function Get-ZoneRecordCounts {
    param([string]$ZoneName)

    if (-not $IncludeRecordCounts) {
        return [pscustomobject]@{
            TotalRecords = $null
            A = $null; AAAA = $null; CNAME = $null; MX = $null; NS = $null; SRV = $null; TXT = $null; PTR = $null
            RecordCountNote = "Record counting disabled (use -IncludeRecordCounts to enable)."
        }
    }

    # Can be heavy. Keep it simple and resilient.
    $recs = Safe-Get { Get-DnsServerResourceRecord -ZoneName $ZoneName -ErrorAction Stop } $null
    if (-not $recs) {
        return [pscustomobject]@{
            TotalRecords = $null
            A = $null; AAAA = $null; CNAME = $null; MX = $null; NS = $null; SRV = $null; TXT = $null; PTR = $null
            RecordCountNote = "Record counting failed (permissions/zone type/size)."
        }
    }

    $byType = $recs | Group-Object -Property RecordType -NoElement | ForEach-Object {
        [pscustomobject]@{ Type = $_.Name; Count = $_.Count }
    }

    $getCount = {
        param($t)
        ($byType | Where-Object { $_.Type -eq $t } | Select-Object -First 1).Count
    }

    return [pscustomobject]@{
        TotalRecords     = $recs.Count
        A               = (& $getCount 'A')
        AAAA            = (& $getCount 'AAAA')
        CNAME           = (& $getCount 'CNAME')
        MX              = (& $getCount 'MX')
        NS              = (& $getCount 'NS')
        SRV             = (& $getCount 'SRV')
        TXT             = (& $getCount 'TXT')
        PTR             = (& $getCount 'PTR')
        RecordCountNote = $null
    }
}

function Get-ZoneIssuesAndRisk {
    param(
        [pscustomobject]$ZoneRow
    )

    $issues = New-Object System.Collections.Generic.List[string]
    $reco   = New-Object System.Collections.Generic.List[string]
    $riskScore = 0

    # Dynamic updates posture (security-critical)
    switch ($ZoneRow.DynamicUpdate) {
        'Secure' { }
        'None' {
            # Not always bad, but note it for zones that might need updates.
            $issues.Add("Dynamic updates: disabled.")
            $reco.Add("If this zone must accept client/DC registrations, enable **Secure** dynamic updates (AD-integrated recommended).")
            $riskScore += 1
        }
        default {
            $issues.Add("Dynamic updates: **non-secure** updates allowed.")
            $reco.Add("Set dynamic updates to **Secure** (especially on AD-integrated zones).")
            $riskScore += 5
        }
    }

    # AD integration and replication scope (operational + security posture context)
    if ($ZoneRow.IsDsIntegrated -ne $true) {
        $issues.Add("Zone is not AD-integrated.")
        $reco.Add("If this is an internal zone, consider AD-integrated zone for secure updates + replication benefits.")
        $riskScore += 2
    }

    # Zone transfers / secondaries controls (if properties available)
    # Different Windows versions expose different fields; treat missing as "unknown".
    if ($ZoneRow.ZoneTransferType -and $ZoneRow.ZoneTransferType -match 'Any') {
        $issues.Add("Zone transfers appear allowed to **any** server.")
        $reco.Add("Restrict zone transfers to authorized IPs/servers only; enable 'Only to servers listed on Name Servers tab' or explicit list.")
        $riskScore += 5
    } elseif (-not $ZoneRow.ZoneTransferType -and -not $ZoneRow.SecureSecondaries) {
        # If we don't have transfer type, still check SecureSecondaries when present
        if ($ZoneRow.SecureSecondaries -eq $false) {
            $issues.Add("Zone transfer security (SecureSecondaries) is disabled/unknown.")
            $reco.Add("Ensure zone transfers are restricted; enable secure secondaries / restrict by IP list.")
            $riskScore += 3
        }
    }

    # Aging/scavenging hygiene (stale records -> attack surface + operational noise)
    # Note: zone aging enabled does not guarantee server scavenging is enabled; still useful per-zone signal.
    if ($ZoneRow.AgingEnabled -eq $false) {
        $issues.Add("Aging/Scavenging: disabled.")
        $reco.Add("Enable aging on appropriate zones and ensure server scavenging is configured; review intervals (No-refresh/Refresh).")
        $riskScore += 2
    }

    # Reverse zones are often neglected (still important)
    if ($ZoneRow.IsReverseLookupZone -eq $true -and $ZoneRow.AgingEnabled -eq $false) {
        $issues.Add("Reverse zone scavenging disabled (common source of stale PTR records).")
        $reco.Add("Enable aging/scavenging for PTR hygiene where appropriate.")
        $riskScore += 1
    }

    # Heuristic: primary zones with non-secure updates are especially risky
    if ($ZoneRow.ZoneType -eq 'Primary' -and $ZoneRow.DynamicUpdate -notin @('Secure','None')) {
        $riskScore += 2
    }

    # Turn score into level
    $riskLevel = if ($riskScore -ge 7) { 'High' }
                 elseif ($riskScore -ge 3) { 'Medium' }
                 else { 'Low' }

    return [pscustomobject]@{
        RiskScore      = $riskScore
        RiskLevel      = $riskLevel
        Issues         = ($issues -join ' | ')
        Recommendations= ($reco -join ' | ')
    }
}

# ----------------------------
# Collect data
# ----------------------------
$outDir = New-OutputFolder -Root $OutputRoot

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$csvPath   = Join-Path $outDir "DNSZoneReport-$timestamp.csv"
$jsonPath  = Join-Path $outDir "DNSZoneReport-$timestamp.json"
$htmlPath  = Join-Path $outDir "DNSZoneReport-$timestamp.html"

# Server-level scavenging setting (important context)
$serverSettings = Safe-Get { Get-DnsServerScavenging } $null

$zones = Get-DnsServerZone

if (-not $IncludeSystemZones) {
    # Filter common system/auto zones; still allow reverse zones (in-addr.arpa) because they matter.
    $zones = $zones | Where-Object {
        $_.IsAutoCreated -ne $true -and $_.ZoneName -notmatch '^TrustAnchors$'
    }
}

$rows = foreach ($z in $zones) {
    $zn = $z.ZoneName
    $zoneDetails = Safe-Get { Get-DnsServerZone -Name $zn } $z

    $aging = Get-ZoneAgingSummary -ZoneName $zn
    $counts = Get-ZoneRecordCounts -ZoneName $zn

    # Build a normalized row with best-effort fields across versions
    $row = [pscustomobject]@{
        Server              = $env:COMPUTERNAME
        ZoneName            = $zoneDetails.ZoneName
        ZoneType            = $zoneDetails.ZoneType
        IsDsIntegrated      = $zoneDetails.IsDsIntegrated
        ReplicationScope    = $zoneDetails.ReplicationScope
        IsReverseLookupZone = $zoneDetails.IsReverseLookupZone
        IsAutoCreated       = $zoneDetails.IsAutoCreated
        DynamicUpdate       = $zoneDetails.DynamicUpdate

        # Transfer-related fields vary by version; keep both if present
        ZoneTransferType    = Safe-Get { $zoneDetails.ZoneTransferType } $null
        SecureSecondaries   = Safe-Get { $zoneDetails.SecureSecondaries } $null
        Notify              = Safe-Get { $zoneDetails.Notify } $null

        AgingEnabled        = $aging.AgingEnabled
        NoRefreshInterval   = $aging.NoRefreshInterval
        RefreshInterval     = $aging.RefreshInterval
        AvailForScavengeTime= $aging.AvailForScavengeTime
        ScavengeServers     = $aging.ScavengeServers
        AgingNote           = $aging.AgingNote

        TotalRecords        = $counts.TotalRecords
        A                   = $counts.A
        AAAA                = $counts.AAAA
        CNAME               = $counts.CNAME
        MX                  = $counts.MX
        NS                  = $counts.NS
        SRV                 = $counts.SRV
        TXT                 = $counts.TXT
        PTR                 = $counts.PTR
        RecordCountNote     = $counts.RecordCountNote
    }

    $risk = Get-ZoneIssuesAndRisk -ZoneRow $row

    # Return final enriched row
    [pscustomobject]@{
        Server              = $row.Server
        ZoneName            = $row.ZoneName
        ZoneType            = $row.ZoneType
        IsDsIntegrated      = $row.IsDsIntegrated
        ReplicationScope    = $row.ReplicationScope
        IsReverseLookupZone = $row.IsReverseLookupZone
        DynamicUpdate       = $row.DynamicUpdate

        ZoneTransferType    = $row.ZoneTransferType
        SecureSecondaries   = $row.SecureSecondaries
        Notify              = $row.Notify

        AgingEnabled        = $row.AgingEnabled
        NoRefreshInterval   = $row.NoRefreshInterval
        RefreshInterval     = $row.RefreshInterval
        AvailForScavengeTime= $row.AvailForScavengeTime
        ScavengeServers     = $row.ScavengeServers

        TotalRecords        = $row.TotalRecords
        A                   = $row.A
        AAAA                = $row.AAAA
        CNAME               = $row.CNAME
        MX                  = $row.MX
        NS                  = $row.NS
        SRV                 = $row.SRV
        TXT                 = $row.TXT
        PTR                 = $row.PTR

        RiskLevel           = $risk.RiskLevel
        RiskScore           = $risk.RiskScore
        Issues              = $risk.Issues
        Recommendations     = $risk.Recommendations

        Notes               = ((@($row.AgingNote, $row.RecordCountNote) | Where-Object { $_ }) -join ' | ')
    }
}

# ----------------------------
# Manager summary
# ----------------------------
$totalZones = $rows.Count
$high   = ($rows | Where-Object RiskLevel -eq 'High').Count
$medium = ($rows | Where-Object RiskLevel -eq 'Medium').Count
$low    = ($rows | Where-Object RiskLevel -eq 'Low').Count

$topFindings = $rows |
    ForEach-Object {
        $_.Issues -split '\s*\|\s*' | Where-Object { $_ }
    } |
    Group-Object | Sort-Object Count -Descending |
    Select-Object -First 10

$serverScav = if ($serverSettings) {
    "Server scavenging: Enabled=$($serverSettings.ScavengingState); RefreshInterval=$([string]$serverSettings.RefreshInterval); NoRefreshInterval=$([string]$serverSettings.NoRefreshInterval)"
} else {
    "Server scavenging: Not available (Get-DnsServerScavenging failed)."
}

# ----------------------------
# Export CSV/JSON
# ----------------------------
$rows | Sort-Object RiskScore -Descending, ZoneName | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath
$rows | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path $jsonPath

# ----------------------------
# Export HTML (readable report)
# ----------------------------
$css = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 18px; }
h1,h2,h3 { margin-bottom: 6px; }
.small { color: #555; font-size: 0.95em; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.9em; }
.high { background: #ffd6d6; border: 1px solid #c40000; }
.medium { background: #fff2cc; border: 1px solid #b38f00; }
.low { background: #d9ead3; border: 1px solid #2d7d2d; }
table { border-collapse: collapse; width: 100%; margin-top: 8px; }
th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
th { background: #f3f3f3; }
code { background: #f6f6f6; padding: 1px 4px; border-radius: 4px; }
</style>
"@

# Build manager table
$summaryObj = [pscustomobject]@{
    Server          = $env:COMPUTERNAME
    Generated       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    ZonesTotal      = $totalZones
    HighRiskZones   = $high
    MediumRiskZones = $medium
    LowRiskZones    = $low
    ServerScavenging= $serverScav
}

$zonesTable = $rows |
    Sort-Object RiskScore -Descending, ZoneName |
    Select-Object ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate,
                  ZoneTransferType, SecureSecondaries, Notify,
                  AgingEnabled, NoRefreshInterval, RefreshInterval,
                  TotalRecords, RiskLevel, RiskScore, Issues, Recommendations, Notes

# Convert risk level to colored badges inside HTML
$zonesHtml = ($zonesTable | ConvertTo-Html -Fragment) -replace '<td>High</td>','<td><span class="badge high">High</span></td>' `
                                                    -replace '<td>Medium</td>','<td><span class="badge medium">Medium</span></td>' `
                                                    -replace '<td>Low</td>','<td><span class="badge low">Low</span></td>'

$topFindingsTable = $topFindings | Select-Object Name, Count

$pre = @"
$css
<h1>DNS Zone Posture Report</h1>
<div class="small">
<b>Server:</b> $($summaryObj.Server)<br/>
<b>Generated:</b> $($summaryObj.Generated)<br/>
<b>Zones:</b> Total=$($summaryObj.ZonesTotal), High=$($summaryObj.HighRiskZones), Medium=$($summaryObj.MediumRiskZones), Low=$($summaryObj.LowRiskZones)<br/>
<b>$($summaryObj.ServerScavenging)</b>
</div>

<h2>Executive summary (manager view)</h2>
<ul>
  <li><b>High risk zones:</b> $high (prioritize these)</li>
  <li><b>Most common findings:</b> see table below</li>
  <li><b>Outputs:</b> HTML (this), CSV (for filtering), JSON (for automation)</li>
</ul>

<h3>Top findings</h3>
"@

$post = @"
<h2>Zone details (technician view)</h2>
<p class="small">
Interpretation guidance:
<ul>
  <li><b>DynamicUpdate</b>: <code>Secure</code> is preferred for internal AD zones; non-secure updates are typically high risk.</li>
  <li><b>Zone transfers</b>: should be restricted to approved secondaries (avoid “Any”).</li>
  <li><b>AgingEnabled</b>: helps remove stale records; review intervals with server scavenging settings.</li>
  <li><b>Record counts</b>: optional; enable with <code>-IncludeRecordCounts</code>.</li>
</ul>
</p>
"@

# Compose HTML
$summaryHtml = ($summaryObj | ConvertTo-Html -Fragment)
$findingsHtml = ($topFindingsTable | ConvertTo-Html -Fragment)

@"
$pre
$findingsHtml
$post
$zonesHtml
"@ | Set-Content -Encoding UTF8 -Path $htmlPath

# ----------------------------
# Output
# ----------------------------
Write-Host "Report generated:"
Write-Host "  HTML:  $htmlPath"
Write-Host "  CSV:   $csvPath"
Write-Host "  JSON:  $jsonPath"
Write-Host ""
Write-Host "Tip: Re-run with -IncludeRecordCounts if you want record type totals (may be slow)."
