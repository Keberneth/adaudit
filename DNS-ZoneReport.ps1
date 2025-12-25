<#
DNS Zone Posture Report (Read-only)
- Produces HTML + CSV + JSON
- Best-effort across different Windows DNS module versions (handles missing properties)
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = (Get-Location).Path,
    [switch]$IncludeRecordCounts,
    [switch]$IncludeSystemZones
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-OutputFolder {
    param([string]$Root)
    $serverName = $env:COMPUTERNAME
    $outDir = Join-Path -Path $Root -ChildPath $serverName
    if (-not (Test-Path -Path $outDir)) { New-Item -Path $outDir -ItemType Directory | Out-Null }
    $outDir
}

function Safe-Get {
    param([scriptblock]$Script,[object]$Default=$null)
    try { & $Script } catch { $Default }
}

function Get-Prop {
    param(
        [Parameter(Mandatory)] [object]$Obj,
        [Parameter(Mandatory)] [string]$Name,
        [object]$Default = $null
    )
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $Default
}

function Format-TimeSpan {
    param([Nullable[TimeSpan]]$Ts)
    if (-not $Ts) { return $null }
    ("{0}d {1}h {2}m" -f $Ts.Days, $Ts.Hours, $Ts.Minutes)
}

function Convert-ScavengeServerListToString {
    param([object]$Value)
    if (-not $Value) { return $null }

    $items =
        @($Value) |
        Where-Object { $_ -ne $null } |
        ForEach-Object {
            $o = $_
            $ipProp = $o.PSObject.Properties['IPAddressToString']
            if ($ipProp -and $ipProp.Value) { return [string]$ipProp.Value }
            foreach ($p in @('IPAddress','Address')) {
                $pp = $o.PSObject.Properties[$p]
                if ($pp -and $pp.Value) { return [string]$pp.Value }
            }
            [string]$o
        } |
        Where-Object { $_ -and $_.Trim() -ne '' } |
        Sort-Object -Unique

    if (-not $items) { return $null }
    ($items -join ', ')
}

function Get-ZoneAgingSummary {
    param([string]$ZoneName)

    $aging = Safe-Get { Get-DnsServerZoneAging -ZoneName $ZoneName -ErrorAction Stop } $null
    if (-not $aging) {
        return [pscustomobject]@{
            AgingEnabled         = $null
            RefreshInterval      = $null
            NoRefreshInterval    = $null
            AvailForScavengeTime = $null
            ScavengeServers      = $null
            AgingNote            = "Aging/Scavenging info not available (cmdlet failed or zone type unsupported)."
        }
    }

    [pscustomobject]@{
        AgingEnabled         = Get-Prop $aging 'AgingEnabled' $null
        RefreshInterval      = Format-TimeSpan (Get-Prop $aging 'RefreshInterval' $null)
        NoRefreshInterval    = Format-TimeSpan (Get-Prop $aging 'NoRefreshInterval' $null)
        AvailForScavengeTime = Safe-Get { (Get-Prop $aging 'AvailForScavengeTime' $null).ToString() } $null
        ScavengeServers      = Convert-ScavengeServerListToString (Get-Prop $aging 'ScavengeServers' $null)
        AgingNote            = $null
    }
}

function Get-ZoneRecordCounts {
    param([string]$ZoneName)

    if (-not $IncludeRecordCounts) {
        return [pscustomobject]@{
            TotalRecords = $null
            A=$null; AAAA=$null; CNAME=$null; MX=$null; NS=$null; SRV=$null; TXT=$null; PTR=$null
            RecordCountNote = "Record counting disabled (use -IncludeRecordCounts to enable)."
        }
    }

    $recs = Safe-Get { Get-DnsServerResourceRecord -ZoneName $ZoneName -ErrorAction Stop } $null
    if (-not $recs) {
        return [pscustomobject]@{
            TotalRecords = $null
            A=$null; AAAA=$null; CNAME=$null; MX=$null; NS=$null; SRV=$null; TXT=$null; PTR=$null
            RecordCountNote = "Record counting failed (permissions/zone type/size)."
        }
    }

    $recsArr = @($recs)
    $byType = $recsArr | Group-Object -Property RecordType -NoElement

    $getCount = {
        param($t)
        $g = $byType | Where-Object Name -eq $t | Select-Object -First 1
        if ($g) { return (Safe-Get { $g.Count } $null) }
        return $null
    }

    [pscustomobject]@{
        TotalRecords     = ($recsArr | Measure-Object).Count
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
    param([pscustomobject]$ZoneRow)

    $issues = New-Object System.Collections.Generic.List[string]
    $reco   = New-Object System.Collections.Generic.List[string]
    $riskScore = 0

    if (-not $ZoneRow.DynamicUpdate) {
        $issues.Add("Dynamic updates: unknown (property not available on this server/version).")
        $reco.Add("Verify zone dynamic update setting in DNS Manager (Zone Properties -> General).")
        $riskScore += 1
    } else {
        switch ($ZoneRow.DynamicUpdate) {
            'Secure' { }
            'None' {
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
    }

    if ($ZoneRow.IsDsIntegrated -ne $true) {
        $issues.Add("Zone is not AD-integrated.")
        $reco.Add("If this is an internal zone, consider AD-integrated zone for secure updates + replication benefits.")
        $riskScore += 2
    }

    if ($ZoneRow.ZoneTransferType -and $ZoneRow.ZoneTransferType -match 'Any') {
        $issues.Add("Zone transfers appear allowed to **any** server.")
        $reco.Add("Restrict zone transfers to authorized IPs/servers only.")
        $riskScore += 5
    } elseif ($ZoneRow.SecureSecondaries -ne $null -and $ZoneRow.SecureSecondaries -eq $false) {
        $issues.Add("Zone transfer security (SecureSecondaries) is disabled.")
        $reco.Add("Restrict zone transfers (secure secondaries / explicit IP allow-list).")
        $riskScore += 3
    }

    if ($ZoneRow.AgingEnabled -eq $false) {
        $issues.Add("Aging/Scavenging: disabled.")
        $reco.Add("Enable aging on appropriate zones and ensure server scavenging is configured; review No-refresh/Refresh intervals.")
        $riskScore += 2
    }

    if ($ZoneRow.IsReverseLookupZone -eq $true -and $ZoneRow.AgingEnabled -eq $false) {
        $issues.Add("Reverse zone scavenging disabled (stale PTR records likely).")
        $reco.Add("Enable aging/scavenging for PTR hygiene where appropriate.")
        $riskScore += 1
    }

    if ($ZoneRow.ZoneType -eq 'Primary' -and $ZoneRow.DynamicUpdate -and $ZoneRow.DynamicUpdate -notin @('Secure','None')) {
        $riskScore += 2
    }

    $riskLevel = if ($riskScore -ge 7) { 'High' } elseif ($riskScore -ge 3) { 'Medium' } else { 'Low' }

    [pscustomobject]@{
        RiskScore       = $riskScore
        RiskLevel       = $riskLevel
        Issues          = ($issues -join ' | ')
        Recommendations = ($reco -join ' | ')
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

$serverSettings = Safe-Get { Get-DnsServerScavenging -ErrorAction Stop } $null

$zones = @(Get-DnsServerZone)
if (-not $IncludeSystemZones) {
    $zones = @($zones | Where-Object { $_.IsAutoCreated -ne $true -and $_.ZoneName -notmatch '^TrustAnchors$' })
}

$rows = @(
    foreach ($z in $zones) {
        $zn = $z.ZoneName
        $zoneDetails = Safe-Get { Get-DnsServerZone -Name $zn -ErrorAction Stop } $z

        $aging  = Get-ZoneAgingSummary -ZoneName $zn
        $counts = Get-ZoneRecordCounts -ZoneName $zn

        $row = [pscustomobject]@{
            Server              = $env:COMPUTERNAME
            ZoneName            = Get-Prop $zoneDetails 'ZoneName' $zn
            ZoneType            = Get-Prop $zoneDetails 'ZoneType' $null
            IsDsIntegrated      = Get-Prop $zoneDetails 'IsDsIntegrated' $null
            ReplicationScope    = Get-Prop $zoneDetails 'ReplicationScope' $null
            IsReverseLookupZone = Get-Prop $zoneDetails 'IsReverseLookupZone' $null
            IsAutoCreated       = Get-Prop $zoneDetails 'IsAutoCreated' $null
            DynamicUpdate       = Get-Prop $zoneDetails 'DynamicUpdate' $null

            ZoneTransferType    = Get-Prop $zoneDetails 'ZoneTransferType' $null
            SecureSecondaries   = Get-Prop $zoneDetails 'SecureSecondaries' $null
            Notify              = Get-Prop $zoneDetails 'Notify' $null

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
)

# Count safely (works even when $rows is empty/1 item)
$totalZones = ($rows | Measure-Object).Count
$high   = ($rows | Where-Object RiskLevel -eq 'High'   | Measure-Object).Count
$medium = ($rows | Where-Object RiskLevel -eq 'Medium' | Measure-Object).Count
$low    = ($rows | Where-Object RiskLevel -eq 'Low'    | Measure-Object).Count

$topFindings = $rows |
    ForEach-Object { $_.Issues -split '\s*\|\s*' | Where-Object { $_ } } |
    Group-Object |
    Sort-Object Count -Descending |
    Select-Object -First 10

$serverScav = if ($serverSettings) {
    "Server scavenging: Enabled=$($serverSettings.ScavengingState); RefreshInterval=$([string]$serverSettings.RefreshInterval); NoRefreshInterval=$([string]$serverSettings.NoRefreshInterval)"
} else {
    "Server scavenging: Not available (Get-DnsServerScavenging failed)."
}

$rows |
    Sort-Object -Property @{Expression="RiskScore";Descending=$true}, @{Expression="ZoneName";Descending=$false} |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath

$rows | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path $jsonPath

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
    Sort-Object -Property @{Expression="RiskScore";Descending=$true}, @{Expression="ZoneName";Descending=$false} |
    Select-Object ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate,
                  ZoneTransferType, SecureSecondaries, Notify,
                  AgingEnabled, NoRefreshInterval, RefreshInterval,
                  TotalRecords, RiskLevel, RiskScore, Issues, Recommendations, Notes

$zonesHtml = ($zonesTable | ConvertTo-Html -Fragment) `
    -replace '<td>High</td>','<td><span class="badge high">High</span></td>' `
    -replace '<td>Medium</td>','<td><span class="badge medium">Medium</span></td>' `
    -replace '<td>Low</td>','<td><span class="badge low">Low</span></td>'

$findingsHtml = (($topFindings | Select-Object Name, Count) | ConvertTo-Html -Fragment)

@"
$css
<h1>DNS Zone Posture Report</h1>
<div class="small">
<b>Server:</b> $($summaryObj.Server)<br/>
<b>Generated:</b> $($summaryObj.Generated)<br/>
<b>Zones:</b> Total=$($summaryObj.ZonesTotal), High=$($summaryObj.HighRiskZones), Medium=$($summaryObj.MediumRiskZones), Low=$($summaryObj.LowRiskZones)<br/>
<b>$($summaryObj.ServerScavenging)</b>
</div>

<h2>Top findings</h2>
$findingsHtml

<h2>Zone details</h2>
$zonesHtml
"@ | Set-Content -Encoding UTF8 -Path $htmlPath

Write-Host "Report generated:"
Write-Host "  HTML:  $htmlPath"
Write-Host "  CSV:   $csvPath"
Write-Host "  JSON:  $jsonPath"
