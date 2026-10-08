<#
    .SYNOPSIS
        ADAudit check: DNS Zone Report

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -dnszone). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-DnsZoneReportCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select dnszone [options]

    .NOTES
        Entry point: Invoke-DnsZoneReportCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: DnsServer.
#>
#region DNS Zone Posture Report (merged)
function Invoke-DnsZonePostureReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputRoot,
        [switch]$IncludeRecordCounts,
        [switch]$IncludeSystemZones
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # ----------------------------
    # Config (function args)
    # ----------------------------
    $script:IncludeRecordCounts  = [bool]$IncludeRecordCounts
    $script:PreferZoneStatistics = $true
    $script:RecordCountMaxRecords= 250000
    $script:IncludeSystemZones   = [bool]$IncludeSystemZones
    $script:FailSoft             = $true
    $script:WriteErrorReport     = $true

    # ----------------------------
    # Error bucket
    # ----------------------------
    $script:CollectionErrors = @()
    $script:ZoneFailures     = @()

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

        # Folder structure: DNS-Reports/<ComputerName>
        $dnsRoot = Join-Path -Path $Root -ChildPath 'DNS-Reports'
        Ensure-Folder $dnsRoot | Out-Null
        $reports = Join-Path -Path $dnsRoot -ChildPath $safeServer
        Ensure-Folder $reports
    }

    # ----------------------------
    # Detect target DNS server (no args)
    # ----------------------------
    function Get-TargetDnsServer {
        $localOk = Safe-Get -Context "Detect: Get-DnsServer local" -Default $false -Script {
            Import-ADAuditModule -Name DnsServer -Required | Out-Null
            $null = Get-DnsServer -ComputerName $env:COMPUTERNAME -ErrorAction Stop
            $true
        }
        if ($localOk) { return $env:COMPUTERNAME }

        $dnsIps = Safe-Get -Context "Detect: Get-DnsClientServerAddress" -Default @() -Script {
            $addrs = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop
            $active = $addrs | Where-Object { $_.InterfaceAlias -and $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 }
            ($active | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
        }

        if (-not $dnsIps -or @($dnsIps).Count -eq 0) {
            return $null
        }

        foreach ($ip in $dnsIps) {
            $ok = Safe-Get -Context "Detect: Test-NetConnection $ip:53" -Default $false -Script {
                (Test-NetConnection -ComputerName $ip -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue)
            }
            if ($ok) { return $ip }
        }

        # @() guards the single-server case: indexing a scalar string would
        # return its first character instead of the IP.
        @($dnsIps)[0]
    }

    # ----------------------------
    # Preflight module - skip the check gracefully if the DnsServer module
    # isn't available or the target server is unreachable. We previously
    # threw here, which aborted every subsequent ADAudit check. Now we log
    # and return so the script can continue with the rest of the audit.
    # ----------------------------
    $dnsModule = Safe-Get -Context "Preflight: Get-Module DnsServer" -Default $null -Script {
        Get-Module -ListAvailable -Name DnsServer | Sort-Object Version -Descending | Select-Object -First 1
    }
    if (-not $dnsModule) {
        Write-Warning "DnsServer module not found. Install DNS role tools / RSAT DNS (DnsServer) on this host. DNS zone report will be skipped."
        throw "DnsServer module not available - DNS zone report skipped."
    }

    Import-ADAuditModule -Name DnsServer -Required | Out-Null

    $ComputerName = Get-TargetDnsServer
    if (-not $ComputerName) {
        Write-Warning "Could not detect a DNS server from local NIC DNS settings, and local host does not appear to be a DNS server. DNS zone report will be skipped."
        throw "DNS server target could not be detected - DNS zone report skipped."
    }

    $serverInfo = Safe-Get -Context "Preflight: Get-DnsServer -ComputerName $ComputerName" -Default $null -Script {
        Get-DnsServer -ComputerName $ComputerName -ErrorAction Stop
    }
    if (-not $serverInfo) {
        Write-Warning "Unable to query DNS server '$ComputerName'. Check connectivity, firewall/RPC, permissions, and that DNS Server role is present. DNS zone report will be skipped."
        throw "Unable to query DNS server '$ComputerName' - DNS zone report skipped."
    }

    # ----------------------------
    # Output paths (Reports + type subfolders)
    # ----------------------------
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $outDir    = New-ReportsFolder -Root $OutputRoot -ServerName $ComputerName

    $txtDir  = Ensure-Folder (Join-Path $outDir 'txt')
    $htmlDir = Ensure-Folder (Join-Path $outDir 'html')

    $csvPath     = Join-Path $outDir  "DNSAudit-$timestamp.csv"
    $jsonPath    = Join-Path $outDir  "DNSAudit-$timestamp.json"
    $htmlPath    = Join-Path $htmlDir "DNSAudit-$timestamp.html"
    $errJsonPath = Join-Path $outDir  "DNSAudit-Errors-$timestamp.json"
    $recHtmlPath = Join-Path $htmlDir "DNS-Recommendations-$timestamp.html"
    $recTxtPath  = Join-Path $txtDir  "DNS-Recommendations-$timestamp.txt"

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

        if (-not $script:IncludeRecordCounts) {
            return [pscustomobject]@{
                TotalRecords    = $null
                A=$null; AAAA=$null; CNAME=$null; MX=$null; NS=$null; SRV=$null; TXT=$null; PTR=$null
                RecordCountNote = "Record counting disabled."
            }
        }

        if ($script:PreferZoneStatistics) {
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
        if ($script:RecordCountMaxRecords -gt 0 -and $arr.Count -gt $script:RecordCountMaxRecords) {
            $arr = $arr[0..($script:RecordCountMaxRecords-1)]
            $truncated = $true
        }

        $byType = $arr | Group-Object -Property RecordType -NoElement

        function Count-Type([string]$t, $groups) {
            $g = @($groups | Where-Object Name -eq $t) | Select-Object -First 1
            if ($g -and $null -ne $g.PSObject.Properties['Count']) { return [int]$g.Count }
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
            RecordCountNote = if ($truncated) { "Counts truncated to first $($script:RecordCountMaxRecords) records (safety cap)." } else { $null }
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

    if (-not $script:IncludeSystemZones) {
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
            if (-not $script:FailSoft) { throw }
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
    $recRowsHtml = ($recommendations | ForEach-Object {
        $badgeCls = switch ($_.Priority) { 'High' { 'badge-high' } 'Medium' { 'badge-medium' } default { 'badge-low' } }
        "<tr><td><span class='badge $badgeCls'>$($_.Priority)</span></td><td>$($_.Area)</td><td>$($_.Topic)</td><td>$($_.Evidence)</td><td>$($_.Recommendation)</td></tr>"
    }) -join "`r`n"

    $recHighCount = @($recommendations | Where-Object { $_.Priority -eq 'High' }).Count
    $recMedCount  = @($recommendations | Where-Object { $_.Priority -eq 'Medium' }).Count
    $recLowCount  = @($recommendations | Where-Object { $_.Priority -eq 'Low' }).Count

@"
$(Get-ADAuditReportHeader -Title 'DNS Recommendations Report')
<div class="hero">
<h1>DNS Recommendations Report</h1>
<div class="meta">Target DNS server: <code>$ComputerName</code> &mdash; Generated: $($serverPosture.Generated)</div>
</div>

<div class="stats">
<div class="stat"><div class="val">$(@($recommendations).Count)</div><div class="lbl">Total</div></div>
<div class="stat"><div class="val" style="color:var(--high)">$recHighCount</div><div class="lbl">High Priority</div></div>
<div class="stat"><div class="val" style="color:var(--medium)">$recMedCount</div><div class="lbl">Medium Priority</div></div>
<div class="stat"><div class="val" style="color:var(--low)">$recLowCount</div><div class="lbl">Low Priority</div></div>
</div>

<h2>Disclaimer</h2>
<pre>$($RecommendationDisclaimer.Trim())</pre>

<h2>Recommendations</h2>
<table><thead>
<tr><th>Priority</th><th>Area</th><th>Topic</th><th>Evidence</th><th>Recommendation</th></tr>
</thead><tbody>
$recRowsHtml
</tbody></table>

$(Get-ADAuditReportFooter)
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
            ZoneFailures    = ($script:ZoneFailures | Measure-Object).Count
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
        Failures        = @($script:ZoneFailures)
        CollectionErrors= @($script:CollectionErrors)
    }

    $jsonObj | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 -Path $jsonPath

    if ($script:WriteErrorReport) {
        [pscustomobject]@{
            ZoneFailures     = @($script:ZoneFailures)
            CollectionErrors = @($script:CollectionErrors)
        } | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path $errJsonPath
    }

    # ----------------------------
    # HTML audit report
    # ----------------------------
    $riskBadgeClass = switch ($serverRisk.RiskLevel) { 'High' { 'badge-high' } 'Medium' { 'badge-medium' } default { 'badge-low' } }

    $serverSummaryHtml = @"
<table><thead>
<tr><th>Field</th><th>Value</th></tr>
</thead><tbody>
<tr><td>TargetDnsServer</td><td><code>$($serverPosture.TargetDnsServer)</code></td></tr>
<tr><td>Generated</td><td>$($serverPosture.Generated)</td></tr>
<tr><td>RunAs</td><td><code>$($serverPosture.RunAs)</code></td></tr>
<tr><td>PowerShellVersion</td><td>$($serverPosture.PowerShellVersion)</td></tr>
<tr><td>OSVersion</td><td>$($serverPosture.OSVersion)</td></tr>
<tr><td>DnsServerModuleVersion</td><td>$($serverPosture.DnsServerModuleVersion)</td></tr>
<tr><td>Recursion</td><td>$($serverPosture.Recursion)</td></tr>
<tr><td>Forwarders</td><td>$($serverPosture.Forwarders)</td></tr>
<tr><td>ScavengingEnabled</td><td>$($serverPosture.ScavengingEnabled)</td></tr>
</tbody></table>
"@

    $zonesTable = $rows |
        Sort-Object -Property @{Expression="RiskScore";Descending=$true}, @{Expression="ZoneName";Descending=$false} |
        Select-Object ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate,
                      ZoneTransferType, SecureSecondaries, Notify, NotifyServers, SecondaryServers,
                      AgingEnabled, NoRefreshInterval, RefreshInterval,
                      TotalRecords, RiskLevel, RiskScore, RiskFactors, Issues, Recommendations, Notes

    $zonesHtml = ($zonesTable | ConvertTo-Html -Fragment) `
        -replace '<td>High</td>','<td><span class="badge badge-high">High</span></td>' `
        -replace '<td>Medium</td>','<td><span class="badge badge-medium">Medium</span></td>' `
        -replace '<td>Low</td>','<td><span class="badge badge-low">Low</span></td>'

    # Fix ConvertTo-Html <table> to use <thead>/<tbody>. ConvertTo-Html -Fragment
    # returns one string per line, so the patterns must not span lines; join first
    # and anchor on the header row / closing tags, each of which occurs exactly once.
    $zonesHtml = ($zonesHtml -join "`n") -replace '<tr><th','<thead><tr><th' -replace '</th></tr>','</th></tr></thead><tbody>' -replace '</table>','</tbody></table>'

    # ----------------------------
    # Findings by Issue (grouped) - replaces the old "Top Findings" mini-table.
    # Each row in this section is one DISTINCT issue, with severity, why-it-
    # matters, recommended fix, and the list of zones it affects (collapsed
    # into a <details> block so the page is short for the operator and only
    # expands on click). This is the section the user actually reads to
    # understand WHAT is wrong, WHY, and WHICH zones to fix.
    # ----------------------------
    $issueExplain = @{
        'Dynamic updates: non-secure updates allowed.' = @{
            Severity = 'High'
            Why      = 'Any client (including unauthenticated/rogue hosts) can register or overwrite DNS records, enabling DNS spoofing, MITM, and credential theft via WPAD/NetBIOS poisoning.'
            Fix      = 'Set the zone Dynamic updates to "Secure only" (DNS Manager: Zone Properties > General). Requires AD-integrated zone.'
        }
        'Zone transfers: allowed to any server.' = @{
            Severity = 'High'
            Why      = 'Anyone on the network can pull the entire zone (all hostnames, IPs, comments) - a full reconnaissance gift for attackers.'
            Fix      = 'Restrict zone transfers to specific authorized secondaries (DNS Manager: Zone Properties > Zone Transfers > Only to servers listed on the Name Servers tab, or an explicit IP list).'
        }
        'Zone transfer security (SecureSecondaries) is disabled.' = @{
            Severity = 'Medium'
            Why      = 'Zone transfers are not restricted to the configured secondary list, expanding the attack surface for zone enumeration.'
            Fix      = 'Enable secure secondaries on the zone or restrict transfers to an explicit IP allow-list.'
        }
        'Zone is not AD-integrated.' = @{
            Severity = 'Medium'
            Why      = 'File-backed (Standard Primary) zones store data in plain text on disk and lack AD replication, ACLs, and Secure dynamic updates. Sensitive internal zones should not run as Standard Primary.'
            Fix      = 'Convert internal zones to AD-integrated (DNS Manager: Zone Properties > General > Change > "Store the zone in Active Directory"). Forwarder/Stub zones are excluded.'
        }
        'Aging/Scavenging: disabled.' = @{
            Severity = 'Medium'
            Why      = 'Stale dynamic records accumulate over time, which causes name-resolution drift, leaks decommissioned host names to attackers, and inflates zone size.'
            Fix      = 'Enable aging on the zone and ensure server-level scavenging is on (No-Refresh + Refresh intervals typically 7 days each). Validate operational impact in a maintenance window first.'
        }
        'Zone aging enabled but server scavenging appears disabled/unknown.' = @{
            Severity = 'Low'
            Why      = 'Per-zone aging is on, but no server is actually deleting expired records, so the aging timestamps build up without effect.'
            Fix      = 'Enable scavenging at the DNS server level (DNS Manager: Server Properties > Advanced > Enable automatic scavenging of stale records).'
        }
        'Dynamic updates: disabled.' = @{
            Severity = 'Low'
            Why      = 'Records are static-only. Not a security risk, but flag it because clients that expected to register will fail silently. Often correct for forward-only or manually-curated zones.'
            Fix      = 'No action if intentional. If the zone is expected to accept registrations, switch to Secure dynamic updates (AD-integrated zones only).'
        }
        'Dynamic updates: unknown (property not available).' = @{
            Severity = 'Low'
            Why      = 'The DNS module did not expose the dynamic-update property for this zone (typical for Forwarder/Stub zones, which do not register records). Worth confirming in DNS Manager for completeness.'
            Fix      = 'Open DNS Manager > Zone Properties > General and confirm the Dynamic updates setting matches policy. Forwarder zones can be ignored.'
        }
    }

    function _Get-IssueMeta {
        param([string]$Issue)
        if ($issueExplain.ContainsKey($Issue)) { return $issueExplain[$Issue] }
        @{ Severity = 'Medium'; Why = '(no canonical explanation registered for this issue)'; Fix = 'Review the affected zone settings in DNS Manager.' }
    }

    # Build per-issue groupings: issue string -> {affected zones, severity, etc}
    $issueGroups = @{}
    foreach ($r in $rows) {
        $issuesForRow = @($r._IssueList)
        foreach ($issue in $issuesForRow) {
            if (-not $issue) { continue }
            if (-not $issueGroups.ContainsKey($issue)) {
                $meta = _Get-IssueMeta -Issue $issue
                $issueGroups[$issue] = [pscustomobject]@{
                    Issue    = $issue
                    Severity = $meta.Severity
                    Why      = $meta.Why
                    Fix      = $meta.Fix
                    Zones    = New-Object System.Collections.Generic.List[string]
                }
            }
            [void]$issueGroups[$issue].Zones.Add([string]$r.ZoneName)
        }
    }

    $sevOrder = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2; 'Information' = 3 }
    $issueGroupList = @($issueGroups.Values |
        Sort-Object @{Expression={$sevOrder[$_.Severity]}}, @{Expression={-1 * $_.Zones.Count}}, Issue)

    $findingsByIssueHtml = New-Object System.Text.StringBuilder
    if (@($issueGroupList).Count -eq 0) {
        [void]$findingsByIssueHtml.Append('<p>No DNS zone issues detected.</p>')
    } else {
        foreach ($g in $issueGroupList) {
            $badgeCls = switch ($g.Severity) { 'High' { 'badge-high' } 'Medium' { 'badge-medium' } 'Low' { 'badge-low' } default { 'badge-info' } }
            $zoneCount = $g.Zones.Count
            $zoneListHtml = ($g.Zones | Sort-Object | ForEach-Object { "<li><code>$([System.Web.HttpUtility]::HtmlEncode([string]$_))</code></li>" }) -join "`n"
            $whyEnc = [System.Web.HttpUtility]::HtmlEncode($g.Why)
            $fixEnc = [System.Web.HttpUtility]::HtmlEncode($g.Fix)
            $issueEnc = [System.Web.HttpUtility]::HtmlEncode($g.Issue)
            [void]$findingsByIssueHtml.Append(@"
<details>
<summary><span class="badge $badgeCls">$($g.Severity)</span> &nbsp; $issueEnc &nbsp;&mdash;&nbsp; <strong>$zoneCount zone(s)</strong></summary>
<div class="detail-body">
<p><strong>Why this matters:</strong> $whyEnc</p>
<p><strong>How to fix:</strong> $fixEnc</p>
<p><strong>Affected zones ($zoneCount):</strong></p>
<ul>
$zoneListHtml
</ul>
</div>
</details>
"@)
        }
    }

    # Try to load HttpUtility for HTML encoding (Add-Type may need to be invoked).
    # Some PS hosts already have it; if not, it's loaded via System.Web here.
    try { [void][System.Web.HttpUtility] } catch { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue }

@"
$(Get-ADAuditReportHeader -Title 'DNS Audit Report')
<div class="hero">
<h1>DNS Audit Report</h1>
<div class="meta">
Target DNS server: <code>$ComputerName</code> &mdash;
Zones: Total=$totalZones, High=$high, Medium=$medium, Low=$low &mdash;
<a href="DNS-Recommendations-$timestamp.html">Recommendations Report</a>
</div>
</div>

<div class="stats">
<div class="stat"><div class="val">$totalZones</div><div class="lbl">Total Zones</div></div>
<div class="stat"><div class="val" style="color:var(--high)">$high</div><div class="lbl">High Risk</div></div>
<div class="stat"><div class="val" style="color:var(--medium)">$medium</div><div class="lbl">Medium Risk</div></div>
<div class="stat"><div class="val" style="color:var(--low)">$low</div><div class="lbl">Low Risk</div></div>
</div>

<h2>How to read this report</h2>
<p>This report has three sections:</p>
<ol>
  <li><strong>Server Posture</strong> - configuration of the DNS server itself (recursion, forwarders, scavenging).</li>
  <li><strong>Findings by Issue</strong> - one entry per distinct DNS misconfiguration with severity, the security risk it creates, the recommended fix, and the list of zones it affects. <em>Start here.</em></li>
  <li><strong>Zone Details (raw)</strong> - the full per-zone table for cross-reference. Collapsed by default.</li>
</ol>

<h2>Server Posture <span class="badge $riskBadgeClass">$($serverRisk.RiskLevel) (Score: $($serverRisk.RiskScore))</span></h2>
$serverSummaryHtml

<h2>Findings by Issue</h2>
<p>One entry per distinct issue type. Click each row to see the affected zones and the recommended fix.</p>
$($findingsByIssueHtml.ToString())

<h2>Zone Details (raw)</h2>
<details>
<summary>Show full per-zone table ($totalZones zones)</summary>
<div class="detail-body">
$zonesHtml
</div>
</details>

$(Get-ADAuditReportFooter)
"@ | Set-Content -Encoding UTF8 -Path $htmlPath

    Write-Host "Report generated:"
    Write-Host "  Target DNS:      $ComputerName"
    Write-Host "  Reports folder:  $outDir"
    Write-Host "  HTML folder:     $htmlDir"
    Write-Host "  TXT folder:      $txtDir"
    Write-Host "  Audit HTML:      $htmlPath"
    Write-Host "  Audit CSV:       $csvPath"
    Write-Host "  Audit JSON:      $jsonPath"
    Write-Host "  Reco HTML:       $recHtmlPath"
    Write-Host "  Reco TXT:        $recTxtPath"
    if ($script:WriteErrorReport) { Write-Host "  ERR JSON:        $errJsonPath" }
}

# Backward-compatible wrapper (older call site in this script)
function Invoke-DNSZoneReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputRoot,
        [switch]$IncludeRecordCounts,
        [switch]$IncludeSystemZones
    )
    Invoke-DnsZonePostureReport -OutputRoot $OutputRoot -IncludeRecordCounts:$IncludeRecordCounts -IncludeSystemZones:$IncludeSystemZones
}

function Invoke-DnsZoneReportCheck {
    Invoke-DNSZoneReport -OutputRoot $(if($DnsZoneOutputRoot){$DnsZoneOutputRoot}else{(Get-RawDataDir -BaseRoot $outputdir)}) -IncludeRecordCounts:$DnsIncludeRecordCounts -IncludeSystemZones:$DnsIncludeSystemZones
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select dnszone @args
}