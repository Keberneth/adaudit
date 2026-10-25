<#
    .SYNOPSIS
        ADAudit check: AD platform health check (replication, dcdiag, SYSVOL/DFSR, NTDS, time, services, events, sites, recycle bin, group hygiene)

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -adhealth). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-HealthCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select adhealth [options]

    .NOTES
        Entry point: Invoke-HealthCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
function Get-ADAuditHostUtcTime {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName)
    Assert-ADAuditRemoteTargetAllowed -ComputerName $ComputerName
    if (Test-ADAuditLocalComputer $ComputerName) { return [DateTime]::UtcNow }
    $clock = Get-ADAuditCimInstance -ComputerName $ComputerName -ClassName Win32_UTCTime -UseWsmanFallback -ErrorAction Stop
    if ($null -eq $clock.Year) { throw 'The UTC clock provider returned no sample.' }
    [DateTime]::new([int]$clock.Year, [int]$clock.Month, [int]$clock.Day, [int]$clock.Hour, [int]$clock.Minute, [int]$clock.Second, [DateTimeKind]::Utc)
}

function Get-ADAuditNtdsStorage {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName)
    $key = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    $database = Get-ADAuditRemoteRegistryValue -ComputerName $ComputerName -SubKey $key -ValueName 'DSA Database file' -ValueType String -UseWsmanFallback
    $logs = Get-ADAuditRemoteRegistryValue -ComputerName $ComputerName -SubKey $key -ValueName 'Database log files path' -ValueType String -UseWsmanFallback
    if (-not $database.Success -or -not $logs.Success -or -not $database.Value -or -not $logs.Value) { throw "NTDS database/log paths unavailable. $($database.Error) $($logs.Error)" }
    $ditPath = [string]$database.Value
    $logPath = [string]$logs.Value
    $drive = Split-Path -Path $logPath -Qualifier
    if (-not $drive) { throw 'The NTDS log path did not identify a local volume.' }
    if (Test-ADAuditLocalComputer $ComputerName) {
        $size = (Get-Item -LiteralPath $ditPath -ErrorAction Stop).Length
        $free = (Get-PSDrive -Name $drive.TrimEnd(':') -ErrorAction Stop).Free
    } else {
        # Exact Name filtering prevents an expensive filesystem-wide WMI scan.
        $escapedPath = $ditPath.Replace('\','\\').Replace("'","\'")
        $file = Get-ADAuditCimInstance -ComputerName $ComputerName -ClassName CIM_DataFile -Filter "Name='$escapedPath'" -Property FileSize -UseWsmanFallback -ErrorAction Stop
        $disk = Get-ADAuditCimInstance -ComputerName $ComputerName -ClassName Win32_LogicalDisk -Filter "DeviceID='$drive'" -Property FreeSpace -UseWsmanFallback -ErrorAction Stop
        $size = $file.FileSize
        $free = $disk.FreeSpace
    }
    if ($null -eq $size -or $null -eq $free) { throw 'Database size or log-volume free space was unavailable.' }
    [pscustomobject]@{DatabasePath=$ditPath; LogPath=$logPath; DatabaseBytes=[long]$size; LogFreeBytes=[long]$free}
}

function Get-ADAuditReplicationPartnerMetadata {
    # Bounded replication-partner read. ADWS calls cannot be cancelled reliably inside a
    # runspace, so remote targets are read in a child process that is killed on expiry.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Target, [string]$Activity = 'AD Health', [double]$PercentComplete = -1)
    Assert-ADAuditRemoteTargetAllowed -ComputerName $Target
    $result = Invoke-ADAuditBoundedOperation -Target $Target -Operation 'replication partner metadata' -Transport 'Adws' -Isolation Process -Activity $Activity -PercentComplete $PercentComplete -ScriptBlock {
        param($Target)
        if (-not (Get-Command Get-ADReplicationPartnerMetadata -ErrorAction SilentlyContinue)) { Import-Module ActiveDirectory -ErrorAction Stop }
        ,@(Get-ADReplicationPartnerMetadata -Target $Target -Scope Server -ErrorAction Stop | Select-Object Partner, LastReplicationSuccess, LastReplicationAttempt, LastReplicationResult)
    } -ArgumentList @($Target)
    $records = Receive-ADAuditOperationResult -Result $result
    @($records)
}

Function Get-ADHealth {
    <#
    .SYNOPSIS
        Performs AD platform health checks (replication, dcdiag, SYSVOL/DFSR, NTDS,
        time sync, core services, event-log scrape, sites/subnets, AD Recycle Bin,
        and group hygiene), then writes AD_Health.html plus per-test evidence files
        to Raw Data\Source. KPSSVC ("Kerberos Key Distribution Proxy") is treated
        as informational only because it is optional - many AD deployments leave
        it stopped intentionally.
    #>
    [CmdletBinding()]
    param()

    Write-Both "    [+] Running AD Health checks (replication, dcdiag, SYSVOL/DFSR, NTDS, time, services, events, sites, recycle bin, group hygiene)"

    $rawDir = Get-RawSourceDataDir
    $htmlDir = Get-HtmlReportsDir -BaseRoot $outputdir
    if (-not (Test-Path -LiteralPath $rawDir))  { New-Item -ItemType Directory -Path $rawDir  -Force | Out-Null }
    if (-not (Test-Path -LiteralPath $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }

    $findings = New-Object System.Collections.Generic.List[object]
    $tests    = New-Object System.Collections.Generic.List[object]
    $weights  = @{ Critical = 25; High = 12; Medium = 5; Low = 1; Info = 0 }
    $healthGaps = @{}
    function _HUnknown {
        param([string]$Path, [string]$Target, [string]$Reason)
        if (-not $healthGaps.ContainsKey($Path)) { $healthGaps[$Path] = 0 }
        $healthGaps[$Path]++
        Register-ADAuditNotAssessed -Name ('AD Health: ' + [IO.Path]::GetFileNameWithoutExtension($Path)) -Switch 'adhealth' -Target $Target -Reason $Reason
    }

    function _Add-HFinding {
        param([string]$Category,[string]$Severity,[string]$Title,[string]$Evidence,[string]$Source)
        $score = if ($weights.ContainsKey($Severity)) { $weights[$Severity] } else { 0 }
        $findings.Add([pscustomobject]@{
            Category = $Category
            Severity = $Severity
            Title    = $Title
            Evidence = $Evidence
            Score    = $score
            Source   = $Source
        }) | Out-Null
    }
    function _Add-HTest {
        param(
            [string]$Title,
            [string]$Subtitle,
            [string]$Status,
            [string]$Detail,
            [string]$EvidencePath
        )
        $gapCount = if ($healthGaps.ContainsKey($EvidencePath)) { $healthGaps[$EvidencePath] } else { 0 }
        if ($gapCount -gt 0) {
            if ($Status -ne 'Fail') { $Status = 'Partial' }
            $Detail = "$Detail; $gapCount collection gap(s) - coverage incomplete"
        }
        $tests.Add([pscustomobject]@{
            Title        = $Title
            Subtitle     = $Subtitle
            Status       = $Status
            Detail       = $Detail
            EvidencePath = $EvidencePath
            NotAssessedCount = $gapCount
        }) | Out-Null
    }

    try {
        Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null
    } catch {
        Write-Both "    [!] AD Health check skipped: ActiveDirectory module not available."
        Register-ADAuditNotAssessed -Name 'AD Health' -Switch 'adhealth' -Reason 'ActiveDirectory module unavailable.'
        return
    }

    try {
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop | Sort-Object Name)
    } catch {
        Write-Both "    [!] AD Health check skipped: could not enumerate DCs ($($_.Exception.Message))."
        Register-ADAuditNotAssessed -Name 'AD Health' -Switch 'adhealth' -Reason $_.Exception.Message
        return
    }
    if ($dcs.Count -eq 0) {
        Register-ADAuditNotAssessed -Name 'AD Health' -Switch 'adhealth' -Reason 'No domain controllers returned.'
        return
    }
    $inventoryDcs = $dcs
    if ($script:ADAuditIsolatedClone) {
        foreach ($dc in $dcs) {
            if (-not (Test-ADAuditLocalComputer $dc.HostName)) {
                Register-ADAuditNotAssessed -Name 'AD Health: isolated-clone scope' -Switch 'adhealth' -Target $dc.HostName -Reason 'Remote DC intentionally excluded from local clone collection; current production state is not assessed.'
            }
        }
        $dcs = @($dcs | Where-Object { Test-ADAuditLocalComputer $_.HostName })
        if ($dcs.Count -eq 0) {
            Register-ADAuditNotAssessed -Name 'AD Health' -Switch 'adhealth' -Reason 'Isolated-clone mode found no directory DC identity matching this computer; no remote targets were contacted.'
            return
        }
    }

    $domain = ''
    try { $domain = (Get-ADDomain -ErrorAction Stop).DNSRoot } catch { $domain = $env:USERDNSDOMAIN }
    $runBy = "$($env:USERDOMAIN)\$($env:USERNAME)"

    # ============================================================
    # 1) Replication health
    # ============================================================
    $replPath = Join-Path $rawDir 'health_replication.txt'
    $replSb   = New-Object System.Text.StringBuilder
    $replFailed = 0
    $replLingeringErr = $false
    Write-ADAuditProgress -Activity 'AD Health' -Status 'Replication evidence' -PercentComplete 0
    if ($script:ADAuditIsolatedClone) {
        _HUnknown $replPath 'Production replication' 'Isolated-clone mode: replication commands are skipped because peer availability and old replication metadata cannot establish current production health.'
        [void]$replSb.AppendLine('Replication collection skipped in isolated-clone mode. Local snapshot data is not a production replication assessment.')
    } else {
    [void]$replSb.AppendLine('=== repadmin /replsummary ===')
    try {
        $replRun = Invoke-ADAuditNativeCommand -FilePath 'repadmin' -ArgumentList '/replsummary' -Operation 'repadmin /replsummary' -Activity 'AD Health' -PercentComplete 0
        if ($replRun.Outcome -ne 'Success') { if ($replRun.Output) { [void]$replSb.AppendLine($replRun.Output) }; throw $replRun.Error }
        $replSummary = [string]$replRun.Output
        if ($replRun.ExitCode -ne 0) { _HUnknown $replPath 'repadmin /replsummary' "Command exited with $($replRun.ExitCode); see evidence." }
        [void]$replSb.AppendLine($replSummary)
        # repadmin /replsummary table format:
        #     Source DSA          largest delta    fails/total %%   error
        #      DC01                  17m:42s        2 /  3   66 (8606) ...
        #      DC02                  >60 days      5 /   5  100  (1722) ...   <- multi-token delta!
        #      DC03                  (unknown)     0 /   0    0
        # The delta column can be a single token (17m:42s), a parenthesised
        # phrase ((unknown)), or a multi-token phrase like ">60 days". Match
        # robustly by anchoring on the "fails / total percentage" pattern
        # itself. Capture group #1 is the actual fails column.
        # /replsummary prints the SAME failures twice - once in the "Source DSA" table
        # and once in the "Destination DSA" table. Count rows from the Source table only,
        # otherwise every failure is double-counted.
        $inSourceTable = $false
        $replParsedRows = 0
        foreach ($line in ($replSummary -split "`r?`n")) {
            if ($line -match 'Source DSA')      { $inSourceTable = $true;  continue }
            if ($line -match 'Destination DSA') { $inSourceTable = $false; continue }
            if (-not $inSourceTable) { continue }
            if ($line -match '^\s*\S+\s+.+?(\d+)\s*/\s*\d+\s+\d+(\s|$)') {
                $f = [int]$matches[1]
                $replParsedRows++
                if ($f -gt 0) { $replFailed += $f }
            }
        }
        if ($replParsedRows -eq 0) { _HUnknown $replPath 'repadmin /replsummary' 'No source-summary rows could be interpreted; empty/localized output is not proof of successful replication.' }
    } catch { _HUnknown $replPath 'repadmin /replsummary' $_.Exception.Message; [void]$replSb.AppendLine("repadmin /replsummary failed: $($_.Exception.Message)") }

    [void]$replSb.AppendLine('')
    [void]$replSb.AppendLine('=== repadmin /showrepl /csv (per-DC, may be truncated) ===')
    try {
        $showreplRun = Invoke-ADAuditNativeCommand -FilePath 'repadmin' -ArgumentList '/showrepl','/csv' -Operation 'repadmin /showrepl /csv' -Activity 'AD Health' -PercentComplete 2
        if ($showreplRun.Outcome -ne 'Success') { if ($showreplRun.Output) { [void]$replSb.AppendLine($showreplRun.Output) }; throw $showreplRun.Error }
        $showrepl = [string]$showreplRun.Output
        if ($showreplRun.ExitCode -ne 0) { _HUnknown $replPath 'repadmin /showrepl' "Command exited with $($showreplRun.ExitCode)." }
        if ($showrepl.Length -gt 32000) { $showrepl = $showrepl.Substring(0,32000) + "`n... (truncated) ..." }
        [void]$replSb.AppendLine($showrepl)
    } catch { _HUnknown $replPath 'repadmin /showrepl' $_.Exception.Message; [void]$replSb.AppendLine("repadmin /showrepl failed: $($_.Exception.Message)") }

    [void]$replSb.AppendLine('')
    [void]$replSb.AppendLine('=== repadmin /queue (per-DC) ===')
    foreach ($dc in $dcs) {
        try {
            $queueTransport = if (Test-ADAuditLocalComputer $dc.HostName) { '' } else { 'Rpc' }
            $queueRun = Invoke-ADAuditNativeCommand -FilePath 'repadmin' -ArgumentList '/queue',$dc.HostName -Target $dc.HostName -Operation 'repadmin /queue' -Activity 'AD Health' -PercentComplete 4 -Transport $queueTransport
            if ($queueRun.Outcome -ne 'Success') { if ($queueRun.Output) { [void]$replSb.AppendLine($queueRun.Output) }; throw $queueRun.Error }
            $q = [string]$queueRun.Output
            if ($queueRun.ExitCode -ne 0) { _HUnknown $replPath $dc.HostName "repadmin /queue exited with $($queueRun.ExitCode)." }
            [void]$replSb.AppendLine("--- $($dc.HostName) ---")
            [void]$replSb.AppendLine($q)
        } catch { _HUnknown $replPath $dc.HostName $_.Exception.Message; [void]$replSb.AppendLine("$($dc.HostName): $($_.Exception.Message)") }
    }

    [void]$replSb.AppendLine('')
    [void]$replSb.AppendLine('=== repadmin /showrepl /errorsonly (advisory replication-error / lingering-object scan) ===')
    try {
        # Advisory-only per-DC replication error scan. This is NOT /removelingeringobjects
        # (which requires a configured clean reference DC and would make changes); it lists
        # replication errors so lingering-object symptoms surface without modifying anything.
        $lingerRun = Invoke-ADAuditNativeCommand -FilePath 'repadmin' -ArgumentList '/showrepl','/errorsonly' -Operation 'repadmin /showrepl /errorsonly' -Activity 'AD Health' -PercentComplete 6
        $linger = [string]$lingerRun.Output
        [void]$replSb.AppendLine($linger)
        if ($lingerRun.Outcome -ne 'Success') { [void]$replSb.AppendLine($lingerRun.Error) }
        if ($lingerRun.Outcome -ne 'Success' -or $lingerRun.ExitCode -ne 0) { $replLingeringErr = $true }
    } catch { $replLingeringErr = $true; [void]$replSb.AppendLine($_.Exception.Message) }

    }
    Set-Content -LiteralPath $replPath -Value $replSb.ToString() -Encoding UTF8

    if ($replFailed -gt 0) {
        _Add-HFinding -Category 'Replication' -Severity 'High' -Title 'Replication failures detected' -Evidence "Total replication failures across DCs: $replFailed" -Source $replPath
        _Add-HTest -Title 'Replication health' -Subtitle 'repadmin /replsummary, /showrepl, /queue, lingering objects' -Status 'Fail' -Detail "$replFailed failure(s)" -EvidencePath $replPath
    } elseif ($replLingeringErr) {
        _HUnknown $replPath 'repadmin /showrepl /errorsonly' 'Advisory command failed; replication-error state was not assessed.'
        _Add-HTest -Title 'Replication health' -Subtitle 'repadmin summary, partner details and queue' -Status 'Partial' -Detail 'Advisory collection incomplete' -EvidencePath $replPath
    } else {
        _Add-HTest -Title 'Replication health' -Subtitle 'repadmin /replsummary, /showrepl, /queue, lingering objects' -Status 'Pass' -Detail 'No issues observed in collected evidence' -EvidencePath $replPath
    }

    # ============================================================
    # 1b) DC interconnect (network reachability between DCs)
    # ----------------------------------------------------------
    # A DC that *exists* in AD but cannot be reached on LDAP/SMB is
    # partitioned (cloned to an isolated network, firewalled off,
    # powered off, etc.). Replication will silently diverge. Severity
    # scales with how much redundancy is left:
    #   - 1 DC total:                  Pass (nothing to partition)
    #   - 2 DCs, any isolated:         Critical (no failover, AD will diverge)
    #   - 3 DCs, 1 isolated:           High
    #   - 4+ DCs, 1 isolated:          Medium
    #   - Multiple isolated and < 2 reachable: Critical
    #   - Multiple isolated, < 3 reachable:    High
    #   - Multiple isolated, 3+ reachable:     Medium
    # Each isolated DC also gets its own per-DC Critical finding.
    # ============================================================
    function _Test-DCTcp {
        param([string]$Target, [int]$Port, [int]$TimeoutMs = 1500)
        # Connect to the cached address so a slow resolver is paid once per DC, not per port.
        $resolution = Resolve-ADAuditTargetAddresses -ComputerName $Target
        if ($resolution.Status -eq 'Unresolvable') { return $false }
        $address = if ($resolution.Status -eq 'Resolved') { [string]@($resolution.Addresses)[0] } else { $Target }
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $tcp.BeginConnect($address, $Port, $null, $null)
            if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
            try { $tcp.EndConnect($async); return $true } catch { return $false }
        } catch { return $false } finally { try { $tcp.Close() } catch {} }
    }

    $icPath = Join-Path $rawDir 'health_dc_interconnect.txt'
    $icSb = New-Object System.Text.StringBuilder
    $totalDCs = $dcs.Count
    $localFqdn = ''
    try { $localFqdn = "$env:COMPUTERNAME.$env:USERDNSDOMAIN".ToLowerInvariant() } catch { $localFqdn = $env:COMPUTERNAME.ToLowerInvariant() }

    [void]$icSb.AppendLine('=== DC interconnect probe ===')
    [void]$icSb.AppendLine("Probed from: $env:COMPUTERNAME ($localFqdn)")
    [void]$icSb.AppendLine("Total DCs in domain: $totalDCs")
    [void]$icSb.AppendLine('Tests per DC: DNS resolve | TCP 389 (LDAP) | TCP 445 (SMB) | replication metadata freshness')
    [void]$icSb.AppendLine('The Isolated field means unreachable from this auditing host only; it does not establish a replication partition.')
    [void]$icSb.AppendLine('')

    $dcReachRows = @()
    foreach ($dc in $dcs) {
        $dcHost = $dc.HostName
        Write-ADAuditProgress -Activity 'AD Health' -Status "DC reachability: $dcHost" -PercentComplete 8
        $isLocalDC = Test-ADAuditLocalComputer $dcHost

        $dnsOk = $false
        $dnsOk = ((Resolve-ADAuditTargetAddresses -ComputerName $dcHost).Status -eq 'Resolved')

        $ldapOk = $false; $smbOk = $false
        if ($dnsOk -or $isLocalDC) {
            $ldapOk = _Test-DCTcp -Target $dcHost -Port 389
            $smbOk  = _Test-DCTcp -Target $dcHost -Port 445
        }

        $replOk = $null
        $lastRepl = $null
        try {
            if ($script:ADAuditIsolatedClone) { throw 'Replication freshness is not assessed from an isolated snapshot.' }
            $partners = @(Get-ADAuditReplicationPartnerMetadata -Target $dcHost -Activity 'AD Health' -PercentComplete 8)
            if ($partners) {
                $stale = $false
                foreach ($p in $partners) {
                    $lastRepl = $p.LastReplicationSuccess
                    if (-not $lastRepl -or $lastRepl -lt (Get-Date).AddDays(-1)) { $stale = $true }
                }
                $replOk = -not $stale
            }
        } catch {
            _HUnknown $icPath $dcHost ("Replication metadata unavailable: " + $_.Exception.Message)
            $replOk = $null
        }

        $isolated = (-not $isLocalDC) -and (-not $ldapOk) -and (-not $smbOk)

        $row = [pscustomobject]@{
            Host       = $dcHost
            IsLocal    = $isLocalDC
            DNS        = $dnsOk
            LDAP       = $ldapOk
            SMB        = $smbOk
            ReplFresh  = $replOk
            LastRepl   = $lastRepl
            Isolated   = $isolated
        }
        $dcReachRows += $row

        [void]$icSb.AppendLine(("DC: {0}  (local={1})" -f $dcHost, $isLocalDC))
        [void]$icSb.AppendLine(("  DNS:                {0}" -f $dnsOk))
        [void]$icSb.AppendLine(("  LDAP TCP 389:       {0}" -f $ldapOk))
        [void]$icSb.AppendLine(("  SMB  TCP 445:       {0}" -f $smbOk))
        [void]$icSb.AppendLine(("  Replication fresh:  {0} (last successful: {1})" -f $replOk, $(if ($lastRepl) { $lastRepl } else { 'unknown' })))
        [void]$icSb.AppendLine(("  Isolated:           {0}" -f $isolated))
        [void]$icSb.AppendLine('')
    }

    $isolatedRows = @($dcReachRows | Where-Object { $_.Isolated })
    $isolatedCount = $isolatedRows.Count
    $reachableCount = $totalDCs - $isolatedCount

    # A management-host reachability failure cannot establish a partition
    # between DCs. Keep observed replication failures separate from reachability.
    $icSeverity = 'Pass'
    $icDetail = "All $totalDCs DC(s) reachable"
    $icOverallSev = $null
    if ($isolatedCount -gt 0) {
        $icSeverity = 'Partial'
        $icDetail = "$isolatedCount/$totalDCs DC(s) not reachable from the auditing host; DC-to-DC connectivity is not established by these probes"
        foreach ($iso in $isolatedRows) {
            _HUnknown $icPath $iso.Host 'LDAP and SMB were not reachable from the auditing host. This does not prove a DC outage or replication failure; confirm from approved DC-to-DC paths.'
        }
    }

    $staleReplication = @($dcReachRows | Where-Object { $null -ne $_.ReplFresh -and -not $_.ReplFresh })
    if ($staleReplication.Count -gt 0) {
        $icSeverity = 'Fail'
        $icDetail = "$($staleReplication.Count) DC(s) with stale observed replication metadata"
        _Add-HFinding -Category 'DC Interconnect' -Severity 'High' -Title 'Stale inbound replication metadata' -Evidence "No recent success for one or more recorded partners on: $(($staleReplication.Host) -join ', '). Validate against site schedules and the replication report." -Source $icPath
    }

    Set-Content -LiteralPath $icPath -Value $icSb.ToString() -Encoding UTF8
    _Add-HTest -Title 'DC interconnect' -Subtitle "$totalDCs DC(s); DNS, LDAP 389, SMB 445, replication freshness" -Status $icSeverity -Detail $icDetail -EvidencePath $icPath

    # ============================================================
    # 2) DC diagnostics (dcdiag)
    # ============================================================
    $dcdiagPath = Join-Path $rawDir 'health_dcdiag.txt'
    $dcdiagSb   = New-Object System.Text.StringBuilder
    $dcdiagFailedTests = 0
    $dcdiagBreakdown   = @{}
    $dcdiagTests = 'Services','Replications','Advertising','FsmoCheck','KCCEvent','NetLogons','SysVolCheck','RidManager','DFSREvent','Intersite'
    foreach ($dc in $dcs) {
        $dcHost = $dc.HostName
        [void]$dcdiagSb.AppendLine("===== dcdiag on $dcHost =====")
        foreach ($t in $dcdiagTests) {
            Write-ADAuditProgress -Activity 'AD Health' -Status "dcdiag $t on $dcHost" -PercentComplete 16
            if ($script:ADAuditIsolatedClone -and $t -notin @('Services','Advertising','NetLogons','SysVolCheck')) {
                _HUnknown $dcdiagPath "$dcHost/$t" 'Isolated-clone mode: replication, FSMO and peer-dependent diagnostics are skipped.'
                continue
            }
            try {
                # dcdiag needs LDAP to the target; one 389 probe gates all ten tests for a DC that is down.
                $dcdiagTransport = if (Test-ADAuditLocalComputer $dcHost) { '' } else { 'Ldap' }
                $dcdiagRun = Invoke-ADAuditNativeCommand -FilePath 'dcdiag' -ArgumentList "/s:$dcHost","/test:$t" -Target $dcHost -Operation "dcdiag /test:$t" -Activity 'AD Health' -PercentComplete 16 -Transport $dcdiagTransport
                $out = [string]$dcdiagRun.Output
                [void]$dcdiagSb.AppendLine($out)
                if ($dcdiagRun.Outcome -ne 'Success') { throw $dcdiagRun.Error }
                if ($out -match '(?im)^\s*\.+\s+\S+\s+failed\s+test\s+') {
                    $dcdiagFailedTests++
                    if (-not $dcdiagBreakdown.ContainsKey($dcHost)) { $dcdiagBreakdown[$dcHost] = 0 }
                    $dcdiagBreakdown[$dcHost] = $dcdiagBreakdown[$dcHost] + 1
                } elseif ($dcdiagRun.ExitCode -ne 0 -or $out -notmatch ('(?im)\bpassed\s+test\s+' + [regex]::Escape($t) + '\b')) {
                    _HUnknown $dcdiagPath "$dcHost/$t" 'No successful test result could be interpreted (command failure, missing or localized output).'
                }
            } catch {
                _HUnknown $dcdiagPath "$dcHost/$t" $_.Exception.Message
                [void]$dcdiagSb.AppendLine("dcdiag $t on $dcHost threw: $($_.Exception.Message)")
            }
        }
    }
    Set-Content -LiteralPath $dcdiagPath -Value $dcdiagSb.ToString() -Encoding UTF8

    if ($dcdiagFailedTests -gt 0) {
        $brk = ($dcdiagBreakdown.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
        _Add-HFinding -Category 'DC Diagnostics' -Severity 'Medium' -Title 'dcdiag tests failing on one or more DCs' -Evidence "Failed tests: $dcdiagFailedTests | DC breakdown: $brk" -Source $dcdiagPath
        _Add-HTest -Title 'DC diagnostics (dcdiag)' -Subtitle 'Services, Replications, Advertising, FsmoCheck, KCCEvent, NetLogons, SysVolCheck, RidManager, DFSREvent, Intersite' -Status 'Warn' -Detail '1 Medium' -EvidencePath $dcdiagPath
    } else {
        _Add-HTest -Title 'DC diagnostics (dcdiag)' -Subtitle 'Services, Replications, Advertising, FsmoCheck, KCCEvent, NetLogons, SysVolCheck, RidManager, DFSREvent, Intersite' -Status 'Pass' -Detail 'No issues observed in collected evidence' -EvidencePath $dcdiagPath
    }

    # ============================================================
    # 3) SYSVOL / DFSR availability (backlog is not measured)
    # ============================================================
    $sysvolPath = Join-Path $rawDir 'health_sysvol_dfsr.txt'
    $sysvolSb   = New-Object System.Text.StringBuilder
    $sysvolBacklog = 0
    foreach ($dc in $dcs) {
        $dcHost = $dc.HostName
        Write-ADAuditProgress -Activity 'AD Health' -Status "SYSVOL and DFSR: $dcHost" -PercentComplete 25
        [void]$sysvolSb.AppendLine("--- $dcHost ---")
        try {
            $share = "\\$dcHost\SYSVOL"
            if (Test-ADAuditLocalComputer $dcHost) {
                $localShare = Get-ADAuditCimInstance -ComputerName $dcHost -ClassName Win32_Share -Filter "Name='SYSVOL'" -ErrorAction Stop
                if (-not $localShare.Path) { throw 'Local SYSVOL share path was not returned by the share provider.' }
                $share = [string]$localShare.Path
            }
            $shareReachable = if (Test-ADAuditLocalComputer $dcHost) { Test-Path -LiteralPath $share -ErrorAction Stop } else {
                # UNC access cannot be cancelled inside a runspace; a child process makes the deadline enforceable.
                $shareProbe = Invoke-ADAuditBoundedOperation -Target $dcHost -Operation 'SYSVOL share access' -Transport 'Smb' -Isolation Process -Activity 'AD Health' -PercentComplete 25 -ScriptBlock { param($Path) Test-Path -LiteralPath $Path -ErrorAction Stop } -ArgumentList @($share)
                [bool](Receive-ADAuditOperationResult -Result $shareProbe)
            }
            if ($shareReachable) {
                [void]$sysvolSb.AppendLine("SYSVOL share reachable: $share")
            } else {
                [void]$sysvolSb.AppendLine("SYSVOL share NOT reachable: $share")
                _HUnknown $sysvolPath $dcHost 'SYSVOL is not reachable from the audit host; share absence or a replication failure was not established.'
            }
        } catch {
            [void]$sysvolSb.AppendLine("Could not reach SYSVOL on ${dcHost}: $($_.Exception.Message)")
            _HUnknown $sysvolPath $dcHost $_.Exception.Message
        }
        try {
            $dfsr = Get-ADAuditCimInstance -ClassName Win32_Service -ComputerName $dcHost -Filter "Name='DFSR'" -ErrorAction Stop
            if ($dfsr) {
                [void]$sysvolSb.AppendLine("DFSR state: $($dfsr.State) / start: $($dfsr.StartMode)")
                if ($dfsr.State -ne 'Running') { $sysvolBacklog++ }
            } else { _HUnknown $sysvolPath $dcHost 'DFSR service was not returned; legacy FRS and migration state were not assessed.' }
        } catch { _HUnknown $sysvolPath $dcHost $_.Exception.Message }
    }
    Set-Content -LiteralPath $sysvolPath -Value $sysvolSb.ToString() -Encoding UTF8
    if ($sysvolBacklog -gt 0) {
        _Add-HFinding -Category 'SYSVOL/DFSR' -Severity 'Medium' -Title 'SYSVOL or DFSR issue detected' -Evidence "DCs with SYSVOL/DFSR concerns: $sysvolBacklog" -Source $sysvolPath
        _Add-HTest -Title 'SYSVOL / DFSR availability' -Subtitle 'SYSVOL share reachability and DFSR service state; backlog not measured' -Status 'Warn' -Detail "$sysvolBacklog issue(s)" -EvidencePath $sysvolPath
    } else {
        _Add-HTest -Title 'SYSVOL / DFSR availability' -Subtitle 'SYSVOL share reachability and DFSR service state; backlog not measured' -Status 'Pass' -Detail 'No issues observed in collected evidence' -EvidencePath $sysvolPath
    }

    # ============================================================
    # 4) FSMO role holders & operations-master health
    #
    # Treats FSMO as INVENTORY + RISK VALIDATION, not "co-location is bad".
    # Co-locating roles on one DC (e.g. RID + PDC) is a normal, supported
    # layout, so simple co-location is reported as informational only and
    # is never failed on its own. A role IS flagged when its holder is
    # missing/unassigned, unresolvable in DNS, an RODC (read-only DCs
    # cannot own an operations-master role), unreachable on LDAP/ADWS,
    # not replicating, or - for the forest-root PDC emulator - has no
    # authoritative external time source.
    # ============================================================
    $fsmoPath = Join-Path $rawDir 'health_fsmo.txt'
    Write-ADAuditProgress -Activity 'AD Health' -Status 'FSMO role inventory' -PercentComplete 33
    $fsmoSb   = New-Object System.Text.StringBuilder
    $fsmoCritical = 0   # Critical findings -> Fail card
    $fsmoHigh     = 0   # High findings     -> Fail card
    $fsmoWarn     = 0   # Medium findings   -> Warn card
    [void]$fsmoSb.AppendLine('=== FSMO role holders & operations-master health ===')
    [void]$fsmoSb.AppendLine('The five FSMO (operations master) roles:')
    [void]$fsmoSb.AppendLine('  Forest-wide : SchemaMaster, DomainNamingMaster')
    [void]$fsmoSb.AppendLine('  Per-domain  : PDCEmulator, RIDMaster, InfrastructureMaster')
    [void]$fsmoSb.AppendLine('Co-locating roles on one DC (e.g. RID + PDC) is normal and supported,')
    [void]$fsmoSb.AppendLine('and is reported as informational only - never failed on its own.')
    [void]$fsmoSb.AppendLine('Observed ownership, RODC, stale replication and time-source issues are findings.')
    [void]$fsmoSb.AppendLine('Failed audit-host lookups and probes reduce coverage; they do not establish an outage.')
    [void]$fsmoSb.AppendLine('')

    $fsmoRoles      = New-Object System.Collections.Generic.List[object]
    $forestRootPdc  = $null
    $fsmoEnumerated = $false
    try {
        $fsmoForest = Get-ADForest -ErrorAction Stop
        $fsmoRoles.Add([pscustomobject]@{ Scope='Forest'; Role='SchemaMaster';       Holder=[string]$fsmoForest.SchemaMaster })       | Out-Null
        $fsmoRoles.Add([pscustomobject]@{ Scope='Forest'; Role='DomainNamingMaster'; Holder=[string]$fsmoForest.DomainNamingMaster }) | Out-Null
        $rootDomainName = [string]$fsmoForest.RootDomain
        foreach ($domName in $fsmoForest.Domains) {
            try {
                if ($script:ADAuditIsolatedClone) {
                    if ($domName -ne $domain) { throw 'Other-domain FSMO inventory is not queried in isolated-clone mode.' }
                    $fsmoDom = Get-ADDomain -ErrorAction Stop
                } else { $fsmoDom = Get-ADDomain -Server $domName -ErrorAction Stop }
                if ($domName -eq $rootDomainName) { $forestRootPdc = [string]$fsmoDom.PDCEmulator }
                $fsmoRoles.Add([pscustomobject]@{ Scope=$domName; Role='PDCEmulator';          Holder=[string]$fsmoDom.PDCEmulator })          | Out-Null
                $fsmoRoles.Add([pscustomobject]@{ Scope=$domName; Role='RIDMaster';            Holder=[string]$fsmoDom.RIDMaster })            | Out-Null
                $fsmoRoles.Add([pscustomobject]@{ Scope=$domName; Role='InfrastructureMaster'; Holder=[string]$fsmoDom.InfrastructureMaster }) | Out-Null
            } catch {
                [void]$fsmoSb.AppendLine("[!] Could not query domain '$domName' (PDC/RID/Infrastructure not validated): $($_.Exception.Message)")
                _HUnknown $fsmoPath $domName $_.Exception.Message
            }
        }
        $fsmoEnumerated = $true
    } catch {
        [void]$fsmoSb.AppendLine("[!] Could not query the forest for FSMO holders: $($_.Exception.Message)")
        _HUnknown $fsmoPath 'Forest FSMO inventory' $_.Exception.Message
    }

    if ($script:ADAuditIsolatedClone) {
        _HUnknown $fsmoPath 'FSMO operational validation' 'Isolated-clone mode: role owners are snapshot inventory only; live holder reachability, replication and time-source validation are skipped.'
        foreach ($roleRow in $fsmoRoles) { [void]$fsmoSb.AppendLine(("  {0} [{1}] -> {2} (snapshot inventory only)" -f $roleRow.Role,$roleRow.Scope,$roleRow.Holder)) }
    } elseif ($fsmoEnumerated -and $fsmoRoles.Count -gt 0) {
        # --- Probe each unique holder once (a single DC can hold several roles) ---
        $holderProbe = @{}
        foreach ($h in (@($fsmoRoles | ForEach-Object { $_.Holder } | Where-Object { $_ } | Sort-Object -Unique))) {
            $hKey = $h.ToLowerInvariant()
            $found = $false; $isRodc = $null; $site = $null; $ipv4 = $null
            try {
                $hdc = Get-ADDomainController -Identity $h -ErrorAction Stop
                if (-not $hdc) { throw 'No DC object returned.' }
                $found = $true; $isRodc = [bool]$hdc.IsReadOnly; $site = [string]$hdc.Site; $ipv4 = [string]$hdc.IPv4Address
            } catch {
                try {
                    $hdc = Get-ADDomainController -Identity $h -Server $h -ErrorAction Stop
                    if (-not $hdc) { throw 'No DC object returned.' }
                    $found = $true; $isRodc = [bool]$hdc.IsReadOnly; $site = [string]$hdc.Site; $ipv4 = [string]$hdc.IPv4Address
                } catch { _HUnknown $fsmoPath $h ("DC object lookup failed: " + $_.Exception.Message) }
            }
            $dnsOk = $false
            $holderResolution = Resolve-ADAuditTargetAddresses -ComputerName $h
            if ($holderResolution.Status -eq 'Resolved') { $dnsOk = $true } else { _HUnknown $fsmoPath $h ("DNS lookup failed from the audit host: " + $holderResolution.Detail) }
            $ldapOk = $false; $adwsOk = $false
            if ($dnsOk -or $found) {
                $ldapOk = _Test-DCTcp -Target $h -Port 389
                $adwsOk = _Test-DCTcp -Target $h -Port 9389
            }
            if (-not $ldapOk -or -not $adwsOk) { _HUnknown $fsmoPath $h 'LDAP or ADWS could not be reached from the audit host. This does not establish an FSMO outage.' }
            # $replOk: $true = fresh, $false = CONFIRMED stale (partners returned but
            # older than 24h), $null = could NOT verify (single DC with no partners,
            # or a cross-domain/RPC-restricted holder we cannot query). Only the
            # confirmed-stale ($false) case raises a finding, so a healthy holder we
            # simply cannot reach for metadata is never falsely flagged.
            $replOk = $null; $lastRepl = $null
            try {
                $rp = @(Get-ADAuditReplicationPartnerMetadata -Target $h -Activity 'AD Health' -PercentComplete 33)
                if ($rp) {
                    $stale = $false
                    foreach ($p in $rp) { $lastRepl = $p.LastReplicationSuccess; if (-not $lastRepl -or $lastRepl -lt (Get-Date).AddDays(-1)) { $stale = $true } }
                    $replOk = -not $stale
                } elseif (@($fsmoForest.Domains).Count -eq 1 -and $dcs.Count -eq 1 -and $h -eq $dcs[0].HostName) {
                    $replOk = $true
                    [void]$fsmoSb.AppendLine("  $h has no partners in the verified single-DC forest; inbound partner checks are not applicable.")
                } else {
                    _HUnknown $fsmoPath $h 'No replication partner metadata returned; replication health could not be established.'
                }
            } catch { $replOk = $null; _HUnknown $fsmoPath $h ("Replication metadata lookup failed: " + $_.Exception.Message) }
            $holderProbe[$hKey] = [pscustomobject]@{ Holder=$h; Found=$found; IsRODC=$isRodc; DNS=$dnsOk; LDAP=$ldapOk; ADWS=$adwsOk; ReplFresh=$replOk; LastRepl=$lastRepl; Site=$site; IPv4=$ipv4 }
        }

        # --- Inventory ---
        [void]$fsmoSb.AppendLine('--- Current FSMO holders ---')
        foreach ($fr in $fsmoRoles) {
            [void]$fsmoSb.AppendLine(("  {0,-20} [{1}] -> {2}" -f $fr.Role, $fr.Scope, $(if ($fr.Holder) { $fr.Holder } else { '(unassigned)' })))
        }
        [void]$fsmoSb.AppendLine('')
        [void]$fsmoSb.AppendLine('--- Per-holder validation ---')

        foreach ($fr in $fsmoRoles) {
            $role = $fr.Role; $holder = $fr.Holder
            if (-not $holder) {
                [void]$fsmoSb.AppendLine("  $role [$($fr.Scope)] -> HOLDER UNASSIGNED")
                _Add-HFinding -Category 'FSMO' -Severity 'Critical' -Title "FSMO role $role has no holder" -Evidence "The $role role ($($fr.Scope)) has no assigned owner. Operations that depend on this role will fail until it is seized to a healthy writable DC." -Source $fsmoPath
                $fsmoCritical++
                [void]$fsmoSb.AppendLine('')
                continue
            }

            $pr = $holderProbe[$holder.ToLowerInvariant()]
            [void]$fsmoSb.AppendLine(("  {0} [{1}] -> {2}" -f $role, $fr.Scope, $holder))
            if ($pr) {
                [void]$fsmoSb.AppendLine(("      DC object found  : {0}{1}" -f $pr.Found, $(if ($pr.Found) { "  (Site=$($pr.Site), IPv4=$($pr.IPv4))" } else { '' })))
                [void]$fsmoSb.AppendLine(("      DNS resolves     : {0}" -f $pr.DNS))
                [void]$fsmoSb.AppendLine(("      LDAP TCP 389     : {0}" -f $pr.LDAP))
                [void]$fsmoSb.AppendLine(("      ADWS TCP 9389    : {0}" -f $pr.ADWS))
                [void]$fsmoSb.AppendLine(("      Read-only (RODC) : {0}" -f $pr.IsRODC))
                [void]$fsmoSb.AppendLine(("      Replication fresh: {0} (last success: {1})" -f $pr.ReplFresh, $(if ($pr.LastRepl) { $pr.LastRepl } else { 'unknown' })))

                if (-not $pr.DNS -or -not $pr.LDAP -or -not $pr.ADWS) {
                    [void]$fsmoSb.AppendLine('      Audit-host connectivity is incomplete. Validate DNS and source/target firewall scope before concluding that role-dependent operations are affected.')
                }
                if ($pr.Found -and $pr.IsRODC -eq $true) {
                    _Add-HFinding -Category 'FSMO' -Severity 'Critical' -Title "Operations-master role held by a read-only DC (RODC)" -Evidence "The $role holder '$holder' is an RODC. RODCs hold a read-only replica and cannot perform operations-master writes - this role must be moved to a writable DC." -Source $fsmoPath
                    $fsmoCritical++
                }
                if ($pr.Found -and $pr.ReplFresh -eq $false) {
                    _Add-HFinding -Category 'FSMO' -Severity 'High' -Title "FSMO holder is not replicating" -Evidence "The $role holder '$holder' is reachable but has no confirmed successful inbound replication in the last 24h (last success: $(if ($pr.LastRepl) { $pr.LastRepl } else { 'unknown' })). A reachable-but-non-replicating operations master serves stale data and is a latent outage." -Source $fsmoPath
                    $fsmoHigh++
                }
                if ($pr.DNS -and $pr.LDAP -and -not $pr.Found) {
                    [void]$fsmoSb.AppendLine('      Note: holder resolves and answers on LDAP but its DC object could not be read (cross-domain / ADWS / permissions). RODC and replication state were not validated for this holder.')
                }
            } else {
                [void]$fsmoSb.AppendLine('      (no probe result)')
            }
            [void]$fsmoSb.AppendLine('')
        }

        # --- Role placement / co-location (informational only) ---
        [void]$fsmoSb.AppendLine('--- Role placement (informational - co-location is normal) ---')
        $byHolder = @($fsmoRoles | Where-Object { $_.Holder } | Group-Object { $_.Holder.ToLowerInvariant() })
        foreach ($g in $byHolder) {
            $rolesOn = ($g.Group | ForEach-Object { $_.Role }) -join ', '
            [void]$fsmoSb.AppendLine(("  {0}: {1}" -f $g.Group[0].Holder, $rolesOn))
        }
        $allOnOne = @($byHolder | Where-Object { $_.Count -ge 5 })
        if ($allOnOne.Count -gt 0) {
            [void]$fsmoSb.AppendLine('')
            [void]$fsmoSb.AppendLine("  [i] All FSMO roles are held by a single DC ($($allOnOne[0].Group[0].Holder)). This is common")
            [void]$fsmoSb.AppendLine('      and supported in a single-domain forest; noted for documentation and DR')
            [void]$fsmoSb.AppendLine('      planning, not flagged as a problem.')
        }
        [void]$fsmoSb.AppendLine('')

        # --- Forest-root PDC emulator: authoritative external time source ---
        if ($forestRootPdc) {
            [void]$fsmoSb.AppendLine('--- Forest-root PDC emulator time source ---')
            [void]$fsmoSb.AppendLine("  Forest-root PDC: $forestRootPdc")
            try {
                $pdcTransport = if (Test-ADAuditLocalComputer $forestRootPdc) { '' } else { 'Rpc' }
                $pdcRun = Invoke-ADAuditNativeCommand -FilePath 'w32tm' -ArgumentList '/query','/source',"/computer:$forestRootPdc" -Target $forestRootPdc -Operation 'w32tm /query /source' -Activity 'AD Health' -PercentComplete 33 -Transport $pdcTransport
                if ($pdcRun.Outcome -ne 'Success') { throw $pdcRun.Error }
                $pdcSource = ([string]$pdcRun.Output).Trim()
                [void]$fsmoSb.AppendLine("  w32tm source   : $pdcSource")
                if ($pdcRun.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($pdcSource) -or $pdcSource -match '(?i)0x800706BA|error|RPC server is unavailable') {
                    _HUnknown $fsmoPath $forestRootPdc ("Time source query failed: " + $pdcSource)
                } elseif ($pdcSource -match '(?i)Local CMOS Clock|Free-running System Clock') {
                    _Add-HFinding -Category 'FSMO' -Severity 'High' -Title 'Forest-root PDC has no authoritative external time source' -Evidence "The forest-root PDC emulator '$forestRootPdc' is syncing from '$pdcSource' rather than an external/hardware NTP source. Every clock in the forest chains to this PDC; with no real upstream source the whole forest can drift and break Kerberos (auth fails at >5 min skew)." -Source $fsmoPath
                    $fsmoHigh++
                } else {
                    [void]$fsmoSb.AppendLine('  Assessment     : external/upstream time source present (OK)')
                }
            } catch {
                [void]$fsmoSb.AppendLine("  w32tm source   : query failed ($($_.Exception.Message))")
                _HUnknown $fsmoPath $forestRootPdc $_.Exception.Message
            }
            [void]$fsmoSb.AppendLine('')
        }
    }

    Set-Content -LiteralPath $fsmoPath -Value $fsmoSb.ToString() -Encoding UTF8
    $fsmoSubtitle = 'Schema, Domain Naming, PDC, RID, Infrastructure: holder writable, resolvable, reachable, replicating'
    if (($fsmoCritical + $fsmoHigh) -gt 0) {
        $fsmoDetail = if ($fsmoCritical -gt 0 -and $fsmoHigh -gt 0) { "$fsmoCritical Critical, $fsmoHigh High" }
                      elseif ($fsmoCritical -gt 0)                  { "$fsmoCritical Critical" }
                      else                                          { "$fsmoHigh High" }
        _Add-HTest -Title 'FSMO role holders' -Subtitle $fsmoSubtitle -Status 'Fail' -Detail $fsmoDetail -EvidencePath $fsmoPath
    } elseif ($fsmoWarn -gt 0) {
        _Add-HTest -Title 'FSMO role holders' -Subtitle $fsmoSubtitle -Status 'Warn' -Detail "$fsmoWarn issue(s)" -EvidencePath $fsmoPath
    } else {
        _Add-HTest -Title 'FSMO role holders' -Subtitle $fsmoSubtitle -Status 'Pass' -Detail 'No issues observed in collected evidence' -EvidencePath $fsmoPath
    }

    # ============================================================
    # 5) NTDS database
    # ============================================================
    $ntdsPath = Join-Path $rawDir 'health_ntds.txt'
    $ntdsSb   = New-Object System.Text.StringBuilder
    $ntdsIssues = 0
    foreach ($dc in $dcs) {
        $dcHost = $dc.HostName
        Write-ADAuditProgress -Activity 'AD Health' -Status "NTDS storage: $dcHost" -PercentComplete 42
        [void]$ntdsSb.AppendLine("--- $dcHost ---")
        try {
            $storage = Get-ADAuditNtdsStorage -ComputerName $dcHost
            $ditPath = $storage.DatabasePath
            $logPath = $storage.LogPath
            [void]$ntdsSb.AppendLine("ntds.dit: $ditPath")
            [void]$ntdsSb.AppendLine("logs:     $logPath")
            $dbInfo = $storage.DatabaseBytes
            $logVolFree = $storage.LogFreeBytes

            if ($null -eq $dbInfo -or $null -eq $logVolFree -or $dbInfo -lt 0 -or $logVolFree -lt 0) { throw 'Database size or log-volume free space was unavailable.' }

            if ($dbInfo -ge 0)     { [void]$ntdsSb.AppendLine(("ntds.dit size: {0:N0} bytes" -f $dbInfo)) }
            if ($logVolFree -ge 0) { [void]$ntdsSb.AppendLine(("log volume free: {0:N0} bytes" -f $logVolFree)) }
            if ($logVolFree -ge 0 -and $logVolFree -lt (1GB)) {
                $ntdsIssues++
                [void]$ntdsSb.AppendLine("  [!] log volume has < 1 GB free")
            }
        } catch {
            [void]$ntdsSb.AppendLine("Could not read NTDS info via local/CIM collection on ${dcHost}: $($_.Exception.Message)")
            _HUnknown $ntdsPath $dcHost $_.Exception.Message
        }
    }
    Set-Content -LiteralPath $ntdsPath -Value $ntdsSb.ToString() -Encoding UTF8
    if ($ntdsIssues -gt 0) {
        _Add-HFinding -Category 'NTDS Database' -Severity 'High' -Title 'NTDS database log volume low on free space' -Evidence "$ntdsIssues DC(s) with low free space on the database log volume" -Source $ntdsPath
        _Add-HTest -Title 'NTDS database' -Subtitle 'ntds.dit size and log volume free space' -Status 'Fail' -Detail "$ntdsIssues issue(s)" -EvidencePath $ntdsPath
    } else {
        _Add-HTest -Title 'NTDS database' -Subtitle 'ntds.dit size and log volume free space' -Status 'Pass' -Detail 'No low-space finding in collected evidence' -EvidencePath $ntdsPath
    }

    # ============================================================
    # 6) Time synchronization
    # ============================================================
    $timePath = Join-Path $rawDir 'health_time.txt'
    $timeSb   = New-Object System.Text.StringBuilder
    $timeIssues = 0
    $samples = @()
    foreach ($dc in $dcs) {
        $dcHost = $dc.HostName
        Write-ADAuditProgress -Activity 'AD Health' -Status "UTC clock sample: $dcHost" -PercentComplete 50
        try {
            # Bracket the remote call with local UTC readings and compare the remote clock
            # against the MIDPOINT of the local window. Comparing raw sequentially-sampled
            # clocks would fold collection round-trip latency (and time blocked on a slow/hung DC)
            # into the result and report it as false clock skew.
            $localBefore = [DateTime]::UtcNow
            $nowUtc = Get-ADAuditHostUtcTime -ComputerName $dcHost
            $localAfter = [DateTime]::UtcNow
            if (($localAfter - $localBefore).TotalSeconds -gt 30) { throw 'Clock sample collection took more than 30 seconds; timing uncertainty is too high.' }
            $localMid = $localBefore.AddTicks([long]((($localAfter - $localBefore).Ticks) / 2))
            $offset = ($nowUtc - $localMid).TotalSeconds
            $samples += [pscustomobject]@{ Host = $dcHost; Offset = $offset }
            [void]$timeSb.AppendLine(("{0} UTC: {1:o}  (offset vs auditor host: {2:N1} sec)" -f $dcHost, $nowUtc, $offset))
        } catch {
            [void]$timeSb.AppendLine("$dcHost UTC: unavailable ($($_.Exception.Message))")
            _HUnknown $timePath $dcHost $_.Exception.Message
        }
    }
    if ($samples.Count -ge 2) {
        for ($i = 0; $i -lt $samples.Count; $i++) {
            for ($j = $i + 1; $j -lt $samples.Count; $j++) {
                $skew = [math]::Abs($samples[$i].Offset - $samples[$j].Offset)
                [void]$timeSb.AppendLine(("Skew {0} <-> {1}: {2:N1} sec" -f $samples[$i].Host, $samples[$j].Host, $skew))
                if ($skew -gt 300) { $timeIssues++ }
            }
        }
    }
    if ($samples.Count -lt 2) { _HUnknown $timePath 'DC clock comparison' 'Fewer than two DC clock samples; pairwise clock agreement cannot be assessed.' }
    Set-Content -LiteralPath $timePath -Value $timeSb.ToString() -Encoding UTF8
    if ($timeIssues -gt 0) {
        _Add-HFinding -Category 'Time Sync' -Severity 'High' -Title 'DC clock skew greater than 5 minutes (Kerberos breaks)' -Evidence "Skewed pairs: $timeIssues" -Source $timePath
        _Add-HTest -Title 'Time synchronization' -Subtitle 'Pairwise skew between DCs (Kerberos breaks at >5 min skew)' -Status 'Fail' -Detail "$timeIssues skewed pair(s)" -EvidencePath $timePath
    } else {
        _Add-HTest -Title 'Time synchronization' -Subtitle 'Pairwise skew between DCs (Kerberos breaks at >5 min skew)' -Status 'Pass' -Detail 'No issues observed in collected evidence' -EvidencePath $timePath
    }

    # ============================================================
    # 7) Core AD services
    # KPSSVC (Kerberos Key Distribution Proxy / KDC Proxy) is OPTIONAL.
    # Many AD deployments leave it Stopped intentionally. We still record
    # its state but classify it as Information, not High/Critical.
    # ============================================================
    $svcPath = Join-Path $rawDir 'health_dc_services.txt'
    $svcSb   = New-Object System.Text.StringBuilder
    $svcCritical = @('NTDS','Netlogon','KDC','DFSR','ADWS','W32Time')
    $svcOptional = @('KPSSVC','DNS')
    $svcAllNames = $svcCritical + $svcOptional
    $svcCriticalIssues = 0
    $svcInfoIssues     = 0
    # One batched query per DC: an unavailable DC incurs one bounded attempt, not eight.
    $svcFilter = ($svcAllNames | ForEach-Object { "Name='$_'" }) -join ' OR '
    foreach ($dc in $dcs) {
        $dcHost = $dc.HostName
        [void]$svcSb.AppendLine("--- $dcHost ---")
        Write-ADAuditProgress -Activity 'AD Health' -Status "Services on $dcHost ($($svcAllNames.Count) services in one query)" -PercentComplete 58 -Force
        $svcRows = @()
        try { $svcRows = @(Get-ADAuditCimInstance -ClassName Win32_Service -ComputerName $dcHost -Filter $svcFilter -Property Name,State,StartMode -ErrorAction Stop) }
        catch {
            [void]$svcSb.AppendLine("  service query failed - $($_.Exception.Message)")
            foreach ($s in $svcAllNames) { _HUnknown $svcPath "$dcHost/$s" $_.Exception.Message }
            continue
        }
        $svcByName = @{}
        foreach ($row in $svcRows) { if ($row.Name) { $svcByName[([string]$row.Name).ToLowerInvariant()] = $row } }
        foreach ($s in $svcAllNames) {
            try {
                $svc = $svcByName[$s.ToLowerInvariant()]
                if (-not $svc) {
                    [void]$svcSb.AppendLine("  $s : NOT INSTALLED")
                    if ($s -in $svcCritical) {
                        # DFSR may be replaced by NTFRS on legacy domains; tolerate that case
                        if ($s -ne 'DFSR') {
                            $svcCriticalIssues++
                            _Add-HFinding -Category 'DC Services' -Severity 'High' -Title 'Required AD service missing' -Evidence "DC $dcHost service $s was not returned by a successful service query." -Source $svcPath
                        }
                    }
                    continue
                }
                $state = [string]$svc.State
                [void]$svcSb.AppendLine("  $s : $state")
                if ($state -ne 'Running') {
                    # DNS may be absent, but an installed DNS role must run.
                    if ($s -eq 'KPSSVC') {
                        $svcInfoIssues++
                        _Add-HFinding -Category 'DC Services' -Severity 'Info' -Title 'Optional AD service not running (informational)' -Evidence "DC $dcHost service $s state: $state - $s is optional and frequently left stopped." -Source $svcPath
                    } else {
                        $svcCriticalIssues++
                        _Add-HFinding -Category 'DC Services' -Severity 'High' -Title 'Critical AD service not running' -Evidence "DC $dcHost service $s state: $state" -Source $svcPath
                    }
                }
            } catch {
                [void]$svcSb.AppendLine("  $s : check failed - $($_.Exception.Message)")
                _HUnknown $svcPath "$dcHost/$s" $_.Exception.Message
            }
        }
    }
    Set-Content -LiteralPath $svcPath -Value $svcSb.ToString() -Encoding UTF8
    if ($svcCriticalIssues -gt 0) {
        _Add-HTest -Title 'Core AD services' -Subtitle 'NTDS, Netlogon, KDC, DNS, DFSR, ADWS, W32Time, KPSSVC' -Status 'Fail' -Detail "$svcCriticalIssues High" -EvidencePath $svcPath
    } elseif ($svcInfoIssues -gt 0) {
        _Add-HTest -Title 'Core AD services' -Subtitle 'NTDS, Netlogon, KDC, DNS, DFSR, ADWS, W32Time, KPSSVC' -Status 'Pass' -Detail 'No critical issues (KPSSVC info only)' -EvidencePath $svcPath
    } else {
        _Add-HTest -Title 'Core AD services' -Subtitle 'NTDS, Netlogon, KDC, DNS, DFSR, ADWS, W32Time, KPSSVC' -Status 'Pass' -Detail 'No issues observed in collected evidence' -EvidencePath $svcPath
    }

    # ============================================================
    # 8) Event log scrape (72h)
    # ============================================================
    $evtPath = Join-Path $rawDir 'health_events_72h.txt'
    $evtSb   = New-Object System.Text.StringBuilder
    $evtIssues = 0
    $evtQueryFailures = 0
    $badIds = @{
        'Directory Service' = 1311,1865,1925,1988,2042
        'DNS Server'        = 4000,4013,4015
        'DFS Replication'   = 5008,5014,5016,4012
        'System'            = 5774,5781,40961
    }
    $cutoff = (Get-Date).AddHours(-72)
    foreach ($dc in $dcs) {
        $dcHost = $dc.HostName
        [void]$evtSb.AppendLine("--- $dcHost ---")
        foreach ($logName in $badIds.Keys) {
            Write-ADAuditProgress -Activity 'AD Health' -Status "Event log $logName on $dcHost" -PercentComplete 67
            $ids = $badIds[$logName]
            try {
                $hits = @(Invoke-ADAuditEventLogQuery -ComputerName $dcHost -FilterHashtable @{ LogName = $logName; Id = $ids; StartTime = $cutoff } -Activity 'AD Health' -PercentComplete 67)
                if ($hits.Count -gt 0) {
                    [void]$evtSb.AppendLine("  ${logName}: $($hits.Count) bad event(s)")
                    $evtIssues += $hits.Count
                    foreach ($h in ($hits | Select-Object -First 5)) {
                        [void]$evtSb.AppendLine("    [$($h.Id)] $($h.TimeCreated) $($h.LevelDisplayName)")
                    }
                }
            } catch {
                # 'No events were found' is handled inside the bounded query; anything else
                # is a failed query, which must not be reported as a clean Pass.
                [void]$evtSb.AppendLine("  ${logName}: query failed - $($_.Exception.Message)")
                $evtQueryFailures++
                _HUnknown $evtPath "$dcHost/$logName" $_.Exception.Message
            }
        }
    }
    Set-Content -LiteralPath $evtPath -Value $evtSb.ToString() -Encoding UTF8
    if ($evtIssues -gt 0) {
        _Add-HFinding -Category 'Event Logs' -Severity 'Medium' -Title 'Known bad event IDs found in DC logs (last 72h)' -Evidence "Events: $evtIssues" -Source $evtPath
        _Add-HTest -Title 'Event log scrape (72h)' -Subtitle 'Directory Service / DNS / DFSR / System logs, known bad IDs' -Status 'Warn' -Detail "$evtIssues event(s)" -EvidencePath $evtPath
    } elseif ($evtQueryFailures -gt 0) {
        _Add-HTest -Title 'Event log scrape (72h)' -Subtitle 'Directory Service / DNS / DFSR / System logs, known bad IDs' -Status 'Warn' -Detail "$evtQueryFailures log query failure(s)" -EvidencePath $evtPath
    } else {
        _Add-HTest -Title 'Event log scrape (72h)' -Subtitle 'Directory Service / DNS / DFSR / System logs, known bad IDs' -Status 'Pass' -Detail 'No issues observed in collected evidence' -EvidencePath $evtPath
    }

    # ============================================================
    # 9) Sites and subnets
    # ============================================================
    $sitePath = Join-Path $rawDir 'health_sites_subnets.txt'
    Write-ADAuditProgress -Activity 'AD Health' -Status 'Site GC inventory' -PercentComplete 75
    $siteSb   = New-Object System.Text.StringBuilder
    $siteIssues = 0
    try {
        $sites = Get-ADReplicationSite -Filter * -ErrorAction Stop
        foreach ($site in $sites) {
            $gcs = $inventoryDcs | Where-Object { $_.IsGlobalCatalog -and $_.Site -eq $site.Name }
            if (-not $gcs) {
                [void]$siteSb.AppendLine("Site $($site.Name): NO GC present")
                $siteIssues++
            } else {
                [void]$siteSb.AppendLine("Site $($site.Name): $($gcs.Count) GC(s)")
            }
        }
    } catch { _HUnknown $sitePath 'Sites' $_.Exception.Message; [void]$siteSb.AppendLine("Site enumeration failed: $($_.Exception.Message)") }
    Set-Content -LiteralPath $sitePath -Value $siteSb.ToString() -Encoding UTF8
    if ($siteIssues -gt 0) {
        _Add-HFinding -Category 'Sites/Subnets' -Severity 'Medium' -Title 'Site without a Global Catalog' -Evidence "Sites lacking GC: $siteIssues" -Source $sitePath
        _Add-HTest -Title 'Site GC placement' -Subtitle 'Global Catalog placement; subnet mapping not assessed' -Status 'Warn' -Detail "$siteIssues site(s)" -EvidencePath $sitePath
    } else {
        _Add-HTest -Title 'Site GC placement' -Subtitle 'Global Catalog placement; subnet mapping not assessed' -Status 'Pass' -Detail 'No issues observed in collected evidence' -EvidencePath $sitePath
    }

    # ============================================================
    # 10) AD Recycle Bin
    # ============================================================
    $rbPath = Join-Path $rawDir 'health_recyclebin.txt'
    Write-ADAuditProgress -Activity 'AD Health' -Status 'Recycle Bin configuration' -PercentComplete 83
    $rbSb   = New-Object System.Text.StringBuilder
    $rbIssue = $false
    try {
        $forest = Get-ADForest -ErrorAction Stop
        $rbFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
        $enabled = $rbFeature -and ($rbFeature.EnabledScopes.Count -gt 0)
        [void]$rbSb.AppendLine("Forest: $($forest.Name)")
        [void]$rbSb.AppendLine("Recycle Bin enabled: $enabled")
        if (-not $enabled) { $rbIssue = $true }
    } catch {
        [void]$rbSb.AppendLine("Recycle Bin probe failed: $($_.Exception.Message)")
        _HUnknown $rbPath 'Recycle Bin' $_.Exception.Message
    }
    Set-Content -LiteralPath $rbPath -Value $rbSb.ToString() -Encoding UTF8
    if ($rbIssue) {
        _Add-HFinding -Category 'Recycle Bin' -Severity 'Low' -Title 'AD Recycle Bin not enabled' -Evidence 'Restoring deleted AD objects with full attributes will not be possible.' -Source $rbPath
        _Add-HTest -Title 'AD Recycle Bin' -Subtitle 'Forest Recycle Bin enablement' -Status 'Warn' -Detail '1 Low' -EvidencePath $rbPath
    } else {
        _Add-HTest -Title 'AD Recycle Bin' -Subtitle 'Forest Recycle Bin enablement' -Status 'Pass' -Detail 'No issues observed in collected evidence' -EvidencePath $rbPath
    }

    # ============================================================
    # 11) Group Hygiene
    # ============================================================
    $ghPath = Join-Path $rawDir 'health_group_hygiene.txt'
    Write-ADAuditProgress -Activity 'AD Health' -Status 'Group inventory' -PercentComplete 92
    $ghSb   = New-Object System.Text.StringBuilder
    $ghTotal = 0
    $ghEmpty = 0
    $ghBuiltinPg = 0
    [void]$ghSb.AppendLine('Group Hygiene')
    # Stamp real UTC (the previous 'Z' suffix was a literal on a LOCAL-time value).
    [void]$ghSb.AppendLine(("Generated: {0} UTC" -f ((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))))
    [void]$ghSb.AppendLine('-' * 70)
    try {
        $groups = Get-ADGroup -Filter * -Properties members,primaryGroupToken -ErrorAction Stop
        $builtinPgIds = @(513,514,515,516,517,518,519,520,521,522,553,571,572)
        foreach ($g in $groups) {
            $ghTotal++
            $isBuiltinPg = ($g.primaryGroupToken -and ($builtinPgIds -contains [int]$g.primaryGroupToken))
            if ($isBuiltinPg) { $ghBuiltinPg++; continue }
            if (-not $g.members -or $g.members.Count -eq 0) { $ghEmpty++ }
        }
        [void]$ghSb.AppendLine("Total groups: $ghTotal | Empty: $ghEmpty | Excluded built-in primaryGroupID-backed: $ghBuiltinPg")
    } catch {
        [void]$ghSb.AppendLine("Group enumeration failed: $($_.Exception.Message)")
        _HUnknown $ghPath 'Groups' $_.Exception.Message
    }
    Set-Content -LiteralPath $ghPath -Value $ghSb.ToString() -Encoding UTF8
    if ($ghEmpty -gt 0) {
        $sev = if ($ghEmpty -gt 100) { 'Medium' } else { 'Low' }
        _Add-HFinding -Category 'Group Hygiene' -Severity $sev -Title 'Empty groups for lifecycle review' -Evidence "Total groups: $ghTotal | Empty: $ghEmpty | Excluded built-in primaryGroupID-backed: $ghBuiltinPg" -Source $ghPath
        _Add-HTest -Title 'Group hygiene' -Subtitle 'Empty groups, primaryGroupID-backed exclusion' -Status 'Warn' -Detail "$ghEmpty empty" -EvidencePath $ghPath
    } else {
        _Add-HTest -Title 'Group hygiene' -Subtitle 'Empty groups, primaryGroupID-backed exclusion' -Status 'Pass' -Detail 'No empty groups' -EvidencePath $ghPath
    }

    # ============================================================
    # Build AD_Health.html
    # ============================================================
    $htmlPath = Join-Path $htmlDir 'AD_Health.html'
    if ($findings.Count -gt 0) {
        $findings | Export-Csv -LiteralPath (Join-Path $rawDir 'health_findings.csv') -NoTypeInformation -Encoding UTF8
    } else {
        '"Category","Severity","Title","Evidence","Score","Source"' | Set-Content -LiteralPath (Join-Path $rawDir 'health_findings.csv') -Encoding UTF8
    }
    $tests | Export-Csv -LiteralPath (Join-Path $rawDir 'health_tests.csv') -NoTypeInformation -Encoding UTF8
    Write-ADHealthReport -OutputPath $htmlPath -Findings $findings -Tests $tests -Domain $domain -RunBy $runBy
    Write-ADAuditProgress -Activity 'AD Health' -Status 'Health evidence written' -PercentComplete 100 -Completed
    Write-Both "    [+] AD Health report saved to HTML Reports\AD_Health.html"
}

Function Write-ADHealthReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Findings,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Tests,
        [string]$Domain,
        [string]$RunBy
    )

    function _HEnc([string]$s) {
        if ($null -eq $s) { return '' }
        return [System.Net.WebUtility]::HtmlEncode($s)
    }

    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Counts (excluding Information per the existing AD_Health design)
    $cCrit = ($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $cHigh = ($Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $cMed  = ($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $cLow  = ($Findings | Where-Object { $_.Severity -eq 'Low' }).Count
    $totalFindings = $cCrit + $cHigh + $cMed + $cLow

    $score = (25 * $cCrit) + (12 * $cHigh) + (5 * $cMed) + (1 * $cLow)
    if ($score -gt 100) { $score = 100 }
    $totalScore = 100 - $score   # higher is better display
    $incompleteTests = @($Tests | Where-Object { $_.Status -in @('Partial','NotAssessed','Skipped','NotRun') -or $_.NotAssessedCount -gt 0 }).Count
    if ($incompleteTests -gt 0 -or $Tests.Count -eq 0) { $totalScore = 'N/A' }

    $bandLabel = 'Healthy'
    $bandColor = '#2e7d32'
    $bandText  = 'No operational findings in the collected evidence.'
    if ($cCrit -gt 0) {
        $bandLabel = 'Critical'; $bandColor = '#c62828'; $bandText = 'Critical issues detected - act now.'
    } elseif ($cHigh -gt 0 -or $score -ge 60) {
        $bandLabel = 'High'; $bandColor = '#ea580c'; $bandText = 'High-priority issues - prioritize remediation.'
    } elseif ($cMed -gt 0 -or $score -ge 25) {
        $bandLabel = 'Medium'; $bandColor = '#d97706'; $bandText = 'Some configuration drift or operational warnings - plan remediation.'
    } elseif ($cLow -gt 0) {
        $bandLabel = 'Low'; $bandColor = '#65a30d'; $bandText = 'Minor advisories only - address during routine maintenance.'
    }
    if ($incompleteTests -gt 0 -or $Tests.Count -eq 0) {
        if ($totalFindings -eq 0) { $bandLabel = 'Incomplete'; $bandColor = '#64748b' }
        $bandText += " Assessment incomplete: $incompleteTests test(s) have collection gaps. Unchecked targets are unknown, not healthy."
    }

    # Needle angle: 0=healthy (left), 100=critical (right)
    # Half-circle gauge: angle from 180deg (left) -> 0deg (right), pivot at (200,180), radius ~100
    $angleDeg = 180 - ([double]$score * 1.8)   # 180 -> 0 across 100
    $rad = ($angleDeg * [math]::PI / 180)
    $needleX = 200 + (100 * [math]::Cos($rad))
    $needleY = 180 - (100 * [math]::Sin($rad))
    # SVG coordinates MUST use '.' as the decimal separator. Using '-f' or
    # ToString() without a CultureInfo would emit a comma on Swedish/German/
    # French/etc. locales and the browser would parse it as a number list,
    # drawing the needle to (0,0) - which looks like a gigantic stray line.
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $nxStr = $needleX.ToString('F2', $invariant)
    $nyStr = $needleY.ToString('F2', $invariant)
    $gaugeScore = $score
    $gaugeNeedle = "<line class='hg-needle' x1='200' y1='180' x2='$nxStr' y2='$nyStr'/><circle class='hg-hub' cx='200' cy='180' r='9'/>"
    if ($incompleteTests -gt 0 -or $Tests.Count -eq 0) { $gaugeScore = 'N/A'; $gaugeNeedle = '' }

    # Pass/Warn/Fail counts
    $tPass = ($Tests | Where-Object { $_.Status -eq 'Pass' }).Count
    $tWarn = ($Tests | Where-Object { $_.Status -eq 'Warn' }).Count
    $tFail = ($Tests | Where-Object { $_.Status -eq 'Fail' }).Count
    $tSkip = ($Tests | Where-Object { $_.Status -eq 'Skipped' }).Count
    $tNone = ($Tests | Where-Object { $_.Status -eq 'NotRun' }).Count
    $tPartial = ($Tests | Where-Object { $_.Status -in @('Partial','NotAssessed') }).Count
    $tTotal = $Tests.Count

    $css = Get-ADAuditReportCss
    $nav = Get-ADAuditPrimaryNav -Active 'health'
    $cloneNotice = Get-ADAuditCloneNotice

    $themeBlock = @'
<style>
html[data-theme="dark"] {
  --bg:#0f172a; --panel:#1e293b; --text:#e2e8f0; --muted:#94a3b8;
  --line:#334155; --shadow:0 10px 24px rgba(0,0,0,.4);
  --accent:#60a5fa; --accent-soft:rgba(96,165,250,.15);
  --critical:#f87171; --critical-soft:rgba(248,113,113,.15);
  --high:#fb923c;    --high-soft:rgba(251,146,60,.15);
  --medium:#60a5fa;  --medium-soft:rgba(96,165,250,.15);
  --low:#4ade80;     --low-soft:rgba(74,222,128,.15);
  --info:#94a3b8;    --info-soft:rgba(148,163,184,.15);
}
html[data-theme="light"] {
  --bg:#f5f7fb; --panel:#ffffff; --text:#1b2430; --muted:#5f6b7a;
  --line:#d9e0ea; --shadow:0 10px 24px rgba(15,23,42,.08);
  --accent:#3b82f6; --accent-soft:#dbeafe;
  --critical:#c62828; --critical-soft:#fdecec;
  --high:#ef6c00;    --high-soft:#fff2e5;
  --medium:#0277bd;  --medium-soft:#e8f4fd;
  --low:#2e7d32;     --low-soft:#edf8ee;
  --info:#6c757d;    --info-soft:#f2f4f6;
}
.theme-toggle{position:fixed;top:18px;right:18px;z-index:100;border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:999px;padding:8px 14px;font-size:13px;font-weight:700;cursor:pointer;box-shadow:var(--shadow)}
.theme-toggle:hover{filter:brightness(1.05)}
</style>
<button id="adAuditThemeToggle" type="button" class="theme-toggle" aria-pressed="false">Toggle theme</button>
<script>
(function(){
  function currentTheme(){
    var s=null; try { s=localStorage.getItem('adaudit-theme'); } catch(_){}
    if (s==='light'||s==='dark') return s;
    return (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
  }
  function applyTheme(t){
    document.documentElement.setAttribute('data-theme', t);
    var b = document.getElementById('adAuditThemeToggle');
    if (b){ b.innerText = (t==='dark') ? 'Light mode' : 'Dark mode'; b.setAttribute('aria-pressed',(t==='dark')?'true':'false'); }
  }
  function setTheme(t){ applyTheme(t); try { localStorage.setItem('adaudit-theme', t); } catch(_){} }
  document.addEventListener('DOMContentLoaded', function(){
    applyTheme(currentTheme());
    var b = document.getElementById('adAuditThemeToggle');
    if (b){ b.addEventListener('click', function(){ setTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark'); }); }
    if (window.matchMedia){
      var mq = window.matchMedia('(prefers-color-scheme: dark)');
      var h = function(e){ var s=null; try { s=localStorage.getItem('adaudit-theme'); } catch(_){} if (s!=='light' && s!=='dark') applyTheme(e.matches?'dark':'light'); };
      if (mq.addEventListener) mq.addEventListener('change', h); else if (mq.addListener) mq.addListener(h);
    }
  });
})();
</script>
'@

    $scriptVer = if ($versionnum) { $versionnum } else { 'unknown' }
    $heroHtml = @"
<div class='hero'><h1>AD Health Report</h1>
<div class='meta'>Domain: <code>$(_HEnc $Domain)</code> &mdash; Script: <code>$(_HEnc $scriptVer)</code> &mdash; Run by: <code>$(_HEnc $RunBy)</code> &mdash; Generated: $now</div>
<p style='margin-top:14px'>Replication, DC diagnostics, SYSVOL/DFSR, NTDS database, time synchronization, service state, event-log scrape, sites &amp; subnets, AD Recycle Bin posture, and group hygiene.</p>
</div>
"@

    $gaugeCss = @'
<style>
.hg-card{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:28px 28px 24px;box-shadow:var(--shadow);margin:0 0 22px;display:grid;grid-template-columns:minmax(280px,420px) 1fr;gap:32px;align-items:center}
@media (max-width:820px){.hg-card{grid-template-columns:1fr;gap:14px}}
.hg-svg{display:block;width:100%;max-width:440px;margin:0 auto}
.hg-arc{fill:none;stroke-width:30;stroke-linecap:round}
.hg-track{stroke:rgba(125,125,125,.14)}
.hg-needle{stroke:var(--text);stroke-width:5;stroke-linecap:round;filter:drop-shadow(0 2px 4px rgba(0,0,0,.25))}
.hg-hub{fill:var(--text)}
.hg-tick{font:600 11.5px 'Segoe UI',system-ui,sans-serif;fill:var(--muted);letter-spacing:.04em}
.hg-score{font:800 56px 'Segoe UI',system-ui,sans-serif;fill:var(--text);text-anchor:middle}
.hg-suffix{font:600 14px 'Segoe UI',system-ui,sans-serif;fill:var(--muted);text-anchor:middle;letter-spacing:.06em}
.hg-summary h3{margin:0 0 4px;font-size:1.7rem;letter-spacing:.02em}
.hg-summary .hg-stat{font:700 12px 'Segoe UI';color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px}
.hg-summary p{color:var(--muted);margin:0 0 14px;line-height:1.55;font-size:.95rem}
.hg-counts{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:6px}
.hg-counts > div{padding:12px 10px;border-radius:12px;text-align:center;border:1px solid var(--line)}
.hg-counts .num{display:block;font:800 22px 'Segoe UI',system-ui,sans-serif;line-height:1.1}
.hg-counts .lbl{display:block;margin-top:4px;font:700 10px 'Segoe UI',system-ui,sans-serif;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}
.hg-formula{margin-top:14px;font-size:.78rem;color:var(--muted);line-height:1.45;border-top:1px solid var(--line);padding-top:10px}
.hg-formula code{background:rgba(125,125,125,.1);padding:1px 5px;border-radius:4px;font-size:.85em}
</style>
'@

    $gaugeHtml = @"
<div class='hg-card'>
  <svg viewBox='0 0 400 220' class='hg-svg' xmlns='http://www.w3.org/2000/svg' role='img' aria-label='AD health risk gauge'>
    <defs>
      <linearGradient id='hg-grad' x1='0%' y1='0%' x2='100%' y2='0%'>
        <stop offset='0%'   stop-color='#16a34a'/>
        <stop offset='30%'  stop-color='#a3e635'/>
        <stop offset='55%'  stop-color='#facc15'/>
        <stop offset='80%'  stop-color='#f97316'/>
        <stop offset='100%' stop-color='#dc2626'/>
      </linearGradient>
    </defs>
    <path class='hg-arc hg-track' d='M 70 180 A 130 130 0 0 1 330 180'/>
    <path class='hg-arc' d='M 70 180 A 130 130 0 0 1 330 180' stroke='url(#hg-grad)'/>
    <text class='hg-tick' x='42'  y='205' text-anchor='middle'>0</text>
    <text class='hg-tick' x='200' y='34'  text-anchor='middle'>50</text>
    <text class='hg-tick' x='358' y='205' text-anchor='middle'>100</text>
    $gaugeNeedle
    <text class='hg-score'  x='200' y='148'>$gaugeScore</text>
    <text class='hg-suffix' x='200' y='168'>RISK / 100</text>
  </svg>
  <div class='hg-summary'>
    <div class='hg-stat'>Overall AD Health Risk</div>
    <h3 style='color:$bandColor'>$bandLabel</h3>
    <p>$bandText</p>
    <div class='hg-counts'>
      <div style='background:rgba(220,38,38,.08)'><span class='num' style='color:#dc2626'>$cCrit</span><span class='lbl'>Critical</span></div>
      <div style='background:rgba(234,88,12,.08)'><span class='num' style='color:#ea580c'>$cHigh</span><span class='lbl'>High</span></div>
      <div style='background:rgba(217,119,6,.08)'><span class='num' style='color:#d97706'>$cMed</span><span class='lbl'>Medium</span></div>
      <div style='background:rgba(101,163,13,.08)'><span class='num' style='color:#65a30d'>$cLow</span><span class='lbl'>Low</span></div>
    </div>
    <div class='hg-formula'>
      Index = <code>min(100, 25*Critical + 12*High + 5*Medium + 1*Low)</code>. Information findings are excluded; the index is unavailable when collection is incomplete. The headline reflects the highest finding severity as well as the index.
    </div>
  </div>
</div>
"@

    $testCss = @'
<style>
.ht-card{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:24px 24px 22px;box-shadow:var(--shadow);margin:0 0 24px}
.ht-card h2{margin:0 0 14px;font-size:1.2rem}
.ht-summary{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 18px;font-size:.85rem}
.ht-summary > span{padding:6px 13px;border-radius:999px;font-weight:700;letter-spacing:.02em}
.ht-grid{display:grid;gap:8px}
.ht-row{display:grid;grid-template-columns:36px 1fr auto;gap:12px;padding:14px 16px;border-radius:12px;border:1px solid var(--line);align-items:center}
.ht-icon{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:8px;color:#fff;font-weight:800;font-size:13px;font-family:Consolas,monospace}
.ht-text .ht-title{font-weight:700;font-size:.96rem}
.ht-text .ht-sub{font-size:.82rem;color:var(--muted);margin-top:2px;line-height:1.4}
.ht-detail{font-weight:700;font-size:.85rem;text-align:right}
.ht-fail{border-left:4px solid #dc2626}      .ht-fail    .ht-detail{color:#dc2626}
.ht-warn{border-left:4px solid #d97706}      .ht-warn    .ht-detail{color:#d97706}
.ht-pass{border-left:4px solid #16a34a}      .ht-pass    .ht-detail{color:#16a34a}
.ht-skipped{border-left:4px solid #6b7280}   .ht-skipped .ht-detail{color:#6b7280}
.ht-notrun{border-left:4px solid #9ca3af;opacity:.6}  .ht-notrun .ht-detail{color:#9ca3af}
</style>
'@

    $testRowsSb = New-Object System.Text.StringBuilder
    foreach ($t in $Tests) {
        $cls = switch ($t.Status) {
            'Fail'    { 'ht-fail';    break }
            'Warn'    { 'ht-warn';    break }
            'Pass'    { 'ht-pass';    break }
            'Partial' { 'ht-skipped'; break }
            'Skipped' { 'ht-skipped'; break }
            default   { 'ht-notrun' }
        }
        $iconBg = switch ($t.Status) {
            'Fail'    { '#dc2626'; break }
            'Warn'    { '#d97706'; break }
            'Pass'    { '#16a34a'; break }
            'Skipped' { '#6b7280'; break }
            default   { '#9ca3af' }
        }
        $iconText = switch ($t.Status) {
            'Fail'    { 'X';  break }
            'Warn'    { '!';  break }
            'Pass'    { 'OK'; break }
            'Skipped' { '-';  break }
            default   { '?' }
        }
        [void]$testRowsSb.AppendLine(@"
<div class='ht-row $cls'>
  <span class='ht-icon' style='background:$iconBg'>$iconText</span>
  <div class='ht-text'>
    <div class='ht-title'>$(_HEnc $t.Title)</div>
    <div class='ht-sub'>$(_HEnc $t.Subtitle)</div>
  </div>
  <div class='ht-detail'>$(_HEnc $t.Detail)</div>
</div>
"@)
    }

    $testHtml = @"
<div class='ht-card'>
  <h2>Tests Performed ($tTotal total)</h2>
  <div class='ht-summary'>
    <span style='background:rgba(22,163,74,.15);color:#16a34a'>$tPass Pass</span>
    <span style='background:rgba(217,119,6,.15);color:#d97706'>$tWarn Warning</span>
    <span style='background:rgba(220,38,38,.15);color:#dc2626'>$tFail Fail</span>
    <span style='background:rgba(107,114,128,.15);color:#6b7280'>$tSkip Skipped</span>
    <span style='background:rgba(156,163,175,.15);color:#9ca3af'>$tNone Not run</span>
    <span style='background:rgba(107,114,128,.15);color:#64748b'>$tPartial Incomplete</span>
  </div>
  <div class='ht-grid'>
$($testRowsSb.ToString())
  </div>
</div>
"@

    $statsHtml = @"
<div class='stats'>
<div class='stat'><div class='val'>$totalFindings</div><div class='lbl'>Findings</div></div>
<div class='stat'><div class='val'>$totalScore</div><div class='lbl'>Total Score</div></div>
<div class='stat'><div class='val'><span class='badge badge-high'>$cHigh</span></div><div class='lbl'>High</div></div>
<div class='stat'><div class='val'><span class='badge badge-medium'>$cMed</span></div><div class='lbl'>Medium</div></div>
<div class='stat'><div class='val'><span class='badge badge-low'>$cLow</span></div><div class='lbl'>Low</div></div>
</div>
"@

    # Helper: best-effort relative href from the HTML output back to the
    # evidence file under Raw Data\Source. Falls back to the leaf file name
    # if the UriBuilder math fails (e.g., different drive letters).
    function _RelHref([string]$AbsSourcePath) {
        if ([string]::IsNullOrWhiteSpace($AbsSourcePath)) { return '' }
        try {
            $htmlAbs = [System.IO.Path]::GetFullPath((Split-Path -Path $OutputPath -Parent))
            $srcAbs  = [System.IO.Path]::GetFullPath($AbsSourcePath)
            $baseUri = New-Object System.Uri(($htmlAbs.TrimEnd('\') + '\'))
            $tgtUri  = New-Object System.Uri($srcAbs)
            return ([System.Uri]::UnescapeDataString($baseUri.MakeRelativeUri($tgtUri).ToString()) -replace '\\','/')
        } catch {
            return (Split-Path -Path $AbsSourcePath -Leaf)
        }
    }

    # Findings tables grouped by Category
    $findingsSb = New-Object System.Text.StringBuilder
    $byCategory = $Findings | Where-Object { $_.Severity -ne 'Info' } | Group-Object -Property Category
    foreach ($grp in $byCategory) {
        [void]$findingsSb.AppendLine("<h2>$(_HEnc $grp.Name) ($($grp.Count))</h2>")
        [void]$findingsSb.AppendLine("<table><thead><tr><th>Severity</th><th>Title</th><th>Evidence</th><th>Score</th><th>Source</th></tr></thead><tbody>")
        foreach ($f in $grp.Group) {
            $sevClass = ($f.Severity).ToLower()
            $relSrc = _RelHref $f.Source
            [void]$findingsSb.AppendLine("<tr><td><span class='badge badge-$sevClass'>$(_HEnc $f.Severity)</span></td><td>$(_HEnc $f.Title)</td><td>$(_HEnc $f.Evidence)</td><td>$($f.Score)</td><td><a href='$(_HEnc $relSrc)'>open</a></td></tr>")
        }
        [void]$findingsSb.AppendLine("</tbody></table>")
    }

    # ---------------------------------------------------------------
    # Test Details: per-test card with summary, why-it-matters,
    # what-to-look-for, how-to-fix, source link and rerun command.
    # Lives at the bottom of the report so the at-a-glance grid above
    # stays uncluttered. Each card is a collapsible <details> block.
    # ---------------------------------------------------------------
    $testMeta = @{
        'Replication health' = @{
            Summary    = 'Probes AD replication state across all DCs using repadmin: a /replsummary roll-up, /showrepl per-DC failures, queue depth, and a lingering-object advisory pass.'
            WhyMatters = 'Replication failures cause directory drift between DCs. Clients can authenticate against an out-of-date copy, recent password changes appear lost, and lingering objects keep pointing at decommissioned trust paths.'
            LookFor    = 'In the evidence file, look for a non-zero "fails" column under repadmin /replsummary, /showrepl entries with errors, queue depth > 0, or DCs that simply did not respond.'
            HowToFix   = 'Confirm DNS/RPC reachability between DCs. Force convergence with `repadmin /syncall /AdePq`. Drill into per-DC failures with `repadmin /showrepl /errorsonly`. If lingering objects are confirmed, run `repadmin /removelingeringobjects` from a clean reference DC.'
            RerunCmd   = 'repadmin /replsummary; repadmin /showrepl /errorsonly; repadmin /queue'
        }
        'DC interconnect' = @{
            Summary    = 'Verifies every DC in the domain is actually reachable on the network from this host. For each DC: DNS A-record, TCP 389 (LDAP), TCP 445 (SMB), and last successful replication time via Get-ADReplicationPartnerMetadata.'
            WhyMatters = 'These probes establish reachability only from the auditing host. Management network segmentation may intentionally block them. Replication health must be established from partner metadata, replication diagnostics and the actual DC-to-DC paths.'
            LookFor    = 'In the evidence file, look at the "Isolated: True" lines and the "Replication fresh" column. An isolated DC has both LDAP and SMB unreachable. A reachable DC with stale replication (LastReplicationSuccess > 1 day) is also a problem, just a different one.'
            HowToFix   = 'Validate the expected management-host and DC-to-DC paths with the AD and network owners. Inspect replication diagnostics on a reachable DC. Do not demote a DC, clean metadata or seize roles solely because an audit-host TCP probe failed.'
            RerunCmd   = 'foreach ($dc in (Get-ADDomainController -Filter *)) { [pscustomobject]@{ DC=$dc.HostName; LDAP=(Test-NetConnection $dc.HostName -Port 389 -InformationLevel Quiet); SMB=(Test-NetConnection $dc.HostName -Port 445 -InformationLevel Quiet) } }'
        }
        'DC diagnostics (dcdiag)' = @{
            Summary    = 'Runs the dcdiag test suite (Services, Replications, Advertising, FsmoCheck, KCCEvent, NetLogons, SysVolCheck, RidManager, DFSREvent, Intersite) against every DC.'
            WhyMatters = 'dcdiag exposes operational issues that are invisible at the directory level - missing SRV records, NetLogon stopped, FSMO unreachable, KCC errors, advertising failures.'
            LookFor    = 'In the evidence file, search for `failed test` lines. The DC name is on the line above; the test name is on the failed-test line.'
            HowToFix   = 'Each test has its own remediation. Common patterns: missing SRV records (re-register with `nltest /dsregdns`), Netlogon/Kdc stopped (`Start-Service Netlogon,Kdc`), FSMO holder offline (transfer or seize roles), DNS not resolving the DC FQDN, or > 5 min time skew (see Time synchronization).'
            RerunCmd   = 'dcdiag /v /s:<DC-FQDN> /test:Replications /test:Advertising /test:FsmoCheck /test:NetLogons /test:SysVolCheck'
        }
        'SYSVOL / DFSR availability' = @{
            Summary    = 'Verifies the SYSVOL share is reachable on each DC and the DFSR service state where present. This check does not measure backlog or file consistency.'
            WhyMatters = 'SYSVOL hosts every GPO and login script. If DFSR stops or backlog builds, GPO content drifts between DCs - clients get inconsistent policy depending on which DC they bind to.'
            LookFor    = "In the evidence file: 'SYSVOL share NOT reachable' lines, DFSR service state != Running, or NTFRS service in use on a domain that should have migrated."
            HowToFix   = 'Start DFSR (`Start-Service DFSR`). Inspect backlog cross-DC: `dfsrdiag backlog /sm:<source> /rm:<receiving> /rfn:"SYSVOL Share"`. Compare DFS Replication event log on each DC. If migration from FRS is incomplete, complete it before further changes.'
            RerunCmd   = 'Get-Service DFSR -ComputerName <DC>; dfsrdiag backlog /sm:<source-DC> /rm:<receiving-DC> /rfn:"SYSVOL Share"'
        }
        'FSMO role holders' = @{
            Summary    = 'Inventories the five operations-master (FSMO) role holders - SchemaMaster and DomainNamingMaster (forest-wide) plus PDCEmulator, RIDMaster and InfrastructureMaster (per domain) - then validates each holder: is it a real writable DC (not an RODC), does it resolve in DNS, is it reachable on LDAP 389 and ADWS 9389, is it still replicating, and (forest-root PDC) does it have an authoritative external time source. Co-location of roles on one DC is reported as informational only.'
            WhyMatters = 'Each FSMO role is single-owner - only one DC performs that operation at a time. If a holder is offline, decommissioned-but-not-transferred, an RODC, unresolvable or not replicating, the dependent operations silently fail: the PDC emulator drives password changes, account lockouts, GPO editing and forest time; the RID master hands out SID pools (no new users/computers once a DC exhausts its pool); Schema and Domain Naming gate schema edits and domain/partition changes. Co-locating roles on one DC (e.g. RID + PDC) is a normal, supported layout, so this check never fails on co-location alone.'
            LookFor    = "In the evidence file (health_fsmo.txt): the 'Current FSMO holders' inventory, then per-holder lines such as 'DC object found: False', 'Read-only (RODC): True', 'DNS resolves: False', 'LDAP TCP 389: False' or 'Replication fresh: False', plus the forest-root PDC time-source assessment."
            HowToFix   = 'For a missing/orphaned or RODC holder, transfer the role to a healthy writable DC: `Move-ADDirectoryServerOperationMasterRole -Identity <DC> -OperationMasterRole <role>` (add `-Force` to SEIZE only when the old holder is permanently gone, then never bring it back online). Restore DNS/LDAP reachability for unreachable holders, fix replication first for non-replicating holders, and point the forest-root PDC at an external NTP source: `w32tm /config /manualpeerlist:"time.windows.com,0x9" /syncfromflags:manual /reliable:yes /update; Restart-Service W32Time`.'
            RerunCmd   = 'netdom query fsmo; Get-ADForest | Select-Object SchemaMaster,DomainNamingMaster; Get-ADDomain | Select-Object PDCEmulator,RIDMaster,InfrastructureMaster'
        }
        'NTDS database' = @{
            Summary    = 'Reads the NTDS registry parameters and measures ntds.dit size plus free space on the database log volume.'
            WhyMatters = 'A full log volume halts AD writes - clients cannot authenticate, Group Policy cannot apply, and replication backs up. ntds.dit growth past expected baselines is also an early signal of an unbounded object explosion.'
            LookFor    = 'In the evidence file: log-volume free space below 1 GB, or ntds.dit size that has grown unexpectedly between runs.'
            HowToFix   = 'Free space on the log volume (clear stale logs from other apps, expand the volume) or move the database log path to a larger volume after a maintenance window. Schedule offline defrag (`ntdsutil "activate instance ntds" "files" "compact to <path>"`) only during planned downtime.'
            RerunCmd   = '.\AdAudit-PS7.ps1 -adhealth  # local reads on the DC; CIM/DCOM for remote storage'
        }
        'Time synchronization' = @{
            Summary    = 'Compares wall-clock UTC across all DCs and reports any pair drifted more than 5 minutes.'
            WhyMatters = 'Kerberos ticket validation requires < 5 min skew between client and KDC. Once a DC drifts past that window, clients silently fail to authenticate and authentication failures get blamed on credentials.'
            LookFor    = 'In the evidence file: "Skew ... > 300 sec" lines and DCs that returned "unavailable". Remote clock samples use CIM/DCOM; missing samples do not establish clock drift.'
            HowToFix   = 'On the PDC emulator, point W32Time at an external authoritative source: `w32tm /config /manualpeerlist:"time.windows.com,0x9" /syncfromflags:manual /reliable:yes /update; Restart-Service W32Time`. On other DCs, force resync: `w32tm /resync /rediscover`.'
            RerunCmd   = '.\AdAudit-PS7.ps1 -adhealth  # local UTC or the Win32_UTCTime provider over CIM/DCOM'
        }
        'Core AD services' = @{
            Summary    = 'Verifies NTDS, Netlogon, KDC, DNS, DFSR, ADWS, W32Time and KPSSVC on every DC. KPSSVC is reported as informational only - it is optional and frequently left stopped on purpose.'
            WhyMatters = 'Each service maps to a discrete capability: NTDS = directory engine, Netlogon = domain auth + secure channels, KDC = Kerberos issuer, DNS = name resolution that AD itself depends on, DFSR = SYSVOL replication, ADWS = PowerShell/RSAT module endpoint, W32Time = Kerberos clock.'
            LookFor    = "In the evidence file: lines that read '`<service>` : Stopped' or '`<service>` : NOT INSTALLED' (DFSR vs NTFRS migration is OK; missing NTDS/Netlogon/KDC/ADWS needs investigation; DNS is an optional role)."
            HowToFix   = 'Start the failed service: `Start-Service <Name> -ComputerName <DC>`. If it will not stay running, check the System and Directory Service event logs on that DC for the underlying error. KPSSVC stopped is expected unless you are intentionally publishing the KDC Proxy.'
            RerunCmd   = "Get-Service NTDS,Netlogon,KDC,DNS,DFSR,ADWS,W32Time,KPSSVC -ComputerName <DC>"
        }
        'Event log scrape (72h)' = @{
            Summary    = 'Pulls events from each DC across Directory Service, DNS Server, DFS Replication and System logs, filtering for known-bad IDs in the last 72 hours.'
            WhyMatters = 'The event log is usually the first place a problem surfaces. Recurring 1311/1865/1925 in Directory Service, 4000/4013/4015 in DNS, 5008/5014/5016 in DFSR or 5774/5781/40961 in System point at replication/auth issues that have not yet broken in the foreground.'
            LookFor    = 'In the evidence file: each DC section lists the IDs hit and a sample (first 5) with timestamps. Cross-reference each ID against Microsoft documentation for the exact root cause.'
            HowToFix   = 'Resolution depends on the ID. 5774/5781 = SRV/A record registration broken (`nltest /dsregdns`), 1311 = KCC routing problem (review site links), 4015 = DNS service-side error (often AD-integrated zone replication), 40961 = LSASS could not establish secure channel (Netlogon / DNS).'
            RerunCmd   = "Get-WinEvent -ComputerName <DC> -FilterHashtable @{ LogName='Directory Service','DNS Server','DFS Replication','System'; Id=1311,1865,1925,4000,4013,4015,5008,5014,5016,5774,5781,40961; StartTime=(Get-Date).AddHours(-72) }"
        }
        'Site GC placement' = @{
            Summary    = 'Walks every AD replication site and confirms at least one Global Catalog DC is present. Sites without a GC are flagged.'
            WhyMatters = 'Universal-group expansion at logon, cross-domain searches and Exchange/Outlook lookups all require a GC. Without a local GC, that traffic falls back across site links and adds latency to every authentication.'
            LookFor    = 'In the evidence file: lines that read "Site `<name>`: NO GC present". Cross-check with subnet coverage (NETLOGON.log on a DC tells you which subnets have no site mapping).'
            HowToFix   = 'Review local GC requirements, universal group membership caching and connectivity to other sites. Where a local GC is required, enable Global Catalog on the NTDS Settings object in Active Directory Sites and Services and verify replication.'
            RerunCmd   = 'Get-ADReplicationSite -Filter * | ForEach-Object { [pscustomobject]@{ Site = $_.Name; GCs = (Get-ADDomainController -Filter * | Where-Object { $_.IsGlobalCatalog -and $_.Site -eq $_.Name }).Count } }'
        }
        'AD Recycle Bin' = @{
            Summary    = 'Checks the forest-wide "Recycle Bin Feature" optional feature is enabled.'
            WhyMatters = 'Without the Recycle Bin, deleted users/groups/computers lose their attributes and group memberships at deletion. Restoring them later means rebuilding by hand instead of `Restore-ADObject`. The feature is irreversible once enabled.'
            LookFor    = "In the evidence file: 'Recycle Bin enabled: False'."
            HowToFix   = '`Enable-ADOptionalFeature -Identity ''Recycle Bin Feature'' -Scope ForestOrConfigurationSet -Target <forest-DNS>` from a Schema/Enterprise Admin context. Once enabled, the feature CANNOT be disabled.'
            RerunCmd   = "Get-ADOptionalFeature -Filter `"Name -eq 'Recycle Bin Feature'`""
        }
        'Group hygiene' = @{
            Summary    = 'Counts AD security/distribution groups, the subset that are empty (no direct members) and excludes the well-known built-in groups whose membership is normally driven by primaryGroupID instead of `member` (e.g., Domain Users, Domain Computers, Domain Controllers).'
            WhyMatters = 'Empty groups are noise in admin tooling and audits. They make it easy to miss a real assignment, complicate access reviews, and keep accruing pointless ACL bindings as years go by.'
            LookFor    = 'In the evidence file: the "Total groups: ... | Empty: ... | Excluded built-in primaryGroupID-backed: ..." line. A high empty count relative to total suggests stale legacy groups left behind.'
            HowToFix   = 'Review the empty groups, document any that are kept-empty-by-design (placeholders for delegation), and remove the rest. PowerShell sketch: `Get-ADGroup -Filter * -Properties members | Where-Object { -not $_.members -and $_.SID -notmatch ''-(513|514|515|516|521)$'' }`.'
            RerunCmd   = "Get-ADGroup -Filter * -Properties members | Where-Object { -not `$_.members } | Select-Object Name,GroupCategory,SID"
        }
    }

    $tdSb = New-Object System.Text.StringBuilder
    foreach ($t in $Tests) {
        $cls = switch ($t.Status) {
            'Fail'    { 'td-fail';    break }
            'Warn'    { 'td-warn';    break }
            'Pass'    { 'td-pass';    break }
            'Partial' { 'td-skip'; break }
            'Skipped' { 'td-skip';    break }
            default   { 'td-notrun' }
        }
        $iconBg = switch ($t.Status) {
            'Fail'    { '#dc2626'; break }
            'Warn'    { '#d97706'; break }
            'Pass'    { '#16a34a'; break }
            'Skipped' { '#6b7280'; break }
            default   { '#9ca3af' }
        }
        $iconText = switch ($t.Status) {
            'Fail'    { 'X';  break }
            'Warn'    { '!';  break }
            'Pass'    { 'OK'; break }
            'Skipped' { '-';  break }
            default   { '?' }
        }
        $meta = $testMeta[$t.Title]
        if (-not $meta) {
            $meta = @{
                Summary    = $t.Subtitle
                WhyMatters = ''
                LookFor    = ''
                HowToFix   = ''
                RerunCmd   = '.\AdAudit-PS7.ps1 -adhealth'
            }
        }
        $sourceLink = ''
        if ($t.EvidencePath) {
            $rel = _RelHref $t.EvidencePath
            $leaf = Split-Path -Path $t.EvidencePath -Leaf
            $sourceLink = "<a href='$(_HEnc $rel)'>$(_HEnc $leaf)</a>"
        } else {
            $sourceLink = "<span style='color:var(--muted)'>no evidence file</span>"
        }
        $rerunCmd = if ($meta.RerunCmd) { $meta.RerunCmd } else { '.\AdAudit-PS7.ps1 -adhealth' }
        $rerunScript = '.\AdAudit-PS7.ps1 -adhealth'

        # Show "Look for" + "How to fix" on Fail/Warn (the user wanted them
        # surfaced when the test is unhappy). Always show summary, why,
        # source link and rerun command - that information helps even when
        # everything passed.
        $lookForBlock = ''
        $howToFixBlock = ''
        if ($t.Status -in @('Fail','Warn') -and $meta.LookFor) {
            $lookForBlock = @"
<div class='td-section'>
  <h4>What to look for</h4>
  <p>$(_HEnc $meta.LookFor)</p>
</div>
"@
        }
        if ($t.Status -in @('Fail','Warn') -and $meta.HowToFix) {
            $howToFixBlock = @"
<div class='td-section'>
  <h4>How to fix</h4>
  <p>$(_HEnc $meta.HowToFix)</p>
</div>
"@
        }

        [void]$tdSb.AppendLine(@"
<details class='td-item $cls'>
  <summary>
    <div class='td-head'>
      <span class='ht-icon' style='background:$iconBg'>$iconText</span>
      <div class='td-head-text'>
        <div class='td-title'>$(_HEnc $t.Title)</div>
        <div class='td-sub'>$(_HEnc $t.Subtitle)</div>
      </div>
      <div class='td-detail'>$(_HEnc $t.Detail)</div>
      <span class='td-chev' aria-hidden='true'>&#9656;</span>
    </div>
  </summary>
  <div class='td-body'>
    <p class='td-summary-text'>$(_HEnc $meta.Summary)</p>
    <div class='td-grid'>
      <div class='td-section'>
        <h4>Why it matters</h4>
        <p>$(_HEnc $meta.WhyMatters)</p>
      </div>
      $lookForBlock
      $howToFixBlock
      <div class='td-section'>
        <h4>Source &amp; full context</h4>
        <p>$sourceLink</p>
        <p style='margin-top:6px;font-size:.82rem;color:var(--muted)'>The evidence file holds the raw command output and any per-DC detail.</p>
      </div>
    </div>
    <div class='td-cmd'>
      <h4>Rerun this check</h4>
      <pre><code>$(_HEnc $rerunCmd)</code></pre>
      <p style='margin:6px 0 0;font-size:.82rem;color:var(--muted)'>Or rerun the whole AD Health check: <code>$(_HEnc $rerunScript)</code></p>
    </div>
  </div>
</details>
"@)
    }

    $tdCss = @'
<style>
.td-card{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:24px 24px 22px;box-shadow:var(--shadow);margin:0 0 24px}
.td-card h2{margin:0 0 6px;font-size:1.2rem}
.td-card .td-intro{color:var(--muted);margin:0 0 16px;font-size:.88rem;line-height:1.55}
.td-list{display:grid;gap:10px}
.td-item{border:1px solid var(--line);border-left:4px solid #9ca3af;border-radius:12px;background:var(--panel);overflow:hidden}
.td-item.td-fail{border-left-color:#dc2626}
.td-item.td-warn{border-left-color:#d97706}
.td-item.td-pass{border-left-color:#16a34a}
.td-item.td-skip{border-left-color:#6b7280}
.td-item summary{cursor:pointer;list-style:none;padding:14px 16px}
.td-item summary::-webkit-details-marker{display:none}
.td-item summary::marker{display:none;content:''}
.td-item summary::before{content:none;display:none}
.td-item .td-head{display:flex;align-items:center;gap:12px}
.td-item .ht-icon{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:8px;color:#fff;font-weight:800;font-size:13px;font-family:Consolas,monospace;flex-shrink:0}
.td-item .td-head-text{flex:1;min-width:0}
.td-item .td-title{font-weight:700;font-size:.96rem;line-height:1.3}
.td-item .td-sub{font-size:.82rem;color:var(--muted);margin-top:2px;line-height:1.4}
.td-item .td-detail{font-weight:700;font-size:.85rem;text-align:right;white-space:nowrap;flex-shrink:0}
.td-item .td-chev{color:var(--muted);font-size:.95rem;transition:transform .15s ease;flex-shrink:0;margin-left:6px;font-family:Segoe UI Symbol,sans-serif}
.td-item[open] .td-chev{transform:rotate(90deg)}
.td-item.td-fail .td-detail{color:#dc2626}
.td-item.td-warn .td-detail{color:#d97706}
.td-item.td-pass .td-detail{color:#16a34a}
.td-body{padding:14px 18px 18px;border-top:1px solid var(--line);background:rgba(125,125,125,.04)}
.td-summary-text{margin:0 0 14px;line-height:1.55;font-size:.92rem}
.td-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px;margin:0}
.td-section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.td-section h4{margin:0 0 6px;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:700}
.td-section p{margin:0;line-height:1.55;font-size:.9rem}
.td-cmd{margin-top:14px}
.td-cmd h4{margin:0 0 6px;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:700}
.td-cmd pre{margin:0;padding:12px 14px;background:rgba(125,125,125,.10);border:1px solid var(--line);border-radius:10px;overflow:auto;font-family:Consolas,Menlo,Monaco,monospace;font-size:.85rem;color:var(--text);white-space:pre-wrap;word-break:break-word}
.td-cmd code{font-family:Consolas,Menlo,Monaco,monospace;font-size:.85em;background:rgba(125,125,125,.10);padding:2px 6px;border-radius:5px}
</style>
'@

    $testDetailsHtml = @"
<div class='td-card'>
  <h2>Test Details</h2>
  <p class='td-intro'>Click any test to see what it checks, why it matters, what to look for if it failed, how to fix it, the matching evidence file, and a copy-paste rerun command. The full command output and per-DC breakdown lives in the evidence file under <code>Raw Data\Source\</code>.</p>
  <div class='td-list'>
$($tdSb.ToString())
  </div>
</div>
"@

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AD Health Report</title>
$css
</head>
<body>
<div class="container">
$themeBlock
$nav
$cloneNotice
$heroHtml
$gaugeCss
$gaugeHtml
$testCss
$testHtml
$statsHtml
$($findingsSb.ToString())
$tdCss
$testDetailsHtml
<div class="footer">Generated by AD Audit &mdash; $now</div>
</div>
</body>
</html>
"@

    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8
}

function Invoke-HealthCheck {
    Get-ADHealth
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select adhealth @args
}
