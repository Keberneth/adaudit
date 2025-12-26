[CmdletBinding()]
Param(
    [string]$InputRoot,
    [string]$OutputHtml,
    [string]$OutputTxt,
    [int]$TopFindings = 10
)

function Invoke-ManagementReport {

    if (-not $InputRoot -or $InputRoot.Trim().Length -eq 0) {
        $InputRoot = Join-Path (Get-Location) $env:COMPUTERNAME
    }
    if (-not (Test-Path -Path $InputRoot)) {
        throw "InputRoot '$InputRoot' does not exist."
    }

    if (-not $OutputHtml) { $OutputHtml = Join-Path $InputRoot 'Management-Report.html' }
    if (-not $OutputTxt)  { $OutputTxt  = Join-Path $InputRoot 'Management-Summary.txt' }

    $ErrorActionPreference = 'Stop'

    # --- Portable HTML encoding (PS 5.1 + PS 7+) ---
    function HtmlEncode([string]$s) {
        if ($null -eq $s) { return '' }
        if ('System.Web.HttpUtility' -as [type]) { return [System.Web.HttpUtility]::HtmlEncode($s) }
        return [System.Net.WebUtility]::HtmlEncode($s)
    }
    function HtmlAttrEncode([string]$s) {
        if ($null -eq $s) { return '' }
        if ('System.Web.HttpUtility' -as [type]) { return [System.Web.HttpUtility]::HtmlAttributeEncode($s) }
        return ([System.Net.WebUtility]::HtmlEncode($s) -replace '"','&quot;')
    }

    function Get-RelPath([string]$path) {
        if (-not $path) { return '' }
        try {
            $abs = [System.IO.Path]::GetFullPath($path)
            $rootAbs = [System.IO.Path]::GetFullPath($InputRoot)
            if ($abs.StartsWith($rootAbs, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $abs.Substring($rootAbs.Length).TrimStart('\','/')
            }
        } catch { }
        return [System.IO.Path]::GetFileName($path)
    }

    function Get-NonHeaderLines([string]$path) {
        if (-not (Test-Path $path)) { return @() }
        try {
            return (Get-Content -LiteralPath $path -ErrorAction Stop) |
                Where-Object { $_ -and $_.Trim().Length -gt 0 -and ($_ -notmatch '^[\s]*@') }
        } catch { return @() }
    }

    function Get-CsvSafe([string]$path) {
        if (-not (Test-Path $path)) { return @() }
        try { return Import-Csv -LiteralPath $path -ErrorAction Stop } catch { return @() }
    }

    $Findings = New-Object System.Collections.Generic.List[object]

    # Base points (start values) - updated
    $SeverityScore = @{
        Critical = 12
        High     = 8
        Medium   = 5
        Low      = 2
    }

    function Normalize-Severity([string]$sev) {
        $s = ($sev -as [string])
        if (-not $s) { return 'Low' }
        $s = $s.Trim()
        switch -Regex ($s.ToUpperInvariant()) {
            '^CRIT'  { return 'Critical' }
            '^HIGH'  { return 'High' }
            '^MED'   { return 'Medium' }
            '^LOW'   { return 'Low' }
            default  { return 'Low' }
        }
    }

    function Add-Finding {
        param(
            [string]$Severity,
            [string]$Title,
            [string]$Evidence,
            [string]$Path,
            [int]$ScoreOverride
        )

        $Severity = Normalize-Severity $Severity
        $score = [int]$SeverityScore[$Severity]
        if ($PSBoundParameters.ContainsKey('ScoreOverride')) {
            $score = [int]$ScoreOverride
        }

        $Findings.Add([PSCustomObject]@{
            Severity = $Severity
            Title    = $Title
            Evidence = $Evidence
            Link     = Get-RelPath $Path
            Score    = $score
        }) | Out-Null
    }

    # Legacy scaler retained (used for some non-baseline count signals)
    function Score-Scaled([string]$Severity,[double]$Count,[int]$maxScale = 50) {
        $Severity = Normalize-Severity $Severity
        $base  = [int]$SeverityScore[$Severity]
        $c     = [Math]::Max([double]$Count, 0)
        $scale = [Math]::Min([Math]::Floor($c / 10), [Math]::Floor($maxScale / 10))
        return ($base + [int]$scale)
    }

    # New: Over-baseline curve (Option A)
    function Score-OverBaselineLog {
        param(
            [string]$Severity,
            [double]$Observed,
            [double]$Baseline,

            # Cap how much *extra* a single finding can add above the base severity score
            [int]$MaxAdd = 18,

            # Aggressiveness (higher = steeper)
            [double]$K = 5
        )

        $Severity = Normalize-Severity $Severity
        $base = [int]$SeverityScore[$Severity]

        if ($Baseline -le 0) { return $base }
        if ($Observed -le $Baseline) { return $base }

        $ratio = $Observed / $Baseline

        # log2(ratio) scaling
        $add = [Math]::Ceiling($K * ([Math]::Log($ratio) / [Math]::Log(2)))

        # cap so no single metric dominates
        $add = [Math]::Min([int]$add, [int]$MaxAdd)

        return ($base + [int]$add)
    }

    function DisplayOrDash($v) {
        if ($null -eq $v) { return '&mdash;' }
        $s = [string]$v
        if ([string]::IsNullOrWhiteSpace($s)) { return '&mdash;' }
        return (HtmlEncode $s)
    }

    # Avoid duplicates (same Severity+Title+Link)
    $dedup = New-Object 'System.Collections.Generic.HashSet[string]'
    function Add-FindingOnce {
        param(
            [string]$Severity,
            [string]$Title,
            [string]$Evidence,
            [string]$Path,
            [int]$ScoreOverride
        )
        $Severity = Normalize-Severity $Severity
        $k = '{0}|{1}|{2}' -f $Severity, (($Title -as [string]).Trim()), (Get-RelPath $Path)
        if ($dedup.Add($k)) {
            Add-Finding -Severity $Severity -Title $Title -Evidence $Evidence -Path $Path -ScoreOverride $ScoreOverride
        }
    }

    # --- Domain stats from ADExtract (optional) ---
    $UsersCount  = $null
    $GroupsCount = $null
    $OUsCount    = $null
    try {
        $adExtract = Join-Path $InputRoot 'ADExtract'
        if (Test-Path $adExtract) {
            $usersCsv  = Get-ChildItem -Path $adExtract -Recurse -File -Filter '*-Users.csv'  | Select-Object -First 1
            $groupsCsv = Get-ChildItem -Path $adExtract -Recurse -File -Filter '*-Groups.csv' | Select-Object -First 1
            $ousCsv    = Get-ChildItem -Path $adExtract -Recurse -File -Filter '*-OUs.csv'    | Select-Object -First 1
            if ($usersCsv)  { $UsersCount  = (Get-CsvSafe $usersCsv.FullName).Count }
            if ($groupsCsv) { $GroupsCount = (Get-CsvSafe $groupsCsv.FullName).Count }
            if ($ousCsv)    { $OUsCount    = (Get-CsvSafe $ousCsv.FullName).Count }
        }
    } catch { }

    # --- HighRisk CSVs ---
    $highRiskDir = Join-Path $InputRoot 'HighRisk'
    if (Test-Path $highRiskDir) {
        $hrFiles = @{
            DUPLICATE_PASSWORDS     = Join-Path $highRiskDir 'DUPLICATE_PASSWORDS.csv'
            KRBTGT                  = Join-Path $highRiskDir 'KRBTGT.csv'
            PRIVILEGED_GROUPS       = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
            INACTIVE_ACCOUNTS       = Join-Path $highRiskDir 'INACTIVE_ACCOUNTS.csv'
            PASSWORD_NEVER_EXPIRES  = Join-Path $highRiskDir 'PASSWORD_NEVER_EXPIRES.csv'
            DISABLED_STALE          = Join-Path $highRiskDir 'DISABLED_STALE.csv'
            MACHINE_ACCOUNT_QUOTA   = Join-Path $highRiskDir 'MACHINE_ACCOUNT_QUOTA.csv'
            Summary                 = Join-Path $highRiskDir 'Summary.csv'
        }

        $dupRows = Get-CsvSafe $hrFiles.DUPLICATE_PASSWORDS
        if ($dupRows.Count -gt 0) {
            Add-FindingOnce 'Critical' 'Duplicate passwords detected' "Accounts with identical password hashes: $($dupRows.Count)" $hrFiles.DUPLICATE_PASSWORDS (Score-Scaled 'Critical' $dupRows.Count 100)
        }

        $krbtgt = Get-CsvSafe $hrFiles.KRBTGT
        if ($krbtgt.Count -gt 0) {
            $ageVal = 0
            try {
                $first = $krbtgt | Select-Object -First 1
                $raw = @($first.AgeDays, $first.PasswordAgeDays) |
                    Where-Object { $_ -ne $null -and $_ -ne '' } |
                    Select-Object -First 1
                if ($raw) { $ageVal = [int](([string]$raw) -replace '[^0-9]','') }
            } catch { $ageVal = 0 }

            $sev = if ($ageVal -ge 365) { 'High' } else { 'Medium' }
            Add-FindingOnce $sev 'KRBTGT password age is high' "Estimated age (days): $ageVal" $hrFiles.KRBTGT (Score-Scaled $sev ([Math]::Max($ageVal,1) / 30))
        }

        $privRows = Get-CsvSafe $hrFiles.PRIVILEGED_GROUPS
        if ($privRows.Count -gt 0) {
            $sev = if ($privRows.Count -ge 20) { 'High' } elseif ($privRows.Count -ge 10) { 'Medium' } else { 'Low' }
            Add-FindingOnce $sev 'Large privileged group membership' "Rows: $($privRows.Count)" $hrFiles.PRIVILEGED_GROUPS (Score-Scaled $sev $privRows.Count)
        }

        $inactiveRows = Get-CsvSafe $hrFiles.INACTIVE_ACCOUNTS
        if ($inactiveRows.Count -gt 0) {
            $sev = if ($inactiveRows.Count -ge 200) { 'High' } elseif ($inactiveRows.Count -ge 50) { 'Medium' } else { 'Low' }
            Add-FindingOnce $sev 'Inactive enabled accounts' "Accounts inactive: $($inactiveRows.Count)" $hrFiles.INACTIVE_ACCOUNTS (Score-Scaled $sev $inactiveRows.Count)
        }

        $pneRows = Get-CsvSafe $hrFiles.PASSWORD_NEVER_EXPIRES
        if ($pneRows.Count -gt 0) {
            $sev = if ($pneRows.Count -ge 50) { 'High' } elseif ($pneRows.Count -ge 10) { 'Medium' } else { 'Low' }
            Add-FindingOnce $sev 'Passwords set to never expire' "Accounts: $($pneRows.Count)" $hrFiles.PASSWORD_NEVER_EXPIRES (Score-Scaled $sev $pneRows.Count)
        }

        $dsRows = Get-CsvSafe $hrFiles.DISABLED_STALE
        if ($dsRows.Count -gt 0) {
            $sev = if ($dsRows.Count -ge 200) { 'Medium' } else { 'Low' }
            Add-FindingOnce $sev 'Disabled stale accounts' "Accounts: $($dsRows.Count)" $hrFiles.DISABLED_STALE (Score-Scaled $sev $dsRows.Count)
        }

        $maqRows = Get-CsvSafe $hrFiles.MACHINE_ACCOUNT_QUOTA
        if ($maqRows.Count -gt 0) {
            $quota = 10
            try {
                $firstRow = $maqRows | Select-Object -First 1
                $quotaCol = ($firstRow | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -match 'quota|Machine|Account' } | Select-Object -ExpandProperty Name -First 1)
                if ($quotaCol) { $quota = [int]$firstRow.$quotaCol }
            } catch { $quota = 10 }

            $sev = if ($quota -gt 10) { 'High' } elseif ($quota -gt 0) { 'Medium' } else { 'Low' }
            Add-FindingOnce $sev 'MachineAccountQuota permits user-created computers' "Quota: $quota" $hrFiles.MACHINE_ACCOUNT_QUOTA (Score-Scaled $sev $quota)
        }
    }

    # --- Text-based checks ---
    $weakKerbPath = Join-Path $InputRoot 'dcs_weak_kerberos_ciphersuite.txt'
    $weakKerbLines = Get-NonHeaderLines $weakKerbPath
    if ($weakKerbLines.Count -gt 0) {
        Add-FindingOnce 'High' 'Domain controllers allow weak Kerberos ciphers' "DCs flagged: $($weakKerbLines.Count)" $weakKerbPath (Score-Scaled 'High' $weakKerbLines.Count)
    }

    $asrepPath = Join-Path $InputRoot 'ASREP.txt'
    $asrepLines = Get-NonHeaderLines $asrepPath
    if ($asrepLines.Count -gt 0) {
        Add-FindingOnce 'High' 'Accounts without Kerberos pre-auth (AS-REP roastable)' "Accounts: $($asrepLines.Count)" $asrepPath (Score-Scaled 'High' $asrepLines.Count)
    }

    $spnPath = Join-Path $InputRoot 'SPNs.txt'
    $spnLines = Get-NonHeaderLines $spnPath
    if ($spnLines.Count -gt 0) {
        Add-FindingOnce 'Medium' 'Kerberoastable SPNs present (review high-value service accounts)' "Lines: $($spnLines.Count)" $spnPath (Score-Scaled 'Medium' $spnLines.Count)
    }
    # Inactive computer objects (>90 days)
    $inactiveCompsPath = Join-Path $InputRoot 'computers_inactive_90days.txt'
    $inactiveCompsLines = Get-NonHeaderLines $inactiveCompsPath
    if ($inactiveCompsLines.Count -gt 0) {
        $obs = $inactiveCompsLines.Count
        # Baseline: adjust if needed; using 5 by default to flag drift early
        $base = 5
        $sev = if ($obs -ge 200) { 'High' } elseif ($obs -ge 50) { 'Medium' } else { 'Low' }
        $score = Score-OverBaselineLog -Severity $sev -Observed $obs -Baseline $base -MaxAdd 14 -K 3
        Add-FindingOnce $sev 'Inactive computer accounts (>90 days)' "Computers inactive: $obs (Baseline: <= $base)" $inactiveCompsPath $score
    }
    
    $pndePath = Join-Path $InputRoot 'accounts_passdontexpire.txt'
    $pndeLines = Get-NonHeaderLines $pndePath
    if ($pndeLines.Count -gt 0) {
        $sev = if ($pndeLines.Count -ge 50) { 'High' } elseif ($pndeLines.Count -ge 10) { 'Medium' } else { 'Low' }
        Add-FindingOnce $sev 'Accounts with password set to not expire' "Accounts: $($pndeLines.Count)" $pndePath (Score-Scaled $sev $pndeLines.Count)
    }

    $lapsRightsPath  = Join-Path $InputRoot 'laps_read-extendedrights.txt'
    $lapsExpiredPath = Join-Path $InputRoot 'laps_expired-passwords.txt'
    if ((Test-Path $lapsRightsPath) -or (Test-Path $lapsExpiredPath)) {
        $rightsCount  = (Get-NonHeaderLines $lapsRightsPath).Count
        $expiredCount = (Get-NonHeaderLines $lapsExpiredPath).Count
        if ($rightsCount -gt 0)  { Add-FindingOnce 'High'   'LAPS password read rights widely delegated' "Readers: $rightsCount" $lapsRightsPath (Score-Scaled 'High' $rightsCount) }
        if ($expiredCount -gt 0) { Add-FindingOnce 'Medium' 'LAPS passwords expired' "Computers flagged: $expiredCount" $lapsExpiredPath (Score-Scaled 'Medium' $expiredCount) }
    }

    $ldapSecPath = Join-Path $InputRoot 'LDAPSecurity.txt'
    if ((Get-NonHeaderLines $ldapSecPath).Count -gt 0) {
        Add-FindingOnce 'High' 'LDAP security misconfiguration detected' 'See LDAPSecurity.txt for details' $ldapSecPath $SeverityScore.High
    }

    $ntlmRestrictPath = Join-Path $InputRoot 'ntlm_restrictions.txt'
    if ((Get-NonHeaderLines $ntlmRestrictPath).Count -gt 0) {
        Add-FindingOnce 'Medium' 'NTLM restrictions require hardening' 'Review NTLM configuration and restrictions' $ntlmRestrictPath $SeverityScore.Medium
    }

    $dnsInsecureZonesPath = Join-Path $InputRoot 'insecure_dns_zones.txt'
    $dnsInsecureLines = Get-NonHeaderLines $dnsInsecureZonesPath
    if ($dnsInsecureLines.Count -gt 0) {
        Add-FindingOnce 'High' 'DNS zones allowing insecure updates' "Zones flagged: $($dnsInsecureLines.Count)" $dnsInsecureZonesPath (Score-Scaled 'High' $dnsInsecureLines.Count)
    }

    # Delegated Permissions
    $delegRoot = Join-Path $InputRoot 'DelegatedPermissions'
    if (Test-Path $delegRoot) {
        $repFolder = Get-ChildItem -Path $delegRoot -Directory | Sort-Object Name | Select-Object -Last 1
        if ($repFolder) {
            $riskTxt = Join-Path $repFolder.FullName 'ADAudit_RiskAssessment.txt'
            $recTxt  = Join-Path $repFolder.FullName 'ADAudit_Recommendations.txt'

            $riskLines = Get-NonHeaderLines $riskTxt
            if ($riskLines.Count -gt 0) {
                $highCount = ($riskLines | Where-Object { $_ -match '(CRITICAL|HIGH)' }).Count
                $sev = if ($highCount -gt 0) { 'High' } else { 'Medium' }
                Add-FindingOnce $sev 'Delegated permissions risks detected' "High/Critical items: $highCount" $riskTxt (Score-Scaled $sev $highCount)
            }

            if (Test-Path $recTxt) {
                Add-FindingOnce 'Low' 'Delegated permissions recommendations available' 'See recommendations file' $recTxt $SeverityScore.Low
            }
        }
    }

    # Admin groups (text files)
    $daPath = Join-Path $InputRoot 'domain_admins.txt'
    $eaPath = Join-Path $InputRoot 'enterprise_admins.txt'
    $saPath = Join-Path $InputRoot 'schema_admins.txt'

    $daCount = (Get-NonHeaderLines $daPath).Count
    $eaCount = (Get-NonHeaderLines $eaPath).Count
    $saCount = (Get-NonHeaderLines $saPath).Count

    if ($daCount -gt 0) {
        $sev = if ($daCount -gt 10) { 'High' } elseif ($daCount -gt 5) { 'Medium' } else { 'Low' }
        $daBase = 5
        Add-FindingOnce $sev 'Domain Admins membership size' "Members: $daCount (Baseline: <= $daBase)" $daPath (Score-OverBaselineLog -Severity $sev -Observed $daCount -Baseline $daBase -MaxAdd 18 -K 4)
    }
    if ($eaCount -gt 0) {
        $sev = if ($eaCount -gt 5) { 'High' } elseif ($eaCount -gt 2) { 'Medium' } else { 'Low' }
        $eaBase = 2
        Add-FindingOnce $sev 'Enterprise Admins membership size' "Members: $eaCount (Baseline: <= $eaBase)" $eaPath (Score-OverBaselineLog -Severity $sev -Observed $eaCount -Baseline $eaBase -MaxAdd 16 -K 4)
    }
    if ($saCount -gt 0) {
        $sev = if ($saCount -gt 5) { 'High' } elseif ($saCount -gt 2) { 'Medium' } else { 'Low' }
        # Baseline effectively 0 except during schema changes; use 1 to avoid divide-by-zero and cap.
        $saBase = 1
        Add-FindingOnce $sev 'Schema Admins membership size' "Members: $saCount (Baseline: 0 except during schema change)" $saPath (Score-OverBaselineLog -Severity $sev -Observed $saCount -Baseline $saBase -MaxAdd 18 -K 4)
    }

    # --- Baseline file parsing: convert [CRITICAL]/[HIGH]/... lines into findings ---
    $baselinePath = Join-Path $InputRoot 'ad_high_risk_baseline.txt'
    if (Test-Path $baselinePath) {
        $lines = Get-Content -LiteralPath $baselinePath -ErrorAction SilentlyContinue
        $inFindings = $false

        foreach ($ln in $lines) {
            if (-not $ln) { continue }
            if ($ln -match '^\s*Findings\s*$') { $inFindings = $true; continue }
            if (-not $inFindings) { continue }

            if ($ln -match '^\s*\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*(.+?)\s*\|\s*Observed:\s*(.+?)\s*\|\s*Baseline:\s*(.+?)\s*$') {
                $sevRaw  = $matches[1]
                $title   = $matches[2].Trim()
                $obs     = $matches[3].Trim()
                $base    = $matches[4].Trim()
                $sev     = Normalize-Severity $sevRaw

                $evidence = "Observed: $obs | Baseline: $base"

                # Default baseline score = base severity points
                $score = [int]$SeverityScore[$sev]

                switch -Regex ($title) {

                    '^krbtgt password age$' {
                        # Prefer "(NNN days)" from Observed text; fall back to first number
                        $obsDays = 0
                        if ($obs -match '\(([0-9]+)\s*days\)') { $obsDays = [int]$matches[1] }
                        elseif ($obs -match '([0-9]+)') { $obsDays = [int]$matches[1] }

                        # Baseline like "<= 180 days"
                        $baseDays = 0
                        if ($base -match '([0-9]+)') { $baseDays = [int]$matches[1] }

                        if ($obsDays -gt 0 -and $baseDays -gt 0) {
                            $score = Score-OverBaselineLog -Severity $sev -Observed $obsDays -Baseline $baseDays -MaxAdd 22 -K 5
                        }
                    }

                    '^Domain Admins$' {
                        $obsCount = 0
                        if ($obs -match '([0-9]+)') { $obsCount = [int]$matches[1] }

                        $baseCount = 0
                        if ($base -match '([0-9]+)') { $baseCount = [int]$matches[1] }

                        if ($obsCount -gt 0 -and $baseCount -gt 0) {
                            $score = Score-OverBaselineLog -Severity $sev -Observed $obsCount -Baseline $baseCount -MaxAdd 18 -K 4
                        }
                    }

                    '^Schema Admins$' {
                        $obsCount = 0
                        if ($obs -match '([0-9]+)') { $obsCount = [int]$matches[1] }

                        # Baseline "0 (except during schema change)" -> treat as effectively zero
                        $baseCount = 0
                        if ($base -match '^\s*0\b') { $baseCount = 0 }
                        elseif ($base -match '([0-9]+)') { $baseCount = [int]$matches[1] }

                        if ($obsCount -gt 0) {
                            if ($baseCount -le 0) {
                                # Baseline effectively 0 => strong deviation; cap bump
                                $score = [int]$SeverityScore[$sev] + 18
                            } else {
                                $score = Score-OverBaselineLog -Severity $sev -Observed $obsCount -Baseline $baseCount -MaxAdd 18 -K 4
                            }
                        }
                    }

                    '^Enabled accounts inactive >\s*180\s*days$' {
                        $obsCount = 0
                        if ($obs -match '([0-9]+)') { $obsCount = [int]$matches[1] }
                        if ($obsCount -gt 0) {
                            # baseline 0 => use 1 for math, cap it
                            $score = Score-OverBaselineLog -Severity $sev -Observed $obsCount -Baseline 1 -MaxAdd 14 -K 3
                        }
                    }

                    '^Enabled user accounts with PasswordNeverExpires$' {
                        $obsCount = 0
                        if ($obs -match '([0-9]+)') { $obsCount = [int]$matches[1] }
                        if ($obsCount -gt 0) {
                            $score = Score-OverBaselineLog -Severity $sev -Observed $obsCount -Baseline 1 -MaxAdd 14 -K 3
                        }
                    }

                    '^ms-DS-MachineAccountQuota$' {
                        $obsVal = 0
                        if ($obs -match '([0-9]+)') { $obsVal = [int]$matches[1] }
                        if ($obsVal -gt 0) {
                            $score = Score-OverBaselineLog -Severity $sev -Observed $obsVal -Baseline 1 -MaxAdd 16 -K 4
                        }
                    }

                    default {
                        # Keep base score for generic baseline lines (stable, non-brittle parsing)
                        $score = [int]$SeverityScore[$sev]
                    }
                }

                Add-FindingOnce $sev $title $evidence $baselinePath $score
            }
        }
    }

    # Severity counts
    $sevCounts = @{
        Critical = ($Findings | Where-Object { (($_.Severity -as [string]).Trim()) -ieq 'Critical' }).Count
        High     = ($Findings | Where-Object { (($_.Severity -as [string]).Trim()) -ieq 'High'     }).Count
        Medium   = ($Findings | Where-Object { (($_.Severity -as [string]).Trim()) -ieq 'Medium'   }).Count
        Low      = ($Findings | Where-Object { (($_.Severity -as [string]).Trim()) -ieq 'Low'      }).Count
    }

    # Overall score
    $TotalScore = 0
    foreach ($f in $Findings) { $TotalScore += [int]$f.Score }

    # ---------------------------
    # Score matrix (neutral) + banding (CONSISTENT everywhere)
    # ---------------------------
    $ScoreBands = @(
        [PSCustomObject]@{
            Level   = 'Low'
            Range   = '0 - 49'
            Meaning = 'Minor control gaps or baseline drift. Address during routine maintenance and continue monitoring.'
        }
        [PSCustomObject]@{
            Level   = 'Medium'
            Range   = '50 - 99'
            Meaning = 'Noticeable control gaps. Plan remediation in the next hardening cycle and track to closure.'
        }
        [PSCustomObject]@{
            Level   = 'High'
            Range   = '100 - 149'
            Meaning = 'Major control gaps. Prioritize remediation and validate that administrative controls are applied consistently.'
        }
        [PSCustomObject]@{
            Level   = 'Critical'
            Range   = '150+'
            Meaning = 'Significant control gaps or privileged configuration drift. Treat as a priority workstream with defined owners and timelines.'
        }
    )

    function Get-ScoreBand([int]$score) {
        if ($score -ge 150) { return 'Critical' }
        elseif ($score -ge 100) { return 'High' }
        elseif ($score -ge 50) { return 'Medium' }
        else { return 'Low' }
    }

    $OverallLevel = Get-ScoreBand $TotalScore

    $bandNow = $OverallLevel
    $scoreMatrixRows = foreach ($b in $ScoreBands) {
        $isActive = ($b.Level -eq $bandNow)
        $cls = if ($isActive) { "matrix-row active sev-$($b.Level)" } else { "matrix-row sev-$($b.Level)" }
@"
<tr class="$cls">
  <td><span class="pill sev-$($b.Level)">$($b.Level)</span></td>
  <td class="mono">$($b.Range)</td>
  <td class="matrix-meaning">$(HtmlEncode $b.Meaning)</td>
</tr>
"@
    }

    # ---------------------------
    # Modern HTML
    # ---------------------------
    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss "UTC"'
    $computerName = Split-Path -Path $InputRoot -Leaf

    $domainInfoBlock = ''
    try {
        $domainInfoBlock = (Get-Content -LiteralPath $baselinePath -ErrorAction SilentlyContinue) -join "`n"
    } catch { }

    $sortedFindings = $Findings | Sort-Object -Property @{Expression='Score';Descending=$true}, @{Expression='Severity';Descending=$false}
    $tableRows = foreach ($f in $sortedFindings) {
        $link  = if ($f.Link) { $f.Link } else { '' }
        $sev   = ($f.Severity -as [string]).Trim()
        $score = [int]$f.Score
@"
<tr data-sev="$sev" data-score="$score">
  <td><span class="pill sev-$sev">$sev</span></td>
  <td class="title">$(HtmlEncode $f.Title)</td>
  <td class="evidence">$(HtmlEncode $f.Evidence)</td>
  <td class="score">$score</td>
  <td class="source"><a href="$(HtmlAttrEncode $link)"><span class="mono">$(HtmlEncode $link)</span></a></td>
</tr>
"@
    }

    # Neutral interpretation text
    $meaning = switch ($OverallLevel) {
        'Critical' { 'The overall score indicates significant gaps relative to the defined baselines. Prioritize remediation for the highest-severity items and confirm governance for privileged access and password controls.' }
        'High'     { 'The overall score indicates material gaps relative to the defined baselines. Prioritize remediation and validate that controls are applied consistently across the environment.' }
        'Medium'   { 'The overall score indicates moderate gaps relative to the defined baselines. Plan remediation in the next hardening cycle and track progress to closure.' }
        Default    { 'The overall score indicates minor gaps relative to the defined baselines. Address as part of routine maintenance and continue monitoring.' }
    }

    $nextSteps = switch ($OverallLevel) {
        'Critical' { @(
            'Assign owners for Critical findings and define target dates for remediation.'
            'Review privileged group membership (Domain Admins / Schema Admins / built-in administrators) and ensure membership is justified, documented, and reviewed regularly.'
            'Address password control items (duplicate passwords, PasswordNeverExpires usage, KRBTGT rotation policy) and confirm they align with operational requirements.'
            'Re-run the assessment after remediation to confirm closure and reduce configuration drift.'
        ) }
        'High' { @(
            'Prioritize High findings and track remediation to closure.'
            'Validate privileged access governance (membership reviews, approvals, and change tracking).'
            'Standardize account lifecycle controls (inactive accounts, disabled account review cadence).'
            'Re-run the assessment after changes to confirm improvements.'
        ) }
        'Medium' { @(
            'Plan remediation for Medium findings in the next hardening cycle.'
            'Ensure baseline expectations and exception handling are documented and reviewed periodically.'
            'Re-run the assessment on a regular cadence to monitor drift.'
        ) }
        Default { @(
            'Address Low findings through routine maintenance.'
            'Continue periodic reviews of privileged access and baseline drift.'
            'Re-run the assessment after major changes.'
        ) }
    }
    $nextStepsHtml = ($nextSteps | ForEach-Object { "<li>$(HtmlEncode $_)</li>" }) -join "`n"

    $css = @"
<style>
:root{
  --bg:#0b1220; --text:#e8edf6; --muted:#b7c0d6; --line:rgba(255,255,255,.10);
  --shadow:0 10px 30px rgba(0,0,0,.35); --radius:14px;
  --critical-bg:rgba(255,77,79,.18); --high-bg:rgba(255,169,64,.18);
  --medium-bg:rgba(105,177,255,.18); --low-bg:rgba(149,222,100,.18);
}
*{box-sizing:border-box}
body{
  margin:0;
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
  background: radial-gradient(1200px 700px at 20% 10%, rgba(105,177,255,.18), transparent 60%),
              radial-gradient(1200px 700px at 80% 0%, rgba(255,169,64,.16), transparent 55%),
              var(--bg);
  color:var(--text);
}
a{color:#cfe1ff;text-decoration:none} a:hover{text-decoration:underline}
.container{max-width:1200px;margin:0 auto;padding:28px 20px 60px}
.header{
  background: linear-gradient(135deg, rgba(255,255,255,.08), rgba(255,255,255,.02));
  border:1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow);
  padding:22px 22px 18px;
}
.h-title{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;flex-wrap:wrap}
h1{font-size:22px;margin:0 0 6px;letter-spacing:.2px}
.meta{color:var(--muted);font-size:13px}
.badge{
  display:inline-flex;align-items:center;gap:10px;
  padding:10px 12px;border-radius:999px;border:1px solid var(--line);
  background: rgba(255,255,255,.06); font-weight:700;
}
.badge .grade{font-size:13px;color:var(--muted);font-weight:600}
.badge .value{font-size:15px}
.badge.Critical{background:var(--critical-bg)} .badge.High{background:var(--high-bg)}
.badge.Medium{background:var(--medium-bg)} .badge.Low{background:var(--low-bg)}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;margin-top:14px}
.card{
  background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
  border:1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow);
  padding:14px 14px 12px; min-height:88px;
}
.card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em}
.card .v{font-size:22px;font-weight:800;margin-top:6px}
.card .s{margin-top:4px;color:var(--muted);font-size:12px}
.span-3{grid-column:span 3} .span-4{grid-column:span 4}
.pill{
  display:inline-flex;align-items:center;justify-content:center;
  padding:4px 10px;border-radius:999px;font-weight:800;font-size:12px;
  border:1px solid var(--line);
  min-width:86px;
}
.sev-Critical{background:var(--critical-bg)} .sev-High{background:var(--high-bg)}
.sev-Medium{background:var(--medium-bg)} .sev-Low{background:var(--low-bg)}
.section{margin-top:18px} .section h2{margin:0 0 10px;font-size:16px}
.callout{border:1px solid var(--line);border-radius: var(--radius);padding:14px;background: rgba(255,255,255,.05)}
.callout p{margin:0;line-height:1.4} .callout ul{margin:10px 0 0 18px} .callout li{margin:6px 0}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between;margin:10px 0}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center}

/* INPUTS (dropdown options readable) */
select,input{
  background:rgba(255,255,255,.06);
  color:var(--text);
  border:1px solid var(--line);
  border-radius:10px;
  padding:8px 10px;
  outline:none;
}
input{min-width:240px}
small{color:var(--muted)}
select option{ background:#0b1220; color:#ffffff; }

table{width:100%;border-collapse:collapse;border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;background:rgba(255,255,255,.03)}
th,td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em;background: rgba(255,255,255,.05);cursor:pointer;user-select:none}
tr:hover td{background:rgba(255,255,255,.04)}
td.score{font-weight:800} td.title{font-weight:700}
.mono{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace}
td.source .mono{font-size:12px;color:#d7e6ff}
pre{white-space:pre-wrap;background:rgba(0,0,0,.25);border:1px solid var(--line);border-radius: var(--radius);padding:12px;color:#dbe6ff;overflow:auto}
.footer{margin-top:16px;color:var(--muted);font-size:12px}

/* SCORE MATRIX ALIGNMENT */
.matrix-wrap{margin-top:10px}
table.matrix{
  table-layout:fixed;
}
table.matrix th, table.matrix td{
  padding:14px 18px;
}
table.matrix th{ cursor:default; }
table.matrix th:nth-child(1), table.matrix td:nth-child(1){
  width:18%;
  padding-left:22px;
}
table.matrix th:nth-child(2), table.matrix td:nth-child(2){
  width:18%;
  text-align:center;
}
table.matrix th:nth-child(3), table.matrix td:nth-child(3){
  width:64%;
  padding-left:22px;
}
.matrix-row.active td{background:rgba(255,255,255,.06)}
</style>
"@

    $js = @"
<script>
(function(){
  function q(sel){return document.querySelector(sel);}
  function qa(sel){return Array.prototype.slice.call(document.querySelectorAll(sel));}
  function rows(){return qa('#findings-body tr');}

  function applyFilters(){
    var sev = q('#sevFilter').value;
    var s = (q('#search').value || '').toLowerCase().trim();
    var visible = 0;

    rows().forEach(function(r){
      var rsev = r.getAttribute('data-sev');
      var text = (r.innerText || '').toLowerCase();
      var okSev = (sev === 'All') || (rsev === sev);
      var okSearch = (!s) || (text.indexOf(s) >= 0);
      var show = okSev && okSearch;
      r.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    q('#visibleCount').innerText = visible;
  }

  var sortCol = null;
  var sortAsc = false;
  var order = ['Critical','High','Medium','Low'];

  function sortBy(col){
    sortAsc = (sortCol === col) ? !sortAsc : true;
    sortCol = col;

    var arr = rows().slice().sort(function(a,b){
      var ka, kb;
      if(col === 'severity'){
        ka = order.indexOf(a.getAttribute('data-sev'));
        kb = order.indexOf(b.getAttribute('data-sev'));
      } else if(col === 'score'){
        ka = parseInt(a.getAttribute('data-score') || '0',10);
        kb = parseInt(b.getAttribute('data-score') || '0',10);
      } else if(col === 'title'){
        ka = (a.querySelector('.title') || {}).innerText || '';
        kb = (b.querySelector('.title') || {}).innerText || '';
      } else {
        ka = a.innerText; kb = b.innerText;
      }
      if(ka < kb) return sortAsc ? -1 : 1;
      if(ka > kb) return sortAsc ? 1 : -1;
      return 0;
    });

    var tbody = q('#findings-body');
    arr.forEach(function(r){tbody.appendChild(r);});
    applyFilters();
  }

  q('#sevFilter').addEventListener('change', applyFilters);
  q('#search').addEventListener('input', applyFilters);
  qa('th[data-sort]').forEach(function(th){
    th.addEventListener('click', function(){ sortBy(th.getAttribute('data-sort')); });
  });

  applyFilters();
  sortBy('score'); sortBy('score'); // start desc
})();
</script>
"@

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AD Audit - Management Summary</title>
$css
</head>
<body>
<div class="container">
  <div class="header">
    <div class="h-title">
      <div>
        <h1>Active Directory Audit - Management Summary</h1>
        <div class="meta">Target: <span class="mono">$(HtmlEncode $computerName)</span> | Generated: $(HtmlEncode $now)</div>
      </div>
      <div class="badge $OverallLevel">
        <div>
          <div class="grade">Overall Risk</div>
          <div class="value">$OverallLevel</div>
        </div>
        <div style="width:1px;height:28px;background:var(--line)"></div>
        <div>
          <div class="grade">Score</div>
          <div class="value">$TotalScore</div>
        </div>
      </div>
    </div>

    <div class="grid">
      <div class="card span-3"><div class="k">Critical findings</div><div class="v">$($sevCounts.Critical)</div><div class="s">Immediate remediation</div></div>
      <div class="card span-3"><div class="k">High findings</div><div class="v">$($sevCounts.High)</div><div class="s">Prioritize</div></div>
      <div class="card span-3"><div class="k">Medium findings</div><div class="v">$($sevCounts.Medium)</div><div class="s">Plan hardening</div></div>
      <div class="card span-3"><div class="k">Low findings</div><div class="v">$($sevCounts.Low)</div><div class="s">Maintain baseline</div></div>

      <div class="card span-4"><div class="k">Users</div><div class="v">$(DisplayOrDash $UsersCount)</div><div class="s">From ADExtract (if present)</div></div>
      <div class="card span-4"><div class="k">Groups</div><div class="v">$(DisplayOrDash $GroupsCount)</div><div class="s">From ADExtract (if present)</div></div>
      <div class="card span-4"><div class="k">OUs</div><div class="v">$(DisplayOrDash $OUsCount)</div><div class="s">From ADExtract (if present)</div></div>
    </div>
  </div>

  <div class="section">
    <h2>Interpretation</h2>
    <div class="callout">
      <p><b>What this means:</b> $(HtmlEncode $meaning)</p>

      <div class="matrix-wrap">
        <p style="margin-top:12px"><b>Score matrix:</b> The total score is mapped to a risk level as follows (current score highlighted).</p><br>
        <table class="matrix">
          <thead>
            <tr>
              <th>Level</th>
              <th>Score range</th>
              <th>Interpretation</th>
            </tr>
          </thead>
          <tbody>
            $(($scoreMatrixRows -join "`n"))
          </tbody>
        </table>
      </div>

      <p style="margin-top:12px"><b>Recommended next steps:</b></p>
      <ul>
        $nextStepsHtml
      </ul>

      <div class="footer">Note: This score is an index based on the findings included in this report and the evidence files available under the input folder. Validate scope and collection completeness.</div>
    </div>
  </div>

  <div class="section">
    <h2>Findings</h2>
    <div class="toolbar">
      <div class="filters">
        <label>
          <small>Severity</small><br>
          <select id="sevFilter">
            <option>All</option>
            <option>Critical</option>
            <option>High</option>
            <option>Medium</option>
            <option>Low</option>
          </select>
        </label>
        <label>
          <small>Search</small><br>
          <input id="search" type="text" placeholder="Search title/evidence/source...">
        </label>
      </div>
      <div>
        <small>Visible: <span id="visibleCount">0</span> / $($Findings.Count)</small>
      </div>
    </div>

    <table id="findings">
      <thead>
        <tr>
          <th data-sort="severity">Severity</th>
          <th data-sort="title">Finding</th>
          <th>Evidence</th>
          <th data-sort="score">Score</th>
          <th>Source</th>
        </tr>
      </thead>
      <tbody id="findings-body">
        $(($tableRows -join "`n"))
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Baseline and Notes</h2>
    <pre>$(HtmlEncode $domainInfoBlock)</pre>
  </div>

  <div class="footer">
    Generated by the Management Report script. Review detailed findings and evidence files for remediation actions.<br>
    This report summarizes configuration and baseline observations. It should be reviewed alongside operational context and existing compensating controls.
  </div>
</div>

$js
</body>
</html>
"@

    Set-Content -LiteralPath $OutputHtml -Value $html -Encoding UTF8

    # ---------------------------
    # TXT executive summary
    # ---------------------------
    $top = ($Findings | Sort-Object -Property @{Expression='Score';Descending=$true}) | Select-Object -First $TopFindings

    $txt = @()
    $txt += "Active Directory Audit - Management Summary"
    $txt += "Target: $computerName"
    $txt += "Generated: $now"
    $txt += "Overall risk level: $OverallLevel (Score=$TotalScore)"
    $txt += "Score matrix: Low=0-49; Medium=50-99; High=100-149; Critical=150+"
    if ($UsersCount)  { $txt += "Users: $UsersCount" }
    if ($GroupsCount) { $txt += "Groups: $GroupsCount" }
    if ($OUsCount)    { $txt += "OUs: $OUsCount" }
    $txt += ""
    $txt += "Top findings:"
    foreach ($f in $top) { $txt += "- [$($f.Severity)] $($f.Title) - $($f.Evidence) (source: $($f.Link))" }
    $txt += ""
    $txt += "See HTML report for links to detailed evidence."

    Set-Content -LiteralPath $OutputTxt -Value ($txt -join "`r`n") -Encoding UTF8

    Write-Host "[+] Management report written:" (Get-RelPath $OutputHtml)
    Write-Host "[+] Executive TXT summary written:" (Get-RelPath $OutputTxt)
}

Invoke-ManagementReport