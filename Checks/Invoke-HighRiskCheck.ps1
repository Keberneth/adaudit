<#
    .SYNOPSIS
        ADAudit check: High-Risk AD Baseline Report

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -highrisk). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-HighRiskCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select highrisk [options]

    .NOTES
        Entry point: Invoke-HighRiskCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory, DSInternals.
#>
#endregion Delegated Permissions Report

Function Get-HighRiskADBaselineReport {
    <#
        .SYNOPSIS
            Generates an executive high-risk AD baseline report (TXT + CSVs + HTML index).
        .DESCRIPTION
            Outputs:
              - ad_high_risk_baseline.txt
              - HighRisk\Summary.csv
              - HighRisk\<RiskId>.csv (one per risk category)
              - ad_high_risk_baseline_index.html (HTML index linking to the outputs)
        .NOTES
            This function is additive and does not modify existing checks or outputs.
    #>

    # Baseline (opinionated, aligned with Microsoft tiering + common security guidance)
    $baseline = [ordered]@{
        'Domain Admins (permanent members)'        = '<= 5'
        'Enterprise Admins (permanent members)'    = '0-2 (temporary only)'
        'Schema Admins (permanent members)'        = '0 (except during schema change)'
        'BUILTIN\Administrators (permanent members)' = 'Minimal (avoid non-DA users)'
        'Account Operators / Server Operators / Backup Operators / Print Operators' = 'Empty'
        'krbtgt password age'                      = '<= 180 days (rotate; 2x after incident)'
        'Enabled user inactivity'                  = 'Disable if inactive > 180 days (adjust to org policy)'
        'Disabled user retention'                  = 'Review/remove if disabled > 180 days'
        'Password never expires (humans)'          = '0 (use gMSA/MSA for services)'
        'MachineAccountQuota'                      = '0'
        'Duplicate passwords'                      = '0 shared passwords (no duplicate NT hashes)'
        'Windows cumulative update (Patch Tuesday)'   = 'Latest monthly cumulative update installed (current Patch Tuesday cycle)'
    }

    $riskOutDir = Join-Path (Get-RawSourceDataDir) 'HighRisk'
    New-Item -ItemType Directory -Path $riskOutDir -Force | Out-Null

    $txtPath = Get-EvidencePath 'ad_high_risk_baseline.txt'
    $summaryCsv = Join-Path $riskOutDir 'Summary.csv'
    $indexPath = Join-Path (Get-HtmlReportsDir -BaseRoot $outputdir) 'ad_high_risk_baseline_index.html'

    # Helper: safe group member enumeration
    function _Get-GroupMembersBySidOrName {
        param(
            [Parameter(Mandatory=$true)][string]$Identity
        )
        # Return $null on failure (distinct from an empty array) so the caller can tell
        # "enumeration failed" apart from "group is genuinely empty". Get-ADGroupMember
        # -Recursive routinely throws on foreign security principals from trusted domains
        # or the 5000-member limit; treating that as an empty group is a false all-clear.
        try {
            $g = Get-ADGroup -Identity $Identity -ErrorAction Stop
            return ,@(Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop)
        } catch {
            return $null
        }
    }

    # Helper: convert byte[] hash to hex
    function _ToHex {
        param([byte[]]$Bytes)
        if (-not $Bytes) { return $null }
        -join ($Bytes | ForEach-Object { $_.ToString('x2') })
    }

    # Collect privileged groups (covering domain/forest + builtin operator groups)
    $domainSid = (Get-ADDomain -Current LoggedOnUser).DomainSID.Value

    $groupDefs = @(
        @{ RiskId='PRIV_DA';   Name='Domain Admins';        Identity=($domainSid + '-512'); Baseline='<= 5'; Severity='CRITICAL' }
        @{ RiskId='PRIV_EA';   Name='Enterprise Admins';    Identity=($domainSid + '-519'); Baseline='0-2 (temporary only)'; Severity='CRITICAL' }
        @{ RiskId='PRIV_SA';   Name='Schema Admins';        Identity=($domainSid + '-518'); Baseline='0 (except during schema change)'; Severity='CRITICAL' }
        @{ RiskId='PRIV_ADM';  Name='BUILTIN\Administrators'; Identity='S-1-5-32-544';        Baseline='Minimal'; Severity='HIGH' }
        @{ RiskId='PRIV_AO';   Name='BUILTIN\Account Operators'; Identity='S-1-5-32-548';     Baseline='Empty'; Severity='HIGH' }
        @{ RiskId='PRIV_SO';   Name='BUILTIN\Server Operators';  Identity='S-1-5-32-549';     Baseline='Empty'; Severity='HIGH' }
        @{ RiskId='PRIV_BO';   Name='BUILTIN\Backup Operators';  Identity='S-1-5-32-551';     Baseline='Empty'; Severity='HIGH' }
        @{ RiskId='PRIV_PO';   Name='BUILTIN\Print Operators';   Identity='S-1-5-32-550';     Baseline='Empty'; Severity='MEDIUM' }
    )

    $privDetails = @()
    $privGroupFailed = @{}
    $privSamSet = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($gd in $groupDefs) {
        $members = _Get-GroupMembersBySidOrName -Identity $gd.Identity
        if ($null -eq $members) {
            $privGroupFailed[$gd.RiskId] = $true
            Register-ADAuditNotAssessed -Name 'HighRisk privileged group enumeration' -Target $gd.Name -Reason 'Get-ADGroupMember -Recursive failed (foreign security principals from a trusted domain, the 5000-member limit, or insufficient rights). Membership count is unknown - re-run with adequate permissions.'
            continue
        }
        foreach ($m in $members) {
            $sam = $m.SamAccountName
            if ($sam) { [void]$privSamSet.Add([string]$sam) }
            $privDetails += [pscustomobject]@{
                RiskId        = $gd.RiskId
                Group         = $gd.Name
                MemberSam     = $m.SamAccountName
                MemberName    = $m.Name
                ObjectClass   = $m.objectClass
                Baseline      = $gd.Baseline
                Severity      = $gd.Severity
            }
        }
    }

    # Summarize privileged group counts vs baseline thresholds
    $privSummary = @()
    foreach ($gd in $groupDefs) {
        if ($privGroupFailed[$gd.RiskId]) {
            # Enumeration failed - record as not assessed rather than a clean pass.
            $privSummary += [pscustomobject]@{
                RiskId         = $gd.RiskId
                Category       = 'Privileged Group Membership'
                Item           = $gd.Name
                Severity       = $gd.Severity
                Baseline       = $gd.Baseline
                Observed       = 'Unknown (enumeration failed)'
                IsFinding      = $false
                Recommendation = 'Re-run with sufficient rights. Get-ADGroupMember -Recursive can fail on foreign security principals or the 5000-member limit; this group was NOT assessed.'
            }
            continue
        }
        $cnt = ($privDetails | Where-Object { $_.RiskId -eq $gd.RiskId } | Measure-Object).Count

        $isFinding = $false
        if ($gd.RiskId -eq 'PRIV_DA' -and $cnt -gt 5) { $isFinding = $true }
        elseif ($gd.RiskId -eq 'PRIV_EA' -and $cnt -gt 2) { $isFinding = $true }
        elseif ($gd.RiskId -eq 'PRIV_SA' -and $cnt -gt 0) { $isFinding = $true }
        elseif ($gd.RiskId -in @('PRIV_AO','PRIV_SO','PRIV_BO','PRIV_PO') -and $cnt -gt 0) { $isFinding = $true }
        elseif ($gd.RiskId -eq 'PRIV_ADM' -and $cnt -gt 0) { $isFinding = $true } # "Minimal" -> always worth review

        $privSummary += [pscustomobject]@{
            RiskId         = $gd.RiskId
            Category       = 'Privileged Group Membership'
            Item           = $gd.Name
            Severity       = $gd.Severity
            Baseline       = $gd.Baseline
            Observed       = $cnt
            IsFinding      = $isFinding
            Recommendation = 'Minimize permanent membership; use JIT/PIM where possible; keep Tier0 separate; monitor changes.'
        }
    }

    # Domain Admins group overlap (DA members in extra groups)
    $daOverlapCsv = Join-Path $riskOutDir 'accounts_domain_admins_group_overlap.csv'
    $daOverlapSummaryObj = $null

    if (Test-Path $daOverlapCsv) {
        $overlaps = Import-Csv $daOverlapCsv

        # Prefer unique accounts (not rows) if SamAccountName exists
        if ($overlaps -and ($overlaps[0].PSObject.Properties.Name -contains 'SamAccountName')) {
            $overlapCount = ($overlaps | Select-Object -ExpandProperty SamAccountName -Unique | Measure-Object).Count
        } else {
            $overlapCount = ($overlaps | Measure-Object).Count
        }

        $daOverlapSummaryObj = [pscustomobject]@{
            RiskId         = 'PRIV_DA_OVERLAP'
            Category       = 'Privileged Group Membership'
            Item           = 'Domain Admins group overlap (extra group memberships)'
            Severity       = 'CRITICAL'
            Baseline       = 0
            Observed       = $overlapCount
            IsFinding      = ($overlapCount -gt 0)
            Recommendation = 'Remove Domain Admin accounts from all non-essential groups. Tier0 identities must be isolated; avoid Tier0+Tier1 overlap and delegated memberships.'
        }
    }

    # krbtgt password age
    $krbtgt = Get-ADUser -Filter { SamAccountName -eq "krbtgt" } -Properties PasswordLastSet -ErrorAction SilentlyContinue
    $krbtgtLastSet = $null
    if ($krbtgt) { $krbtgtLastSet = $krbtgt.PasswordLastSet }
    $krbtgtDays = $null
    if ($krbtgtLastSet) { $krbtgtDays = [int]((New-TimeSpan -Start $krbtgtLastSet -End (Get-Date)).TotalDays) }
    $krbtgtFinding = $false
    if ($krbtgtDays -ne $null -and $krbtgtDays -gt 180) { $krbtgtFinding = $true }

    $krbtgtObj = [pscustomobject]@{
        RiskId='KRB_KRBTGT'
        Category='Kerberos'
        Item='krbtgt password age'
        Severity='CRITICAL'
        Baseline='<= 180 days'
        Observed= $(if ($krbtgtLastSet) { "$krbtgtLastSet ($krbtgtDays days)" } else { 'Unknown' })
        IsFinding=$krbtgtFinding
        Recommendation='Rotate krbtgt regularly; after incident perform two resets per Microsoft guidance (allow ticket lifetime between resets).'
    }

    # Enabled inactive users (>180 days)
    # Enabled inactive users (>180 days) - SAFE (handles invalid FILETIME values)
$inactiveDays = 180
$cutoff = (Get-Date).AddDays(-$inactiveDays)

function _SafeFromFileTimeUtc {
    param([Nullable[long]]$FileTime)
    if ($null -eq $FileTime) { return $null }
    try { return [datetime]::FromFileTimeUtc([int64]$FileTime) } catch { return $null }
}

# Generic list: array += in a loop over every enabled user is O(n^2)
$inactiveDetails = [System.Collections.Generic.List[object]]::new()

# Enabled users (bitwise filter for "not disabled"). A failed query must be
# recorded as not-assessed, never as a clean Observed=0.
$inactiveQueryFailed = $false
try {
    $enabledUsers = Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
        -Properties lastLogonTimestamp,whenCreated,SamAccountName,Name -ErrorAction Stop
} catch {
    $inactiveQueryFailed = $true
    $enabledUsers = @()
    Register-ADAuditNotAssessed -Name 'HighRisk inactive-account enumeration' -Reason "Get-ADUser query failed: $($_.Exception.Message)"
}

foreach ($u in $enabledUsers) {
    $lltRaw = $null
    try { $lltRaw = [int64]$u.lastLogonTimestamp } catch { $lltRaw = $null }

    $llt = _SafeFromFileTimeUtc -FileTime $lltRaw
    $invalidFileTime = ($null -ne $lltRaw -and $null -eq $llt)

    # If lastLogonTimestamp is missing/invalid, fall back to whenCreated as a best-effort heuristic
    $isInactive =
        (($llt -ne $null) -and ($llt -lt $cutoff)) -or
        (($llt -eq $null) -and ($u.whenCreated -lt $cutoff))

    if ($isInactive) {
        $inactiveDetails.Add([pscustomobject]@{
            RiskId               = 'ACCT_INACTIVE'
            SamAccountName       = $u.SamAccountName
            Name                 = $u.Name
            LastLogonDate        = $llt
            LastLogonTimestampRaw= $lltRaw
            InvalidFileTime      = $invalidFileTime
            WhenCreated          = $u.whenCreated
            Baseline             = "Disable if inactive > $inactiveDays days"
            Severity             = 'HIGH'
            IsPrivileged         = $privSamSet.Contains([string]$u.SamAccountName)
        })
    }
}

$inactiveObj = [pscustomobject]@{
    RiskId='ACCT_INACTIVE'
    Category='Account Hygiene'
    Item="Enabled accounts inactive > $inactiveDays days"
    Severity='HIGH'
    Baseline="0 (disable if inactive > $inactiveDays days)"
    Observed=$(if ($inactiveQueryFailed) { 'Unknown (query failed)' } else { ($inactiveDetails | Measure-Object).Count })
    IsFinding=((($inactiveDetails | Measure-Object).Count) -gt 0)
    Recommendation='Disable or remove accounts that are no longer used; verify HR/offboarding; prioritize privileged and service accounts.'
}
    
    # Password never expires (enabled users)
    $pneQueryFailed = $false
    try {
        $pneUsers = Search-ADAccount -PasswordNeverExpires -UsersOnly -ErrorAction Stop | Where-Object { $_.Enabled -eq $true }
    } catch {
        $pneQueryFailed = $true
        $pneUsers = @()
        Register-ADAuditNotAssessed -Name 'HighRisk PasswordNeverExpires enumeration' -Reason "Search-ADAccount query failed: $($_.Exception.Message)"
    }
    $pneDetails = [System.Collections.Generic.List[object]]::new()
    foreach ($u in $pneUsers) {
        $pneDetails.Add([pscustomobject]@{
            RiskId='PWD_NEVER_EXPIRES'
            SamAccountName=$u.SamAccountName
            Name=$u.Name
            Baseline='0 (humans); use gMSA/MSA for services'
            Severity= $(if ($privSamSet.Contains([string]$u.SamAccountName)) { 'CRITICAL' } else { 'HIGH' })
            IsPrivileged= $privSamSet.Contains([string]$u.SamAccountName)
        })
    }
    $pneObj = [pscustomobject]@{
        RiskId='PWD_NEVER_EXPIRES'
        Category='Credential Hygiene'
        Item='Enabled user accounts with PasswordNeverExpires'
        Severity='HIGH'
        Baseline='0 (humans); services should use gMSA/MSA'
        Observed=$(if ($pneQueryFailed) { 'Unknown (query failed)' } else { ($pneDetails | Measure-Object).Count })
        IsFinding=((($pneDetails | Measure-Object).Count) -gt 0)
        Recommendation='Eliminate non-expiring human passwords; migrate service accounts to gMSA; rotate credentials; enforce MFA for admins.'
    }

    # Disabled accounts stale (>180 days) based on whenChanged (best-effort)
    $disabledRetentionDays = 180
    $disabledQueryFailed = $false
    try {
        $disabledOld = Get-ADUser -Filter { Enabled -eq $false } -Properties whenChanged,SamAccountName,Name -ErrorAction Stop |
                       Where-Object { $_.whenChanged -lt (Get-Date).AddDays(-$disabledRetentionDays) }
    } catch {
        $disabledQueryFailed = $true
        $disabledOld = @()
        Register-ADAuditNotAssessed -Name 'HighRisk stale disabled-account enumeration' -Reason "Get-ADUser query failed: $($_.Exception.Message)"
    }
    $disabledOldDetails = [System.Collections.Generic.List[object]]::new()
    foreach ($u in $disabledOld) {
        $disabledOldDetails.Add([pscustomobject]@{
            RiskId='ACCT_DISABLED_STALE'
            SamAccountName=$u.SamAccountName
            Name=$u.Name
            whenChanged=$u.whenChanged
            Baseline="Review/remove if disabled > $disabledRetentionDays days"
            Severity='MEDIUM'
        })
    }
    $disabledOldObj = [pscustomobject]@{
        RiskId='ACCT_DISABLED_STALE'
        Category='Account Hygiene'
        Item="Disabled accounts not reviewed > $disabledRetentionDays days"
        Severity='MEDIUM'
        Baseline="0 (review/remove if disabled > $disabledRetentionDays days)"
        Observed=$(if ($disabledQueryFailed) { 'Unknown (query failed)' } else { ($disabledOldDetails | Measure-Object).Count })
        IsFinding=((($disabledOldDetails | Measure-Object).Count) -gt 0)
        Recommendation='Remove or archive long-disabled accounts; verify business/legal retention; reduce directory clutter and attack surface.'
    }

    # MachineAccountQuota
    $maq = $null
    try {
        $maq = (Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | Get-ADObject -Property 'ms-DS-MachineAccountQuota' | Select-Object -ExpandProperty ms-DS-MachineAccountQuota)
    } catch { }
    $maqFinding = $false
    if ($maq -ne $null -and [int]$maq -gt 0) { $maqFinding = $true }
    $maqObj = [pscustomobject]@{
        RiskId='DOMAIN_MAQ'
        Category='Domain Configuration'
        Item='ms-DS-MachineAccountQuota'
        Severity='HIGH'
        Baseline='0'
        Observed= $(if ($maq -ne $null) { [int]$maq } else { 'Unknown' })
        IsFinding=$maqFinding
        Recommendation='Set ms-DS-MachineAccountQuota to 0; delegate domain join to a controlled group/process; monitor computer object creation.'
    }

    # Duplicate passwords (requires DSInternals)
    $dupSummaryObj = [pscustomobject]@{
        RiskId='PWD_DUPLICATE'
        Category='Credential Hygiene'
        Item='Duplicate passwords (duplicate NT hashes)'
        Severity='CRITICAL'
        Baseline='0'
        Observed='Not evaluated (DSInternals not available)'
        IsFinding=$false
        Recommendation='Eliminate password reuse; enforce unique passwords; use password filters / banned password lists; monitor for duplicates.'
    }
    $dupDetails = @()

    if (Import-ADAuditModule -Name DSInternals) {
        try {
            $dcObj = Get-ADDomainController -Discover
            $dc = $dcObj.DNSHostName
            if (-not $dc) { $dc = $dcObj.HostName }
            if (-not $dc) { $dc = $dcObj.Name }
            $dc = [string]$dc

            $domain = Get-ADDomain
            $domainDN = $domain.DistinguishedName

            $replAccounts = Get-ADAuditReplAccountsCached -Server $dc -NamingContext $domainDN
            $hashGroups = @()

            foreach ($ra in $replAccounts) {
                $sam = $ra.SamAccountName
                $hex = _ToHex -Bytes $ra.NTHash
                if ($sam -and $hex) {
                    $hashGroups += [pscustomobject]@{ SamAccountName=$sam; NTHash=$hex }
                }
            }

            $dups = $hashGroups | Group-Object NTHash | Where-Object { $_.Count -gt 1 } |
                Sort-Object { @(($_.Group | Select-Object -ExpandProperty SamAccountName | Sort-Object))[0] }

            $dupGroupIndex = 0
            foreach ($g in $dups) {
                $dupGroupIndex++
                $members = @($g.Group | Select-Object -ExpandProperty SamAccountName | Sort-Object)
                $groupLabel = ('PWD-REUSE-{0:d3}' -f $dupGroupIndex)
                $samePasswordAccounts = [string]::Join('; ', $members)

                foreach ($m in $members) {
                    $isPrivileged = $privSamSet.Contains([string]$m)
                    $dupDetails += [pscustomobject]@{
                        RiskId='PWD_DUPLICATE'
                        PasswordGroup=$groupLabel
                        SharedCount=@($members).Count
                        SamAccountName=$m
                        SamePasswordAccounts=$samePasswordAccounts
                        IsPrivileged=$isPrivileged
                        Severity= $(if ($isPrivileged) { 'CRITICAL' } else { 'HIGH' })
                        Baseline='0'
                    }
                }
            }

            $dupDetails = @($dupDetails | Sort-Object PasswordGroup, SamAccountName)

            $dupCount = ($dups | Measure-Object).Count
            $dupSummaryObj = [pscustomobject]@{
                RiskId='PWD_DUPLICATE'
                Category='Credential Hygiene'
                Item='Duplicate passwords (duplicate NT hashes)'
                Severity='CRITICAL'
                Baseline='0'
                Observed="$dupCount duplicate-hash groups; $($dupDetails.Count) affected accounts"
                IsFinding=($dupDetails.Count -gt 0)
                Recommendation='Eliminate password reuse; prioritize privileged accounts; enforce unique passwords; rotate; consider banned password lists.'
            }
        } catch {
            # Keep default "Not evaluated" if anything fails
        }
    }

    # Build summary table
    $summary = @()
    $summary += $privSummary
    if ($daOverlapSummaryObj) { $summary += $daOverlapSummaryObj }
    $summary += $krbtgtObj
    $summary += $inactiveObj
    $summary += $pneObj
    $summary += $disabledOldObj
    $summary += $maqObj
    $summary += $dupSummaryObj

    # Write TXT report (with baseline table embedded)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("=== Active Directory High Risk Baseline Report ===")
    $lines.Add("Generated: $(Get-Date -Format o)")
    try {
        $d = Get-ADDomain
        $lines.Add("Domain:   $($d.DNSRoot)")
        $lines.Add("Forest:   $((Get-ADForest).Name)")
    } catch { }
    $lines.Add("")
    $lines.Add("Baseline (target values)")
    $lines.Add(('-' * 80))
    foreach ($k in $baseline.Keys) { $lines.Add(("{0}: {1}" -f $k, $baseline[$k])) }
    $lines.Add("")
    $lines.Add("Findings")
    $lines.Add(('-' * 80))

    $crit = $summary | Where-Object { $_.IsFinding -eq $true -and $_.Severity -eq 'CRITICAL' }
    $high = $summary | Where-Object { $_.IsFinding -eq $true -and $_.Severity -eq 'HIGH' }
    $med  = $summary | Where-Object { $_.IsFinding -eq $true -and $_.Severity -eq 'MEDIUM' }

    foreach ($item in ($crit | Sort-Object RiskId,Item)) {
        $lines.Add("[CRITICAL] $($item.Item) | Observed: $($item.Observed) | Baseline: $($item.Baseline)")
    }
    foreach ($item in ($high | Sort-Object RiskId,Item)) {
        $lines.Add("[HIGH]     $($item.Item) | Observed: $($item.Observed) | Baseline: $($item.Baseline)")
    }
    foreach ($item in ($med | Sort-Object RiskId,Item)) {
        $lines.Add("[MEDIUM]   $($item.Item) | Observed: $($item.Observed) | Baseline: $($item.Baseline)")
    }

    if (($crit | Measure-Object).Count -eq 0 -and ($high | Measure-Object).Count -eq 0 -and ($med | Measure-Object).Count -eq 0) {
        $lines.Add("[OK] No high-risk findings detected by this baseline.")
    }

    $lines.Add("")
    $lines.Add("Recommendations (per finding)")
    $lines.Add(('-' * 80))
    foreach ($item in ($summary | Where-Object { $_.IsFinding -eq $true } | Sort-Object Severity,RiskId,Item)) {
        $lines.Add("$($item.RiskId) [$($item.Severity)] $($item.Item)")
        $lines.Add("  Baseline: $($item.Baseline)")
        $lines.Add("  Observed: $($item.Observed)")
        $lines.Add("  Action:   $($item.Recommendation)")
        $lines.Add("")
    }

    $lines | Out-File -FilePath $txtPath -Encoding UTF8

    # Export CSVs (one per risk + overall summary)
    $summary | Select-Object RiskId,Category,Item,Severity,Baseline,Observed,IsFinding,Recommendation |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path $summaryCsv

    # Per-risk detail CSVs
    $privDetails  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $riskOutDir 'PRIVILEGED_GROUPS.csv')
    $inactiveDetails | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $riskOutDir 'INACTIVE_ACCOUNTS.csv')
    $pneDetails   | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $riskOutDir 'PASSWORD_NEVER_EXPIRES.csv')
    $disabledOldDetails | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $riskOutDir 'DISABLED_STALE.csv')
    @($krbtgtObj) | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $riskOutDir 'KRBTGT.csv')
    @($maqObj)    | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $riskOutDir 'MACHINE_ACCOUNT_QUOTA.csv')
    $dupDetails   | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $riskOutDir 'DUPLICATE_PASSWORDS.csv')

    # HTML index (replaces XLSX requirement; no external modules)
$indexPath = Join-Path (Get-HtmlReportsDir -BaseRoot $outputdir) 'ad_high_risk_baseline_index.html'
$html = New-Object System.Collections.Generic.List[string]
$html.Add((Get-ADAuditReportHeader -Title 'AD High Risk Baseline Report'))
$html.Add("<div class='hero'><h1>Active Directory High Risk Baseline Report</h1>")
$domainMeta = ''
try {
    $d = Get-ADDomain
    $domainMeta = "Domain: <code>$($d.DNSRoot)</code> &mdash; Forest: <code>$((Get-ADForest).Name)</code> &mdash; "
} catch { }
$html.Add("<div class='meta'>${domainMeta}Generated: $(Get-Date -Format 'u')</div></div>")

$critCount = ($crit | Measure-Object).Count
$highCount = ($high | Measure-Object).Count
$medCount  = ($med  | Measure-Object).Count
$html.Add("<div class='stats'>")
$html.Add("<div class='stat'><div class='val'>$($critCount + $highCount + $medCount)</div><div class='lbl'>Total Findings</div></div>")
$html.Add("<div class='stat'><div class='val' style='color:var(--critical)'>$critCount</div><div class='lbl'>Critical</div></div>")
$html.Add("<div class='stat'><div class='val' style='color:var(--high)'>$highCount</div><div class='lbl'>High</div></div>")
$html.Add("<div class='stat'><div class='val' style='color:var(--medium)'>$medCount</div><div class='lbl'>Medium</div></div>")
$html.Add("</div>")

$html.Add('<h2>Baseline (target values)</h2>')
$html.Add('<table><thead><tr><th>Control</th><th>Baseline</th></tr></thead><tbody>')
foreach ($k in $baseline.Keys) {
    $html.Add("<tr><td>$([System.Security.SecurityElement]::Escape([string]$k))</td><td><code>$([System.Security.SecurityElement]::Escape([string]$baseline[$k]))</code></td></tr>")
}
$html.Add('</tbody></table>')

$html.Add('<h2>Evidence Files</h2><ul class="link-list">')
$html.Add("<li><a href='../Raw Data/Source/ad_high_risk_baseline.txt'>Executive TXT report (includes baseline + findings)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/Summary.csv'>Summary CSV</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/PRIVILEGED_GROUPS.csv'>Privileged group membership (detail)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/accounts_domain_admins_group_overlap.csv'>Domain Admins group overlap (detail)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/KRBTGT.csv'>krbtgt password age (detail)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/INACTIVE_ACCOUNTS.csv'>Inactive enabled accounts (detail)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/PASSWORD_NEVER_EXPIRES.csv'>Password never expires (detail)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/DISABLED_STALE.csv'>Disabled stale accounts (detail)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/MACHINE_ACCOUNT_QUOTA.csv'>MachineAccountQuota (detail)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/DUPLICATE_PASSWORDS.csv'>Duplicate passwords (detail; requires DSInternals + replication privileges)</a></li>")
$html.Add('</ul>')

$html.Add('<h2>Finding Counts</h2>')
$html.Add('<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>')
$html.Add("<tr><td><span class='badge badge-critical'>CRITICAL</span></td><td>$critCount</td></tr>")
$html.Add("<tr><td><span class='badge badge-high'>HIGH</span></td><td>$highCount</td></tr>")
$html.Add("<tr><td><span class='badge badge-medium'>MEDIUM</span></td><td>$medCount</td></tr>")
$html.Add('</tbody></table>')

$html.Add((Get-ADAuditReportFooter))
$html | Out-File -Encoding UTF8 -FilePath $indexPath
Write-Both "    [+] High-risk AD baseline report generated: ad_high_risk_baseline.txt"
    Write-Both "    [+] High-risk CSVs generated in: $riskOutDir"
    if (Test-Path $indexPath) { Write-Both "    [+] High-risk HTML index generated: ad_high_risk_baseline_index.html" }
}

function Invoke-HighRiskCheck {
    Get-HighRiskADBaselineReport
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select highrisk @args
}