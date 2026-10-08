<#
    .SYNOPSIS
        ADAudit check: Accounts Audit

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -accounts). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-AccountsCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select accounts [options]

    .NOTES
        Entry point: Invoke-AccountsCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
Function Get-PrivilegedGroupAccounts {
    #Lists users in Admininstrators, DA and EA groups
    [array]$privilegedusers = @()
    $privilegedusers += Get-ADGroupMember $Administrators   -Recursive
    $privilegedusers += Get-ADGroupMember $DomainAdmins     -Recursive
    $privilegedusers += Get-ADGroupMember $EnterpriseAdmins -Recursive
    $privusersunique = $privilegedusers | Sort-Object -Unique
    $count = 0
    $totalcount = ($privilegedusers | Measure-Object | Select-Object Count).count
    foreach ($account in $privusersunique) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for users who are in privileged groups..." -Status "Currently identified $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path (Get-EvidencePath 'accounts_userPrivileged.txt') -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    Write-Progress -Activity "Searching for users who are in privileged groups..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] There are $count accounts in privileged groups, see accounts_userPrivileged.txt (KB426)"
        Write-Nessus-Finding "PrivilegedGroupMembers" "KB426" ([System.IO.File]::ReadAllText((Get-EvidencePath 'accounts_userPrivileged.txt')))
    }
}

# ---------------------------------------------------------------------------
# Domain Admins size-adjusted review (KB427)
# Microsoft AD guidance is that Domain Admins should be empty for day-to-day
# work and only used for build / disaster recovery, with everything else
# delegated. Many security baselines pin a static benchmark of 5. Real
# environments scale: a 100-user shop with 6 named DAs is high risk; a
# 3,000-user shop with 6 named DAs is "review and justify, not necessarily
# break-glass-fail". The functions below let the script reflect that without
# normalising dangerous DA sprawl - scaling is capped at 10, and any service
# account / computer / gMSA / nested group inside DA is automatic Critical.
# ---------------------------------------------------------------------------
Function Get-DomainAdminTargetMax {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$EnabledHumanUsers)
    if ($EnabledHumanUsers -le 100)   { return 2 }
    if ($EnabledHumanUsers -le 500)   { return 3 }
    if ($EnabledHumanUsers -le 1000)  { return 4 }
    if ($EnabledHumanUsers -le 1500)  { return 5 }
    if ($EnabledHumanUsers -le 2500)  { return 6 }
    if ($EnabledHumanUsers -le 5000)  { return 8 }
    return 10
}

Function Get-DomainAdminSizeAdjustedLimit {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$EnabledHumanUsers)
    if ($EnabledHumanUsers -le 500) { return 5 }
    $limit = 5 + [math]::Ceiling(($EnabledHumanUsers - 500) / 1000)
    return [math]::Min([int]$limit, 10)   # hard cap - scaling stops here
}

Function Get-PrincipalKindForDA {
    <#
    .SYNOPSIS
        Classifies a Domain Admins (or other privileged group) member into one
        of: BuiltinAdmin500, gMSA, Computer, Service, NestedGroup, NormalUser,
        Unknown. Used to count "high risk" inhabitants regardless of total
        membership count.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Member,
        [string]$DomainSid
    )
    if (-not $Member) { return 'Unknown' }

    $sid = $null
    try { $sid = [string]$Member.SID } catch { $sid = $null }
    # Get-ADObject-hydrated members carry objectSid instead of the SID extended property
    if ([string]::IsNullOrEmpty($sid)) {
        try { $sid = [string]$Member.objectSid } catch { $sid = $null }
    }
    $cls = ''
    try { $cls = [string]$Member.objectClass } catch { $cls = '' }
    $sam = [string]$Member.SamAccountName

    # Built-in domain Administrator (RID-500) - exclude only THIS specific
    # account. Local Administrators on member servers do not appear in
    # Get-ADGroupMember results, so no further filter is needed.
    if ($sid -and $DomainSid -and ($sid -ieq "$DomainSid-500")) {
        return 'BuiltinAdmin500'
    }

    if ($cls -ieq 'msDS-GroupManagedServiceAccount') { return 'gMSA' }
    if ($cls -ieq 'computer')                        { return 'Computer' }
    if ($cls -ieq 'group')                           { return 'NestedGroup' }

    if ($sam -and $sam.EndsWith('$')) { return 'Computer' }   # MSA / computer
    if ($sam -match '^(svc|sa)[\-_]|[\-_](svc|service|sa)$|^service[\-_]') {
        return 'Service'
    }

    # Best-effort SPN check - any account holding SPNs is acting as a service
    try {
        if ($Member.PSObject.Properties['servicePrincipalName'] -and
            $Member.servicePrincipalName -and $Member.servicePrincipalName.Count -gt 0) {
            return 'Service'
        }
    } catch { }

    return 'NormalUser'
}

Function Get-DomainAdminScaledRisk {
    <#
    .SYNOPSIS
        Reviews Domain Admins membership against AD size, classifies each
        member, computes a size-adjusted severity, and writes two evidence
        files: domain_admins_scaled.txt (the main review) and
        domain_admin_builtin_rid500.txt (RID-500 hygiene). Both files start
        with a 'Severity:' header so Invoke-ManagementReport can pick up
        the precomputed severity directly.
    .NOTES
        Severity model:
          - High-risk members > 0  -> Critical
          - Effective permanent > hard cap (10)  -> High
          - Effective permanent > size-adjusted limit  -> High
          - Effective permanent > static benchmark (5) -> Medium
          - Effective permanent > recommended target   -> Low
          - Else -> Information
    #>
    [CmdletBinding()]
    param()

    Write-Both "    [+] Reviewing Domain Admins against AD size and principal class (KB427)"

    try {
        Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null
    } catch {
        Write-Both "    [!] Domain Admins review skipped: ActiveDirectory module not available."
        return
    }

    $domain = $null
    try { $domain = Get-ADDomain -ErrorAction Stop } catch {
        Write-Both "    [!] Domain Admins review skipped: Get-ADDomain failed ($($_.Exception.Message))"
        return
    }
    $domainSid = $domain.DomainSID.Value
    $domainDns = $domain.DNSRoot

    # Enabled human AD users denominator. Best-effort exclusion of service
    # principals (sAMAccountName ending '$', gMSAs, common service-naming
    # patterns). The denominator is for SIZE, not for finding generation, so
    # mild over/under counting is OK.
    $enabledHumanUsers = 0
    try {
        $allEnabledUsers = @(Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Properties servicePrincipalName -ErrorAction Stop)
        foreach ($u in $allEnabledUsers) {
            $samLower = ([string]$u.SamAccountName).ToLowerInvariant()
            if ($samLower.EndsWith('$')) { continue }
            if ($samLower -match '^(svc|sa)[\-_]|[\-_](svc|service|sa)$|^service[\-_]') { continue }
            $enabledHumanUsers++
        }
    } catch {
        Write-Both "    [!] Could not enumerate enabled users for size context: $($_.Exception.Message)"
    }

    $targetMax  = Get-DomainAdminTargetMax       -EnabledHumanUsers $enabledHumanUsers
    $sizeLimit  = Get-DomainAdminSizeAdjustedLimit -EnabledHumanUsers $enabledHumanUsers
    $hardCap    = 10
    $staticBenchmark = 5

    # Walk Domain Admins recursively. Capture each member's principal kind
    # plus disabled/stale signals. -Recursive expands nested groups, so the
    # member set is the *effective* set; nested-group detection is done by a
    # separate non-recursive pass (so we know when a nested group is hiding
    # large effective membership behind a single direct entry).
    $effectiveMembers = @()
    try {
        $effectiveMembers = @(Get-ADGroupMember -Identity $script:DomainAdminsSID -Recursive -ErrorAction Stop)
    } catch {
        Write-Both "    [!] Could not enumerate Domain Admins members: $($_.Exception.Message)"
        return
    }
    $directMembers = @()
    try {
        $directMembers = @(Get-ADGroupMember -Identity $script:DomainAdminsSID -ErrorAction Stop)
    } catch { }

    $directNestedGroups = @($directMembers | Where-Object { $_.objectClass -ieq 'group' })
    $directNestedGroupCount = $directNestedGroups.Count

    # Direct nested groups hide effective membership behind a single direct
    # entry. Treat them as high-risk principals in their own right (in
    # addition to evaluating their expanded members below).
    $nestedGroupRows = @()
    foreach ($g in $directNestedGroups) {
        $nestedGroupRows += [pscustomobject]@{
            SamAccountName = $g.SamAccountName
            DN             = $g.distinguishedName
            Kind           = 'NestedGroup'
            Enabled        = $true
            Stale          = $false
        }
    }

    # Hydrate each effective member with the attributes we need to classify.
    $rows = @()
    foreach ($m in $effectiveMembers) {
        $obj = $null
        $hydrated = $false
        try {
            # NOTE: 'Enabled' is NOT a valid Get-ADObject property (it is an extended
            # property of Get-ADUser/Get-ADComputer only) and requesting it throws for
            # every member. Derive enabled state from userAccountControl (bit 0x2) instead.
            $obj = Get-ADObject -Identity $m.distinguishedName -Properties SamAccountName, userAccountControl, lastLogonTimestamp, servicePrincipalName, objectClass, sIDHistory, objectSid -ErrorAction Stop
            $hydrated = $true
        } catch {
            $obj = $m
            Write-Both "        [i] Could not fully hydrate Domain Admins member $($m.distinguishedName): $($_.Exception.Message)"
        }
        $kind = Get-PrincipalKindForDA -Member $obj -DomainSid $domainSid
        # Default to enabled/not-stale on a hydration failure so we do not falsely
        # escalate the whole finding to Critical when a single member cannot be read.
        $enabled = $true
        if ($hydrated -and $obj.PSObject.Properties['userAccountControl'] -and $null -ne $obj.userAccountControl) {
            $enabled = -not ([bool]([int]$obj.userAccountControl -band 0x2))
        }
        $stale = $false
        if ($hydrated) {
            try {
                if ($obj.lastLogonTimestamp) {
                    $llt = [DateTime]::FromFileTime([long]$obj.lastLogonTimestamp)
                    if ($llt -lt (Get-Date).AddDays(-90)) { $stale = $true }
                } else {
                    $stale = $true   # never logged on
                }
            } catch { }
        }
        $rows += [pscustomobject]@{
            SamAccountName = $obj.SamAccountName
            DN             = $m.distinguishedName
            Kind           = $kind
            Enabled        = $enabled
            Stale          = $stale
        }
    }

    $rid500Count   = ($rows | Where-Object { $_.Kind -eq 'BuiltinAdmin500' }).Count
    $effectivePerm = ($rows | Where-Object { $_.Kind -eq 'NormalUser' -and $_.Enabled }).Count
    $highRiskFromRecursive = $rows | Where-Object {
        $_.Kind -in @('Service','Computer','gMSA') -or
        (-not $_.Enabled -and $_.Kind -ne 'BuiltinAdmin500') -or
        ($_.Kind -eq 'NormalUser' -and $_.Stale -and $_.Enabled)
    }
    # Direct nested groups are high-risk regardless: they hide effective
    # membership and complicate access reviews.
    $highRiskRows  = @($highRiskFromRecursive) + @($nestedGroupRows)
    $highRiskCount = ($highRiskRows | Measure-Object).Count

    # Severity ladder
    $severity = 'Information'
    $reason   = 'Permanent Domain Admin count is within the recommended target.'
    if ($highRiskCount -gt 0) {
        $severity = 'Critical'
        $reason   = "$highRiskCount high-risk principal(s) inside Domain Admins (service / computer / gMSA / nested / stale / disabled-but-member). High risk regardless of total count."
    }
    elseif ($effectivePerm -gt $hardCap) {
        $severity = 'High'
        $reason   = "Effective permanent named Domain Admins ($effectivePerm) exceeds the hard cap ($hardCap). Scaling stops here - use PAM/PIM/JIT or temporary elevation."
    }
    elseif ($effectivePerm -gt $sizeLimit) {
        $severity = 'High'
        $reason   = "Effective permanent named Domain Admins ($effectivePerm) exceeds the size-adjusted threshold ($sizeLimit) for $enabledHumanUsers enabled human users."
    }
    elseif ($effectivePerm -gt $staticBenchmark) {
        $severity = 'Medium'
        $reason   = "Effective permanent named Domain Admins ($effectivePerm) is above the static benchmark of $staticBenchmark, but within the size-adjusted threshold ($sizeLimit). Validate business justification."
    }
    elseif ($effectivePerm -gt $targetMax) {
        $severity = 'Low'
        $reason   = "Effective permanent named Domain Admins ($effectivePerm) is within the size-adjusted threshold but above the recommended target ($targetMax) for this AD size."
    }

    # Other privileged groups (folded in for one-stop review)
    $otherGroups = @(
        @{ Name = $script:Administrators;   SID = 'S-1-5-32-544' }
        @{ Name = $script:EnterpriseAdmins; SID = $script:EnterpriseAdminsSID }
        @{ Name = $script:SchemaAdmins;     SID = $script:SchemaAdminsSID }
    )
    $extraBuiltins = @('Backup Operators','Account Operators','Server Operators','Print Operators','Group Policy Creator Owners','Cert Publishers')
    foreach ($n in $extraBuiltins) {
        try {
            $g = Get-ADGroup -Identity $n -ErrorAction SilentlyContinue
            if ($g) { $otherGroups += @{ Name = $g.SamAccountName; SID = $g.SID.Value } }
        } catch { }
    }
    $otherGroupSummaries = @()
    foreach ($og in $otherGroups) {
        if ([string]::IsNullOrWhiteSpace($og.Name)) { continue }
        $members = @()
        try { $members = @(Get-ADGroupMember -Identity $og.SID -Recursive -ErrorAction Stop) } catch { continue }
        $kindCounts = @{ BuiltinAdmin500=0; NormalUser=0; Service=0; Computer=0; gMSA=0; NestedGroup=0; Unknown=0 }
        $rowsLocal = @()
        foreach ($m in $members) {
            $obj = $m
            try { $obj = Get-ADObject -Identity $m.distinguishedName -Properties SamAccountName, objectClass, servicePrincipalName, objectSid -ErrorAction Stop } catch { }
            $k = Get-PrincipalKindForDA -Member $obj -DomainSid $domainSid
            if (-not $kindCounts.ContainsKey($k)) { $kindCounts[$k] = 0 }
            $kindCounts[$k]++
            $rowsLocal += [pscustomobject]@{ Sam = $obj.SamAccountName; Kind = $k }
        }
        $otherGroupSummaries += [pscustomobject]@{
            Group   = $og.Name
            Members = $members.Count
            Counts  = $kindCounts
            Rows    = $rowsLocal
        }
    }

    # ---- Write the main evidence file ----
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=========================================')
    [void]$sb.AppendLine('  DOMAIN ADMINS - SIZE-ADJUSTED REVIEW')
    [void]$sb.AppendLine('=========================================')
    [void]$sb.AppendLine("Severity: $severity")
    [void]$sb.AppendLine("Generated: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))")
    [void]$sb.AppendLine("Domain: $domainDns")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('----- COUNTS -----')
    [void]$sb.AppendLine("Enabled human AD users (denominator): $enabledHumanUsers")
    [void]$sb.AppendLine("Total Domain Admins members (recursive): $($rows.Count)")
    [void]$sb.AppendLine("  - Built-in domain Administrator (RID-500): $rid500Count")
    [void]$sb.AppendLine("  - Effective permanent named (enabled human): $effectivePerm")
    [void]$sb.AppendLine("  - High-risk (service/computer/gMSA/nested/stale/disabled-but-member): $highRiskCount")
    [void]$sb.AppendLine("  - Direct nested groups in Domain Admins: $directNestedGroupCount")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('----- THRESHOLDS -----')
    [void]$sb.AppendLine("Static benchmark (Microsoft baseline):       $staticBenchmark")
    [void]$sb.AppendLine("Recommended target for this AD size:         $targetMax")
    [void]$sb.AppendLine("Size-adjusted threshold (severity floor):    $sizeLimit")
    [void]$sb.AppendLine("Hard cap (PAM/PIM/JIT recommended beyond):   $hardCap")
    [void]$sb.AppendLine('Formula: limit = min(10, 5 + ceil((users - 500) / 1000))')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('----- VERDICT -----')
    [void]$sb.AppendLine("Severity: $severity")
    [void]$sb.AppendLine("Reason: $reason")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('----- WHY IT MATTERS -----')
    [void]$sb.AppendLine('Microsoft AD guidance is that Domain Admins is intended for build')
    [void]$sb.AppendLine('and disaster-recovery scenarios only, with day-to-day work performed')
    [void]$sb.AppendLine('via delegated administration, tiered admin accounts, and temporary')
    [void]$sb.AppendLine('elevation (PAM / PIM / JIT). Many security baselines use 5 named')
    [void]$sb.AppendLine('Domain Admins as a static benchmark. Service accounts, computer')
    [void]$sb.AppendLine('accounts, gMSAs and nested groups in Domain Admins are dangerous')
    [void]$sb.AppendLine('regardless of count: long-lived credentials, weak interactive')
    [void]$sb.AppendLine('monitoring, and effective-membership inflation through nesting.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('----- HOW TO FIX -----')
    [void]$sb.AppendLine(' - Reduce permanent Domain Admins membership where possible.')
    [void]$sb.AppendLine(' - Use delegated administration for routine tasks (do NOT add admins to DA for OU/GPO work).')
    [void]$sb.AppendLine(' - Use temporary group membership for high-privilege tasks:')
    [void]$sb.AppendLine('     Add-ADGroupMember -Identity "Domain Admins" -Members <admin> -MemberTimeToLive (New-TimeSpan -Hours 4)')
    [void]$sb.AppendLine('   (requires Privileged Access Management Feature enabled at the forest level).')
    [void]$sb.AppendLine(' - Adopt a third-party PAM (CyberArk / Delinea / BeyondTrust) or MIM PAM (isolated/legacy only).')
    [void]$sb.AppendLine(' - Move all service workloads off Domain Admins. gMSAs that need elevation should be granted ')
    [void]$sb.AppendLine('   targeted rights via delegation, not blanket DA membership.')
    [void]$sb.AppendLine(' - Note: Microsoft Entra PIM for Groups does NOT cover on-prem-synced groups, so it is not a')
    [void]$sb.AppendLine('   direct native solution for the on-prem Domain Admins group.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('----- DOMAIN ADMINS MEMBERS -----')
    $allMembersForDisplay = @($rows) + @($nestedGroupRows)
    foreach ($r in ($allMembersForDisplay | Sort-Object Kind, SamAccountName)) {
        $flags = @()
        if (-not $r.Enabled) { $flags += 'DISABLED' }
        if ($r.Stale)        { $flags += 'STALE>90d' }
        $flagStr = if ($flags.Count -gt 0) { ' [' + ($flags -join ',') + ']' } else { '' }
        [void]$sb.AppendLine(("  [{0}] {1}{2}    {3}" -f $r.Kind.PadRight(15), $r.SamAccountName, $flagStr, $r.DN))
    }
    [void]$sb.AppendLine('')
    if ($highRiskCount -gt 0) {
        [void]$sb.AppendLine('----- HIGH-RISK MEMBERS DETAIL -----')
        foreach ($r in $highRiskRows) {
            $whys = @()
            if ($r.Kind -in @('Service','Computer','gMSA','NestedGroup')) { $whys += "principal type = $($r.Kind)" }
            if (-not $r.Enabled -and $r.Kind -ne 'BuiltinAdmin500')        { $whys += 'disabled but still a member' }
            if ($r.Kind -eq 'NormalUser' -and $r.Stale -and $r.Enabled)    { $whys += 'no logon in 90 days' }
            [void]$sb.AppendLine(("  [{0}] {1}: {2}" -f $r.Kind.PadRight(15), $r.SamAccountName, ($whys -join '; ')))
        }
        [void]$sb.AppendLine('')
    }
    [void]$sb.AppendLine('----- OTHER PRIVILEGED GROUPS (one-stop review) -----')
    [void]$sb.AppendLine('(Folded in from accounts_userPrivileged.txt sources. RID-500 visibility is')
    [void]$sb.AppendLine(' broken out so you can see where the same account shows up across groups.)')
    [void]$sb.AppendLine('')
    foreach ($og in $otherGroupSummaries) {
        $c = $og.Counts
        [void]$sb.AppendLine(("Group: {0}    members={1}  (Users={2}  Service={3}  Computer={4}  gMSA={5}  Nested={6}  RID-500={7})" -f `
            $og.Group, $og.Members,
            ([int]$c['NormalUser']), ([int]$c['Service']), ([int]$c['Computer']),
            ([int]$c['gMSA']), ([int]$c['NestedGroup']), ([int]$c['BuiltinAdmin500'])))
        foreach ($m in ($og.Rows | Sort-Object Kind, Sam)) {
            [void]$sb.AppendLine(("    [{0}] {1}" -f $m.Kind.PadRight(15), $m.Sam))
        }
        [void]$sb.AppendLine('')
    }

    Set-Content -LiteralPath (Get-EvidencePath 'domain_admins_scaled.txt') -Value $sb.ToString() -Encoding UTF8
    Write-Both "    [!] Domain Admins review: severity=$severity (effective=$effectivePerm, high-risk=$highRiskCount, threshold=$sizeLimit, target=$targetMax for $enabledHumanUsers users). See domain_admins_scaled.txt"

    # Pass the computed size-adjusted severity; Get-NessusSeverityTuple has no
    # 'Information' case, so map it to the tuple's 'Info' key.
    $nessusSev = if ($severity -eq 'Information') { 'Info' } else { $severity }
    Write-Nessus-Finding "DomainAdminsSizeAdjustedReview" "KB427" ([System.IO.File]::ReadAllText((Get-EvidencePath 'domain_admins_scaled.txt'))) $nessusSev

    # ---- RID-500 hygiene as a separate finding ----
    $rid500Sev = 'Information'
    $rid500Reason = 'Built-in domain Administrator (RID-500) is present and looks healthy. Continue to use it only as a documented break-glass / disaster-recovery account.'
    $rid500Lines = New-Object System.Text.StringBuilder
    [void]$rid500Lines.AppendLine('=========================================')
    [void]$rid500Lines.AppendLine('  BUILT-IN DOMAIN ADMINISTRATOR (RID-500) HYGIENE')
    [void]$rid500Lines.AppendLine('=========================================')
    try {
        $rid500 = Get-ADUser -Identity "$domainSid-500" -Properties PasswordLastSet, LastLogonDate, servicePrincipalName, Enabled, 'msDS-SupportedEncryptionTypes', AccountNotDelegated, MemberOf -ErrorAction Stop
        $pwdAgeDays = if ($rid500.PasswordLastSet) { [int]((Get-Date) - $rid500.PasswordLastSet).TotalDays } else { -1 }
        $hasSpn     = ($rid500.servicePrincipalName -and $rid500.servicePrincipalName.Count -gt 0)

        $issues = @()
        # A DISABLED built-in Administrator is the recommended hardened posture, not a
        # finding - do not flag it. (The account's enabled state is still recorded in the
        # evidence file below for context.)
        if ($pwdAgeDays -ge 0 -and $pwdAgeDays -gt 180) { $issues += "password age $pwdAgeDays days (>180d) - rotate" }
        if ($hasSpn) { $issues += 'has SPN(s) - is being used as a service account' }
        try {
            $protectedUsersGroup = Get-ADGroup -Identity ("$domainSid-525") -ErrorAction SilentlyContinue
            if ($protectedUsersGroup -and $rid500.MemberOf -and ($rid500.MemberOf -notcontains $protectedUsersGroup.DistinguishedName)) {
                $issues += 'not a member of Protected Users (consider adding once break-glass procedures account for it)'
            }
        } catch { }

        if ($issues.Count -gt 0) {
            $rid500Sev = if ($issues -match 'SPN' -or $issues -match 'rotate') { 'High' } else { 'Medium' }
            $rid500Reason = "Issues with built-in RID-500 account: " + ($issues -join '; ')
        }

        # Build evidence content
        $rid500EvSb = New-Object System.Text.StringBuilder
        [void]$rid500EvSb.AppendLine("Severity: $rid500Sev")
        [void]$rid500EvSb.AppendLine("Generated: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))")
        [void]$rid500EvSb.AppendLine("Domain: $domainDns")
        [void]$rid500EvSb.AppendLine('')
        [void]$rid500EvSb.AppendLine("Account: $($rid500.SamAccountName)  ($($rid500.DistinguishedName))")
        [void]$rid500EvSb.AppendLine("SID: $($rid500.SID)")
        [void]$rid500EvSb.AppendLine("Enabled: $($rid500.Enabled)")
        [void]$rid500EvSb.AppendLine("PasswordLastSet: $(if ($rid500.PasswordLastSet) { $rid500.PasswordLastSet } else { 'never' }) (age: $pwdAgeDays days)")
        [void]$rid500EvSb.AppendLine("LastLogonDate: $(if ($rid500.LastLogonDate) { $rid500.LastLogonDate } else { 'never' })")
        [void]$rid500EvSb.AppendLine("Has SPN(s): $hasSpn")
        if ($issues.Count -gt 0) {
            [void]$rid500EvSb.AppendLine('')
            [void]$rid500EvSb.AppendLine('Issues:')
            foreach ($i in $issues) { [void]$rid500EvSb.AppendLine("  - $i") }
        }
        [void]$rid500EvSb.AppendLine('')
        [void]$rid500EvSb.AppendLine("Reason: $rid500Reason")
        [void]$rid500EvSb.AppendLine('')
        [void]$rid500EvSb.AppendLine('----- WHY IT MATTERS -----')
        [void]$rid500EvSb.AppendLine('The built-in domain Administrator account cannot be deleted, has unrestricted access in the domain (and the')
        [void]$rid500EvSb.AppendLine('forest, in the root domain), is the prime target if the account or its password is compromised, and is')
        [void]$rid500EvSb.AppendLine('explicitly flagged by Microsoft Defender for Identity when the password is older than 180 days.')
        [void]$rid500EvSb.AppendLine('')
        [void]$rid500EvSb.AppendLine('----- HOW TO FIX -----')
        [void]$rid500EvSb.AppendLine(' - Reserve this account for initial build and break-glass / disaster recovery only. Do NOT use for daily admin work.')
        [void]$rid500EvSb.AppendLine(' - Rotate the password on a defined schedule (180 days max recommended) and store it in a sealed/escrowed location.')
        [void]$rid500EvSb.AppendLine(' - Set "Account is sensitive and cannot be delegated" (UAC bit 0x100000).')
        [void]$rid500EvSb.AppendLine(' - Remove any SPNs - this account must not be used as a service account or scheduled task account.')
        [void]$rid500EvSb.AppendLine(' - Restrict interactive logon (e.g. deny logon from workstations / member servers via GPO).')
        [void]$rid500EvSb.AppendLine(' - Consider adding to Protected Users once break-glass procedures account for the Kerberos restrictions.')
        [void]$rid500EvSb.AppendLine(' - Monitor for any logon and group-membership change.')
        Set-Content -LiteralPath (Get-EvidencePath 'domain_admin_builtin_rid500.txt') -Value $rid500EvSb.ToString() -Encoding UTF8
        # Only raise a Nessus finding when there is an actual hygiene issue; a hardened
        # (disabled, fresh password, no SPN) RID-500 should not surface as a finding. Pass
        # the computed severity so the export reflects High/Medium rather than the KB default.
        if ($issues.Count -gt 0) {
            Write-Nessus-Finding "BuiltinDomainAdminRid500" "KB428" ([System.IO.File]::ReadAllText((Get-EvidencePath 'domain_admin_builtin_rid500.txt'))) $rid500Sev
        }
    } catch {
        Write-Both "    [!] Could not inspect RID-500 account: $($_.Exception.Message)"
    }
}

Function Get-ProtectedUsers {
    # Protected Users group: actual Microsoft requirement is Domain Functional
    # Level Windows Server 2012 R2 (the group was introduced in 2012R2 and the
    # KDC-side restrictions ship at that DFL). The previous version of this
    # script gated on Windows2019Domain, which incorrectly skipped the check on
    # 2012R2/2016/2019 server estates that were perfectly capable of running it.
    $DomainLevel = (Get-ADDomain).DomainMode
    $evPath = Get-EvidencePath 'accounts_protectedusers.txt'

    if (Test-ADAuditFunctionalLevelAtLeast -Mode $DomainLevel -MinimumMode 'Windows2012R2Domain') {
        try {
            $ProtectedUsersSID = ((Get-ADDomain -Current LoggedOnUser).DomainSID.Value) + "-525"
            $ProtectedUsers    = (Get-ADGroup -Identity $ProtectedUsersSID).SamAccountName
            $protectedaccounts = (Get-ADGroup $ProtectedUsers -Properties Members).Members
        } catch {
            Write-Both "    [!] Could not query the Protected Users group: $($_.Exception.Message)"
            return
        }

        $count      = 0
        $totalcount = ($protectedaccounts | Measure-Object | Select-Object -ExpandProperty Count)
        foreach ($members in $protectedaccounts) {
            if ($totalcount -eq 0) { break }
            Write-Progress -Activity "Searching for protected users..." -Status "Currently identified $count" -PercentComplete ($count / $totalcount * 100)
            $account = Get-ADObject $members -Properties SamAccountName
            Add-Content -Path $evPath -Value "$($account.SamAccountName) ($($account.Name))"
            $count++
        }
        Write-Progress -Activity "Searching for protected users..." -Status "Ready" -Completed

        if ($count -gt 0) {
            Write-Both "    [!] There are $count accounts in the 'Protected Users' group, see accounts_protectedusers.txt"
            Write-Nessus-Finding "ProtectedUsers" "KB549" ([System.IO.File]::ReadAllText($evPath))
        } else {
            # Empty Protected Users on a domain that supports it is itself a
            # finding - admin accounts almost always SHOULD be in this group.
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine('Protected Users group is EMPTY on this domain.')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("Domain functional level: $DomainLevel (>= Windows2012R2Domain - Protected Users is supported).")
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('Why this matters:')
            [void]$sb.AppendLine(' - Members of Protected Users get hard Kerberos restrictions (no NTLM, no DES,')
            [void]$sb.AppendLine('   no RC4, no unconstrained delegation, no credential delegation, no cached')
            [void]$sb.AppendLine('   logon, ticket lifetime fixed at 4h). These mitigations defeat almost every')
            [void]$sb.AppendLine('   common credential-theft attack: pass-the-hash, overpass-the-hash, ticket')
            [void]$sb.AppendLine('   reuse on cached creds, RC4-based Kerberoasting against admin accounts.')
            [void]$sb.AppendLine(' - Without anyone in the group, admins still log on the way they always have')
            [void]$sb.AppendLine('   and an attacker who lands on a workstation can dump and reuse their hash.')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('How to fix:')
            [void]$sb.AppendLine(' - Add Tier0 / Domain Admin / Enterprise Admin accounts to the Protected Users')
            [void]$sb.AppendLine('   group:  Add-ADGroupMember -Identity "Protected Users" -Members <admin>')
            [void]$sb.AppendLine(' - Roll out gradually. Do NOT add service accounts that depend on NTLM, DES,')
            [void]$sb.AppendLine('   RC4 or unconstrained delegation - they will break.')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('Consequences if NOT fixed:')
            [void]$sb.AppendLine(' - Admin credentials remain stealable from any system the admin signs in to.')
            [void]$sb.AppendLine(' - Kerberos tickets for these accounts can be issued with weak ciphers if')
            [void]$sb.AppendLine('   anything in the trust path is misconfigured.')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('Consequences AFTER you fix it (things to test before rollout):')
            [void]$sb.AppendLine(' - The protected account cannot use NTLM at all - any app that auths via NTLM')
            [void]$sb.AppendLine('   (older SQL Server, some printer/scan-to-folder, legacy line-of-business apps)')
            [void]$sb.AppendLine('   will fail for that user. Test before adding accounts in bulk.')
            [void]$sb.AppendLine(' - The protected account cannot be delegated (constrained or unconstrained),')
            [void]$sb.AppendLine('   so any "double-hop" scenario (e.g. admin runs a tool that fans out via')
            [void]$sb.AppendLine('   Kerberos delegation) will break.')
            [void]$sb.AppendLine(' - Cached logon does not work, so a reachable DC is required at every logon.')
            [void]$sb.AppendLine(' - Ticket lifetime is 4h with no renewal - long-running interactive sessions')
            [void]$sb.AppendLine('   need to re-authenticate.')
            Set-Content -LiteralPath $evPath -Value $sb.ToString() -Encoding UTF8
            Write-Both "    [!] 'Protected Users' group is empty - no Tier0 admins are protected (KB549). See accounts_protectedusers.txt for context, fix, and trade-offs."
            Write-Nessus-Finding "ProtectedUsersEmpty" "KB549" ([System.IO.File]::ReadAllText($evPath))
        }
    }
    else {
        # DFL too low. Write structured guidance to the evidence file so the
        # HTML report and Nessus output have a real finding (not a silent skip).
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("Protected Users check SKIPPED - Domain Functional Level ($DomainLevel) is below Windows2012R2Domain.")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Why this matters:')
        [void]$sb.AppendLine(' - Protected Users is the single most effective Microsoft-provided mitigation')
        [void]$sb.AppendLine('   for credential theft against admin accounts. It only exists at DFL 2012R2+.')
        [void]$sb.AppendLine(' - Below DFL 2012R2 the group cannot be used at all - Tier0 accounts have no')
        [void]$sb.AppendLine('   built-in protection against pass-the-hash, RC4 Kerberoasting, etc.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('How to fix:')
        [void]$sb.AppendLine(' - Raise the Domain Functional Level. From any DC:')
        [void]$sb.AppendLine('     Set-ADDomainMode -Identity (Get-ADDomain) -DomainMode Windows2016Domain')
        [void]$sb.AppendLine('   or via the AD Domains and Trusts MMC. Do this AFTER all DCs are running an')
        [void]$sb.AppendLine('   OS that supports the target DFL (no remaining Server 2008 R2 DCs for 2012R2,')
        [void]$sb.AppendLine('   no remaining 2012R2 DCs for 2016, etc).')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Consequences if NOT fixed:')
        [void]$sb.AppendLine(' - No way to opt admin accounts into the Kerberos hardening Protected Users')
        [void]$sb.AppendLine('   provides. PtH/RC4-roasting/ticket reuse risks remain on every admin.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Consequences AFTER you raise the DFL (review before doing it):')
        [void]$sb.AppendLine(' - Once raised, the DFL cannot be lowered to a downlevel value (Server 2016+ adds')
        [void]$sb.AppendLine('   one-way restrictions). You cannot revert without a domain rebuild.')
        [void]$sb.AppendLine(' - Any DC running an OS below the new DFL must be removed from the domain BEFORE')
        [void]$sb.AppendLine('   raising. The Set-ADDomainMode command fails if a too-old DC is still present.')
        [void]$sb.AppendLine(' - Some legacy clients/applications that explicitly require an older DFL or older')
        [void]$sb.AppendLine('   schema features may stop working - inventory and test before raising.')
        Set-Content -LiteralPath $evPath -Value $sb.ToString() -Encoding UTF8
        Write-Both "    [!] Protected Users check skipped - DFL is $DomainLevel (need Windows2012R2Domain). See accounts_protectedusers.txt for context, fix, and trade-offs."
        Write-Nessus-Finding "ProtectedUsersDflTooLow" "KB549" ([System.IO.File]::ReadAllText($evPath))
    }
}

Function Get-NULLSessions {
    # Anonymous-access (null session) settings live in HKLM\...\Lsa and are a
    # PER-MACHINE setting on each DC. Reading the LOCAL registry only makes sense
    # when the script runs ON a DC; from a jump server it would audit the jump
    # server, not the DCs. So we read each DC's Lsa values via remote registry and
    # mark a DC NotAssessed (not a finding) when it cannot be reached.
    $subKey = 'SYSTEM\CurrentControlSet\Control\Lsa'
    $dcList = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
    if (-not $dcList -or $dcList.Count -eq 0) {
        Register-ADAuditNotAssessed -Name 'Get-NULLSessions' -Switch 'accounts' -Reason "No domain controllers enumerated; cannot assess anonymous-access (null session) registry settings."
        return
    }

    foreach ($dc in $dcList) {
        $ra  = Get-ADAuditRemoteRegistryDword -ComputerName $dc -SubKey $subKey -ValueName 'RestrictAnonymous'
        $ras = Get-ADAuditRemoteRegistryDword -ComputerName $dc -SubKey $subKey -ValueName 'RestrictAnonymousSam'
        $eia = Get-ADAuditRemoteRegistryDword -ComputerName $dc -SubKey $subKey -ValueName 'everyoneincludesanonymous'

        if (-not ($ra.Success -or $ras.Success -or $eia.Success)) {
            Register-ADAuditNotAssessed -Name 'Get-NULLSessions' -Switch 'accounts' -Target $dc -RequiresRemotePS -Reason "Could not read HKLM\...\Lsa anonymous-access values on $dc (remote registry over CIM/DCOM/WinRM unavailable): $($ra.Error)"
            continue
        }

        if ($ra.Success -and $ra.Value -eq 0) {
            Write-Both "    [!] RestrictAnonymous is set to 0 on $dc! (KB81)"
            Write-Nessus-Finding "NullSessions" "KB81" "RestrictAnonymous is set to 0 on $dc"
        }
        if ($ras.Success -and $ras.Value -eq 0) {
            Write-Both "    [!] RestrictAnonymousSam is set to 0 on $dc! (KB81)"
            Write-Nessus-Finding "NullSessions" "KB81" "RestrictAnonymousSam is set to 0 on $dc"
        }
        if ($eia.Success -and $eia.Value -eq 1) {
            Write-Both "    [!] EveryoneIncludesAnonymous is set to 1 on $dc! (KB81)"
            Write-Nessus-Finding "NullSessions" "KB81" "EveryoneIncludesAnonymous is set to 1 on $dc"
        }
    }
}

Function Get-InactiveAccounts {

    [CmdletBinding()]
    param(
        [int]$InactiveDays = 180
    )

    $ErrorActionPreference = 'Stop'

    $count = 0
    $progresscount = 0

    # Output paths (match script convention: txt in root outputdir, csv in HighRisk)
    $txtPath = Get-EvidencePath 'accounts_inactive.txt'
    $highRiskDir = Join-Path (Get-RawSourceDataDir) 'HighRisk'
    $csvPath = Join-Path $highRiskDir ("accounts_inactive_{0}days.csv" -f $InactiveDays)

    if (-not (Test-Path -LiteralPath $highRiskDir)) {
        New-Item -ItemType Directory -Path $highRiskDir -Force | Out-Null
    }

    # lastLogonTimestamp is replicated; good for inactivity reporting
    $cutoffUtc = [datetime]::UtcNow.AddDays(-1 * [math]::Abs($InactiveDays))
    $cutoffFt  = $cutoffUtc.ToFileTimeUtc()

    # Enabled users + inactive (old lastLogonTimestamp or missing)
    $ldapFilter =
        "(&(objectCategory=person)(objectClass=user)" +
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
        "(|(lastLogonTimestamp<=$cutoffFt)(!(lastLogonTimestamp=*))))"

    $props = @('samAccountName','name','distinguishedName','lastLogonTimestamp','whenCreated','pwdLastSet')

    $inactiveUsers = Get-ADUser -LDAPFilter $ldapFilter -Properties $props

    $totalcount = ($inactiveUsers | Measure-Object).Count

    if ($totalcount -gt 0) {
        "Accounts inactive (no logon) for the past $InactiveDays days (based on lastLogonTimestamp)" |
            Set-Content -Encoding UTF8 -Path $txtPath
    } else {
        # Ensure no stale file from previous runs
        if (Test-Path -LiteralPath $txtPath) { Remove-Item -LiteralPath $txtPath -Force -ErrorAction SilentlyContinue }
        # Also clear CSV
        if (Test-Path -LiteralPath $csvPath) { Remove-Item -LiteralPath $csvPath -Force -ErrorAction SilentlyContinue }
    }

    $results = foreach ($u in $inactiveUsers) {
        $progresscount++
        Write-Progress -Activity "Searching for inactive users..." -Status "Currently identified $count" -PercentComplete (($progresscount / [math]::Max($totalcount,1)) * 100)

        $lastLogonUtc = $null
        if ($u.lastLogonTimestamp) {
            try { $lastLogonUtc = [datetime]::FromFileTimeUtc([int64]$u.lastLogonTimestamp) } catch { $lastLogonUtc = $null }
        }

        $pwdLastSetUtc = $null
        if ($u.pwdLastSet) {
            try { $pwdLastSetUtc = [datetime]::FromFileTimeUtc([int64]$u.pwdLastSet) } catch { $pwdLastSetUtc = $null }
        }

        $lltText = if ($lastLogonUtc) { $lastLogonUtc.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' }

        Add-Content -Encoding UTF8 -Path $txtPath -Value "User $($u.SamAccountName) ($($u.Name)) has not logged on since $lltText"
        $count++

        [pscustomobject]@{
            SamAccountName    = $u.SamAccountName
            Name              = $u.Name
            LastLogonDateUTC  = $lastLogonUtc
            PwdLastSetUTC     = $pwdLastSetUtc
            WhenCreated       = $u.whenCreated
            DistinguishedName = $u.DistinguishedName
        }
    }

    Write-Progress -Activity "Searching for inactive users..." -Status "Ready" -Completed

    if ($count -gt 0) {
        # Sort: oldest logon first (nulls last)
        $resultsSorted = $results | Sort-Object @{
            Expression = { if ($_.LastLogonDateUTC) { $_.LastLogonDateUTC } else { [datetime]::MaxValue } }
            Ascending  = $true
        }, SamAccountName

        $resultsSorted | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath

        Write-Both "    [!] $count inactive user accounts($InactiveDays days), see accounts_inactive.txt (KB500)"
        Write-Both "        - CSV: HighRisk\$(Split-Path -Leaf $csvPath)"
        Write-Nessus-Finding "InactiveAccounts" "KB500" ([System.IO.File]::ReadAllText($txtPath))
    }
}

Function Get-AdminAccountChecks {
    #Checks if Administrator account has been renamed, replaced and is no longer used.
    $AdministratorSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-500"
    # One lookup of the RID-500 account instead of three identical queries.
    $Administrator500 = Get-ADUser -Filter { SID -eq $AdministratorSID } -Properties SamAccountName, Name, LastLogonDate
    $AdministratorSAMAccountName = $Administrator500.SamAccountName
    $AdministratorName = $Administrator500.Name
    if ($AdministratorTranslation -contains $AdministratorSAMAccountName) {
        Write-Both "    [!] Built-in domain Administrator account (RID 500) has not been renamed (KB309)"
        Write-Nessus-Finding "AdminAccountRenamed" "KB309" "Built-in domain Administrator account (RID 500) has not been renamed"
    }
    else {
        $count = 0
        foreach ($AdminName in $AdministratorTranslation) {
            if ((Get-ADUser -Filter { SamAccountName -eq $AdminName })) { $count++ }
        }
        if ($count -eq 0) {
            Write-Both "    [!] Built-in domain Administrator account (RID 500) renamed to $AdministratorSAMAccountName ($($AdministratorName)), but no decoy 'Administrator' account was created in its place! (KB309)"
            Write-Nessus-Finding "AdminAccountRenamed" "KB309" "Built-in domain Administrator account (RID 500) renamed to $AdministratorSAMAccountName ($($AdministratorName)), but no decoy 'Administrator' account was created in its place"
        }
    }
    $AdministratorLastLogonDate = $Administrator500.LastLogonDate
    if ($AdministratorLastLogonDate -gt (Get-Date).AddDays(-180)) {
        Write-Both "    [!] Built-in domain Administrator account (RID 500) is still in use, last used $AdministratorLastLogonDate! (KB309)"
        Write-Nessus-Finding "AdminAccountRenamed" "KB309" "Built-in domain Administrator account (RID 500) is still in use, last used $AdministratorLastLogonDate"
    }
}

Function Get-DomainAdminsGroupOverlap {
    [CmdletBinding()]
    Param(
        # Baseline groups that should NOT be treated as overlap for Tier-0 admin accounts
        [string[]]$BaselineGroups = @(
            'Domain Users',
            'Domain Admins',
            'Administrators',
            'Users',
            # Default transitive membership for all Tier-0 groups since the 2008 schema
            'Denied RODC Password Replication Group',

            # Common Tier-0 extensions (policy-based but usually acceptable for Tier-0 accounts)
            'Group Policy Creator Owners',
            'Protected Users',
            'Key Admins',
            'Enterprise Key Admins',

            # Forest-level Tier-0 (only if the account is intended to operate at forest scope)
            'Schema Admins',
            'Enterprise Admins'
        ),

        # Tier-0 groups (for detecting tier-mixing, not for allowlisting)
        [string[]]$Tier0Groups = @(
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Domain Admins',
            'Account Operators',
            'Server Operators',
            'Backup Operators',
            'Key Admins',
            'Enterprise Key Admins',
            'Organization Management',
            'Exchange Trusted Subsystem',
            'Exchange Windows Permissions',
            'Protected Users',
            'Denied RODC Password Replication Group'
        ),

        # Privileged but not Tier 0 (DC-level / Tier 0 service rights): membership by a DA is
        # overlap / tier mixing. Same classification as the lateral-movement catalog.
        [string[]]$Tier1Groups = @(
            'Print Operators',
            'DnsAdmins',
            'Cert Publishers',
            'Group Policy Creator Owners',
            'Remote Desktop Users',
            'Remote Management Users',
            'Hyper-V Administrators',
            'Incoming Forest Trust Builders'
        ),

        # If set, only write results when overlap is found (default: true)
        [switch]$OnlyReportFindings = $true
    )

    # Ensure HighRisk output folder exists
    $highRiskDir = Join-Path (Get-RawSourceDataDir) 'HighRisk'
    if (-not (Test-Path $highRiskDir)) {
        New-Item -Path $highRiskDir -ItemType Directory -Force | Out-Null
    }

    # Output files:
    # - TXT in root output folder
    # - CSV in HighRisk folder (as requested)
    $outTxt = Join-Path $outputdir   "accounts_domain_admins_group_overlap.txt"
    $outCsv = Join-Path $highRiskDir "accounts_domain_admins_group_overlap.csv"

    # Resolve the Domain Admins group name already used by the script if present
    $daGroupName = $script:DomainAdmins
    if ([string]::IsNullOrEmpty($daGroupName)) { $daGroupName = 'Domain Admins' }

    # Case-insensitive lookup tables
    $baselineSet = @{}
    foreach ($g in $BaselineGroups) {
        if ($g) { $baselineSet[$g.ToLowerInvariant()] = $true }
    }

    $tier0Set = @{}
    foreach ($g in $Tier0Groups) {
        if ($g) { $tier0Set[$g.ToLowerInvariant()] = $true }
    }

    $tier1Set = @{}
    foreach ($g in $Tier1Groups) {
        if ($g) { $tier1Set[$g.ToLowerInvariant()] = $true }
    }

    $results = @()

    try {
        # Enumerate effective members (recursive) of Domain Admins
        $members = Get-ADGroupMember -Identity $daGroupName -Recursive -ErrorAction Stop |
            Where-Object { $_.objectClass -eq 'user' }
    }
    catch {
        Write-Both "    [!] Failed to enumerate members of '$daGroupName' : $($_.Exception.Message)"
        return
    }

    # Recursive DA members share most transitive groups; cache the SID-to-name
    # translation so each group is resolved once instead of once per member.
    $groupNameBySid = @{}
    foreach ($m in $members) {
        try {
            # tokenGroups is fetched together with the other properties - a second
            # per-member Get-ADUser call just for it doubled the LDAP round trips.
            $u = Get-ADUser -Identity $m.DistinguishedName -Properties Enabled,SamAccountName,Name,DistinguishedName,tokenGroups -ErrorAction Stop

            # Effective (transitive) group membership. Get-ADPrincipalGroupMembership returns
            # only DIRECT groups, so a Domain Admin nested into a Tier-1 group via an
            # intermediate group would be missed - exactly the indirection this check exists to
            # catch. Use the constructed tokenGroups attribute (all nested/indirect SIDs) and
            # translate each SID to a group name; fall back to direct membership if unavailable.
            $groupsNorm = @()
            try {
                if (-not $u.tokenGroups -or $u.tokenGroups.Count -eq 0) { throw 'tokenGroups unavailable' }
                foreach ($sid in $u.tokenGroups) {
                    $sidKey = [string]$sid
                    if (-not $groupNameBySid.ContainsKey($sidKey)) {
                        $groupNameBySid[$sidKey] = try { [string](Get-ADGroup -Identity $sid -ErrorAction Stop).SamAccountName } catch { $null }
                    }
                    if ($groupNameBySid[$sidKey]) { $groupsNorm += $groupNameBySid[$sidKey] }
                }
            } catch {
                $groupsNorm = @(Get-ADPrincipalGroupMembership -Identity $u.DistinguishedName -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty SamAccountName | Where-Object { $_ } | ForEach-Object { $_.ToString() })
            }

            # Extra groups beyond baseline (case-insensitive)
            $extra = @()
            foreach ($g in $groupsNorm) {
                if (-not $baselineSet.ContainsKey($g.ToLowerInvariant())) {
                    $extra += $g
                }
            }

            # Tier hits (not mutually exclusive)
            $tier0Hits = @()
            $tier1Hits = @()
            foreach ($g in $groupsNorm) {
                $gl = $g.ToLowerInvariant()
                if ($tier0Set.ContainsKey($gl)) { $tier0Hits += $g }
                if ($tier1Set.ContainsKey($gl)) { $tier1Hits += $g }
            }

            $flagExtra    = (($extra | Measure-Object).Count -gt 0)
            $flagTier1    = (($tier1Hits | Measure-Object).Count -gt 0)
            $flagTierMix  = (($tier0Hits | Measure-Object).Count -gt 0 -and ($tier1Hits | Measure-Object).Count -gt 0)

            if ($flagExtra -or $flagTier1 -or $flagTierMix) {
                $flags = @()
                if ($flagExtra)   { $flags += 'ExtraGroupsBeyondBaseline' }
                if ($flagTier1)   { $flags += 'Tier1MembershipDetected' }
                if ($flagTierMix) { $flags += 'Tier0AndTier1Overlap' }

                $results += [pscustomobject]@{
                    SamAccountName     = $u.SamAccountName
                    Name               = $u.Name
                    Enabled            = $u.Enabled
                    ExtraGroupCount    = ($extra | Measure-Object).Count
                    ExtraGroups        = ($extra | Sort-Object -Unique) -join '; '
                    Tier0GroupsFound   = ($tier0Hits | Sort-Object -Unique) -join '; '
                    Tier1GroupsFound   = ($tier1Hits | Sort-Object -Unique) -join '; '
                    Flags              = ($flags -join '|')
                }
            }
            elseif (-not $OnlyReportFindings) {
                $results += [pscustomobject]@{
                    SamAccountName     = $u.SamAccountName
                    Name               = $u.Name
                    Enabled            = $u.Enabled
                    ExtraGroupCount    = 0
                    ExtraGroups        = ''
                    Tier0GroupsFound   = ($tier0Hits | Sort-Object -Unique) -join '; '
                    Tier1GroupsFound   = ''
                    Flags              = ''
                }
            }
        }
        catch {
            Write-Both "    [!] Failed processing DA member '$($m.SamAccountName)' : $($_.Exception.Message)"
        }
    }

    if (($results | Measure-Object).Count -gt 0) {
        # CSV -> HighRisk folder
        $results | Sort-Object ExtraGroupCount -Descending |
            Export-Csv -NoTypeInformation -Encoding UTF8 -Path $outCsv

        # TXT -> root output folder
        "Domain Admins users with group overlap beyond baseline ($($BaselineGroups -join ', ')):" |
            Out-File -Encoding UTF8 $outTxt

        $results | Sort-Object ExtraGroupCount -Descending |
            ForEach-Object {
                "{0} ({1}) Enabled={2} ExtraGroups={3} Flags={4}`n  Extra: {5}`n  Tier0:  {6}`n  Tier1:  {7}`n" -f `
                    $_.SamAccountName, $_.Name, $_.Enabled, $_.ExtraGroupCount, $_.Flags, $_.ExtraGroups, $_.Tier0GroupsFound, $_.Tier1GroupsFound
            } | Add-Content -Encoding UTF8 -Path $outTxt

        Write-Both "    [!] Domain Admins group overlap findings: $((($results | Measure-Object).Count)) account(s)."
        Write-Both "        - TXT: $(Split-Path -Leaf $outTxt)"
        Write-Both "        - CSV: HighRisk\$(Split-Path -Leaf $outCsv)"
    }
    else {
        Write-Both "    [+] No Domain Admin users found with group overlap beyond baseline."
    }
}

Function Get-DisabledAccounts {

    [CmdletBinding()]
    param()

    $ErrorActionPreference = 'Stop'

    $count = 0
    $txtPath = Get-EvidencePath 'accounts_disabled.txt'

    # Disabled user accounts (UAC bit 0x2)
    $ldapFilter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"

    $disabledaccounts = Get-ADUser -LDAPFilter $ldapFilter -Properties SamAccountName,Name

    $totalcount = ($disabledaccounts | Measure-Object).Count

    if ($totalcount -gt 0) {
        # Reset file for this run
        Set-Content -Encoding UTF8 -Path $txtPath -Value "# Disabled user accounts"
    } else {
        # Ensure no stale output from previous runs
        if (Test-Path -LiteralPath $txtPath) { Remove-Item -LiteralPath $txtPath -Force -ErrorAction SilentlyContinue }
    }

    foreach ($account in $disabledaccounts) {
        if ($totalcount -eq 0) { break }

        Write-Progress -Activity "Searching for disabled users..." -Status "Currently identified $count" -PercentComplete (($count / $totalcount) * 100)

        Add-Content -Encoding UTF8 -Path $txtPath -Value "Account $($account.SamAccountName) ($($account.Name)) is disabled"
        $count++
    }

    Write-Progress -Activity "Searching for disabled users..." -Status "Ready" -Completed

    if ($count -gt 0) {
        Write-Both "    [!] $count disabled user accounts, see accounts_disabled.txt (KB501)"
        Write-Nessus-Finding "DisabledAccounts" "KB501" ([System.IO.File]::ReadAllText($txtPath))
    }
}

Function Get-LockedAccounts {
    #Lists locked accounts
    # Search-ADAccount -LockedOut filters server-side; the previous Get-ADUser -Filter *
    # downloaded every user object in the domain just to filter the locked ones locally.
    $lockedAccounts = @(Search-ADAccount -LockedOut -UsersOnly)
    $count = 0
    $totalcount = ($lockedAccounts | Measure-Object | Select-Object Count).Count
    foreach ($account in $lockedAccounts) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for locked users..." -Status "Currently identified $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path (Get-EvidencePath 'accounts_locked.txt') -Value "Account $($account.SamAccountName) ($($account.Name)) is locked"
        $count++
    }
    Write-Progress -Activity "Searching for locked users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count locked user accounts, see accounts_locked.txt"
    }
}

Function Get-GMSAStatus {
    # Identifies service accounts with SPNs that are NOT Group Managed Service Accounts (gMSA)
    # gMSA passwords are automatically rotated by AD, reducing credential theft risk
    $count = 0
    $gmsakount = 0
    $evidencePath = Get-EvidencePath 'gmsa_status.txt'
    Remove-Item -LiteralPath $evidencePath -Force -ErrorAction SilentlyContinue

    # Find gMSA accounts
    $gmsaAccounts = @(Get-ADServiceAccount -Filter * -Properties Name, SamAccountName, Enabled -ErrorAction SilentlyContinue)
    $gmsakount = ($gmsaAccounts | Measure-Object).Count

    # Find user accounts with SPNs set (likely service accounts)
    $svcAccounts = @(Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Properties SamAccountName, Name, ServicePrincipalName)

    foreach ($svc in $svcAccounts) {
        $spnList = ($svc.ServicePrincipalName -join '; ')
        Add-Content -Path $evidencePath -Value "User account $($svc.SamAccountName) ($($svc.Name)) has SPNs: $spnList - consider migrating to gMSA"
        $count++
    }

    Write-Both "    [+] Found $gmsakount Group Managed Service Account(s) (gMSA)"
    if ($count -gt 0) {
        Write-Both "    [!] $count enabled user account(s) with SPNs (likely service accounts) are not using gMSA (KB1201)"
        Write-Both "    [!] These accounts use static passwords - consider migrating to gMSA for automatic password rotation"
        Write-Nessus-Finding "ServiceAccountsNotGMSA" "KB1201" ([System.IO.File]::ReadAllText($evidencePath))
    }
    else {
        Write-Both "    [+] No enabled user accounts with SPNs found (all service accounts may be using gMSA)"
    }
}

Function Get-RC4OnlyAccounts {
    <#
        Detects AD accounts (users, computers, gMSA, krbtgt, trust accounts) whose
        msDS-SupportedEncryptionTypes attribute does NOT include AES128 (0x8) or
        AES256 (0x10). Such accounts are affected by the RC4 hardening shipped with
        Microsoft's CVE-2026-20833 update: once the KDC enforces the change, the
        KDC will no longer issue RC4-encrypted service tickets for these accounts
        and authentication can break unless AES support is enabled.

        Bitmask reference (msDS-SupportedEncryptionTypes):
            0x1  DES_CBC_CRC
            0x2  DES_CBC_MD5
            0x4  RC4_HMAC_MD5
            0x8  AES128_CTS_HMAC_SHA1_96
            0x10 AES256_CTS_HMAC_SHA1_96
            0x20 AES256_CTS_HMAC_SHA1_96_SK (session key, newer)
            0x40 FAST supported
            0x80 Compound identity supported
        Recommended value for AES-only: 24 (0x18 = AES128 + AES256).

        References:
        - https://www.cayosoft.com/blog/kerberos-rc4-hardening-what-microsoft-s-cve-2026-20833-update-really-means-for-active-directory-admins/
        - https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc
    #>

    $evidencePath = Get-EvidencePath 'rc4_only_accounts.txt'
    $csvPath      = Get-EvidencePath 'rc4_only_accounts.csv'
    $authPath     = Get-EvidencePath 'rc4_authentication_events.txt'
    Remove-Item -LiteralPath $evidencePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $csvPath      -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $authPath     -Force -ErrorAction SilentlyContinue

    $header = @"
# RC4-only accounts (CVE-2026-20833 / Kerberos RC4 hardening)
#
# These accounts have msDS-SupportedEncryptionTypes set such that no AES key
# (AES128 0x8 / AES256 0x10) is advertised. After Microsoft's RC4 hardening
# update (CVE-2026-20833) the KDC stops issuing RC4-encrypted service tickets
# for affected accounts and authentication will fail unless AES is enabled.
#
# How to remediate (per account):
#   1. Add AES support to the account:
#        Set-ADUser     <account> -Replace @{'msDS-SupportedEncryptionTypes'=24}
#        Set-ADComputer <account> -Replace @{'msDS-SupportedEncryptionTypes'=24}
#      Value 24 = AES128 + AES256 (recommended). Use 28 if RC4 must coexist.
#   2. Force a password change so AES keys are actually generated in the KDS:
#        - User / service account: reset the password
#        - Computer account:       Reset-ComputerMachinePassword (or rejoin)
#        - Service account with SPN: rotate password or migrate to gMSA
#   3. Validate the account no longer requests RC4 by inspecting DC event 4769
#      (TicketEncryptionType 0x17 = RC4-HMAC, 0x12 = AES256, 0x11 = AES128).
#   4. For the krbtgt account, perform a planned double-rotation - do NOT use
#      this script's remediation steps directly on krbtgt.
#
# Domain-wide controls referenced by the CVE update:
#   - DefaultDomainSupportedEncTypes (HKLM\SYSTEM\CCS\Services\Kdc) controls
#     the fallback used when an account's attribute is unset (0). Set to 0x18
#     so blank accounts negotiate AES rather than RC4.
#   - KrbtgtFullPacSignature / Audit mode registry knobs may need to be
#     reviewed alongside the RC4 hardening update.
#
# References:
#   https://www.cayosoft.com/blog/kerberos-rc4-hardening-what-microsoft-s-cve-2026-20833-update-really-means-for-active-directory-admins/
#   https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc

"@
    # Buffer evidence lines and only materialise rc4_only_accounts.txt on disk if
    # at least one at-risk account is found. A clean run with zero findings should
    # not leave behind a header-only file that looks like a finding.
    $evidenceBuffer = New-Object System.Collections.Generic.List[string]
    $evidenceBuffer.Add($header) | Out-Null

    # Pull all security principals that can hold a Kerberos key
    $props = @('SamAccountName','DistinguishedName','ObjectClass','Enabled','msDS-SupportedEncryptionTypes','PasswordLastSet','ServicePrincipalName','userAccountControl')

    $allAccounts = New-Object System.Collections.Generic.List[object]
    $enumFailures = @()
    try { Get-ADUser     -Filter * -Properties $props -ErrorAction Stop | ForEach-Object { $allAccounts.Add($_) | Out-Null } } catch { $enumFailures += "Get-ADUser: $($_.Exception.Message)" }
    try { Get-ADComputer -Filter * -Properties $props -ErrorAction Stop | ForEach-Object { $allAccounts.Add($_) | Out-Null } } catch { $enumFailures += "Get-ADComputer: $($_.Exception.Message)" }
    if ($allAccounts.Count -eq 0 -and $enumFailures.Count -gt 0) {
        # A failed enumeration must not fall through to the 'no accounts found' all-clear
        Register-ADAuditNotAssessed -Name 'Get-RC4OnlyAccounts' -Switch 'accounts' -Reason "Account enumeration failed: $($enumFailures -join '; ')"
        return
    }

    # Domain default fallback (when attribute is null/0). Best effort - read from PDC.
    $domainDefault = $null
    try {
        $pdc = (Get-ADDomain -ErrorAction SilentlyContinue).PDCEmulator
        if ($pdc) {
            $reg = Invoke-CimMethod -ClassName StdRegProv -Namespace 'root/default' -MethodName GetDWORDValue -Arguments @{
                hDefKey     = [uint32]2147483650
                sSubKeyName = 'SYSTEM\CurrentControlSet\Services\Kdc'
                sValueName  = 'DefaultDomainSupportedEncTypes'
            } -CimSession (New-CimSession -ComputerName $pdc -ErrorAction Stop) -ErrorAction Stop
            $domainDefault = $reg.uValue
        }
    } catch { }
    # OS hardcoded fallback used by Windows DCs (Server 2008+) when neither the
    # account's msDS-SupportedEncryptionTypes nor DefaultDomainSupportedEncTypes is
    # set. Value 0x1C = AES256 (0x10) + AES128 (0x8) + RC4_HMAC (0x4). This is what
    # the KDC actually uses at ticket-issuance time, and why most accounts with a
    # null attribute negotiate AES in practice (verifiable via DSInternals - the
    # KerberosNew credentials block contains AES256/AES128 keys for these accounts).
    $osHardcodedFallback = 0x1C

    if ($null -ne $domainDefault) {
        $domainDefaultHex = '0x{0:X}' -f [int]$domainDefault
        $evidenceBuffer.Add("# Domain DefaultDomainSupportedEncTypes (KDC fallback) = $domainDefault ($domainDefaultHex)`n") | Out-Null
    } else {
        $evidenceBuffer.Add("# Domain DefaultDomainSupportedEncTypes is not set on the PDC. Using Windows OS hardcoded fallback 0x1C (AES256+AES128+RC4) for accounts with a null msDS-SupportedEncryptionTypes attribute.`n") | Out-Null
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($acct in $allAccounts) {
        $encType = $acct.'msDS-SupportedEncryptionTypes'
        $effective = $encType
        $effectiveSource = 'attribute'
        if ($null -eq $encType -or $encType -eq 0) {
            # Attribute is unset - the KDC falls back to DefaultDomainSupportedEncTypes
            # if that registry value is configured on the PDC, otherwise to the Windows
            # OS hardcoded default (0x1C = AES256+AES128+RC4). Only treat the account
            # as at-risk when the *fallback itself* lacks AES bits - a null attribute
            # alone is not a problem on a modern DC where the OS default already
            # includes AES and the KDS holds AES keys for the account.
            if ($null -ne $domainDefault) {
                $effective = $domainDefault
                $effectiveSource = 'DefaultDomainSupportedEncTypes'
            } else {
                $effective = $osHardcodedFallback
                $effectiveSource = 'OS hardcoded default'
            }
        }

        $hasAes128 = (($effective -band 0x8)  -ne 0)
        $hasAes256 = (($effective -band 0x10) -ne 0)
        $hasRc4    = (($effective -band 0x4)  -ne 0)
        $hasDes    = (($effective -band 0x3)  -ne 0)

        if (-not $hasAes128 -and -not $hasAes256) {
            $supported = @()
            if ($hasDes)    { $supported += 'DES' }
            if ($hasRc4)    { $supported += 'RC4_HMAC_MD5' }
            if (-not $supported) { $supported += '(none)' }

            $rows.Add([pscustomobject]@{
                ObjectClass     = $acct.ObjectClass
                SamAccountName  = $acct.SamAccountName
                Enabled         = $acct.Enabled
                RawValue        = $encType
                EffectiveValue  = $effective
                EffectiveHex    = ('0x{0:X}' -f [int]$effective)
                EffectiveSource = $effectiveSource
                Supported       = ($supported -join ', ')
                PasswordLastSet = $acct.PasswordLastSet
                HasSPN          = [bool]($acct.ServicePrincipalName -and $acct.ServicePrincipalName.Count -gt 0)
                DistinguishedName = $acct.DistinguishedName
            }) | Out-Null

            $line = "{0,-8} {1,-35} Enabled={2,-5} Raw={3,-6} Effective={4,-6} ({5}) Source={6} Supports=[{7}] PwdLastSet={8} DN={9}" -f `
                $acct.ObjectClass, $acct.SamAccountName, $acct.Enabled, ($encType), $effective, ('0x{0:X}' -f [int]$effective), $effectiveSource, ($supported -join ','), $acct.PasswordLastSet, $acct.DistinguishedName
            $evidenceBuffer.Add($line) | Out-Null
        }
    }

    if ($rows.Count -gt 0) {
        Set-Content -LiteralPath $evidencePath -Value ($evidenceBuffer -join "`n") -Encoding UTF8
        $rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
        Write-Both "    [!] $($rows.Count) account(s) lack AES Kerberos support and are affected by CVE-2026-20833 RC4 hardening (KB1205)"
        Write-Both "    [!] Set msDS-SupportedEncryptionTypes to 24 (AES128+AES256) and rotate passwords - see rc4_only_accounts.txt"
        Write-Nessus-Finding "RC4OnlyAccountsCVE202620833" "KB1205" ([System.IO.File]::ReadAllText($evidencePath))
    } else {
        Write-Both "    [+] No accounts found that rely solely on RC4/DES for Kerberos (CVE-2026-20833)"
    }

    # ---- Best-effort runtime check: query DC security logs for RC4 service ticket events ----
    # Event 4769 (Kerberos service ticket request). TicketEncryptionType:
    #   0x12 = AES256-CTS-HMAC-SHA1-96
    #   0x11 = AES128-CTS-HMAC-SHA1-96
    #   0x17 = RC4-HMAC
    #   0x18 = RC4-HMAC-EXP
    # Event 4768 (TGT request) uses the same field for TGT key.
    $authHeader = @"
# Accounts observed using RC4 in Kerberos exchanges (best-effort)
#
# Source: Security event log on each domain controller, events 4768 (TGT) and
# 4769 (service ticket), filtered to TicketEncryptionType 0x17 (RC4-HMAC) or
# 0x18 (RC4-HMAC-EXP). Lookback window: last 7 days, capped per DC.
#
# Note: this requires the DC to be auditing Kerberos Service Ticket Operations
# (Audit Kerberos Authentication Service / Audit Kerberos Service Ticket
# Operations - both Success). If logging is disabled the section will be empty
# even though RC4 may still be in use.
#
# Use this list together with rc4_only_accounts.txt to identify which clients
# or services are still negotiating RC4 against the KDC.

"@
    # Buffer the auth-events output instead of writing it directly. The file is only
    # created on disk if we actually have something to report (hits or query errors),
    # so empty checks don't leave behind a misleading "header-only" evidence file.
    $authLines = New-Object System.Collections.Generic.List[string]
    $authHasContent = $false

    $startTime = (Get-Date).AddDays(-7)
    $perDcCap  = 5000
    $dcs = @()
    try { $dcs = @(Get-ADDomainController -Filter * -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HostName) } catch { }

    $rc4UserHits = @{}
    foreach ($dc in $dcs) {
        try {
            $events = Get-WinEvent -ComputerName $dc -FilterHashtable @{
                LogName   = 'Security'
                Id        = @(4768,4769)
                StartTime = $startTime
            } -MaxEvents $perDcCap -ErrorAction Stop
        } catch {
            # "No events were found" is a clean result (no RC4 traffic in the window), not
            # a query failure - it must not create the evidence file on its own.
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
                $authLines.Add("# Could not query Security log on ${dc}: $($_.Exception.Message)") | Out-Null
                $authHasContent = $true
            }
            continue
        }

        foreach ($evt in $events) {
            # TicketEncryptionType is exposed as an integer (UInt32) in event Properties.
            # 0x17 (23) = RC4-HMAC, 0x18 (24) = RC4-HMAC-EXP
            # 0x11 (17) = AES128, 0x12 (18) = AES256
            $encVal = $null
            try {
                # 4769: Properties index 5 = TicketEncryptionType ; 4768: index 7
                # (TicketEncryptionType; index 8 is PreAuthType)
                if ($evt.Id -eq 4769 -and $evt.Properties.Count -ge 6) {
                    $encVal = $evt.Properties[5].Value
                } elseif ($evt.Id -eq 4768 -and $evt.Properties.Count -ge 8) {
                    $encVal = $evt.Properties[7].Value
                }
            } catch { }
            if ($null -eq $encVal) { continue }

            # Coerce to integer (Properties.Value may already be UInt32, or a hex string in some locales)
            $encInt = 0
            if ($encVal -is [string] -and $encVal -match '^0x') {
                try { $encInt = [Convert]::ToInt32($encVal, 16) } catch { continue }
            } else {
                try { $encInt = [int]$encVal } catch { continue }
            }
            $encStr = '0x{0:X2}' -f $encInt

            if ($encInt -eq 0x17 -or $encInt -eq 0x18) {
                $user   = $null
                $svc    = $null
                try {
                    if ($evt.Id -eq 4769) {
                        $user = [string]$evt.Properties[0].Value
                        $svc  = [string]$evt.Properties[2].Value
                    } else {
                        $user = [string]$evt.Properties[0].Value
                    }
                } catch { }
                if (-not $user) { continue }

                $key = "$user|$svc|$($evt.Id)"
                if (-not $rc4UserHits.ContainsKey($key)) {
                    $rc4UserHits[$key] = [pscustomobject]@{
                        DC          = $dc
                        EventId     = $evt.Id
                        User        = $user
                        Service     = $svc
                        EncType     = $encStr
                        FirstSeen   = $evt.TimeCreated
                        Count       = 0
                    }
                }
                $rc4UserHits[$key].Count++
            }
        }
    }

    # A DC whose Security log could not be read is reduced coverage, not evidence: it goes
    # to not_assessed and the evidence file is only written when there are actual hits.
    foreach ($l in @($authLines | Where-Object { $_ -like '# Could not query Security log on *' })) {
        $dcName = ($l -replace '^# Could not query Security log on ', '') -replace ':.*$', ''
        Register-ADAuditNotAssessed -Name 'Get-RC4OnlyAccounts (Kerberos RC4 event scan)' -Switch 'accounts' -Target $dcName -RequiresRemotePS -Reason ($l.TrimStart('# '))
    }
    $authLines = New-Object System.Collections.Generic.List[string]
    $authHasContent = $false

    if ($rc4UserHits.Count -gt 0) {
        $rc4UserHits.Values | Sort-Object User, Service | ForEach-Object {
            $line = "{0,-30} svc={1,-40} event={2} encType={3} count={4} firstSeen={5} dc={6}" -f `
                $_.User, ($_.Service), $_.EventId, $_.EncType, $_.Count, $_.FirstSeen, $_.DC
            $authLines.Add($line) | Out-Null
        }
        $authHasContent = $true
        Write-Both "    [!] Detected $($rc4UserHits.Count) distinct RC4 Kerberos exchanges in the last 7 days - see rc4_authentication_events.txt"
    } else {
        Write-Both "    [+] No RC4 Kerberos events observed in the last 7 days (or Kerberos auditing not enabled on DCs)"
    }

    # Only materialise rc4_authentication_events.txt if we have something to report
    # (actual hits or per-DC query errors). A clean run with no hits leaves no file.
    if ($authHasContent) {
        Add-Content -Path $authPath -Value $authHeader
        foreach ($l in $authLines) { Add-Content -Path $authPath -Value $l }
    }
}

function Invoke-AccountsCheck {
    Invoke-AuditStep -Name 'Get-InactiveAccounts' -Switch 'accounts' -Body { Get-InactiveAccounts }
    Invoke-AuditStep -Name 'Get-DisabledAccounts' -Switch 'accounts' -Body { Get-DisabledAccounts }
    Invoke-AuditStep -Name 'Get-LockedAccounts' -Switch 'accounts' -Body { Get-LockedAccounts }
    Invoke-AuditStep -Name 'Get-AdminAccountChecks' -Switch 'accounts' -Body { Get-AdminAccountChecks }
    Invoke-AuditStep -Name 'Get-NULLSessions' -Switch 'accounts' -Body { Get-NULLSessions }
    Invoke-AuditStep -Name 'Get-PrivilegedGroupAccounts' -Switch 'accounts' -Body { Get-PrivilegedGroupAccounts }
    Invoke-AuditStep -Name 'Get-DomainAdminScaledRisk' -Switch 'accounts' -Body { Get-DomainAdminScaledRisk }
    Invoke-AuditStep -Name 'Get-ProtectedUsers' -Switch 'accounts' -Body { Get-ProtectedUsers }
    Invoke-AuditStep -Name 'Get-DomainAdminsGroupOverlap' -Switch 'accounts' -Body { Get-DomainAdminsGroupOverlap }
    Invoke-AuditStep -Name 'Get-GMSAStatus' -Switch 'accounts' -Body { Get-GMSAStatus }
    Invoke-AuditStep -Name 'Get-RC4OnlyAccounts' -Switch 'accounts' -Body { Get-RC4OnlyAccounts }
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select accounts @args
}