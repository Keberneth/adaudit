<#
    .SYNOPSIS
        ADAudit reporting library: management / audit HTML reports and end-of-run assembly.

    .DESCRIPTION
        Dot-sourced by AdAudit-PS7.ps1 after ADAudit.Common.ps1. Invoke-ManagementReport reads
        the evidence files every check wrote under <output>\Raw Data\Source and renders
        ADAudit-Results.html and Risk-Report.html; the companion-report functions wrap the
        other HTML outputs in the shared shell; Invoke-ADAuditFinalReports is the end-of-run
        sequence the runner calls last (move legacy artifacts, build the reports, keep only
        the primary and linked HTML files).

    .NOTES
        Functions moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was split.
#>
function Invoke-ManagementReport {
    [CmdletBinding()]
    param(
        [string]$InputRoot,
        [string]$OutputHtml,
        [string]$OutputTxt,
        [string]$AuditHtml,
        [int]$TopFindings = 10
    )

    if (-not $InputRoot -or $InputRoot.Trim().Length -eq 0) {
        $InputRoot = Join-Path (Get-Location) $env:COMPUTERNAME
    }
    if (-not (Test-Path -Path $InputRoot)) {
        throw "InputRoot '$InputRoot' does not exist."
    }

    if (-not $OutputHtml) { $OutputHtml = Join-Path (Get-HtmlReportsDir -BaseRoot $InputRoot) 'Risk-Report.html' }
    if (-not $AuditHtml)  { $AuditHtml  = Join-Path (Get-HtmlReportsDir -BaseRoot $InputRoot) 'ADAudit-Results.html' }
    $outputHtmlDir = Split-Path -Path $OutputHtml -Parent
    if ($outputHtmlDir -and -not (Test-Path -LiteralPath $outputHtmlDir)) { New-Item -ItemType Directory -Path $outputHtmlDir -Force | Out-Null }
    $auditHtmlDir = Split-Path -Path $AuditHtml -Parent
    if ($auditHtmlDir -and -not (Test-Path -LiteralPath $auditHtmlDir)) { New-Item -ItemType Directory -Path $auditHtmlDir -Force | Out-Null }
    if (-not $PSBoundParameters.ContainsKey('OutputTxt') -or [string]::IsNullOrWhiteSpace($OutputTxt)) { $OutputTxt = $null }

    $ErrorActionPreference = 'Stop'

    # ---------------------------
    # Tunable baselines
    # ---------------------------
    $Baselines = @{
        DisabledUserAccounts = 20   # policy baseline for disabled user accounts (review/cleanup cadence)
    }

    # ---------------------------
    # Encoding helpers
    # ---------------------------
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

    function Resolve-AuditArtifactPath([string]$Path) {
        if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

        $rawDataRoot   = Get-RawDataDir -BaseRoot $InputRoot
        $rawSourceRoot = Get-RawSourceDataDir -BaseRoot $InputRoot

        $candidateList = New-Object 'System.Collections.Generic.List[string]'
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

        function Add-Candidate([string]$Value) {
            if ([string]::IsNullOrWhiteSpace($Value)) { return }
            if ($seen.Add($Value)) { $candidateList.Add($Value) | Out-Null }
        }

        $isRooted = $false
        try { $isRooted = [System.IO.Path]::IsPathRooted($Path) } catch { $isRooted = $false }

        if ($isRooted) {
            Add-Candidate $Path
            try {
                $full = [System.IO.Path]::GetFullPath($Path)
                Add-Candidate $full

                $rootAbs = [System.IO.Path]::GetFullPath($InputRoot)
                if ($full.StartsWith($rootAbs, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $relative = $full.Substring($rootAbs.Length).TrimStart('\','/')
                    if (-not [string]::IsNullOrWhiteSpace($relative)) {
                        Add-Candidate (Join-Path $rawSourceRoot $relative)
                        Add-Candidate (Join-Path $rawDataRoot $relative)
                    }
                }
            } catch { }
        }
        else {
            Add-Candidate (Join-Path $InputRoot $Path)
            Add-Candidate (Join-Path $rawSourceRoot $Path)
            Add-Candidate (Join-Path $rawDataRoot $Path)
        }

        foreach ($candidate in $candidateList) {
            try {
                if (Test-Path -LiteralPath $candidate) {
                    return [System.IO.Path]::GetFullPath($candidate)
                }
            } catch { }
        }

        try { return [System.IO.Path]::GetFullPath($Path) } catch { return $Path }
    }

    # Extract only DOMAIN\account lines from pq_*.txt files (filters out headers/footers)
    function Get-PqAccountLines([string]$path) {
        $path = Resolve-AuditArtifactPath $path
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { return @() }
        try {
            return @((Get-Content -LiteralPath $path -ErrorAction Stop) |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -match '^[^=\-\s].*\\' })
        } catch { return @() }
    }

    function Get-NonHeaderLines([string]$path) {
        $path = Resolve-AuditArtifactPath $path
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { return @() }
        try {
            return (Get-Content -LiteralPath $path -ErrorAction Stop) |
                ForEach-Object {
                    $line = ([string]$_).Trim()
                    if ($line.StartsWith('@') -and $line.Length -gt 1) {
                        $line = $line.Substring(1).Trim()
                    }
                    $line
                } |
                Where-Object {
                    # Skip blank lines and '#' comment lines (used as evidence-file headers).
                    # Without this, multi-line explanatory headers would be counted as
                    # findings and inflate severity (e.g. Critical >= 25 line threshold).
                    $_ -and $_.Trim().Length -gt 0 -and -not ($_.TrimStart().StartsWith('#'))
                }
        } catch { return @() }
    }

    function Get-CsvSafe([string]$path) {
        $path = Resolve-AuditArtifactPath $path
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { return @() }
        try { return Import-Csv -LiteralPath $path -ErrorAction Stop } catch { return @() }
    }

    # ---------------------------
    # Parsers
    # ---------------------------

    # accounts_disabled.txt parsing
    function Get-DisabledAccounts {
        param([string]$Path)

        $Path = Resolve-AuditArtifactPath $Path
        if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }

        $lines = @()
        try { $lines = Get-Content -LiteralPath $Path -ErrorAction Stop } catch { return @() }
        if (-not $lines -or $lines.Count -eq 0) { return @() }

        $results = New-Object 'System.Collections.Generic.List[object]'
        foreach ($ln in $lines) {
            if ($null -eq $ln) { continue }
            $t = ($ln -as [string]).Trim()
            if ($t.Length -eq 0) { continue }

            # skip headers/metadata
            if ($t -match '^[\s]*@') { continue }
            if ($t -match '^\s*Disabled user accounts\s*$') { continue }

            # Example:
            # Account $RON000-1LMLA83QPUGL (Exchange Online-ApplicationAccount) is disabled
            if ($t -match '^\s*Account\s+(?<Sam>\S+)\s+\((?<Display>.+?)\)\s+is\s+disabled\s*$') {
                $results.Add([PSCustomObject]@{
                    SamAccountName = $matches['Sam'].Trim()
                    DisplayName    = $matches['Display'].Trim()
                    Line           = $t
                }) | Out-Null
                continue
            }

            # fallback
            if ($t -match '^\s*Account\s+(?<Sam>\S+)\s+is\s+disabled\s*$') {
                $results.Add([PSCustomObject]@{
                    SamAccountName = $matches['Sam'].Trim()
                    DisplayName    = ''
                    Line           = $t
                }) | Out-Null
            }
        }

        return $results.ToArray()
    }

    # ASREP.txt parsing
    function Get-AsrepAccounts([string]$path) {
        $path = Resolve-AuditArtifactPath $path
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { return @() }

        $lines = @()
        try { $lines = Get-Content -LiteralPath $path -ErrorAction Stop } catch { return @() }

        $results = New-Object 'System.Collections.Generic.List[object]'

        foreach ($ln in $lines) {
            if (-not $ln) { continue }

            $t = $ln.TrimEnd()
            if ($t.Trim().Length -eq 0) { continue }

            if ($t -notmatch '^[^\s]') { continue }
            if ($t -match '^Accounts\s*\(') { continue }

            if ($t -match '^(?<Display>.+?)\s+\((?<Sam>[A-Za-z0-9._-]{1,64})\)\s*$') {
                $results.Add([PSCustomObject]@{
                    DisplayName    = $matches['Display'].Trim()
                    SamAccountName = $matches['Sam'].Trim()
                    Line           = $t
                }) | Out-Null
            }
        }

        return $results.ToArray()
    }

    # password_quality.txt parsing (reversible encryption section)
    function Get-ReversibleEncryptionAccounts {
        param([string]$Path)

        $Path = Resolve-AuditArtifactPath $Path
        if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }

        $lines = @()
        try { $lines = Get-Content -LiteralPath $Path -ErrorAction Stop } catch { return @() }
        if (-not $lines -or $lines.Count -eq 0) { return @() }

        $startIdx = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if (($lines[$i] -as [string]) -match '^\s*Passwords of these accounts are stored using reversible encryption:\s*$') {
                $startIdx = $i + 1
                break
            }
        }
        if ($startIdx -lt 0 -or $startIdx -ge $lines.Count) { return @() }

        $results = New-Object 'System.Collections.Generic.List[string]'

        for ($j = $startIdx; $j -lt $lines.Count; $j++) {
            $ln = $lines[$j]
            if ($null -eq $ln) { continue }

            if ($ln -match '^\s*LM hashes of passwords of these accounts are present:\s*$') { break }

            $t = ($ln -as [string]).Trim()
            if ($t.Length -eq 0) { continue }
            if ($t -match ':\s*$') { continue }

            $results.Add($t) | Out-Null
        }

        return $results.ToArray()
    }

    # ---------------------------
    # Findings framework
    # ---------------------------
    $Findings = New-Object System.Collections.Generic.List[object]

    $SeverityScore = @{
        Critical    = 12
        High        = 8
        Medium      = 5
        Low         = 2
        Information = 0
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
            '^INFO'  { return 'Information' }
            default  { return 'Low' }
        }
    }

    function Get-CanonicalTitle([string]$Title) {
        $t = ($Title -as [string])
        if (-not $t) { return '' }
        $t = $t.Trim()

        switch -Regex ($t) {
            '^Enabled accounts inactive >\s*180\s*days$' { return 'Observed inactive enabled accounts (>180 days)' }
            '^Inactive enabled accounts$'                { return 'Observed inactive enabled accounts (>180 days)' }

            '^Accounts with password set to not expire$' { return 'Enabled user accounts with PasswordNeverExpires' }
            '^Passwords set to never expire$'            { return 'Enabled user accounts with PasswordNeverExpires' }

            default { return $t }
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
        $Title = Get-CanonicalTitle $Title

        $score = [int]$SeverityScore[$Severity]
        if ($PSBoundParameters.ContainsKey('ScoreOverride')) {
            $score = [int]$ScoreOverride
        }

        $resolvedPath = $null
        if (-not [string]::IsNullOrWhiteSpace($Path)) {
            try { $resolvedPath = [System.IO.Path]::GetFullPath($Path) } catch { $resolvedPath = $Path }
        }

        $Findings.Add([PSCustomObject]@{
            Severity = $Severity
            Title    = $Title
            Evidence = $Evidence
            Link     = $resolvedPath
            Score    = $score
        }) | Out-Null
    }

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
        $Title = Get-CanonicalTitle $Title

        $pathKey = $null
        if (-not [string]::IsNullOrWhiteSpace($Path)) {
            try { $pathKey = [System.IO.Path]::GetFullPath($Path) } catch { $pathKey = $Path }
        }
        $k = '{0}|{1}|{2}' -f $Severity, (($Title -as [string]).Trim()), $pathKey
        if ($dedup.Add($k)) {
            Add-Finding -Severity $Severity -Title $Title -Evidence $Evidence -Path $Path -ScoreOverride $ScoreOverride
        }
    }

    function Score-Scaled([string]$Severity,[double]$Count,[int]$maxScale = 50) {
        $Severity = Normalize-Severity $Severity
        $base  = [int]$SeverityScore[$Severity]
        $c     = [Math]::Max([double]$Count, 0)
        $scale = [Math]::Min([Math]::Floor($c / 10), [Math]::Floor($maxScale / 10))
        return ($base + [int]$scale)
    }

    function Score-OverBaselineLog {
        param(
            [string]$Severity,
            [double]$Observed,
            [double]$Baseline,
            [int]$MaxAdd = 18,
            [double]$K = 5
        )

        $Severity = Normalize-Severity $Severity
        $base = [int]$SeverityScore[$Severity]

        if ($Baseline -le 0) { return $base }
        if ($Observed -le $Baseline) { return $base }

        $ratio = $Observed / $Baseline
        $add = [Math]::Ceiling($K * ([Math]::Log($ratio) / [Math]::Log(2)))
        $add = [Math]::Min([int]$add, [int]$MaxAdd)
        return ($base + [int]$add)
    }

    function Score-BaselineZeroLog {
        param(
            [string]$Severity,
            [double]$Observed,
            [int]$MaxAdd = 34,
            [double]$K = 10
        )

        $Severity = Normalize-Severity $Severity
        $base = [int]$SeverityScore[$Severity]

        $obs = [Math]::Max([double]$Observed, 0)
        if ($obs -le 0) { return $base }

        $add = [Math]::Ceiling($K * ([Math]::Log($obs + 1) / [Math]::Log(2)))
        $add = [Math]::Min([int]$add, [int]$MaxAdd)
        return ($base + [int]$add)
    }

    function DisplayOrDash($v) {
        if ($null -eq $v) { return '&mdash;' }
        $s = [string]$v
        if ([string]::IsNullOrWhiteSpace($s)) { return '&mdash;' }
        return (HtmlEncode $s)
    }

    function Get-SeverityRank([string]$Severity) {
        switch (Normalize-Severity $Severity) {
            'Critical'    { return 5 }
            'High'        { return 4 }
            'Medium'      { return 3 }
            'Low'         { return 2 }
            'Information' { return 1 }
            default       { return 0 }
        }
    }

    function New-Slug([string]$Value) {
        $slug = (($Value -as [string]) -replace '[^A-Za-z0-9]+','-').Trim('-').ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($slug)) { return 'finding' }
        return $slug
    }

    function New-FindingAnchor([object]$Finding) {
        return ('finding-' + (New-Slug ('{0}-{1}' -f $Finding.Title, $Finding.Link)))
    }

    function Get-FindingCategory([string]$Title) {
        switch -Regex ($Title) {
            '^Lateral movement' { return 'Lateral movement (group nesting)' }
            'Domain Admins membership review \(size-adjusted\)|Built-in domain Administrator \(RID-500\) hygiene' { return 'Privileged access' }
            'cannot reach replication partners|DC unreachable|replication broken with this peer|Replication failures detected|Lingering-object' { return 'DC reachability and replication' }
            'Domain Admins|Enterprise Admins|Schema Admins|Administrators|Operators|privileged|overlap|Delegated permissions' { return 'Privileged access' }
            'password|Password|KRBTGT|Kerberos|AS-REP|SPN|reversible|weak.*encryption|LM hashes|no password|dictionary|breach|DES-only|AES keys|CVE-2026-20833|RC4'  { return 'Authentication and password security' }
            'delegation|gMSA|service account'                                                         { return 'Delegation and service accounts' }
            'LAPS|LDAP|NTLM|cipher|SMB signing'                                                     { return 'Identity hardening' }
            'DNS'                                                                                    { return 'DNS security' }
            'computer|MachineAccountQuota'                                                           { return 'Computer hygiene' }
            'Print Spooler|tombstone'                                                                { return 'DC hardening' }
            'disabled|inactive'                                                                      { return 'Account hygiene' }
            'GPO|Group Policy'                                                                       { return 'Group policy' }
            'ACL'                                                                                    { return 'Access control' }
            default                                                                                  { return 'General' }
        }
    }

    function Get-FindingWhyItMatters([string]$Title) {
        switch -Regex ($Title) {
            '^Lateral movement:.*\(LM01\)' {
                return 'A group that is not a designed Tier 0 group is nested (directly or through other groups) into Domain Admins, Administrators, Backup/Account/Server Operators, the Exchange permission groups or another Tier 0 group - or into a privileged DC-level group such as DnsAdmins. Everyone in that group inherits the Tier 0 privilege exactly as if they were a direct member, but a review of the privileged group shows only the nested group name. This is the mechanism behind most "we did not know helpdesk was Domain Admin" incidents.'
            }
            '^Lateral movement:.*\(LM02\)' {
                return 'These accounts are effectively Tier 0: their access token contains a Tier 0 group SID. Critical ones reach it only through a nesting chain and are invisible as direct members. An attacker does not need a Domain Admin - any one of these accounts (phished, Kerberoasted, left logged on to a client) gives the same result. whoami /groups on a compromised machine lists the whole chain.'
            }
            '^Lateral movement:.*\(LM03\)' {
                return 'A computer account in a Tier 0 group means anyone who is SYSTEM on that machine is Tier 0; a service account there is a Kerberoastable Tier 0 credential; Everyone / Authenticated Users makes the privilege public; cross-domain principals move the trust boundary to a domain that is not audited here.'
            }
            '^Lateral movement:.*\(LM04\)' {
                return 'primaryGroupID membership is not stored in the member attribute of the group, so Get-ADGroupMember, ADUC and access reviews do not show it. Setting it to 512 (Domain Admins) is a documented persistence technique.'
            }
            '^Lateral movement:.*\(LM05\)' {
                return 'Groups in a membership loop are functionally one group: every member of either has the union of all rights and the direction of the model (role -> resource) is gone.'
            }
            '^Lateral movement:.*\(LM06\)' {
                return 'An "all employees"-style group (or Domain Users / Authenticated Users / Everyone) is nested into an access-granting group. Everyone in the domain - consultants, service accounts, guests - gets that access, and the broad group looks harmless because its member list is simply "everyone"; the error is in its memberOf.'
            }
            '^Lateral movement:.*\(LM0[789]\)|^Lateral movement:.*\(LM10\)' {
                return 'AGDLP violations: role group in role group, resource group in resource group, users directly in resource groups, or groups that are both role and resource. Each one makes effective rights unreadable in two steps and creates identity inheritance that nobody approved. Long enough chains have the same effect as a circular nesting.'
            }
            '^Lateral movement:.*\(LM1[12]\)|^Lateral movement:.*\(LM1[78]\)|^Lateral movement:.*\(LM2[01]\)' {
                return 'Group hygiene problems that keep privilege paths alive: temporary/legacy groups that still grant access, nesting chains too deep to review, distribution groups in security chains, orphaned AdminSDHolder protection, empty groups pre-nested into Tier 0 (a dormant escalation path) and token bloat.'
            }
            '^Lateral movement:.*\(LM1[345]\)' {
                return 'Tiering is only as strong as the accounts: a Tier 1/2 group or account that reaches Tier 0 collapses the model with one edge; a Tier 0 account that is also member of daily-work groups exposes its credential on every server and client it touches; Tier 0 accounts with SPNs, without pre-authentication, with old or never-expiring passwords, outside Protected Users or looking like standard user accounts are the attacker''s first targets.'
            }
            '^Lateral movement:.*\(LM19\)' {
                return 'Every chain in this report started with one new group-to-group edge that looked reasonable at the time. Detecting new nesting edges against an approved baseline is the single control that catches the whole class before it is exploited.'
            }
            '^Lateral movement' {
                return 'Group nesting is the hidden privilege path in Active Directory: "I am memberOf X" means "I inherit the rights of X", transitively, and ADUC shows only one hop. See Lateral-Movement.html for the map and the Rules & guidance tab for each rule.'
            }
            'cannot reach replication partners|replication broken with this peer|DC unreachable' {
                return 'A DC that exists in AD but cannot be reached on the network is a partition. Replication silently diverges, password changes are lost, FSMO transfers fail, and clients in different network segments authenticate against different copies of the directory. The risk depends on how much redundancy is left: a 2-DC domain with one isolated has zero failover (Critical); a 4-DC domain with one isolated still has redundancy (Medium overall) but the isolated DC itself is Critical because anything binding to it gets stale data.'
            }
            'Replication failures detected' {
                return 'repadmin /replsummary reports non-zero failures across DC pairs. Replication is the mechanism that keeps every DC consistent; failures here mean directory state is drifting. Common root causes: DNS issues between DCs, RPC/firewall blocks, expired Kerberos secure channel, time skew >5 min, USN rollback after an improper restore.'
            }
            'Domain Admins membership review \(size-adjusted\)' {
                return 'Microsoft AD guidance is that Domain Admins is intended for build and disaster-recovery scenarios only, with day-to-day admin work performed via delegated administration, tiered admin accounts, and temporary elevation (PAM / PIM / JIT). The static benchmark of 5 named Domain Admins is a common security baseline; this script also applies a size-adjusted threshold (capped at 10) so a 3,000-user environment is not held to the same absolute number as a 100-user one - but scaling never makes the finding "safe", and any service account, computer account, gMSA, or nested group inside Domain Admins is high risk regardless of total count.'
            }
            'Built-in domain Administrator \(RID-500\) hygiene' {
                return 'The built-in domain Administrator account (SID ending in -500) cannot be deleted, has unrestricted access in the domain (and across the forest in the root domain), and is the prime target if its credential is compromised. Microsoft Defender for Identity explicitly flags this account when its password is older than 180 days. It must be reserved for build / break-glass / disaster recovery, not used for daily work, and never used as a service account or scheduled task account.'
            }
            'Duplicate passwords|sharing the same password|identical NTLM hash' {
                return 'Password reuse across privileged or service accounts can materially reduce the effort required to expand access after a single compromise.'
            }
            'KRBTGT password age' {
                return 'A stale KRBTGT password extends the lifetime of forged Kerberos tickets and weakens incident response after domain compromise.'
            }
            'AS-REP roastable|without Kerberos pre-auth' {
                return 'Accounts without Kerberos pre-auth can be targeted offline, allowing attackers to attempt password cracking without interacting further with the domain.'
            }
            'Kerberoastable SPNs|SPN' {
                return 'Service accounts with SPNs can be targeted for offline ticket cracking, especially when passwords are static, old, or weak.'
            }
            'reversible encryption' {
                return 'Reversible password storage materially weakens credential protection and should only exist for rare legacy compatibility requirements.'
            }
            'privileged group|Domain Admins|Enterprise Admins|Schema Admins|Administrators|Operators|overlap' {
                return 'Excessive or overlapping privilege expands blast radius and increases the probability of privileged misuse or lateral movement.'
            }
            # Specific before generic: these titles also contain 'disabled' and
            # must not fall into the generic inactive/disabled case below.
            'no password set \((all )?disabled\)' {
                return 'These accounts have PASSWD_NOTREQD set but are currently disabled, so they cannot be used as-is. The risk is latent: if re-enabled they could be used with no password. Their presence also indicates weak account-creation hygiene.'
            }
            'inactive|disabled|Inactive computer' {
                return 'Inactive or disabled objects increase attack surface, complicate review, and often indicate weak lifecycle controls. Disabled accounts left in place can be re-enabled by an attacker who gains sufficient rights.'
            }
            'PasswordNeverExpires|never expire' {
                return 'Passwords that never expire are frequently associated with unmanaged service accounts and create long-lived credential exposure.'
            }
            'MachineAccountQuota' {
                return 'Allowing standard users to join computers can be abused to create attack paths and should be tightly controlled.'
            }
            'weak Kerberos ciphers' {
                return 'Legacy Kerberos ciphers reduce cryptographic strength and should be retired in favor of AES-only configurations where possible.'
            }
            'LAPS' {
                return 'Overly broad local administrator password access or expired LAPS passwords weakens workstation and server credential hygiene.'
            }
            'LDAP security|NTLM authentication|NTLM restrictions|NTLM is not restricted' {
                return 'Weak LDAP or NTLM settings enable downgrade and relay scenarios and indicate incomplete hardening of identity protocols.'
            }
            'DNS zones allowing insecure updates' {
                return 'Insecure dynamic updates allow unauthenticated or weakly authenticated name changes and can enable spoofing or persistence.'
            }
            'unconstrained.*delegation' {
                return 'Accounts with unconstrained delegation can impersonate any user who authenticates to them, enabling credential theft and lateral movement across the domain.'
            }
            'gMSA|service account.*not.*gMSA' {
                return 'Service accounts using static passwords are vulnerable to credential theft and Kerberoasting. gMSA provides automatic password rotation managed by AD.'
            }
            'tombstone lifetime' {
                return 'A short tombstone lifetime reduces the AD Recycle Bin recovery window and can cause lingering objects during extended replication outages.'
            }
            'Print Spooler' {
                return 'The Print Spooler service on domain controllers exposes them to PrintNightmare and authentication coercion attacks that can lead to domain compromise.'
            }
            'SMB signing' {
                return 'Without required SMB signing, attackers can perform NTLM relay attacks to authenticate as the domain controller and escalate privileges.'
            }
            'weak.*encryption|legacy.*encryption' {
                return 'Accounts still configured with DES or RC4 Kerberos encryption are vulnerable to offline credential attacks. After an in-place AD upgrade the domain supports AES, but accounts whose passwords have not been reset continue to negotiate with the weaker ciphers stamped at their last password change.'
            }
            'LM hashes' {
                return 'LM hashes use weak DES-based encryption and can be cracked in seconds. Their presence indicates legacy password storage that should have been eliminated.'
            }
            'no password set' {
                return 'Accounts without passwords can be accessed without any authentication, providing trivial entry points for attackers.'
            }
            'dictionary|breach' {
                return 'Passwords found in known dictionaries or breach lists can be cracked instantly using widely available tools and wordlists.'
            }
            'default.*computer.*password|computer.*default' {
                return 'Computer accounts with default passwords have not completed domain join properly or have been reset, making them vulnerable to impersonation.'
            }
            'AES keys missing' {
                return 'Accounts missing Kerberos AES keys will fall back to weaker encryption (RC4/DES) for Kerberos authentication, increasing vulnerability to offline attacks.'
            }
            'CVE-2026-20833|RC4' {
                return 'Microsoft''s CVE-2026-20833 update hardens the KDC so it stops issuing RC4-encrypted Kerberos service tickets for accounts that do not advertise AES support. Accounts whose msDS-SupportedEncryptionTypes lacks AES128/AES256 (or whose passwords were last set before AES keys were generated) will fail to authenticate after the hardening enforcement, and any traffic still using RC4 today is cryptographically weak and Kerberoastable.'
            }
            'DES-only' {
                return 'DES encryption is cryptographically broken and can be cracked in real-time. Accounts restricted to DES-only are critically vulnerable.'
            }
            'admin.*delegat|delegat.*admin' {
                return 'Administrative accounts allowed for delegation can be impersonated by services, creating privilege escalation paths if those services are compromised.'
            }
            'not required to have a password|password not required' {
                return 'The PASSWD_NOTREQD flag allows accounts to exist with empty passwords, bypassing the domain password policy entirely.'
            }
            default {
                return 'This finding indicates a deviation from common Active Directory hardening expectations and should be reviewed in context.'
            }
        }
    }

    function Get-FindingRecommendation([string]$Title) {
        switch -Regex ($Title) {
            '^Lateral movement:.*\(LM01\)|^Lateral movement:.*\(LM20\)' {
                return 'Remove the nested group from the Tier 0 group (Remove-ADGroupMember -Identity <Tier0 group> -Members <group>). If the members genuinely need the right, give it through a dedicated, named Tier 0 group with direct, reviewed and time-bound membership (PAM/PIM) - never through a role or resource group that exists for another purpose. Re-run the check and keep lateral_movement_edges.csv as the baseline for the next run.'
            }
            '^Lateral movement:.*\(LM02\)|^Lateral movement:.*\(LM1[345]\)' {
                return 'For every account decide whether the person is supposed to be Tier 0. If yes: dedicated Tier 0 admin account (recognizable naming), member of Protected Users, marked "sensitive and cannot be delegated", no SPN, pre-auth enabled, rotated password, no memberships outside Tier 0, logon denied on Tier 1/2 systems via GPO. If no: remove the edge in the chain that grants the privilege (see the LM01 findings and the Tier 0 paths tab of Lateral-Movement.html).'
            }
            '^Lateral movement:.*\(LM03\)' {
                return 'Remove computer accounts, service accounts, foreign security principals and cross-domain principals from Tier 0 / privileged groups. Grant services the specific delegated right they need (gMSA with least privilege) or run the workload on a host managed as Tier 0.'
            }
            '^Lateral movement:.*\(LM04\)' {
                return 'Add the account to Domain Users, set primaryGroupID back to 513 (Set-ADUser <account> -Replace @{primaryGroupID=513}), then investigate who changed the attribute (events 4738 / 5136) and review the account''s other memberships.'
            }
            '^Lateral movement:.*\(LM05\)' {
                return 'Break the loop by removing the edge that was added last (compare with the baseline) and re-model the groups as one role group -> one resource group with a single direction.'
            }
            '^Lateral movement:.*\(LM06\)' {
                return 'Remove the broad group from the parent group. If everyone really needs the access, grant read rights inside the application instead of nesting an "all employees" group into an administrative or resource group. Never nest Domain Users / Authenticated Users into access-granting groups.'
            }
            '^Lateral movement:.*\(LM0[789]\)|^Lateral movement:.*\(LM10\)' {
                return 'Apply AGDLP: users -> one Global role group -> one Domain Local resource group per system and permission level -> ACL. Remove role-in-role and resource-in-resource edges, move directly-added users into role groups, and split groups that are both role and resource. Document approved exceptions with -ApprovedNestings so they stop being reported.'
            }
            '^Lateral movement:.*\(LM1[12]\)|^Lateral movement:.*\(LM1[78]\)|^Lateral movement:.*\(LM21\)' {
                return 'Clean up: remove temporary/legacy groups or their nesting after confirming with an owner, flatten chains deeper than role -> resource, keep distribution lists out of security nesting, clear orphaned adminCount and re-enable inheritance, and require an owner (managedBy) for every access-granting group.'
            }
            '^Lateral movement:.*\(LM19\)' {
                return 'Review every new group-to-group edge with the person who created it (events 4728 / 4756 on the DCs). Store lateral_movement_edges.csv of each approved state as the next baseline (-LateralBaselinePath) and alert on differences.'
            }
            '^Lateral movement' {
                return 'Open Lateral-Movement.html, start from the Findings tab sorted by severity, and use the map in focus mode to follow each chain hop by hop before removing an edge.'
            }
            'cannot reach replication partners|replication broken with this peer|DC unreachable' {
                return 'For each isolated DC: 1) Confirm whether it should still exist - if it was decommissioned, remove the AD record cleanly with `ntdsutil "metadata cleanup"` from a healthy DC. 2) If it should be online, restore network reachability (firewall, routing, VPN, VLAN). Verify with `Test-NetConnection <DC> -Port 389/445` from each remaining DC. 3) Once reachable, force convergence with `repadmin /syncall /AdePq`. 4) For cloned VMs that were placed on isolated networks: do NOT let them rejoin the production domain - clones must either be properly demoted or kept fully isolated (different domain), otherwise USN rollback can corrupt the directory.'
            }
            'Replication failures detected' {
                return 'Drill into per-DC failures with `repadmin /showrepl /errorsonly`. Common fixes: confirm DNS forward+reverse for each DC, verify TCP 135 (RPC EPM) + dynamic RPC + 445 + 88 between DCs, check `w32tm /monitor` for time skew, reset the secure channel with `nltest /sc_reset:<domain>` or rejoin if needed. Once root cause is fixed, force convergence with `repadmin /syncall /AdePq`.'
            }
            'Domain Admins membership review \(size-adjusted\)' {
                return 'Reduce permanent Domain Admins membership where possible. Delegate routine tasks (OU/GPO/print/help-desk) instead of granting Domain Admin rights. Use temporary group membership for high-privilege work: Add-ADGroupMember -Identity "Domain Admins" -Members <admin> -MemberTimeToLive (New-TimeSpan -Hours 4) (requires the Privileged Access Management Feature enabled at the forest level). Adopt a third-party PAM (CyberArk / Delinea / BeyondTrust) or MIM PAM for isolated/legacy estates. Move all service workloads off Domain Admins; gMSAs that need elevation should get targeted delegated rights, not blanket DA membership. Note: Microsoft Entra PIM for Groups does NOT cover on-prem-synced groups, so it is not a direct native solution for the on-prem Domain Admins group.'
            }
            'Built-in domain Administrator \(RID-500\) hygiene' {
                return 'Reserve the built-in RID-500 account for initial build and break-glass / disaster recovery only - do not use it for daily admin work. Rotate its password on a defined schedule (180 days max recommended) and store the password in a sealed/escrowed location. Set "Account is sensitive and cannot be delegated". Remove any SPNs - this account must not be used as a service account or scheduled task account. Restrict interactive logon (deny logon from workstations / member servers via GPO). Consider adding to Protected Users once break-glass procedures account for the Kerberos restrictions. Monitor for any logon and group-membership change.'
            }
            'Duplicate passwords|sharing the same password|identical NTLM hash' {
                return 'Reset affected passwords, eliminate password reuse, prefer gMSA where applicable, and verify privileged accounts follow a separate credential standard.'
            }
            'KRBTGT password age' {
                return 'Plan and execute a controlled double KRBTGT rotation, validate ticket lifetimes, and document the ongoing rotation cadence.'
            }
            'AS-REP roastable|without Kerberos pre-auth' {
                return 'Re-enable Kerberos pre-auth unless a documented exception exists, and review service account usage and password quality.'
            }
            'Kerberoastable SPNs|SPN' {
                return 'Review each service account, prefer gMSA, require strong unique passwords, and enforce modern Kerberos encryption types.'
            }
            'reversible encryption' {
                return 'Disable reversible password storage, identify the legacy dependency, and reset affected account passwords after policy change.'
            }
            'privileged group|Domain Admins|Enterprise Admins|Schema Admins|Administrators|Operators|overlap' {
                return 'Reduce standing privilege, separate admin tiers, remove stale memberships, and require approval and periodic recertification for privileged access.'
            }
            # Specific before generic: these titles also contain 'disabled' and
            # must not fall into the generic inactive/disabled case below.
            'no password set \((all )?disabled\)' {
                return 'These accounts are disabled - do NOT set a password and re-enable them. Confirm each is genuinely unused, then delete it, or keep it disabled and clear the PASSWD_NOTREQD flag (Set-ADUser <account> -PasswordNotRequired $false) so it cannot later be re-enabled without a policy-compliant password. Investigate why the flag was set.'
            }
            'inactive|disabled|Inactive computer' {
                return 'Review ownership, remove genuinely unused accounts and computer objects, and enforce a documented lifecycle and exception process. Leave accounts disabled (not re-enabled with a fresh password) until they are confirmed unused, then delete them.'
            }
            'PasswordNeverExpires|never expire' {
                return 'Minimize PasswordNeverExpires usage, migrate eligible services to gMSA, and maintain approved exceptions with regular review.'
            }
            'MachineAccountQuota' {
                return 'Set MachineAccountQuota to 0 unless there is a defined business need, and delegate computer join rights only to approved processes or groups.'
            }
            'weak Kerberos ciphers' {
                return 'Remove legacy cipher support where supported, validate application compatibility, and standardize on stronger Kerberos encryption.'
            }
            'LAPS' {
                return 'Restrict password readers to the minimum required set, rotate expired passwords, and validate LAPS policy application across managed systems.'
            }
            'LDAP security|NTLM authentication|NTLM restrictions|NTLM is not restricted' {
                return 'Harden LDAP signing and channel binding, reduce NTLM usage, and validate compatibility before enforcing stricter settings.'
            }
            'DNS zones allowing insecure updates' {
                return 'Change affected zones to secure-only dynamic updates and verify DHCP/DNS integration and update ownership.'
            }
            'unconstrained.*delegation' {
                return 'Remove unconstrained delegation, migrate to constrained delegation or resource-based constrained delegation, and audit all delegation settings regularly.'
            }
            'gMSA|service account.*not.*gMSA' {
                return 'Migrate eligible service accounts to Group Managed Service Accounts (gMSA) for automatic password rotation. Document exceptions for accounts that cannot be migrated.'
            }
            'tombstone lifetime' {
                return 'Set the tombstone lifetime to at least 180 days via ADSI Edit (CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration) to ensure adequate Recycle Bin retention.'
            }
            'Print Spooler' {
                return 'Disable the Print Spooler service on all domain controllers. DCs should not serve as print servers. Use Group Policy to enforce: Set Spooler service to Disabled.'
            }
            'SMB signing' {
                return 'Enable SMB signing on all DCs via Group Policy: "Microsoft network server: Digitally sign communications (always)" = Enabled. Validate client compatibility before enforcement.'
            }
            'weak.*encryption|legacy.*encryption' {
                return 'Force a password change for affected user accounts. For computer accounts use Reset-ComputerMachinePassword or rejoin the domain. For service accounts rotate the password or migrate to gMSA. Set msDS-SupportedEncryptionTypes to 24 (AES128+AES256) on all accounts via Group Policy or directly: Set-ADUser <account> -Replace @{''msDS-SupportedEncryptionTypes''=24}. Verify with Get-ADUser <account> -Properties msDS-SupportedEncryptionTypes.'
            }
            'LM hashes' {
                return 'Disable LM hash storage via Group Policy (Network security: Do not store LAN Manager hash value on next password change = Enabled). Force password changes for all affected accounts to eliminate stored LM hashes.'
            }
            'no password set' {
                return 'Set passwords on all affected (enabled) accounts immediately and clear the PASSWD_NOTREQD flag (Set-ADUser <account> -PasswordNotRequired $false). Review why these accounts were created without passwords and enforce the domain password policy.'
            }
            'dictionary|breach' {
                return 'Force immediate password changes for all affected accounts. Implement Azure AD Password Protection or a third-party banned-password filter to prevent dictionary passwords from being set.'
            }
            'default.*computer.*password|computer.*default' {
                return 'Rejoin affected computers to the domain to trigger machine account password rotation. Investigate why the machine account password was not updated during the join process.'
            }
            'AES keys missing' {
                return 'Force a password change or reset for affected accounts. The new password hash will include AES keys. For computer accounts use Reset-ComputerMachinePassword. For service accounts consider migrating to gMSA.'
            }
            'CVE-2026-20833|RC4' {
                return 'For each affected account set msDS-SupportedEncryptionTypes to 24 (AES128+AES256): Set-ADUser <acct> -Replace @{''msDS-SupportedEncryptionTypes''=24} or Set-ADComputer <acct> -Replace @{''msDS-SupportedEncryptionTypes''=24}. Then force a password change so AES keys are actually generated (Reset-ComputerMachinePassword for computers; rotate or migrate to gMSA for service accounts; perform a planned double-rotation for krbtgt). At the domain level set the KDC registry value DefaultDomainSupportedEncTypes to 0x18 so accounts with a blank attribute fall back to AES instead of RC4. Validate by inspecting DC events 4768/4769 (TicketEncryptionType 0x11/0x12 = AES, 0x17/0x18 = RC4). References: https://www.cayosoft.com/blog/kerberos-rc4-hardening-what-microsoft-s-cve-2026-20833-update-really-means-for-active-directory-admins/ and https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc'
            }
            'DES-only' {
                return 'Remove the DES restriction from affected accounts: Set-ADUser <account> -Replace @{''msDS-SupportedEncryptionTypes''=24}. Clear the "Use Kerberos DES encryption types for this account" checkbox in account properties. Force a password change after the update.'
            }
            'admin.*delegat|delegat.*admin' {
                return 'Mark sensitive administrative accounts as "Account is sensitive and cannot be delegated" in account properties, or add them to the Protected Users group. Review which services need delegation and use constrained delegation with specific target SPNs.'
            }
            'not required to have a password|password not required' {
                return 'Clear the PASSWD_NOTREQD flag on affected accounts: Set-ADUser <account> -PasswordNotRequired $false. Then force a password change to ensure a proper password is set. Review why the flag was enabled.'
            }
            default {
                return 'Review the affected configuration, identify the owning team, and document a remediation plan with validation after implementation.'
            }
        }
    }

    function Get-FindingSourceLabel([string]$Path) {
        if ([string]::IsNullOrWhiteSpace($Path)) { return 'Embedded evidence' }
        try {
            return [System.IO.Path]::GetFileName($Path)
        } catch {
            return $Path
        }
    }

    function Get-EvidencePreviewLines([string]$Path, [int]$MaxLines = 10) {
        $preview = New-Object 'System.Collections.Generic.List[string]'
        $Path = Resolve-AuditArtifactPath $Path
        if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return @() }

        $ext = ''
        try { $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant() } catch { }

        switch ($ext) {
            '.csv' {
                try {
                    $rows = Import-Csv -LiteralPath $Path -ErrorAction Stop | Select-Object -First $MaxLines
                    foreach ($row in $rows) {
                        $parts = @()
                        foreach ($prop in ($row.PSObject.Properties | Where-Object { $_.Value -ne $null -and ([string]$_.Value).Trim().Length -gt 0 } | Select-Object -First 4)) {
                            $parts += ('{0}={1}' -f $prop.Name, ([string]$prop.Value))
                        }
                        if ($parts.Count -gt 0) {
                            $preview.Add(($parts -join ' | ')) | Out-Null
                        }
                    }
                } catch { }
            }
            '.txt' {
                try {
                    $lines = Get-Content -LiteralPath $Path -ErrorAction Stop |
                        Where-Object { $_ -and $_.Trim().Length -gt 0 -and ($_ -notmatch '^[\s]*@') } |
                        Select-Object -First $MaxLines
                    foreach ($line in $lines) {
                        $preview.Add(([string]$line).Trim()) | Out-Null
                    }
                } catch { }
            }
            '.html' {
                $preview.Add('Detailed HTML companion report generated for this check.') | Out-Null
            }
            default {
                $preview.Add(('Source: {0}' -f (Get-FindingSourceLabel $Path))) | Out-Null
            }
        }

        return $preview.ToArray()
    }

    function Get-CompanionHtmlReports([string]$Root, [string[]]$Exclude = @()) {
        $items = New-Object 'System.Collections.Generic.List[object]'
        $seen  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

        $excludeMap = @{}
        foreach ($p in $Exclude) {
            if (-not [string]::IsNullOrWhiteSpace($p)) {
                try { $excludeMap[[System.IO.Path]::GetFullPath($p)] = $true } catch { }
            }
        }

        $candidates = New-Object 'System.Collections.Generic.List[System.IO.FileInfo]'

        $htmlRoot = Get-HtmlReportsDir -BaseRoot $Root
        if (Test-Path -LiteralPath $htmlRoot) {
            foreach ($f in (Get-ChildItem -Path $htmlRoot -File -Filter '*.html' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\.source\.html$' })) {
                $candidates.Add($f) | Out-Null
            }
        }

        foreach ($f in (Get-ChildItem -Path $Root -File -Filter '*.html' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\.source\.html$' })) {
            $candidates.Add($f) | Out-Null
        }

        $delegIndex = Get-ChildItem -Path (Join-Path (Get-RawDataDir -BaseRoot $Root) 'DelegatedPermissions') -Recurse -File -Filter 'index.html' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($delegIndex) { $candidates.Add($delegIndex) | Out-Null }

        $dnsAudit = Get-ChildItem -Path $Root -Recurse -File -Filter 'DNSAudit-*.html' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '\.source\.html$' } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($dnsAudit) { $candidates.Add($dnsAudit) | Out-Null }

        $dnsReco = Get-ChildItem -Path $Root -Recurse -File -Filter 'DNS-Recommendations-*.html' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '\.source\.html$' } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($dnsReco) { $candidates.Add($dnsReco) | Out-Null }

        foreach ($file in $candidates) {
            if (-not $file) { continue }

            $full = $null
            try { $full = [System.IO.Path]::GetFullPath($file.FullName) } catch { $full = $file.FullName }
            if ($excludeMap.ContainsKey($full)) { continue }
            if (-not $seen.Add($full)) { continue }

            $title = switch -Regex ($file.Name) {
                '^GPOReport\.html$'                      { 'Group Policy report' ; break }
                '^overlapping_group_memberships\.html$'  { 'Overlapping group membership report' ; break }
                '^multiple_nested_paths\.html$'          { 'Multiple nested paths report' ; break }
                '^dangerousACLs\.html$'                 { 'Dangerous ACL report' ; break }
                '^ad_high_risk_baseline_index\.html$'   { 'High-risk baseline report' ; break }
                '^Lateral-Movement\.html$'              { 'Lateral movement map' ; break }
                '^index\.html$'                         { 'Delegated permissions report' ; break }
                '^DNSAudit-.*\.html$'                   { 'DNS audit report' ; break }
                '^DNS-Recommendations-.*\.html$'        { 'DNS recommendations report' ; break }
                default                                 { ($file.BaseName -replace '[-_]+',' ') }
            }

            $items.Add([pscustomobject]@{
                Title    = $title
                FullPath = $full
            }) | Out-Null
        }

        return $items.ToArray()
    }

    function Ensure-DirectoryPath([string]$Path) {
        if ([string]::IsNullOrWhiteSpace($Path)) { return }
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
    }

    function Get-NormalizedAbsolutePath([string]$Path) {
        if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
        try { return [System.IO.Path]::GetFullPath($Path) } catch { return $Path }
    }

    function Get-RelativeHref([string]$FromFile, [string]$ToPath) {
        if ([string]::IsNullOrWhiteSpace($ToPath)) { return '' }

        try {
            $fromDir = Split-Path -Path $FromFile -Parent
            if ([string]::IsNullOrWhiteSpace($fromDir)) { $fromDir = Split-Path -Path (Get-NormalizedAbsolutePath $FromFile) -Parent }
            $fromAbs = [System.IO.Path]::GetFullPath($fromDir)
            $targetAbs = [System.IO.Path]::GetFullPath($ToPath)

            $baseUri = New-Object System.Uri(($fromAbs.TrimEnd('\') + '\'))
            $targetUri = New-Object System.Uri($targetAbs)
            return ([System.Uri]::UnescapeDataString($baseUri.MakeRelativeUri($targetUri).ToString()) -replace '\\','/')
        } catch {
            return [System.IO.Path]::GetFileName($ToPath)
        }
    }

    function Format-PreviewValue($Value) {
        if ($null -eq $Value) { return '' }
        if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
        return [string]$Value
    }

    function New-PreviewTableHtml {
        param(
            [object[]]$Rows,
            [string[]]$Columns,
            [int]$MaxRows = 250
        )

        if (-not $Rows -or $Rows.Count -eq 0) {
            return "<div class='result-empty'>No detailed rows were available for this finding.</div>"
        }

        $displayRows = @($Rows | Select-Object -First $MaxRows)
        $availableColumns = @()
        try { $availableColumns = @($displayRows[0].PSObject.Properties.Name) } catch { $availableColumns = @() }

        if (-not $Columns -or $Columns.Count -eq 0) {
            $Columns = @($availableColumns | Select-Object -First 8)
        } else {
            $Columns = @($Columns | Where-Object { $_ -in $availableColumns })
            if ($Columns.Count -eq 0) {
                $Columns = @($availableColumns | Select-Object -First 8)
            }
        }

        if (-not $Columns -or $Columns.Count -eq 0) {
            return "<div class='result-empty'>Detailed rows were detected, but no displayable columns were available.</div>"
        }

        $headHtml = ($Columns | ForEach-Object { "<th>$(HtmlEncode ([string]$_))</th>" }) -join ''
        $rowHtml = New-Object 'System.Collections.Generic.List[string]'

        foreach ($row in $displayRows) {
            $cellHtml = New-Object 'System.Collections.Generic.List[string]'
            foreach ($col in $Columns) {
                $val = $null
                try {
                    if ($row.PSObject.Properties[$col]) {
                        $val = $row.PSObject.Properties[$col].Value
                    } else {
                        $val = $row.$col
                    }
                } catch { $val = $null }

                $cellHtml.Add("<td>$(HtmlEncode (Format-PreviewValue $val))</td>") | Out-Null
            }
            $rowHtml.Add("<tr>$($cellHtml -join '')</tr>") | Out-Null
        }

        $note = if ($Rows.Count -gt $displayRows.Count) {
            "Showing the first $($displayRows.Count) of $($Rows.Count) rows. Use the download link for the complete result."
        } else {
            "Rows: $($Rows.Count)"
        }

        return @"
<div class="result-note">$(HtmlEncode $note)</div>
<div class="result-scroll">
  <table class="result-table">
    <thead>
      <tr>$headHtml</tr>
    </thead>
    <tbody>
      $($rowHtml -join "`n")
    </tbody>
  </table>
</div>
"@
    }

    function New-PreviewTextHtml {
        param(
            [string[]]$Lines,
            [int]$MaxLines = 300
        )

        if (-not $Lines -or $Lines.Count -eq 0) {
            return "<div class='result-empty'>No detailed lines were available for this finding.</div>"
        }

        $displayLines = @($Lines | Select-Object -First $MaxLines)
        $note = if ($Lines.Count -gt $displayLines.Count) {
            "Showing the first $($displayLines.Count) of $($Lines.Count) lines. Use the download link for the complete result."
        } else {
            "Lines: $($Lines.Count)"
        }

        $content = HtmlEncode (($displayLines | ForEach-Object { [string]$_ }) -join "`r`n")
        return @"
<div class="result-note">$(HtmlEncode $note)</div>
<div class="result-scroll">
  <pre class="result-pre">$content</pre>
</div>
"@
    }

    function Get-CsvDownloadName {
        param(
            [string]$Name,
            [string]$Fallback = 'result.csv'
        )

        if ([string]::IsNullOrWhiteSpace($Name)) { return $Fallback }

        $base = ''
        try { $base = [System.IO.Path]::GetFileNameWithoutExtension($Name) } catch { $base = $Name }
        if ([string]::IsNullOrWhiteSpace($base)) { $base = 'result' }
        return ('{0}.csv' -f $base)
    }

    function Convert-LinesToTableRows {
        param(
            [string[]]$Lines,
            [string]$PrimaryColumn = 'Result'
        )

        $rows = New-Object 'System.Collections.Generic.List[object]'
        if (-not $Lines) { return @() }

        $lineNumber = 1
        foreach ($line in $Lines) {
            if ($null -eq $line) { continue }
            $text = ([string]$line).Trim()
            if ($text.Length -eq 0) { continue }

            $rows.Add([pscustomobject]@{
                Line = $lineNumber
                $PrimaryColumn = $text
            }) | Out-Null

            $lineNumber++
        }

        return $rows.ToArray()
    }

    function Get-TextFindingTableData {
        param(
            [object]$Finding,
            [object]$Definition,
            [string]$SourcePath
        )

        $SourcePath = Resolve-AuditArtifactPath $SourcePath
        $title = Get-CanonicalTitle $Finding.Title
        $rows = @()
        $columns = @()
        $lines = if ($SourcePath) { @(Get-NonHeaderLines $SourcePath) } else { @() }

        switch -Regex ($title) {
            '^Inactive computer accounts \(>90 days\)$' {
                $tmp = New-Object 'System.Collections.Generic.List[object]'
                foreach ($line in $lines) {
                    if ($line -match '^Computer\s+(?<Name>\S+)\s+\((?<DNSHostName>.*?)\)\s+OS:\s+(?<OperatingSystem>.*?)\s+last logon:\s+(?<LastLogon>.+)$') {
                        $tmp.Add([pscustomobject]@{
                            Name            = $matches['Name'].Trim()
                            DNSHostName     = $matches['DNSHostName'].Trim()
                            OperatingSystem = $matches['OperatingSystem'].Trim()
                            LastLogon       = $matches['LastLogon'].Trim()
                        }) | Out-Null
                    }
                }
                $rows = $tmp.ToArray()
                $columns = @('Name','DNSHostName','OperatingSystem','LastLogon')
                break
            }

            '^Domain controllers allow weak Kerberos ciphers$' {
                $tmp = New-Object 'System.Collections.Generic.List[object]'
                $current = [ordered]@{}
                foreach ($line in $lines) {
                    $t = ([string]$line).Trim()
                    if ($t -match '^Link:') { continue }

                    if ($t -match '^Decimal Value:\s*(?<Value>.+)$') {
                        $current['DecimalValue'] = $matches['Value'].Trim()
                        continue
                    }
                    if ($t -match '^Hex Value:\s*(?<Value>.+)$') {
                        $current['HexValue'] = $matches['Value'].Trim()
                        continue
                    }
                    if ($t -match '^Supported Encryption Types:\s*(?<Value>.+)$') {
                        $current['SupportedEncryptionTypes'] = $matches['Value'].Trim()
                        if ($current.Contains('DomainController')) {
                            $tmp.Add([pscustomobject]@{
                                DomainController          = [string]$current['DomainController']
                                DecimalValue              = [string]$current['DecimalValue']
                                HexValue                  = [string]$current['HexValue']
                                SupportedEncryptionTypes  = [string]$current['SupportedEncryptionTypes']
                            }) | Out-Null
                        }
                        $current = [ordered]@{}
                        continue
                    }

                    if (-not $t.Contains(':')) {
                        if ($current.Contains('DomainController')) {
                            $tmp.Add([pscustomobject]@{
                                DomainController          = [string]$current['DomainController']
                                DecimalValue              = [string]$current['DecimalValue']
                                HexValue                  = [string]$current['HexValue']
                                SupportedEncryptionTypes  = [string]$current['SupportedEncryptionTypes']
                            }) | Out-Null
                        }
                        $current = [ordered]@{ DomainController = $t }
                    }
                }

                if ($current.Contains('DomainController')) {
                    $tmp.Add([pscustomobject]@{
                        DomainController          = [string]$current['DomainController']
                        DecimalValue              = [string]$current['DecimalValue']
                        HexValue                  = [string]$current['HexValue']
                        SupportedEncryptionTypes  = [string]$current['SupportedEncryptionTypes']
                    }) | Out-Null
                }

                $rows = $tmp.ToArray()
                $columns = @('DomainController','DecimalValue','HexValue','SupportedEncryptionTypes')
                break
            }

            '^Kerberoastable SPNs present \(review high-value service accounts\)$' {
                $rows = @(
                    $lines |
                    Where-Object { $_ -and $_ -notmatch '^No high value kerberoastable user accounts identified\.$' } |
                    ForEach-Object {
                        [pscustomobject]@{ AccountName = ([string]$_).Trim() }
                    }
                )
                $columns = @('AccountName')
                break
            }

            '^LAPS password read rights widely delegated$' {
                $tmp = New-Object 'System.Collections.Generic.List[object]'
                foreach ($line in $lines) {
                    if ($line -match '^(?<Trustee>.+?) can read password attribute of (?<ObjectDN>.+)$') {
                        $tmp.Add([pscustomobject]@{
                            Trustee  = $matches['Trustee'].Trim()
                            ObjectDN = $matches['ObjectDN'].Trim()
                        }) | Out-Null
                    }
                }
                $rows = $tmp.ToArray()
                $columns = @('Trustee','ObjectDN')
                break
            }

            '^LAPS passwords expired$' {
                $tmp = New-Object 'System.Collections.Generic.List[object]'
                foreach ($line in $lines) {
                    if ($line -match '^(?<Computer>.+?) password is expired since (?<Expiration>.+)$') {
                        $tmp.Add([pscustomobject]@{
                            Computer   = $matches['Computer'].Trim()
                            Expiration = $matches['Expiration'].Trim()
                        }) | Out-Null
                    }
                }
                $rows = $tmp.ToArray()
                $columns = @('Computer','Expiration')
                break
            }

            '^LDAP security misconfiguration detected$' {
                $rows = @(Convert-LinesToTableRows -Lines $lines -PrimaryColumn 'Issue')
                $columns = @('Issue')
                break
            }

            '^NTLM authentication is not restricted or hardened by GPO$|^NTLM restrictions require hardening$' {
                $tmp = New-Object 'System.Collections.Generic.List[object]'
                foreach ($line in $lines) {
                    if ($line -match '^NTLM restricted by GPO \[(?<GPO>.+?)\] with value \[(?<Value>.+?)\]$') {
                        $tmp.Add([pscustomobject]@{
                            Type  = 'RestrictedByGPO'
                            GPO   = $matches['GPO'].Trim()
                            Value = $matches['Value'].Trim()
                        }) | Out-Null
                        continue
                    }
                    if ($line -match '^NTLM audit GPO \[(?<GPO>.+?)\] with value \[(?<Value>.+?)\]$') {
                        $tmp.Add([pscustomobject]@{
                            Type  = 'AuditByGPO'
                            GPO   = $matches['GPO'].Trim()
                            Value = $matches['Value'].Trim()
                        }) | Out-Null
                        continue
                    }
                    if ($line -match '^NTLM auth exceptions (?<Value>.+)$') {
                        $tmp.Add([pscustomobject]@{
                            Type  = 'Exceptions'
                            GPO   = ''
                            Value = $matches['Value'].Trim()
                        }) | Out-Null
                        continue
                    }

                    $tmp.Add([pscustomobject]@{
                        Type  = 'Detail'
                        GPO   = ''
                        Value = ([string]$line).Trim()
                    }) | Out-Null
                }
                $rows = $tmp.ToArray()
                $columns = @('Type','GPO','Value')
                break
            }

            '^DNS zones allowing insecure updates$' {
                $tmp = New-Object 'System.Collections.Generic.List[object]'
                foreach ($line in $lines) {
                    if ($line -match '^The DNS Zone (?<ZoneName>.+?) on DNS server (?<DnsServer>.+?) allows insecure updates \((?<DynamicUpdate>.+)\)$') {
                        $tmp.Add([pscustomobject]@{
                            ZoneName      = $matches['ZoneName'].Trim()
                            DnsServer     = $matches['DnsServer'].Trim()
                            DynamicUpdate = $matches['DynamicUpdate'].Trim()
                        }) | Out-Null
                    }
                }
                $rows = $tmp.ToArray()
                $columns = @('ZoneName','DnsServer','DynamicUpdate')
                break
            }

            '^Delegated permissions risks detected$|^Delegated permissions recommendations available$' {
                $rows = @(Convert-LinesToTableRows -Lines $lines -PrimaryColumn 'Note')
                $columns = @('Note')
                break
            }
        }

        if (-not $rows -or $rows.Count -eq 0) {
            $rows = @(Convert-LinesToTableRows -Lines $lines -PrimaryColumn 'Result')
            $columns = @('Result')
        }

        return [pscustomobject]@{
            Rows    = @($rows)
            Columns = @($columns)
            Lines   = @($lines)
        }
    }

    function Get-FindingArtifactDefinition {
        param([object]$Finding)

        $title = Get-CanonicalTitle $Finding.Title
        $sourceRoot  = Get-RawSourceDataDir -BaseRoot $InputRoot
        $highRiskDir = Resolve-AuditArtifactPath (Join-Path $InputRoot 'HighRisk')
        $htmlRoot = Get-HtmlReportsDir -BaseRoot $InputRoot
        $sourcePath = Resolve-AuditArtifactPath (Get-NormalizedAbsolutePath $Finding.Link)
        $sourceExt = ''
        try { $sourceExt = [System.IO.Path]::GetExtension($sourcePath).ToLowerInvariant() } catch { }

        $definition = [ordered]@{
            Type        = 'auto'
            SourcePath  = $sourcePath
            DownloadName = if ($sourcePath) { [System.IO.Path]::GetFileName($sourcePath) } else { ('{0}.txt' -f (New-Slug $title)) }
            ButtonText  = 'Download Result'
            Columns     = @()
            FilterColumn = $null
            FilterValue  = $null
        }

        switch -Regex ($title) {
            '^Domain Admins group overlap \(extra group memberships\)$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'accounts_domain_admins_group_overlap.csv'
                $definition.DownloadName = 'accounts_domain_admins_group_overlap.csv'
                $definition.Columns = @('SamAccountName','Name','Enabled','ExtraGroupCount','ExtraGroups','Tier1GroupsFound','Flags')
                break
            }
            '^Domain Admins$|^Domain Admins membership size$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'Domain_Admins.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'Domain Admins'
                break
            }
            '^Enterprise Admins$|^Enterprise Admins membership size$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'Enterprise_Admins.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'Enterprise Admins'
                break
            }
            '^Schema Admins$|^Schema Admins membership size$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'Schema_Admins.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'Schema Admins'
                break
            }
            '^BUILTIN\\Administrators$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'BUILTIN_Administrators.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'BUILTIN\Administrators'
                break
            }
            '^BUILTIN\\Account Operators$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'BUILTIN_Account_Operators.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'BUILTIN\Account Operators'
                break
            }
            '^BUILTIN\\Server Operators$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'BUILTIN_Server_Operators.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'BUILTIN\Server Operators'
                break
            }
            '^BUILTIN\\Backup Operators$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'BUILTIN_Backup_Operators.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'BUILTIN\Backup Operators'
                break
            }
            '^BUILTIN\\Print Operators$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'BUILTIN_Print_Operators.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'BUILTIN\Print Operators'
                break
            }
            '^Large privileged group membership$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'PRIVILEGED_GROUPS.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass','Baseline','Severity')
                break
            }
            '^Observed inactive enabled accounts \(>180 days\)$|^Inactive enabled accounts$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'INACTIVE_ACCOUNTS.csv'
                $definition.DownloadName = 'INACTIVE_ACCOUNTS.csv'
                $definition.Columns = @('SamAccountName','Name','LastLogonDate','WhenCreated','IsPrivileged')
                break
            }
            '^Enabled user accounts with PasswordNeverExpires$|^Accounts with password set to not expire$|^Passwords set to never expire$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PASSWORD_NEVER_EXPIRES.csv'
                $definition.DownloadName = 'PASSWORD_NEVER_EXPIRES.csv'
                break
            }
            '^Disabled stale accounts$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'DISABLED_STALE.csv'
                $definition.DownloadName = 'DISABLED_STALE.csv'
                break
            }
            '^Duplicate passwords detected$|^Duplicate passwords' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'DUPLICATE_PASSWORDS.csv'
                $definition.DownloadName = 'DUPLICATE_PASSWORDS.csv'
                $definition.Columns = @('PasswordGroup','SharedCount','SamAccountName','SamePasswordAccounts','IsPrivileged','Severity','Baseline')
                break
            }
            '^KRBTGT password age is high$|^krbtgt password age$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'KRBTGT.csv'
                $definition.DownloadName = 'KRBTGT.csv'
                break
            }
            '^ms-DS-MachineAccountQuota$|^MachineAccountQuota permits user-created computers$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'MACHINE_ACCOUNT_QUOTA.csv'
                $definition.DownloadName = 'MACHINE_ACCOUNT_QUOTA.csv'
                break
            }
            '^Passwords stored using reversible encryption$' {
                $definition.Type = 'reversible'
                $definition.SourcePath = Join-Path $InputRoot 'password_quality.txt'
                $definition.DownloadName = 'reversible_encryption_accounts.txt'
                break
            }
            '^Accounts without Kerberos pre-auth \(AS-REP roastable\)$' {
                $definition.Type = 'asrep'
                $definition.SourcePath = Join-Path $InputRoot 'ASREP.txt'
                $definition.DownloadName = 'ASREP.txt'
                break
            }
            '^Disabled user accounts present \(review and cleanup\)$' {
                $definition.Type = 'disabled-accounts'
                $definition.SourcePath = Join-Path $InputRoot 'accounts_disabled.txt'
                $definition.DownloadName = 'accounts_disabled.txt'
                break
            }
            '^Domain controllers allow weak Kerberos ciphers$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'dcs_weak_kerberos_ciphersuite.txt'
                $definition.DownloadName = 'dcs_weak_kerberos_ciphersuite.txt'
                break
            }
            '^Kerberoastable SPNs present \(review high-value service accounts\)$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'SPNs.txt'
                $definition.DownloadName = 'SPNs.txt'
                break
            }
            '^Inactive computer accounts \(>90 days\)$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'computers_inactive_90days.txt'
                $definition.DownloadName = 'computers_inactive_90days.txt'
                break
            }
            '^LAPS password read rights widely delegated$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'laps_read-extendedrights.txt'
                $definition.DownloadName = 'laps_read-extendedrights.txt'
                break
            }
            '^LAPS passwords expired$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'laps_expired-passwords.txt'
                $definition.DownloadName = 'laps_expired-passwords.txt'
                break
            }
            '^LDAP security misconfiguration detected$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'LDAPSecurity.txt'
                $definition.DownloadName = 'LDAPSecurity.txt'
                break
            }
            '^NTLM authentication is not restricted or hardened by GPO$|^NTLM restrictions require hardening$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'ntlm_restrictions.txt'
                $definition.DownloadName = 'ntlm_restrictions.txt'
                break
            }
            '^DNS zones allowing insecure updates$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'insecure_dns_zones.txt'
                $definition.DownloadName = 'insecure_dns_zones.txt'
                break
            }
            '^Delegated permissions risks detected$|^Delegated permissions recommendations available$' {
                $definition.Type = 'text'
                if ($sourcePath) { $definition.DownloadName = [System.IO.Path]::GetFileName($sourcePath) }
                break
            }
            '^Group Policy report available$' {
                $definition.Type = 'html'
                $definition.SourcePath = Join-Path $htmlRoot 'GPOReport.html'
                $definition.DownloadName = 'GPOReport.html'
                $definition.ButtonText = 'Open Report'
                break
            }
            '^Lateral movement map report available$' {
                $definition.Type = 'html'
                $definition.SourcePath = Join-Path $htmlRoot 'Lateral-Movement.html'
                $definition.DownloadName = 'Lateral-Movement.html'
                $definition.ButtonText = 'Open Report'
                break
            }
            '^Overlapping group membership report available$' {
                $definition.Type = 'html'
                $definition.SourcePath = Join-Path $htmlRoot 'overlapping_group_memberships.html'
                $definition.DownloadName = 'overlapping_group_memberships.html'
                $definition.ButtonText = 'Open Report'
                break
            }
            '^Multiple nested paths report available$' {
                $definition.Type = 'html'
                $definition.SourcePath = Join-Path $htmlRoot 'multiple_nested_paths.html'
                $definition.DownloadName = 'multiple_nested_paths.html'
                $definition.ButtonText = 'Open Report'
                break
            }
            '^Dangerous ACL report available$' {
                $definition.Type = 'html'
                $definition.SourcePath = Join-Path $htmlRoot 'dangerousACLs.html'
                $definition.DownloadName = 'dangerousACLs.html'
                $definition.ButtonText = 'Open Report'
                break
            }
            '^Delegated permissions report available$|^DNS audit report available$|^DNS recommendations report available$|^High-risk baseline report available$' {
                $definition.Type = 'html'
                if ($sourcePath) { $definition.DownloadName = [System.IO.Path]::GetFileName($sourcePath) }
                $definition.ButtonText = 'Open Report'
                break
            }
            'unconstrained.*delegation' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $sourceRoot 'unconstrained_delegation.txt'
                $definition.DownloadName = 'unconstrained_delegation.txt'
                break
            }
            'gMSA|service account.*not.*gMSA' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $sourceRoot 'gmsa_status.txt'
                $definition.DownloadName = 'gmsa_status.txt'
                break
            }
            'Print Spooler' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $sourceRoot 'dc_print_spooler.txt'
                $definition.DownloadName = 'dc_print_spooler.txt'
                break
            }
            'SMB signing' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $sourceRoot 'dc_smb_signing.txt'
                $definition.DownloadName = 'dc_smb_signing.txt'
                break
            }
        }

        if ($definition.Type -eq 'auto') {
            switch ($sourceExt) {
                '.csv'  { $definition.Type = 'csv' }
                '.txt'  { $definition.Type = 'text' }
                '.html' { $definition.Type = 'html'; $definition.ButtonText = 'Open Report' }
                default { $definition.Type = 'text' }
            }
        }

        $definition.SourcePath = Resolve-AuditArtifactPath (Get-NormalizedAbsolutePath $definition.SourcePath)
        return [pscustomobject]$definition
    }

    function Copy-DownloadFile([string]$SourcePath, [string]$DestinationPath) {
        if ([string]::IsNullOrWhiteSpace($SourcePath) -or [string]::IsNullOrWhiteSpace($DestinationPath)) { return $false }
        if (-not (Test-Path -LiteralPath $SourcePath)) { return $false }

        try {
            Ensure-DirectoryPath (Split-Path -Path $DestinationPath -Parent)
            Copy-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop
            return $true
        } catch {
            return $false
        }
    }

    function Publish-CommonDownloadArtifacts {
        param(
            [string]$Root,
            [string]$DownloadRoot
        )

        Ensure-DirectoryPath $DownloadRoot
        Ensure-DirectoryPath (Join-Path $DownloadRoot 'HighRisk')
    }

    function New-FindingResultPresentation {
        param(
            [object]$Finding,
            [string]$AuditReportPath,
            [string]$DownloadRoot
        )

        $definition = Get-FindingArtifactDefinition -Finding $Finding
        $sourcePath = $definition.SourcePath
        $downloadPath = $null
        $downloadHref = ''
        $downloadLabel = ''
        $resultsHtml = "<div class='result-empty'>Detailed result data was not available for this finding.</div>"
        $buttonText = if ($definition.ButtonText) { [string]$definition.ButtonText } else { 'Download Result' }
        $openInNewTab = $false

        switch ($definition.Type) {
            'html' {
                if ($sourcePath -and (Test-Path -LiteralPath $sourcePath)) {
                    $downloadPath = $sourcePath
                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                    $resultsHtml = "<div class='result-empty'>This finding is backed by a companion HTML report. Use the button below to open the full report.</div>"
                    $openInNewTab = $true
                }
            }

            'csv' {
                $rows = if ($sourcePath) { @(Get-CsvSafe $sourcePath) } else { @() }
                $filtered = $false
                if ($rows.Count -gt 0 -and $definition.FilterColumn -and $definition.FilterValue) {
                    $rows = @(
                        $rows | Where-Object {
                            $_.PSObject.Properties[$definition.FilterColumn] -and
                            ([string]$_.PSObject.Properties[$definition.FilterColumn].Value).Trim() -eq [string]$definition.FilterValue
                        }
                    )
                    $filtered = $true
                }

                if ($rows.Count -gt 0) {
                    if ($filtered) {
                        $downloadPath = Join-Path $DownloadRoot $definition.DownloadName
                        Ensure-DirectoryPath (Split-Path -Path $downloadPath -Parent)
                        $rows | Export-Csv -LiteralPath $downloadPath -NoTypeInformation -Encoding UTF8
                    }
                    else {
                        $downloadPath = $sourcePath
                    }

                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                    $resultsHtml = New-PreviewTableHtml -Rows $rows -Columns $definition.Columns -MaxRows 250
                }
                elseif ($sourcePath -and (Test-Path -LiteralPath $sourcePath)) {
                    $resultsHtml = "<div class='result-empty'>The source CSV exists, but no rows matched this finding after filtering.</div>"
                }
            }

            'text' {
                $tableData = Get-TextFindingTableData -Finding $Finding -Definition $definition -SourcePath $sourcePath
                $rows = @($tableData.Rows)

                if ($rows.Count -gt 0) {
                    $downloadPath = Join-Path $DownloadRoot (Get-CsvDownloadName -Name $definition.DownloadName -Fallback ('{0}.csv' -f (New-Slug $Finding.Title)))
                    Ensure-DirectoryPath (Split-Path -Path $downloadPath -Parent)
                    $rows | Export-Csv -LiteralPath $downloadPath -NoTypeInformation -Encoding UTF8

                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                    $resultsHtml = New-PreviewTableHtml -Rows $rows -Columns $tableData.Columns -MaxRows 250
                }
                elseif ($sourcePath -and (Test-Path -LiteralPath $sourcePath)) {
                    $downloadPath = $sourcePath
                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                    $resultsHtml = "<div class='result-empty'>A source text file exists for this finding, but no detailed rows could be parsed into a table.</div>"
                }
            }

            'disabled-accounts' {
                $rows = if ($sourcePath) { @(Get-DisabledAccounts -Path $sourcePath) } else { @() }
                if ($rows.Count -gt 0) {
                    $downloadPath = Join-Path $DownloadRoot (Get-CsvDownloadName -Name $definition.DownloadName -Fallback 'accounts_disabled.csv')
                    Ensure-DirectoryPath (Split-Path -Path $downloadPath -Parent)
                    $rows | Export-Csv -LiteralPath $downloadPath -NoTypeInformation -Encoding UTF8

                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                    $resultsHtml = New-PreviewTableHtml -Rows $rows -Columns @('SamAccountName','DisplayName') -MaxRows 250
                }
            }

            'asrep' {
                $rows = if ($sourcePath) { @(Get-AsrepAccounts -Path $sourcePath) } else { @() }
                if ($rows.Count -gt 0) {
                    $downloadPath = Join-Path $DownloadRoot (Get-CsvDownloadName -Name $definition.DownloadName -Fallback 'ASREP.csv')
                    Ensure-DirectoryPath (Split-Path -Path $downloadPath -Parent)
                    $rows | Export-Csv -LiteralPath $downloadPath -NoTypeInformation -Encoding UTF8

                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                    $resultsHtml = New-PreviewTableHtml -Rows $rows -Columns @('SamAccountName','DisplayName') -MaxRows 250
                }
            }

            'reversible' {
                $lines = if ($sourcePath) { @(Get-ReversibleEncryptionAccounts -Path $sourcePath) } else { @() }
                if ($lines.Count -gt 0) {
                    $rows = @(
                        $lines | ForEach-Object {
                            [pscustomobject]@{ Account = ([string]$_).Trim() }
                        }
                    )

                    $downloadPath = Join-Path $DownloadRoot (Get-CsvDownloadName -Name $definition.DownloadName -Fallback 'reversible_encryption_accounts.csv')
                    Ensure-DirectoryPath (Split-Path -Path $downloadPath -Parent)
                    $rows | Export-Csv -LiteralPath $downloadPath -NoTypeInformation -Encoding UTF8

                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                    $resultsHtml = New-PreviewTableHtml -Rows $rows -Columns @('Account') -MaxRows 250
                }
            }

            default {
                if ($sourcePath -and (Test-Path -LiteralPath $sourcePath)) {
                    $downloadPath = $sourcePath
                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                }
            }
        }

        return [pscustomobject]@{
            DownloadHref  = $downloadHref
            DownloadLabel = $downloadLabel
            DownloadText  = $buttonText
            ResultsHtml   = $resultsHtml
            OpenInNewTab  = $openInNewTab
            ResolvedSourcePath = $sourcePath
        }
    }

    function Write-AuditHtmlReport {
        [CmdletBinding()]
        param(
            [string]$Path,
            [object[]]$Items,
            [hashtable]$Counts,
            [string]$ComputerName,
            [string]$GeneratedOn,
            [string]$ManagementReportPath,
            [object[]]$CompanionReports
        )

        $severityOrder = @('Critical','High','Medium','Low','Information')
        $totalCount = if ($Items) { $Items.Count } else { 0 }
        $managementRel = Get-RelativeHref -FromFile $Path -ToPath $ManagementReportPath

        $priorityItems = @(
            $Items |
            Where-Object { (Normalize-Severity $_.Severity) -in @('Critical','High') } |
            Sort-Object -Property @{Expression={ Get-SeverityRank $_.Severity }; Descending=$true}, @{Expression='Score';Descending=$true}, @{Expression='Title';Descending=$false} |
            Select-Object -First 8
        )

        $countCards = New-Object 'System.Collections.Generic.List[string]'
        foreach ($sev in $severityOrder) {
            $count = 0
            if ($Counts.ContainsKey($sev)) { $count = [int]$Counts[$sev] }
            $countCards.Add(@"
<div class="metric sev-$sev">
  <div class="metric-label">$sev</div>
  <div class="metric-value">$count</div>
</div>
"@) | Out-Null
        }

        $priorityHtml = @()
        if ($priorityItems.Count -gt 0) {
            foreach ($item in $priorityItems) {
                $anchor = New-FindingAnchor $item
                $priorityHtml += @"
<li>
  <span class="badge sev-$(Normalize-Severity $item.Severity)">$(Normalize-Severity $item.Severity)</span>
  <a class="priority-title" href="#$anchor">$(HtmlEncode $item.Title)</a>
  <span class="priority-evidence">$(HtmlEncode $item.Evidence)</span>
</li>
"@
            }
        } else {
            $priorityHtml += '<li>No high-priority findings were identified from the collected results.</li>'
        }

        $findingIndexHtml = New-Object 'System.Collections.Generic.List[string]'
        foreach ($sev in $severityOrder) {
            $bucket = @(
                $Items |
                Where-Object { (Normalize-Severity $_.Severity) -eq $sev } |
                Sort-Object -Property @{Expression='Score';Descending=$true}, @{Expression='Title';Descending=$false}
            )

            if ($bucket.Count -eq 0) { continue }

            $indexRows = New-Object 'System.Collections.Generic.List[string]'
            foreach ($item in $bucket) {
                $anchor = New-FindingAnchor $item
                $indexRows.Add("<li><a href='#$(HtmlAttrEncode $anchor)'>$(HtmlEncode $item.Title)</a></li>") | Out-Null
            }

            $findingIndexHtml.Add(@"
<details class="index-detail">
  <summary>$sev ($($bucket.Count))</summary>
  <ol>
    $($indexRows -join "`n")
  </ol>
</details>
"@) | Out-Null
        }

        if ($findingIndexHtml.Count -eq 0) {
            $findingIndexHtml.Add('<div class="empty">No finding index entries were available.</div>') | Out-Null
        }

        $sectionHtml = New-Object 'System.Collections.Generic.List[string]'
        foreach ($sev in $severityOrder) {
            $bucket = @(
                $Items |
                Where-Object { (Normalize-Severity $_.Severity) -eq $sev } |
                Sort-Object -Property @{Expression='Score';Descending=$true}, @{Expression='Title';Descending=$false}
            )

            $bucketHtml = New-Object 'System.Collections.Generic.List[string]'
            if ($bucket.Count -eq 0) {
                $bucketHtml.Add('<div class="empty">No findings in this severity band.</div>') | Out-Null
            }
            else {
                foreach ($item in $bucket) {
                    $sevNorm = Normalize-Severity $item.Severity
                    $anchor  = New-FindingAnchor $item
                    $category = Get-FindingCategory $item.Title

                    $downloadHref = ''
                    $downloadLabel = ''
                    $downloadText = 'Download Result'
                    $resultPanelHtml = "<div class='result-empty'>Detailed result data was not available for this finding.</div>"
                    $downloadModeAttrs = ''

                    if ($item.PSObject.Properties['DownloadHref'] -and $item.DownloadHref) { $downloadHref = [string]$item.DownloadHref }
                    if ($item.PSObject.Properties['DownloadLabel'] -and $item.DownloadLabel) { $downloadLabel = [string]$item.DownloadLabel }
                    if ($item.PSObject.Properties['DownloadText'] -and $item.DownloadText) { $downloadText = [string]$item.DownloadText }
                    if ($item.PSObject.Properties['ResultsHtml'] -and $item.ResultsHtml) { $resultPanelHtml = [string]$item.ResultsHtml }
                    if ($item.PSObject.Properties['OpenInNewTab'] -and $item.OpenInNewTab) {
                        $downloadModeAttrs = " target='_blank' rel='noopener'"
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($downloadLabel)) {
                        $downloadModeAttrs = " download='" + (HtmlAttrEncode $downloadLabel) + "'"
                    }

                    $downloadHtml = if (-not [string]::IsNullOrWhiteSpace($downloadHref)) {
                        @"
<a class="download-link" href="$(HtmlAttrEncode $downloadHref)"$downloadModeAttrs>$(HtmlEncode $downloadText)</a>
<div class="download-name mono">$(HtmlEncode $downloadLabel)</div>
"@
                    } else {
                        "<span class='mono'>No downloadable result file was generated for this finding.</span>"
                    }

                    $bucketHtml.Add(@"
<details class="finding sev-$sevNorm" data-sev="$sevNorm" data-category="$(HtmlAttrEncode $category)" id="$anchor">
  <summary>
    <div class="finding-head">
      <div class="finding-title-wrap">
        <span class="badge sev-$sevNorm">$sevNorm</span>
        <span class="category">$(HtmlEncode $category)</span>
        <span class="finding-title">$(HtmlEncode $item.Title)</span>
      </div>
      <div class="finding-summary">$(HtmlEncode $item.Evidence)</div>
    </div>
  </summary>
  <div class="finding-body">
    <div class="finding-grid">
      <div class="panel">
        <h4>What was observed</h4>
        <p>$(HtmlEncode $item.Evidence)</p>
      </div>
      <div class="panel">
        <h4>Why it matters</h4>
        <p>$(HtmlEncode (Get-FindingWhyItMatters $item.Title))</p>
      </div>
      <div class="panel">
        <h4>Recommended action</h4>
        <p>$(HtmlEncode (Get-FindingRecommendation $item.Title))</p>
      </div>
      <div class="panel">
        <h4>Download Result</h4>
        <div class="download-wrap">
          $downloadHtml
        </div>
      </div>
    </div>
    <div class="panel evidence">
      <h4>Result details</h4>
      $resultPanelHtml
    </div>
  </div>
</details>
"@) | Out-Null
                }
            }

            $sectionHtml.Add(@"
<section class="severity-section" id="section-$(New-Slug $sev)">
  <div class="section-header">
    <h2>$sev</h2>
    <div class="section-count">$($bucket.Count) findings</div>
  </div>
  $($bucketHtml -join "`n")
</section>
"@) | Out-Null
        }

        $companionHtml = New-Object 'System.Collections.Generic.List[string]'
        if ($CompanionReports -and $CompanionReports.Count -gt 0) {
            foreach ($report in $CompanionReports) {
                $reportHref = ''
                if ($report.PSObject.Properties['FullPath'] -and $report.FullPath) {
                    $reportHref = Get-RelativeHref -FromFile $Path -ToPath $report.FullPath
                }
                elseif ($report.PSObject.Properties['RelativePath'] -and $report.RelativePath) {
                    $reportHref = [string]$report.RelativePath
                }

                if ($reportHref) {
                    $companionHtml.Add("<li><a href='$(HtmlAttrEncode $reportHref)'>$(HtmlEncode $report.Title)</a></li>") | Out-Null
                }
            }
        }
        if ($companionHtml.Count -eq 0) {
            $companionHtml.Add('<li>No additional HTML companion reports were detected.</li>') | Out-Null
        }

        $css = @"
<style>
:root{
  --bg:#f5f7fb;
  --panel:#ffffff;
  --text:#1b2430;
  --muted:#5f6b7a;
  --line:#d9e0ea;
  --shadow:0 10px 24px rgba(15,23,42,.08);
  --critical:#c62828;
  --high:#ef6c00;
  --medium:#0277bd;
  --low:#2e7d32;
  --information:#6c757d;
  --critical-soft:#fdecec;
  --high-soft:#fff2e5;
  --medium-soft:#e8f4fd;
  --low-soft:#edf8ee;
  --information-soft:#f2f4f6;
  --result-panel:#ffffff;
}
body[data-theme="dark"]{
  --bg:#0f172a;
  --panel:#111827;
  --text:#e5e7eb;
  --muted:#94a3b8;
  --line:#334155;
  --shadow:0 10px 24px rgba(0,0,0,.35);
  --critical:#f87171;
  --high:#fb923c;
  --medium:#60a5fa;
  --low:#4ade80;
  --information:#cbd5e1;
  --critical-soft:rgba(248,113,113,.15);
  --high-soft:rgba(251,146,60,.14);
  --medium-soft:rgba(96,165,250,.14);
  --low-soft:rgba(74,222,128,.14);
  --information-soft:rgba(203,213,225,.12);
  --result-panel:#0b1220;
}
*{box-sizing:border-box}
body{
  margin:0;
  font-family:Segoe UI,Arial,sans-serif;
  background:var(--bg);
  color:var(--text);
}
a{color:#0f5cb8;text-decoration:none}
body[data-theme="dark"] a{color:#93c5fd}
a:hover{text-decoration:underline}
.container{max-width:1280px;margin:0 auto;padding:28px 22px 48px}
.hero{
  background:var(--panel);
  border:1px solid var(--line);
  border-radius:18px;
  box-shadow:var(--shadow);
  padding:24px;
}
.hero-top{
  display:flex;
  justify-content:space-between;
  gap:20px;
  flex-wrap:wrap;
  align-items:flex-start;
}
.hero-actions{
  display:flex;
  flex-direction:column;
  align-items:flex-end;
  gap:12px;
}
.theme-toggle{
  border:1px solid var(--line);
  background:var(--panel);
  color:var(--text);
  border-radius:999px;
  padding:10px 14px;
  font-size:13px;
  font-weight:700;
  cursor:pointer;
}
.theme-toggle:hover{transform:translateY(-1px)}
h1{margin:0 0 8px;font-size:28px}
.meta{color:var(--muted);font-size:14px;line-height:1.6}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-top:22px}
.metric{
  border:1px solid var(--line);
  border-radius:14px;
  padding:14px 16px;
  background:var(--panel);
}
.metric-label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700}
.metric-value{font-size:30px;font-weight:800;margin-top:6px}
.metric.sev-Critical{background:var(--critical-soft)}
.metric.sev-High{background:var(--high-soft)}
.metric.sev-Medium{background:var(--medium-soft)}
.metric.sev-Low{background:var(--low-soft)}
.metric.sev-Information{background:var(--information-soft)}
.layout{display:grid;grid-template-columns:280px minmax(0,1fr);gap:20px;margin-top:20px}
.sidebar{
  position:sticky;top:18px;align-self:start;
  background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:18px;
}
.sidebar h3,.content h2{margin-top:0}
.sidebar ul{list-style:none;padding:0;margin:0}
.sidebar li{margin:10px 0}
.index-group{margin-top:18px;padding-top:18px;border-top:1px solid var(--line)}
.index-group h4{margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.index-detail{border:1px solid var(--line);border-radius:12px;padding:8px 10px;background:#f8fafc;margin-bottom:10px}
body[data-theme="dark"] .index-detail{background:var(--result-panel)}
.index-detail summary{cursor:pointer;font-weight:700;list-style:none}
.index-detail summary::-webkit-details-marker{display:none}
.index-detail ol{margin:10px 0 0 18px;padding:0;max-height:260px;overflow:auto}
.index-detail li{margin:6px 0}
.index-detail a{color:var(--text)}
.badge{
  display:inline-flex;
  align-items:center;
  border-radius:999px;
  padding:4px 10px;
  font-size:12px;
  font-weight:800;
  letter-spacing:.02em;
  margin-right:8px;
  border:1px solid transparent;
}
.badge.sev-Critical{background:var(--critical-soft);color:var(--critical);border-color:rgba(198,40,40,.25)}
.badge.sev-High{background:var(--high-soft);color:var(--high);border-color:rgba(239,108,0,.25)}
.badge.sev-Medium{background:var(--medium-soft);color:var(--medium);border-color:rgba(2,119,189,.25)}
.badge.sev-Low{background:var(--low-soft);color:var(--low);border-color:rgba(46,125,50,.25)}
.badge.sev-Information{background:var(--information-soft);color:var(--information);border-color:rgba(108,117,125,.25)}
.category{
  display:inline-flex;
  align-items:center;
  border-radius:999px;
  padding:4px 10px;
  font-size:12px;
  font-weight:700;
  color:var(--muted);
  background:#f4f6f9;
  border:1px solid var(--line);
  margin-right:8px;
}
body[data-theme="dark"] .category{background:#1f2937}
.toolbar{
  background:var(--panel);
  border:1px solid var(--line);
  border-radius:18px;
  box-shadow:var(--shadow);
  padding:16px;
  margin-bottom:18px;
}
.toolbar-row{
  display:flex;
  gap:12px;
  flex-wrap:wrap;
  align-items:flex-end;
}
label{font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
select,input{
  width:100%;
  min-height:42px;
  border:1px solid var(--line);
  border-radius:10px;
  padding:10px 12px;
  background:var(--panel);
  color:var(--text);
}
.filter{min-width:220px;flex:1}
.section-header{
  display:flex;justify-content:space-between;align-items:center;gap:12px;
  margin:0 0 12px;
}
.section-header h2{margin:0;font-size:24px}
.section-count{color:var(--muted);font-size:14px;font-weight:700}
.finding{
  background:var(--panel);
  border:1px solid var(--line);
  border-left:6px solid var(--information);
  border-radius:16px;
  box-shadow:var(--shadow);
  margin-bottom:14px;
  overflow:hidden;
}
.finding.sev-Critical{border-left-color:var(--critical)}
.finding.sev-High{border-left-color:var(--high)}
.finding.sev-Medium{border-left-color:var(--medium)}
.finding.sev-Low{border-left-color:var(--low)}
.finding.sev-Information{border-left-color:var(--information)}
.finding summary{
  list-style:none;
  cursor:pointer;
  padding:18px 18px 16px;
}
.finding summary::-webkit-details-marker{display:none}
.finding-head{display:flex;flex-direction:column;gap:10px}
.finding-title-wrap{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.finding-title{font-size:18px;font-weight:800}
.finding-summary{color:var(--muted);line-height:1.5}
.finding-body{padding:0 18px 18px}
.finding-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.panel{
  background:#f8fafc;
  border:1px solid var(--line);
  border-radius:12px;
  padding:14px;
}
body[data-theme="dark"] .panel{background:var(--result-panel)}
.panel h4{margin:0 0 8px;font-size:14px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.panel p{margin:0;line-height:1.55}
.panel.evidence{margin-top:12px}
.priority{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:18px;margin-bottom:18px}
.priority ul{margin:0;padding-left:18px}
.priority li{margin:10px 0;line-height:1.5}
.priority-title{font-weight:700;color:var(--text)}
.priority-evidence{display:block;color:var(--muted);margin-top:4px}
.empty{background:var(--panel);border:1px dashed var(--line);border-radius:14px;padding:16px;color:var(--muted)}
.companion{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:18px;margin-top:18px}
.companion ul{margin:0;padding-left:18px}
.mono{font-family:Consolas,Menlo,Monaco,monospace}
.download-wrap{display:flex;flex-direction:column;gap:10px}
.download-link{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-height:40px;
  padding:10px 14px;
  border-radius:10px;
  border:1px solid var(--line);
  background:var(--panel);
  color:var(--text);
  font-weight:700;
  max-width:220px;
}
.download-name{font-size:13px;color:var(--muted);word-break:break-word}
.result-note{font-size:13px;color:var(--muted);margin-bottom:10px}
.result-scroll{
  max-height:360px;
  overflow:auto;
  border:1px solid var(--line);
  border-radius:10px;
  background:var(--panel);
}
.result-table{
  width:100%;
  border-collapse:collapse;
  font-size:13px;
}
.result-table th,.result-table td{
  border-bottom:1px solid var(--line);
  padding:10px 12px;
  vertical-align:top;
  text-align:left;
}
.result-table th{
  position:sticky;
  top:0;
  background:#eef2f7;
  z-index:1;
}
body[data-theme="dark"] .result-table th{background:#0b1220}
.result-pre{
  margin:0;
  padding:12px;
  white-space:pre-wrap;
  word-break:break-word;
  font-family:Consolas,Menlo,Monaco,monospace;
  color:var(--text);
}
.result-empty{color:var(--muted);line-height:1.5}
@media (max-width: 980px){
  .layout{grid-template-columns:1fr}
  .sidebar{position:static}
  .hero-actions{align-items:flex-start}
}
</style>
"@

        $js = @"
<script>
(function(){
  function q(sel){return document.querySelector(sel);}
  function qa(sel){return Array.prototype.slice.call(document.querySelectorAll(sel));}
  function findings(){return qa('.finding');}

  // Theme: explicit user choice (localStorage) wins, otherwise we follow the
  // OS's prefers-color-scheme. Earlier the report defaulted to light no
  // matter what the user's OS was set to; now a dark-mode workstation gets
  // a dark report by default and the toggle button still lets the user pin
  // either mode.
  function osPrefersDark(){
    return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  }
  function currentTheme(){
    var stored = null;
    try { stored = localStorage.getItem('adaudit-theme'); } catch (_) {}
    if (stored === 'light' || stored === 'dark') return stored;
    return osPrefersDark() ? 'dark' : 'light';
  }
  function applyTheme(theme){
    document.body.setAttribute('data-theme', theme);
    var btn = q('#themeToggle');
    if (btn) {
      btn.innerText = theme === 'dark' ? 'Light mode' : 'Dark mode';
      btn.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
    }
  }
  // Persist ONLY on an explicit user choice. applyTheme() must not write to
  // localStorage, or the first auto-detect call would pin the theme and the
  // "follow OS live" handler below would never fire again.
  function setTheme(theme){
    applyTheme(theme);
    try { localStorage.setItem('adaudit-theme', theme); } catch (e) {}
  }

  function applyFilters(){
    var sev = q('#severityFilter').value;
    var query = (q('#searchFilter').value || '').toLowerCase().trim();
    var visible = 0;

    findings().forEach(function(item){
      var itemSev = item.getAttribute('data-sev');
      var text = (item.textContent || '').toLowerCase();
      var show = (sev === 'All' || itemSev === sev) && (!query || text.indexOf(query) >= 0);
      item.style.display = show ? '' : 'none';
      if(show){ visible++; }
    });

    var el = q('#visibleFindings');
    if (el) { el.value = visible; }
  }

  var btn = q('#themeToggle');
  if (btn) {
    btn.addEventListener('click', function(){
      var next = document.body.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      setTheme(next);
    });
  }

  applyTheme(currentTheme());

  // If the user has not explicitly toggled, follow the OS theme live.
  if (window.matchMedia) {
    var mq = window.matchMedia('(prefers-color-scheme: dark)');
    var handler = function(e){
      var stored = null;
      try { stored = localStorage.getItem('adaudit-theme'); } catch(_) {}
      // localStorage was set above by applyTheme(); to honour "follow OS"
      // we accept the most recent applyTheme value - keep it simple and
      // only react if storage was explicitly cleared.
      if (stored !== 'light' && stored !== 'dark') {
        applyTheme(e.matches ? 'dark' : 'light');
      }
    };
    if (mq.addEventListener) { mq.addEventListener('change', handler); }
    else if (mq.addListener) { mq.addListener(handler); }
  }

  q('#severityFilter').addEventListener('change', applyFilters);
  q('#searchFilter').addEventListener('input', applyFilters);
  applyFilters();
})();
</script>
"@

        $primaryNav = Get-ADAuditPrimaryNav -Active 'audit'

        $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ADAudit - Audit Results</title>
$css
</head>
<body data-theme="light">
<div class="container">
$primaryNav
  <section class="hero">
    <div class="hero-top">
      <div>
        <h1>Active Directory Audit Results</h1>
        <div class="meta">
          Target: <span class="mono">$(HtmlEncode $ComputerName)</span><br>
          Generated: $(HtmlEncode $GeneratedOn)<br>
          Report style: HTML audit summary with severity-based findings and embedded evidence<br>
          Finding details include in-report result previews with per-finding downloads.<br>
          Downloaded evidence is written to the <span class="mono">Raw Data</span> folder for technician handoff and follow-up work.
        </div>
      </div>
      <div class="hero-actions">
        <button type="button" class="theme-toggle" id="themeToggle" aria-pressed="false">Dark mode</button>
        <div class="meta">
          Total findings: <b>$totalCount</b><br>
          Risk report: <a href="$(HtmlAttrEncode $managementRel)">$(HtmlEncode ([System.IO.Path]::GetFileName($ManagementReportPath)))</a>
        </div>
      </div>
    </div>

    <div class="metrics">
      $($countCards -join "`n")
    </div>
  </section>

  <div class="layout">
    <aside class="sidebar">
      <h3>Navigate</h3>
      <ul>
        <li><a href="#priority-actions">Priority actions</a></li>
        <li><a href="#section-critical">Critical findings</a></li>
        <li><a href="#section-high">High findings</a></li>
        <li><a href="#section-medium">Medium findings</a></li>
        <li><a href="#section-low">Low findings</a></li>
        <li><a href="#section-information">Information</a></li>
        <li><a href="#companion-reports">Companion reports</a></li>
      </ul>
      <div class="index-group">
        <h4>Finding index</h4>
        $($findingIndexHtml -join "`n")
      </div>
    </aside>

    <main class="content">
      <section class="priority" id="priority-actions">
        <div class="section-header">
          <h2>Priority actions</h2>
          <div class="section-count">Highest-severity findings first</div>
        </div>
        <ul>
          $($priorityHtml -join "`n")
        </ul>
      </section>

      <section class="toolbar">
        <div class="toolbar-row">
          <div class="filter">
            <label for="severityFilter">Severity</label>
            <select id="severityFilter">
              <option>All</option>
              <option>Critical</option>
              <option>High</option>
              <option>Medium</option>
              <option>Low</option>
              <option>Information</option>
            </select>
          </div>
          <div class="filter">
            <label for="searchFilter">Search</label>
            <input id="searchFilter" type="text" placeholder="Search findings, evidence, result details, category">
          </div>
          <div class="filter">
            <label>Visible findings</label>
            <input type="text" value="$totalCount" id="visibleFindings" readonly>
          </div>
        </div>
      </section>

      $($sectionHtml -join "`n")

      <section class="companion" id="companion-reports">
        <div class="section-header">
          <h2>Companion reports</h2>
          <div class="section-count">Additional HTML outputs detected</div>
        </div>
        <ul>
          $($companionHtml -join "`n")
        </ul>
      </section>
    </main>
  </div>
</div>
$js
</body>
</html>
"@

        Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
    }

    # ---------------------------
    # Baseline parsing (authoritative)
    # ---------------------------
    $baselinePath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'ad_high_risk_baseline.txt')

    $baselineHasDA        = $false
    $baselineHasEA        = $false
    $baselineHasSA        = $false
    $baselineHasInactive180 = $false
    $baselineHasPNE         = $false
    $baselineHasKrbtgt      = $false
    $baselineHasMAQ         = $false

    if ($baselinePath -and (Test-Path -LiteralPath $baselinePath)) {
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

                # suppress baseline duplicate-password line (keep only HighRisk\DUPLICATE_PASSWORDS.csv)
                if ($title -match '^\s*Duplicate passwords\b') { continue }

                if ($title -match '^Enabled accounts inactive >\s*180\s*days$') { $baselineHasInactive180 = $true }
                if ($title -match '^Enabled user accounts with PasswordNeverExpires$') { $baselineHasPNE = $true }

                $evidence = "Observed: $obs | Baseline: $base"
                $score = [int]$SeverityScore[$sev]

                switch -Regex ($title) {

                    '^krbtgt password age$' {
                        $baselineHasKrbtgt = $true
                        $obsDays = 0
                        if ($obs -match '\(([0-9]+)\s*days\)') { $obsDays = [int]$matches[1] }
                        elseif ($obs -match '([0-9]+)') { $obsDays = [int]$matches[1] }

                        $baseDays = 0
                        if ($base -match '([0-9]+)') { $baseDays = [int]$matches[1] }

                        if ($obsDays -gt 0 -and $baseDays -gt 0) {
                            $score = Score-OverBaselineLog -Severity $sev -Observed $obsDays -Baseline $baseDays -MaxAdd 22 -K 5
                        }
                    }

                    '^Domain Admins$' {
                        $baselineHasDA = $true
                        $obsCount = 0
                        if ($obs -match '([0-9]+)') { $obsCount = [int]$matches[1] }
                        $baseCount = 0
                        if ($base -match '([0-9]+)') { $baseCount = [int]$matches[1] }
                        if ($obsCount -gt 0 -and $baseCount -gt 0) {
                            $score = Score-OverBaselineLog -Severity $sev -Observed $obsCount -Baseline $baseCount -MaxAdd 18 -K 4
                        }
                    }

                    '^Enterprise Admins$' { $baselineHasEA = $true }

                    '^Schema Admins$' {
                        $baselineHasSA = $true
                        $obsCount = 0
                        if ($obs -match '([0-9]+)') { $obsCount = [int]$matches[1] }

                        $baseCount = 0
                        if ($base -match '^\s*0\b') { $baseCount = 0 }
                        elseif ($base -match '([0-9]+)') { $baseCount = [int]$matches[1] }

                        if ($obsCount -gt 0) {
                            if ($baseCount -le 0) {
                                $score = Score-BaselineZeroLog -Severity 'Critical' -Observed $obsCount -MaxAdd 28 -K 8
                                $sev = 'Critical'
                            } else {
                                $score = Score-OverBaselineLog -Severity $sev -Observed $obsCount -Baseline $baseCount -MaxAdd 18 -K 4
                            }
                        }
                    }

                    '^Domain Admins group overlap' {
                        $obsCount = 0
                        if ($obs -match '([0-9]+)') { $obsCount = [int]$matches[1] }
                        if ($obsCount -gt 0) {
                            $sev = 'Critical'
                            $score = Score-BaselineZeroLog -Severity 'Critical' -Observed $obsCount -MaxAdd 34 -K 10
                        }
                    }

                    '^Enabled accounts inactive >\s*180\s*days$' {
                        $obsCount = 0
                        if ($obs -match '([0-9]+)') { $obsCount = [int]$matches[1] }
                        if ($obsCount -gt 0) {
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
                        $baselineHasMAQ = $true
                        $obsVal = 0
                        if ($obs -match '([0-9]+)') { $obsVal = [int]$matches[1] }
                        if ($obsVal -gt 0) {
                            $score = Score-OverBaselineLog -Severity $sev -Observed $obsVal -Baseline 1 -MaxAdd 16 -K 4
                        }
                    }

                    default { $score = [int]$SeverityScore[$sev] }
                }

                Add-FindingOnce $sev $title $evidence $baselinePath $score
            }
        }
    }

    # PasswordNeverExpires is reported by up to three sources (baseline text,
    # HighRisk CSV, DSInternals pq file, and accounts_passdontexpire.txt). Track a
    # single "already reported" flag so the finding appears exactly once.
    $pneReported = $baselineHasPNE

    # ---------------------------
    # Domain stats from ADExtract (optional)
    # ---------------------------
    $UsersCount  = $null
    $GroupsCount = $null
    $OUsCount    = $null
    try {
        $adExtract = Resolve-AuditArtifactPath (Join-Path (Get-RawDataDir -BaseRoot $InputRoot) 'ADExtract')
        if ($adExtract -and (Test-Path -LiteralPath $adExtract)) {
            $usersCsv  = Get-ChildItem -Path $adExtract -Recurse -File -Filter '*-Users.csv'  | Select-Object -First 1
            $groupsCsv = Get-ChildItem -Path $adExtract -Recurse -File -Filter '*-Groups.csv' | Select-Object -First 1
            $ousCsv    = Get-ChildItem -Path $adExtract -Recurse -File -Filter '*-OUs.csv'    | Select-Object -First 1
            if ($usersCsv)  { $UsersCount  = (Get-CsvSafe $usersCsv.FullName).Count }
            if ($groupsCsv) { $GroupsCount = (Get-CsvSafe $groupsCsv.FullName).Count }
            if ($ousCsv)    { $OUsCount    = (Get-CsvSafe $ousCsv.FullName).Count }
        }
    } catch { }

    # ---------------------------
    # HighRisk CSVs
    # ---------------------------
    $highRiskDir = Resolve-AuditArtifactPath (Join-Path $InputRoot 'HighRisk')
    if ($highRiskDir -and (Test-Path -LiteralPath $highRiskDir)) {
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

        # The DSInternals password-quality file (pq_duplicate_passwords.txt) reports the
        # same shared-password accounts below with richer per-group detail, so only emit
        # this HighRisk-CSV finding when that richer source is not present.
        $pqDupEarlyPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_duplicate_passwords.txt')
        $pqDupEarlyPresent = ($pqDupEarlyPath -and (Test-Path -LiteralPath $pqDupEarlyPath) -and ((Get-PqAccountLines $pqDupEarlyPath).Count -gt 0))
        $dupRows = Get-CsvSafe $hrFiles.DUPLICATE_PASSWORDS
        if ($dupRows.Count -gt 0 -and -not $pqDupEarlyPresent) {
            Add-FindingOnce 'Critical' 'Duplicate passwords detected' "Affected accounts in shared-password groups: $($dupRows.Count)" $hrFiles.DUPLICATE_PASSWORDS (Score-Scaled 'Critical' $dupRows.Count 100)
        }

        # Suppress when the baseline text already reported krbtgt password age.
        $krbtgt = Get-CsvSafe $hrFiles.KRBTGT
        if ($krbtgt.Count -gt 0 -and -not $baselineHasKrbtgt) {
            $ageVal = 0
            try {
                $first = $krbtgt | Select-Object -First 1
                # Also try Observed column which may contain "date (N days)" format
                $raw = @($first.AgeDays, $first.PasswordAgeDays) |
                    Where-Object { $_ -ne $null -and $_ -ne '' } |
                    Select-Object -First 1
                if (-not $raw -and $first.Observed -and $first.Observed -ne 'Unknown') {
                    if ($first.Observed -match '\((\d+)\s*days?\)') { $raw = $Matches[1] }
                }
                if ($raw) { $ageVal = [int](([string]$raw) -replace '[^0-9]','') }
            } catch { $ageVal = 0 }

            if ($ageVal -gt 180) {
                $sev = if ($ageVal -ge 730) { 'Critical' }
                       elseif ($ageVal -ge 365) { 'High' }
                       else { 'Medium' }
                Add-FindingOnce $sev 'KRBTGT password age is high' "Estimated age (days): $ageVal" $hrFiles.KRBTGT (Score-Scaled $sev ([Math]::Max($ageVal,1) / 30))
            }
        }

        # PRIVILEGED_GROUPS.csv is an unconditional full membership dump (never
        # empty in any domain); only raise the finding when the baseline
        # collector itself judged at least one group to be over baseline.
        $privRows = Get-CsvSafe $hrFiles.PRIVILEGED_GROUPS
        $privOverBaseline = @(Get-CsvSafe $hrFiles.Summary | Where-Object { "$($_.RiskId)" -like 'PRIV_*' -and "$($_.IsFinding)" -match '^(true|1)$' })
        if ($privRows.Count -gt 0 -and $privOverBaseline.Count -gt 0) {
            $sev = if ($privRows.Count -ge 20) { 'High' } elseif ($privRows.Count -ge 10) { 'Medium' } else { 'Low' }
            Add-FindingOnce $sev 'Large privileged group membership' "Groups over baseline: $($privOverBaseline.Count); membership rows: $($privRows.Count)" $hrFiles.PRIVILEGED_GROUPS (Score-Scaled $sev $privRows.Count)
        }

        # Keep ONLY baseline inactive >180 days (renamed), suppress HighRisk\INACTIVE_ACCOUNTS.csv
        if (-not $baselineHasInactive180) {
            $inactiveRows = Get-CsvSafe $hrFiles.INACTIVE_ACCOUNTS
            if ($inactiveRows.Count -gt 0) {
                $sev = if ($inactiveRows.Count -ge 200) { 'High' } elseif ($inactiveRows.Count -ge 50) { 'Medium' } else { 'Low' }
                Add-FindingOnce $sev 'Inactive enabled accounts' "Accounts inactive: $($inactiveRows.Count)" $hrFiles.INACTIVE_ACCOUNTS (Score-Scaled $sev $inactiveRows.Count)
            }
        }

        # Report PasswordNeverExpires from a single source only (see $pneReported).
        if (-not $pneReported) {
            $pneRows = Get-CsvSafe $hrFiles.PASSWORD_NEVER_EXPIRES
            if ($pneRows.Count -gt 0) {
                $sev = if ($pneRows.Count -ge 50) { 'High' } elseif ($pneRows.Count -ge 10) { 'Medium' } else { 'Low' }
                Add-FindingOnce $sev 'Passwords set to never expire' "Accounts: $($pneRows.Count)" $hrFiles.PASSWORD_NEVER_EXPIRES (Score-Scaled $sev $pneRows.Count)
                $pneReported = $true
            }
        }

        $dsRows = Get-CsvSafe $hrFiles.DISABLED_STALE
        if ($dsRows.Count -gt 0) {
            $sev = if ($dsRows.Count -ge 200) { 'Medium' } else { 'Low' }
            Add-FindingOnce $sev 'Disabled stale accounts' "Accounts: $($dsRows.Count)" $hrFiles.DISABLED_STALE (Score-Scaled $sev $dsRows.Count)
        }

        # Suppress when the baseline text already reported ms-DS-MachineAccountQuota.
        $maqRows = Get-CsvSafe $hrFiles.MACHINE_ACCOUNT_QUOTA
        if ($maqRows.Count -gt 0 -and -not $baselineHasMAQ) {
            $firstRow = $maqRows | Select-Object -First 1
            # The real quota is in the Observed column ('Unknown' when it could not be
            # read); IsFinding is the collector's verdict. Read the actual value and only
            # flag when the quota is really > 0 (a correctly hardened MAQ=0 is not a finding).
            $quota = 0
            if ($firstRow.Observed -and "$($firstRow.Observed)" -ne 'Unknown') {
                $quota = [int]("$($firstRow.Observed)" -replace '[^0-9]', '')
            }
            $maqIsFinding = ("$($firstRow.IsFinding)" -match '^(true|1)$')
            if ($maqIsFinding -and $quota -gt 0) {
                $sev = if ($quota -gt 10) { 'High' } else { 'Medium' }
                Add-FindingOnce $sev 'MachineAccountQuota permits user-created computers' "ms-DS-MachineAccountQuota is $quota (baseline: 0)" $hrFiles.MACHINE_ACCOUNT_QUOTA (Score-Scaled $sev $quota)
            }
        }
    }

    # ---------------------------
    # Text-based checks
    # ---------------------------
    $weakKerbPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'dcs_weak_kerberos_ciphersuite.txt')
    $weakKerbLines = Get-NonHeaderLines $weakKerbPath
    # The evidence file holds four lines per DC plus a Link footer; count one
    # marker line per DC block so 'DCs flagged' reflects actual DCs.
    $weakKerbDcCount = @($weakKerbLines | Where-Object { $_ -match '^Decimal Value:' }).Count
    if ($weakKerbDcCount -gt 0) {
        Add-FindingOnce 'High' 'Domain controllers allow weak Kerberos ciphers' "DCs flagged: $weakKerbDcCount" $weakKerbPath (Score-Scaled 'High' $weakKerbDcCount)
    }

    # ---------------------------
    # Disabled user accounts (accounts_disabled.txt) - UPDATED SCORING
    # ---------------------------
    $disabledPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'accounts_disabled.txt')
    $disabled = @(Get-DisabledAccounts -Path $disabledPath)
    $disabledUnique = @(
        $disabled |
        Select-Object -ExpandProperty SamAccountName -Unique |
        Where-Object { $_ -and $_.Trim().Length -gt 0 }
    )
    $disabledCount = $disabledUnique.Count

    if ($disabledCount -gt 0) {
        $base = [int]$Baselines.DisabledUserAccounts

        # Risk-class behavior:
        # - Medium by default (lifecycle control)
        # - Escalate to High when volume is large (governance failure signal)
        $sev = 'Medium'
        if ($disabledCount -ge 200) { $sev = 'High' }

        $preview = if ($disabledUnique.Count -le 10) {
            ($disabledUnique -join ', ')
        } else {
            (($disabledUnique | Select-Object -First 10) -join ', ') + ', ...'
        }

        # Stronger scaling than before (so 256 with baseline 20 is not "Low + small bump")
        # Example for 256: High base(8) + ceil(4*log2(12.8))=8+15 => 23 (capped by MaxAdd 20, not hit)
        $score = Score-OverBaselineLog -Severity $sev -Observed $disabledCount -Baseline ([Math]::Max($base,1)) -MaxAdd 20 -K 4

        Add-FindingOnce $sev 'Disabled user accounts present (review and cleanup)' ("Disabled accounts: $disabledCount (Baseline: <= $base) | Example: $preview") $disabledPath $score
    }

    # ---------------------------
    # Password quality (reversible encryption) - try split file first, fall back to combined
    # ---------------------------
    $pqRevPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_reversible_encryption.txt')
    $pqPath    = Resolve-AuditArtifactPath (Join-Path $InputRoot 'password_quality.txt')
    # The split pq_reversible_encryption.txt carries header/footer lines that
    # Get-ReversibleEncryptionAccounts (written for the combined report) would
    # count as accounts; parse it with the DOMAIN\account-only parser instead.
    $revAccounts = @()
    if ($pqRevPath -and (Test-Path -LiteralPath $pqRevPath)) { $revAccounts = @(Get-PqAccountLines $pqRevPath) }
    if ($revAccounts.Count -eq 0) {
        $revAccounts = @(Get-ReversibleEncryptionAccounts -Path $pqPath)
    }
    $revCount = $revAccounts.Count
    if ($revCount -gt 0) {
        $preview = if ($revCount -le 10) {
            ($revAccounts -join ', ')
        } else {
            (($revAccounts | Select-Object -First 10) -join ', ') + ', ...'
        }
        $revEvidencePath = if ($pqRevPath) { $pqRevPath } else { $pqPath }
        $score = Score-BaselineZeroLog -Severity 'Critical' -Observed $revCount -MaxAdd 34 -K 10
        Add-FindingOnce 'Critical' 'Passwords stored using reversible encryption' "Accounts: $revCount | Example: $preview" $revEvidencePath $score
    }

    # ---------------------------
    # Password quality split files - additional category findings
    # ---------------------------
    # LM hashes present
    $pqLmPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_lm_hashes.txt')
    $pqLmLines = Get-PqAccountLines $pqLmPath
    if ($pqLmLines.Count -gt 0) {
        $score = Score-BaselineZeroLog -Severity 'Critical' -Observed $pqLmLines.Count -MaxAdd 34 -K 10
        Add-FindingOnce 'Critical' 'LM hashes of passwords present in AD' "Accounts: $($pqLmLines.Count)" $pqLmPath $score
    }

    # Accounts with no password set - cross-reference with Users.csv to check enabled/disabled
    $pqNoPwdPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_no_password.txt')
    $pqNoPwdLines = Get-PqAccountLines $pqNoPwdPath
    if ($pqNoPwdLines.Count -gt 0) {
        # Extract SamAccountNames from DOMAIN\user format
        $noPwdSams = @($pqNoPwdLines | ForEach-Object { ($_ -split '\\', 2)[-1].Trim() } | Where-Object { $_ })

        # Try to determine how many are enabled via Users.csv (userAccountControl bit 0x2 = disabled)
        $enabledNoPwd = 0
        $disabledNoPwd = $pqNoPwdLines.Count
        try {
            $adExtractDir = Resolve-AuditArtifactPath (Join-Path (Get-RawDataDir -BaseRoot $InputRoot) 'ADExtract')
            if ($adExtractDir -and (Test-Path -LiteralPath $adExtractDir)) {
                $uCsv = Get-ChildItem -Path $adExtractDir -Recurse -File -Filter '*-Users.csv' | Select-Object -First 1
                if ($uCsv) {
                    # ADExtract CSVs are written pipe-delimited (see Export-ADAuditDataExtract)
                    $allUserRows = @(Import-Csv -LiteralPath $uCsv.FullName -Delimiter '|' -ErrorAction Stop)
                    $noPwdSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($s in $noPwdSams) { $noPwdSet.Add($s) | Out-Null }
                    $enabledNoPwd = 0
                    foreach ($row in $allUserRows) {
                        $sam = $row.SamAccountName
                        if (-not $sam -or -not $noPwdSet.Contains($sam)) { continue }
                        # The extract writes userAccountControl as text ("Disabled - Password Does
                        # Not Expire", "Unknown User Account Type - 66082"), so a plain [int] cast
                        # failed silently, left 0 and counted every account as ENABLED.
                        $uacText = [string]$row.userAccountControl
                        $disabled = $false
                        if ($uacText -match '(?i)\bdisabled\b') { $disabled = $true }
                        elseif ($uacText -match '(\d+)') { $disabled = (([int64]$matches[1]) -band 2) -ne 0 }
                        if (-not $disabled) { $enabledNoPwd++ }
                    }
                    $disabledNoPwd = $pqNoPwdLines.Count - $enabledNoPwd
                }
            }
        } catch {}

        if ($enabledNoPwd -gt 0) {
            # Enabled accounts with no password = Critical
            $score = Score-BaselineZeroLog -Severity 'Critical' -Observed $enabledNoPwd -MaxAdd 34 -K 10
            Add-FindingOnce 'Critical' 'Accounts with no password set (ENABLED)' "Enabled: $enabledNoPwd of $($pqNoPwdLines.Count) total" $pqNoPwdPath $score
        }
        if ($disabledNoPwd -gt 0 -and $enabledNoPwd -eq 0) {
            # All disabled = Low severity (common for shared mailboxes / service accounts)
            Add-FindingOnce 'Low' 'Accounts with no password set (all disabled)' "Disabled accounts: $disabledNoPwd" $pqNoPwdPath (Score-Scaled 'Low' $disabledNoPwd)
        } elseif ($disabledNoPwd -gt 0 -and $enabledNoPwd -gt 0) {
            Add-FindingOnce 'Low' 'Accounts with no password set (disabled)' "Disabled accounts: $disabledNoPwd (review and cleanup)" $pqNoPwdPath (Score-Scaled 'Low' $disabledNoPwd)
        }
    }

    # Dictionary passwords found
    $pqDictPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_dictionary_passwords.txt')
    $pqDictLines = Get-PqAccountLines $pqDictPath
    if ($pqDictLines.Count -gt 0) {
        $score = Score-BaselineZeroLog -Severity 'Critical' -Observed $pqDictLines.Count -MaxAdd 34 -K 10
        Add-FindingOnce 'Critical' 'Passwords found in dictionary/breach list' "Accounts: $($pqDictLines.Count)" $pqDictPath $score
    }

    # Default computer passwords
    $pqDefCompPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_default_computer_passwords.txt')
    $pqDefCompLines = Get-PqAccountLines $pqDefCompPath
    if ($pqDefCompLines.Count -gt 0) {
        $sev = if ($pqDefCompLines.Count -ge 5) { 'Critical' } else { 'High' }
        $score = Score-BaselineZeroLog -Severity $sev -Observed $pqDefCompLines.Count -MaxAdd 20 -K 8
        Add-FindingOnce $sev 'Computer accounts with default passwords' "Accounts: $($pqDefCompLines.Count)" $pqDefCompPath $score
    }

    # Missing Kerberos AES keys
    $pqAesPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_missing_aes_keys.txt')
    $pqAesLines = Get-PqAccountLines $pqAesPath
    if ($pqAesLines.Count -gt 0) {
        Add-FindingOnce 'Medium' 'Kerberos AES keys missing from accounts' "Accounts: $($pqAesLines.Count)" $pqAesPath (Score-Scaled 'Medium' $pqAesLines.Count)
    }

    # DES-only encryption accounts
    $pqDesPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_des_only.txt')
    $pqDesLines = Get-PqAccountLines $pqDesPath
    if ($pqDesLines.Count -gt 0) {
        $score = Score-BaselineZeroLog -Severity 'Critical' -Observed $pqDesLines.Count -MaxAdd 34 -K 10
        Add-FindingOnce 'Critical' 'Accounts restricted to DES-only encryption' "Accounts: $($pqDesLines.Count)" $pqDesPath $score
    }

    # Admin accounts allowed delegation
    $pqAdminDelegPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_admin_delegation.txt')
    $pqAdminDelegLines = Get-PqAccountLines $pqAdminDelegPath
    if ($pqAdminDelegLines.Count -gt 0) {
        $sev = if ($pqAdminDelegLines.Count -ge 5) { 'Critical' } else { 'High' }
        Add-FindingOnce $sev 'Administrative accounts allowed to be delegated' "Accounts: $($pqAdminDelegLines.Count)" $pqAdminDelegPath (Score-Scaled $sev $pqAdminDelegLines.Count)
    }

    # Password not required flag
    $pqPwdNotReqPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_password_not_required.txt')
    $pqPwdNotReqLines = Get-PqAccountLines $pqPwdNotReqPath
    if ($pqPwdNotReqLines.Count -gt 0) {
        $score = Score-BaselineZeroLog -Severity 'High' -Observed $pqPwdNotReqLines.Count -MaxAdd 20 -K 8
        Add-FindingOnce 'High' 'Accounts not required to have a password' "Accounts: $($pqPwdNotReqLines.Count)" $pqPwdNotReqPath $score
    }

    # Duplicate passwords (accounts sharing the same NTLM hash)
    # DSInternals groups accounts that have identical NTLM hashes, which means
    # they share the exact same plaintext password. Count both accounts and
    # groups so the finding makes the pass-the-hash / lateral-movement risk
    # explicit in the HTML report.
    $pqDupPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_duplicate_passwords.txt')
    $pqDupLines = Get-PqAccountLines $pqDupPath
    if ($pqDupLines.Count -gt 0) {
        $pqDupGroupCount = 0
        try {
            if ($pqDupPath -and (Test-Path -LiteralPath $pqDupPath)) {
                $rawDup = Get-Content -LiteralPath $pqDupPath -ErrorAction Stop
                $inGroup = $false
                foreach ($rawLine in $rawDup) {
                    $t = ([string]$rawLine).Trim()
                    if ($t -match '^[^=\-#].*\\') {
                        if (-not $inGroup) { $pqDupGroupCount++ ; $inGroup = $true }
                    } else {
                        $inGroup = $false
                    }
                }
            }
        } catch {}
        $sev = if ($pqDupLines.Count -ge 10 -or $pqDupGroupCount -ge 3) { 'Critical' } else { 'High' }
        $score = Score-BaselineZeroLog -Severity $sev -Observed $pqDupLines.Count -MaxAdd 30 -K 8
        $detail = if ($pqDupGroupCount -gt 0) {
            "Accounts: $($pqDupLines.Count) across $pqDupGroupCount group(s) - accounts in the same group share the IDENTICAL NTLM hash (same plaintext password). Risk: one credential compromise unlocks every account in the group via pass-the-hash; reused passwords across privilege tiers create direct lateral-movement paths."
        } else {
            "Accounts: $($pqDupLines.Count) - accounts grouped together share the same NTLM hash (same plaintext password). Risk: pass-the-hash unlocks every account in the group from a single credential compromise."
        }
        Add-FindingOnce $sev 'Accounts sharing the same password (identical NTLM hash)' $detail $pqDupPath $score
    }

    # Historical dictionary passwords
    $pqHistDictPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_historical_dictionary.txt')
    $pqHistDictLines = Get-PqAccountLines $pqHistDictPath
    if ($pqHistDictLines.Count -gt 0) {
        Add-FindingOnce 'Medium' 'Historical (previous) passwords found in dictionary/breach list' "Accounts: $($pqHistDictLines.Count)" $pqHistDictPath (Score-Scaled 'Medium' $pqHistDictLines.Count)
    }

    # Kerberos pre-auth not required. ASREP.txt (native -asrep check, below) reports the
    # same accounts as Critical with a user list, so only emit this DSInternals view when
    # ASREP.txt is not present - otherwise the same issue appears twice with two severities.
    $asrepEarlyPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'ASREP.txt')
    $asrepEarlyPresent = ($asrepEarlyPath -and (Test-Path -LiteralPath $asrepEarlyPath) -and (@(Get-AsrepAccounts -path $asrepEarlyPath).Count -gt 0))
    $pqNoPreauthPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_no_preauth.txt')
    $pqNoPreauthLines = Get-PqAccountLines $pqNoPreauthPath
    if ($pqNoPreauthLines.Count -gt 0 -and -not $asrepEarlyPresent) {
        $score = Score-BaselineZeroLog -Severity 'High' -Observed $pqNoPreauthLines.Count -MaxAdd 20 -K 8
        Add-FindingOnce 'High' 'Accounts with Kerberos pre-authentication disabled (AS-REP roastable)' "Accounts: $($pqNoPreauthLines.Count)" $pqNoPreauthPath $score
    }

    # Password never expires (DSInternals view, complements accounts_passdontexpire.txt)
    $pqPwdNeverExpPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_password_never_expires.txt')
    $pqPwdNeverExpLines = Get-PqAccountLines $pqPwdNeverExpPath
    if ($pqPwdNeverExpLines.Count -gt 0 -and -not $pneReported) {
        $sev = if ($pqPwdNeverExpLines.Count -ge 50) { 'High' } elseif ($pqPwdNeverExpLines.Count -ge 10) { 'Medium' } else { 'Low' }
        Add-FindingOnce $sev 'Accounts with PasswordNeverExpires set' "Accounts: $($pqPwdNeverExpLines.Count)" $pqPwdNeverExpPath (Score-Scaled $sev $pqPwdNeverExpLines.Count)
        $pneReported = $true
    }

    # Kerberoastable (DSInternals view, complements SPNs.txt). This is the richer of the
    # two kerberoast sources; when present it suppresses the SPNs.txt finding below.
    $pqKerbPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_kerberoastable.txt')
    $pqKerbLines = Get-PqAccountLines $pqKerbPath
    $pqKerbPresent = ($pqKerbLines.Count -gt 0)
    if ($pqKerbPresent) {
        $score = Score-BaselineZeroLog -Severity 'High' -Observed $pqKerbLines.Count -MaxAdd 20 -K 8
        Add-FindingOnce 'High' 'Kerberoastable accounts (SPN set on user account, weak password risk)' "Accounts: $($pqKerbLines.Count)" $pqKerbPath $score
    }

    # ---------------------------
    # AS-REP roastable
    # ---------------------------
    $asrepPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'ASREP.txt')
    $asrepAccounts = @(Get-AsrepAccounts -path $asrepPath)
    $asrepCount = @($asrepAccounts).Count
    if ($asrepCount -gt 0) {
        $sev = 'Critical'
        $score = if ($asrepCount -eq 1) { [int]$SeverityScore.Critical }
        else { Score-BaselineZeroLog -Severity $sev -Observed $asrepCount -MaxAdd 34 -K 10 }

        $samList = @($asrepAccounts | Select-Object -ExpandProperty SamAccountName -Unique)
        $samPreview = if ($samList.Count -le 10) { ($samList -join ', ') }
        else { (($samList | Select-Object -First 10) -join ', ') + ', ...' }

        Add-FindingOnce $sev 'Accounts without Kerberos pre-auth (AS-REP roastable)' "Accounts: $asrepCount | Users: $samPreview" $asrepPath $score
    }

    # Exclude the "no findings" sentinel line so a clean domain does not produce a
    # false "Kerberoastable SPNs present" finding, and defer to the richer DSInternals
    # kerberoastable finding above when it is present.
    $spnPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'SPNs.txt')
    $spnLines = @(Get-NonHeaderLines $spnPath | Where-Object { $_ -notmatch '^\s*No high value kerberoastable user accounts identified\.?\s*$' })
    if ($spnLines.Count -gt 0 -and -not $pqKerbPresent) {
        Add-FindingOnce 'Medium' 'Kerberoastable SPNs present (review high-value service accounts)' "Lines: $($spnLines.Count)" $spnPath (Score-Scaled 'Medium' $spnLines.Count)
    }

    # Inactive computer objects (>90 days)
    $inactiveCompsPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'computers_inactive_90days.txt')
    $inactiveCompsLines = Get-NonHeaderLines $inactiveCompsPath
    if ($inactiveCompsLines.Count -gt 0) {
        $obs = $inactiveCompsLines.Count
        $base = 5
        $sev = if ($obs -ge 200) { 'High' } elseif ($obs -ge 50) { 'Medium' } else { 'Low' }
        $score = Score-OverBaselineLog -Severity $sev -Observed $obs -Baseline $base -MaxAdd 14 -K 3
        Add-FindingOnce $sev 'Inactive computer accounts (>90 days)' "Computers inactive: $obs (Baseline: <= $base)" $inactiveCompsPath $score
    }

    # Suppress accounts_passdontexpire.txt when PasswordNeverExpires was already reported.
    $pndePath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'accounts_passdontexpire.txt')
    if (-not $pneReported) {
        $pndeLines = Get-NonHeaderLines $pndePath
        if ($pndeLines.Count -gt 0) {
            $sev = if ($pndeLines.Count -ge 50) { 'High' } elseif ($pndeLines.Count -ge 10) { 'Medium' } else { 'Low' }
            Add-FindingOnce $sev 'Accounts with password set to not expire' "Accounts: $($pndeLines.Count)" $pndePath (Score-Scaled $sev $pndeLines.Count)
        }
    }

    $lapsRightsPath  = Resolve-AuditArtifactPath (Join-Path $InputRoot 'laps_read-extendedrights.txt')
    $lapsExpiredPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'laps_expired-passwords.txt')
    if (($lapsRightsPath -and (Test-Path -LiteralPath $lapsRightsPath)) -or ($lapsExpiredPath -and (Test-Path -LiteralPath $lapsExpiredPath))) {
        $rightsCount  = (Get-NonHeaderLines $lapsRightsPath).Count
        $expiredCount = (Get-NonHeaderLines $lapsExpiredPath).Count
        if ($rightsCount -gt 0)  { Add-FindingOnce 'High'   'LAPS password read rights widely delegated' "Readers: $rightsCount" $lapsRightsPath (Score-Scaled 'High' $rightsCount) }
        if ($expiredCount -gt 0) { Add-FindingOnce 'Medium' 'LAPS passwords expired' "Computers flagged: $expiredCount" $lapsExpiredPath (Score-Scaled 'Medium' $expiredCount) }
    }

    $ldapSecPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'LDAPSecurity.txt')
    if ((Get-NonHeaderLines $ldapSecPath).Count -gt 0) {
        Add-FindingOnce 'High' 'LDAP security misconfiguration detected' 'See LDAPSecurity.txt for details' $ldapSecPath $SeverityScore.High
    }

    # Flag only when the collector recorded that NTLM is NOT restricted. A file that
    # merely lists existing restrictions is evidence of hardening, not a finding; a
    # missing file means the GPO check did not run.
    $ntlmRestrictPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'ntlm_restrictions.txt')
    if ($ntlmRestrictPath -and (Test-Path -LiteralPath $ntlmRestrictPath)) {
        $ntlmContent = Get-Content -LiteralPath $ntlmRestrictPath -ErrorAction SilentlyContinue
        if ($ntlmContent -match '^Status:\s*NotRestricted') {
            Add-FindingOnce 'Medium' 'NTLM authentication is not restricted or hardened by GPO' 'No GPO denies NTLM or restricts LM/NTLMv1 across the domain. Audit first (Network security: Restrict NTLM: Audit ...), then restrict, to cut NTLM relay and pass-the-hash exposure.' $ntlmRestrictPath $SeverityScore.Medium
        }
    }

    $dnsInsecureZonesPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'insecure_dns_zones.txt')
    $dnsInsecureLines = Get-NonHeaderLines $dnsInsecureZonesPath
    if ($dnsInsecureLines.Count -gt 0) {
        Add-FindingOnce 'High' 'DNS zones allowing insecure updates' "Zones flagged: $($dnsInsecureLines.Count)" $dnsInsecureZonesPath (Score-Scaled 'High' $dnsInsecureLines.Count)
    }

    # Unconstrained Kerberos delegation
    $unconstrainedPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'unconstrained_delegation.txt')
    $unconstrainedLines = Get-NonHeaderLines $unconstrainedPath
    if ($unconstrainedLines.Count -gt 0) {
        $sev = if ($unconstrainedLines.Count -ge 3) { 'Critical' } else { 'High' }
        Add-FindingOnce $sev 'Accounts with unconstrained Kerberos delegation' "Accounts: $($unconstrainedLines.Count)" $unconstrainedPath (Score-Scaled $sev $unconstrainedLines.Count)
    }

    # gMSA status
    $gmsaPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'gmsa_status.txt')
    $gmsaLines = Get-NonHeaderLines $gmsaPath
    if ($gmsaLines.Count -gt 0) {
        $sev = if ($gmsaLines.Count -ge 10) { 'Medium' } else { 'Low' }
        Add-FindingOnce $sev 'Service accounts not using gMSA' "Accounts with static passwords: $($gmsaLines.Count)" $gmsaPath (Score-Scaled $sev $gmsaLines.Count)
    }

    # Print Spooler on DCs
    $spoolerPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'dc_print_spooler.txt')
    $spoolerLines = Get-NonHeaderLines $spoolerPath
    if ($spoolerLines.Count -gt 0) {
        Add-FindingOnce 'High' 'Print Spooler running on domain controllers' "DCs affected: $($spoolerLines.Count)" $spoolerPath (Score-Scaled 'High' $spoolerLines.Count)
    }

    # SMB signing on DCs
    $smbSignPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'dc_smb_signing.txt')
    $smbSignLines = Get-NonHeaderLines $smbSignPath
    if ($smbSignLines.Count -gt 0) {
        Add-FindingOnce 'High' 'SMB signing not enforced on domain controllers' "DCs affected: $($smbSignLines.Count)" $smbSignPath (Score-Scaled 'High' $smbSignLines.Count)
    }

    # RC4-only accounts (CVE-2026-20833 Kerberos RC4 hardening)
    $rc4Path  = Resolve-AuditArtifactPath (Join-Path $InputRoot 'rc4_only_accounts.txt')
    $rc4Lines = Get-NonHeaderLines $rc4Path
    if ($rc4Lines.Count -gt 0) {
        $sev = if ($rc4Lines.Count -ge 25) { 'Critical' } elseif ($rc4Lines.Count -ge 5) { 'High' } else { 'Medium' }
        Add-FindingOnce $sev 'Accounts without AES Kerberos support (CVE-2026-20833)' "Accounts: $($rc4Lines.Count)" $rc4Path (Score-Scaled $sev $rc4Lines.Count)
    }
    $rc4AuthPath  = Resolve-AuditArtifactPath (Join-Path $InputRoot 'rc4_authentication_events.txt')
    $rc4AuthLines = Get-NonHeaderLines $rc4AuthPath
    if ($rc4AuthLines.Count -gt 0) {
        Add-FindingOnce 'High' 'Active RC4 Kerberos authentications observed' "Distinct exchanges: $($rc4AuthLines.Count)" $rc4AuthPath (Score-Scaled 'High' $rc4AuthLines.Count)
    }

    # DC port connectivity - reads the per-(source,target,port) CSV that
    # Test-DCPortConnectivity generates and produces ONE finding per closed
    # port name+severity combination so the HTML report makes the WHY/FIX
    # obvious without forcing the operator to open the txt.
    $portCsvPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'dc_port_connectivity.csv')
    $portTxtPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'dc_port_connectivity.txt')
    if ($portCsvPath -and (Test-Path -LiteralPath $portCsvPath)) {
        $portRows = @(Get-CsvSafe $portCsvPath)
        $closedRows = @($portRows | Where-Object { ([string]$_.Open) -in @('False','false','No','no','0') })
        $byPortName = $closedRows | Group-Object PortName
        foreach ($g in $byPortName) {
            $first = $g.Group | Select-Object -First 1
            $sev = switch ([string]$first.Severity) {
                'Critical' { 'Critical' }
                'High'     { 'High' }
                'Medium'   { 'Medium' }
                'Low'      { 'Low' }
                default    { 'Medium' }
            }
            $targets = @($g.Group | Select-Object -ExpandProperty Target -Unique)
            $detail = "Port $($first.Port)/$($first.Proto) ($($first.PortName)) closed for $($g.Count) probe(s) across $($targets.Count) target(s). See dc_port_connectivity.txt for WHY this matters and the recommended fix."
            $portTitle = if ([int]$first.Port -eq 0) { "DC unreachable: $(@($g | ForEach-Object { $_.Target } | Sort-Object -Unique) -join ', ') does not resolve in DNS" } else { "DC port closed: $($first.PortName) ($($first.Port)/$($first.Proto))" }
            Add-FindingOnce $sev $portTitle $detail $portTxtPath (Score-Scaled $sev $g.Count)
        }

        # LDAPS-not-reachable specific finding (security risk, not just connectivity)
        $ldapsClosedTargets = @($closedRows | Where-Object { [int]$_.Port -eq 636 } | Select-Object -ExpandProperty Target -Unique)
        if ($ldapsClosedTargets.Count -gt 0) {
            Add-FindingOnce 'High' 'LDAPS (636) not reachable - LDAP traffic forced to plaintext' `
                "DCs without LDAPS: $($ldapsClosedTargets -join ', '). All LDAP binds and searches against these DCs run on plaintext 389 and can be sniffed/relayed (LDAP relay to LDAPS is a documented attack path). Issue an LDAPS certificate and verify with `ldp.exe -SSL`." `
                $portTxtPath (Score-Scaled 'High' $ldapsClosedTargets.Count)
        }
    }

    # Delegated Permissions
    $delegRoot = Resolve-AuditArtifactPath (Join-Path (Get-RawDataDir -BaseRoot $InputRoot) 'DelegatedPermissions')
    if ($delegRoot -and (Test-Path -LiteralPath $delegRoot)) {
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

            if ($recTxt -and (Test-Path -LiteralPath $recTxt)) {
                Add-FindingOnce 'Low' 'Delegated permissions recommendations available' 'See recommendations file' $recTxt $SeverityScore.Low
            }
        }
    }

    # Admin group text files (suppressed if baseline includes)
    $daPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'domain_admins.txt')
    $eaPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'enterprise_admins.txt')
    $saPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'schema_admins.txt')

    if (-not $baselineHasDA) {
        $daCount = (Get-NonHeaderLines $daPath).Count
        if ($daCount -gt 0) {
            $sev = if ($daCount -gt 10) { 'High' } elseif ($daCount -gt 5) { 'Medium' } else { 'Low' }
            $daBase = 5
            Add-FindingOnce $sev 'Domain Admins membership size' "Members: $daCount (Baseline: <= $daBase)" $daPath (Score-OverBaselineLog -Severity $sev -Observed $daCount -Baseline $daBase -MaxAdd 18 -K 4)
        }
    }

    if (-not $baselineHasEA) {
        $eaCount = (Get-NonHeaderLines $eaPath).Count
        if ($eaCount -gt 0) {
            $sev = if ($eaCount -gt 5) { 'High' } elseif ($eaCount -gt 2) { 'Medium' } else { 'Low' }
            $eaBase = 2
            Add-FindingOnce $sev 'Enterprise Admins membership size' "Members: $eaCount (Baseline: <= $eaBase)" $eaPath (Score-OverBaselineLog -Severity $sev -Observed $eaCount -Baseline $eaBase -MaxAdd 16 -K 4)
        }
    }

    if (-not $baselineHasSA) {
        $saCount = (Get-NonHeaderLines $saPath).Count
        if ($saCount -gt 0) {
            $sev = if ($saCount -gt 5) { 'High' } elseif ($saCount -gt 2) { 'Medium' } else { 'Low' }
            $saBase = 1
            Add-FindingOnce $sev 'Schema Admins membership size' "Members: $saCount (Baseline: <= $saBase except during schema change)" $saPath (Score-OverBaselineLog -Severity $sev -Observed $saCount -Baseline $saBase -MaxAdd 18 -K 4)
        }
    }

    # ----------------------------------------------------------------
    # Domain Admins size-adjusted review (KB427) and built-in RID-500
    # hygiene (KB428). The check function precomputes severity and writes
    # it as a 'Severity:' header in each evidence file - we trust that
    # value here, so all the AD-size math lives in one place.
    # ----------------------------------------------------------------
    $daScaledFile = Resolve-AuditArtifactPath (Join-Path $InputRoot 'domain_admins_scaled.txt')
    if ($daScaledFile -and (Test-Path -LiteralPath $daScaledFile)) {
        $daText = Get-Content -LiteralPath $daScaledFile -Raw
        $daSev = $null
        $daReason = ''
        $mSev = [regex]::Match($daText, '(?m)^\s*Severity:\s*(\S+)\s*$')
        if ($mSev.Success) { $daSev = Normalize-Severity $mSev.Groups[1].Value }
        $mReason = [regex]::Match($daText, '(?ms)^-+\s*VERDICT\s*-+\s*$\r?\n.*?Reason:\s*(.+?)\r?\n')
        if ($mReason.Success) { $daReason = $mReason.Groups[1].Value.Trim() }
        if ($daSev) {
            $score = [int]$SeverityScore[$daSev]
            $titleScaled = 'Domain Admins membership review (size-adjusted)'
            $evidence = if ($daReason) { $daReason } else { 'See domain_admins_scaled.txt for full breakdown.' }
            Add-FindingOnce $daSev $titleScaled $evidence $daScaledFile $score
        }
    }

    $rid500File = Resolve-AuditArtifactPath (Join-Path $InputRoot 'domain_admin_builtin_rid500.txt')
    if ($rid500File -and (Test-Path -LiteralPath $rid500File)) {
        $rText = Get-Content -LiteralPath $rid500File -Raw
        $rSev = $null
        $rReason = ''
        $mSev = [regex]::Match($rText, '(?m)^\s*Severity:\s*(\S+)\s*$')
        if ($mSev.Success) { $rSev = Normalize-Severity $mSev.Groups[1].Value }
        $mReason = [regex]::Match($rText, '(?m)^\s*Reason:\s*(.+)$')
        if ($mReason.Success) { $rReason = $mReason.Groups[1].Value.Trim() }
        if ($rSev) {
            $score = [int]$SeverityScore[$rSev]
            $titleRid = 'Built-in domain Administrator (RID-500) hygiene'
            $evidence = if ($rReason) { $rReason } else { 'Built-in RID-500 account inspected. See evidence file.' }
            Add-FindingOnce $rSev $titleRid $evidence $rid500File $score
        }
    }

    # ----------------------------------------------------------------
    # Lateral movement (Invoke-LateralMovementCheck.ps1). One finding per
    # rule (LM01-LM21), severity = worst finding of that rule, linked to
    # lateral_movement.txt. LM16 (well-known group population) is skipped
    # here because the HighRisk baseline already reports those groups.
    # ----------------------------------------------------------------
    $lmFindingsCsv = Resolve-AuditArtifactPath (Join-Path (Join-Path $InputRoot 'LateralMovement') 'lateral_movement_findings.csv')
    $lmTxtPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'lateral_movement.txt')
    if ($lmFindingsCsv -and (Test-Path -LiteralPath $lmFindingsCsv)) {
        $lmRows = @(Get-CsvSafe $lmFindingsCsv)
        $lmLink = if ($lmTxtPath -and (Test-Path -LiteralPath $lmTxtPath)) { $lmTxtPath } else { $lmFindingsCsv }
        foreach ($lmGroup in ($lmRows | Where-Object { $_.RuleId -and $_.RuleId -ne 'LM16' } | Group-Object RuleId | Sort-Object Name)) {
            $lmWorst = 'Information'
            foreach ($r in $lmGroup.Group) { if ((Get-SeverityRank $r.Severity) -gt (Get-SeverityRank $lmWorst)) { $lmWorst = Normalize-Severity $r.Severity } }
            $lmTitle = ($lmGroup.Group | Select-Object -First 1).Rule
            $lmCritical = @($lmGroup.Group | Where-Object { (Normalize-Severity $_.Severity) -eq 'Critical' }).Count
            $lmSample = @($lmGroup.Group | Sort-Object { Get-SeverityRank $_.Severity } -Descending | Select-Object -First 3 | ForEach-Object { $_.Subject })
            $lmEvidence = "$($lmGroup.Count) finding(s)$(if ($lmCritical -gt 0) { ", $lmCritical Critical" }). Examples: $($lmSample -join ', '). Interactive map: Lateral-Movement.html; details: lateral_movement.txt and LateralMovement\lateral_movement_findings.csv."
            Add-FindingOnce $lmWorst "Lateral movement: $lmTitle ($($lmGroup.Name))" $lmEvidence $lmLink (Score-Scaled $lmWorst $lmGroup.Count)
        }
    }
    $lmHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $InputRoot) 'Lateral-Movement.html'
    if (Test-Path $lmHtmlPath) {
        Add-FindingOnce 'Information' 'Lateral movement map report available' 'Interactive group-nesting map: filter groups and users, follow memberOf hop by hop, see Tier 0 paths, per-user and per-group risk and how to fix each finding.' $lmHtmlPath $SeverityScore.Information
    }

    # Companion HTML outputs
    $gpoReportPath = Join-Path (Get-HtmlReportsDir -BaseRoot $InputRoot) 'GPOReport.html'
    if (Test-Path $gpoReportPath) {
        Add-FindingOnce 'Information' 'Group Policy report available' 'Detailed GPO export generated as HTML.' $gpoReportPath $SeverityScore.Information
    }

    $overlapHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $InputRoot) 'overlapping_group_memberships.html'
    if (Test-Path $overlapHtmlPath) {
        Add-FindingOnce 'Information' 'Overlapping group membership report available' 'Detailed overlapping membership report generated as HTML.' $overlapHtmlPath $SeverityScore.Information
    }

    $nestedPathHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $InputRoot) 'multiple_nested_paths.html'
    if (Test-Path $nestedPathHtmlPath) {
        Add-FindingOnce 'Information' 'Multiple nested paths report available' 'Report showing target groups reachable via multiple nesting chains from a single direct group.' $nestedPathHtmlPath $SeverityScore.Information
    }

    $dangerousAclHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $InputRoot) 'dangerousACLs.html'
    if (Test-Path $dangerousAclHtmlPath) {
        Add-FindingOnce 'Information' 'Dangerous ACL report available' 'Detailed ACL findings generated as HTML.' $dangerousAclHtmlPath $SeverityScore.Information
    }

    $delegatedIndexPath = Get-ChildItem -Path (Join-Path (Get-RawDataDir -BaseRoot $InputRoot) 'DelegatedPermissions') -Recurse -File -Filter 'index.html' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($delegatedIndexPath) {
        Add-FindingOnce 'Information' 'Delegated permissions report available' 'Detailed delegated permissions HTML report generated.' $delegatedIndexPath.FullName $SeverityScore.Information
    }

    $dnsAuditHtmlPath = Get-ChildItem -Path $InputRoot -Recurse -File -Filter 'DNSAudit-*.html' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '\.source\.html$' } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($dnsAuditHtmlPath) {
        Add-FindingOnce 'Information' 'DNS audit report available' 'Detailed DNS audit HTML report generated.' $dnsAuditHtmlPath.FullName $SeverityScore.Information
    }

    $dnsRecoHtmlPath = Get-ChildItem -Path $InputRoot -Recurse -File -Filter 'DNS-Recommendations-*.html' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '\.source\.html$' } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($dnsRecoHtmlPath) {
        Add-FindingOnce 'Information' 'DNS recommendations report available' 'Supplementary DNS recommendations HTML report generated.' $dnsRecoHtmlPath.FullName $SeverityScore.Information
    }

    # ---------------------------
    # Prepare report download artifacts and in-report result previews
    # ---------------------------
    $downloadsDirLocal = Get-HtmlDownloadsDir -BaseRoot $InputRoot
    Publish-CommonDownloadArtifacts -Root $InputRoot -DownloadRoot $downloadsDirLocal

    foreach ($finding in $Findings) {
        $presentation = New-FindingResultPresentation -Finding $finding -AuditReportPath $AuditHtml -DownloadRoot $downloadsDirLocal
        $finding | Add-Member -NotePropertyName DownloadHref -NotePropertyValue $presentation.DownloadHref -Force
        $finding | Add-Member -NotePropertyName DownloadLabel -NotePropertyValue $presentation.DownloadLabel -Force
        $finding | Add-Member -NotePropertyName DownloadText -NotePropertyValue $presentation.DownloadText -Force
        $finding | Add-Member -NotePropertyName ResultsHtml -NotePropertyValue $presentation.ResultsHtml -Force
        $finding | Add-Member -NotePropertyName OpenInNewTab -NotePropertyValue $presentation.OpenInNewTab -Force
        if ($presentation.ResolvedSourcePath) {
            $finding.Link = $presentation.ResolvedSourcePath
        }
    }

    # ---------------------------
    # Totals
    # ---------------------------
    $sevCounts = @{
        Critical    = ($Findings | Where-Object { (($_.Severity -as [string]).Trim()) -ieq 'Critical'    }).Count
        High        = ($Findings | Where-Object { (($_.Severity -as [string]).Trim()) -ieq 'High'        }).Count
        Medium      = ($Findings | Where-Object { (($_.Severity -as [string]).Trim()) -ieq 'Medium'      }).Count
        Low         = ($Findings | Where-Object { (($_.Severity -as [string]).Trim()) -ieq 'Low'         }).Count
        Information = ($Findings | Where-Object { (($_.Severity -as [string]).Trim()) -ieq 'Information' }).Count
    }

    $TotalScore = 0
    foreach ($f in $Findings) { $TotalScore += [int]$f.Score }

    # ---------------------------
    # Score matrix + banding
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
    # HTML output
    # ---------------------------
    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'
    $computerName = Split-Path -Path $InputRoot -Leaf

    $domainInfoBlock = ''
    try {
        if ($baselinePath -and (Test-Path -LiteralPath $baselinePath)) {
            $domainInfoBlock = (Get-Content -LiteralPath $baselinePath -ErrorAction SilentlyContinue) -join "`n"
        }
    } catch { }

    $sortedFindings = $Findings | Sort-Object -Property @{Expression={ Get-SeverityRank $_.Severity };Descending=$true}, @{Expression='Score';Descending=$true}, @{Expression='Title';Descending=$false}

    $companionReports = Get-CompanionHtmlReports -Root $InputRoot -Exclude @($AuditHtml, $OutputHtml)
    Write-AuditHtmlReport -Path $AuditHtml -Items $sortedFindings -Counts $sevCounts -ComputerName $computerName -GeneratedOn $now -ManagementReportPath $OutputHtml -CompanionReports $companionReports

    $auditRel = [System.IO.Path]::GetFileName($AuditHtml)
    $tableRows = foreach ($f in $sortedFindings) {
        $sev      = Normalize-Severity $f.Severity
        $score    = [int]$f.Score
        $anchorId = New-FindingAnchor $f
        $auditRef = '{0}#{1}' -f $auditRel, $anchorId
        $sourceLabel = Get-FindingSourceLabel $f.Link
@"
<tr data-sev="$sev" data-score="$score">
  <td><span class="pill sev-$sev">$sev</span></td>
  <td class="title">$(HtmlEncode $f.Title)</td>
  <td class="evidence">$(HtmlEncode $f.Evidence)</td>
  <td class="score">$score</td>
  <td class="source"><a href="$(HtmlAttrEncode $auditRef)" title="$(HtmlAttrEncode $sourceLabel)"><span class="mono">Audit details</span></a></td>
</tr>
"@
    }

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
            'Reduce standing privilege and align with tiering (Tier 0 vs Tier 1 separation). Avoid Tier0+Tier1 overlap.'
            'Address password control items (duplicate passwords, PasswordNeverExpires usage, KRBTGT rotation policy) and confirm they align with operational requirements.'
            'Disable reversible password encryption and remediate affected accounts (password reset + policy review).'
            'Re-run the assessment after remediation to confirm closure and reduce configuration drift.'
        ) }
        'High' { @(
            'Prioritize High findings and track remediation to closure.'
            'Validate privileged access governance (membership reviews, approvals, and change tracking).'
            'Reduce standing privilege and align with tiering (Tier 0 vs Tier 1 separation).'
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

    # Risk-Report styling: now supports BOTH light and dark with an explicit
    # data-theme override. Default chooses OS preference (prefers-color-scheme
    # media query) and the toggle button at the top stores the user choice in
    # localStorage so they can override it. Earlier the report was hard-coded
    # dark-only with no way to switch, which made it unreadable on light-mode
    # workstations and inconsistent with every other report in the bundle.
    $css = @"
<style>
:root{
  /* Light theme (default) */
  --bg:#f5f7fb;
  --bg-glow1: rgba(105,177,255,.10);
  --bg-glow2: rgba(255,169,64,.10);
  --panel:#ffffff;
  --panel-soft: rgba(15,23,42,.04);
  --panel-softer: rgba(15,23,42,.02);
  --text:#1b2430;
  --muted:#5f6b7a;
  --line:#d9e0ea;
  --shadow:0 10px 24px rgba(15,23,42,.08);
  --radius:14px;
  --critical-bg:#fdecec; --critical-text:#c62828;
  --high-bg:#fff2e5;     --high-text:#ef6c00;
  --medium-bg:#e8f4fd;   --medium-text:#0277bd;
  --low-bg:#edf8ee;      --low-text:#2e7d32;
  --info-bg:#f2f4f6;     --info-text:#6c757d;
  --link:#0f5cb8;
  --pre-bg:#f8fafc; --pre-text:#1b2430;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg:#0b1220;
    --bg-glow1: rgba(105,177,255,.18);
    --bg-glow2: rgba(255,169,64,.16);
    --panel:#111827;
    --panel-soft: rgba(255,255,255,.06);
    --panel-softer: rgba(255,255,255,.03);
    --text:#e8edf6;
    --muted:#b7c0d6;
    --line:rgba(255,255,255,.10);
    --shadow:0 10px 30px rgba(0,0,0,.35);
    --critical-bg:rgba(255,77,79,.18); --critical-text:#fecaca;
    --high-bg:rgba(255,169,64,.18);    --high-text:#fed7aa;
    --medium-bg:rgba(105,177,255,.18); --medium-text:#bfdbfe;
    --low-bg:rgba(149,222,100,.18);    --low-text:#bbf7d0;
    --info-bg:rgba(160,160,160,.18);   --info-text:#e2e8f0;
    --link:#cfe1ff;
    --pre-bg:rgba(0,0,0,.25); --pre-text:#dbe6ff;
  }
}
/* Manual override (toggle button) wins over OS preference */
html[data-theme="light"]{
  --bg:#f5f7fb;
  --bg-glow1: rgba(105,177,255,.10);
  --bg-glow2: rgba(255,169,64,.10);
  --panel:#ffffff;
  --panel-soft: rgba(15,23,42,.04);
  --panel-softer: rgba(15,23,42,.02);
  --text:#1b2430;
  --muted:#5f6b7a;
  --line:#d9e0ea;
  --shadow:0 10px 24px rgba(15,23,42,.08);
  --critical-bg:#fdecec; --critical-text:#c62828;
  --high-bg:#fff2e5;     --high-text:#ef6c00;
  --medium-bg:#e8f4fd;   --medium-text:#0277bd;
  --low-bg:#edf8ee;      --low-text:#2e7d32;
  --info-bg:#f2f4f6;     --info-text:#6c757d;
  --link:#0f5cb8;
  --pre-bg:#f8fafc; --pre-text:#1b2430;
}
html[data-theme="dark"]{
  --bg:#0b1220;
  --bg-glow1: rgba(105,177,255,.18);
  --bg-glow2: rgba(255,169,64,.16);
  --panel:#111827;
  --panel-soft: rgba(255,255,255,.06);
  --panel-softer: rgba(255,255,255,.03);
  --text:#e8edf6;
  --muted:#b7c0d6;
  --line:rgba(255,255,255,.10);
  --shadow:0 10px 30px rgba(0,0,0,.35);
  --critical-bg:rgba(255,77,79,.18); --critical-text:#fecaca;
  --high-bg:rgba(255,169,64,.18);    --high-text:#fed7aa;
  --medium-bg:rgba(105,177,255,.18); --medium-text:#bfdbfe;
  --low-bg:rgba(149,222,100,.18);    --low-text:#bbf7d0;
  --info-bg:rgba(160,160,160,.18);   --info-text:#e2e8f0;
  --link:#cfe1ff;
  --pre-bg:rgba(0,0,0,.25); --pre-text:#dbe6ff;
}
*{box-sizing:border-box}
body{
  margin:0;
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
  background: radial-gradient(1200px 700px at 20% 10%, var(--bg-glow1), transparent 60%),
              radial-gradient(1200px 700px at 80% 0%, var(--bg-glow2), transparent 55%),
              var(--bg);
  color:var(--text);
}
a{color:var(--link);text-decoration:none} a:hover{text-decoration:underline}
.container{max-width:1200px;margin:0 auto;padding:28px 20px 60px}
.header{
  background: var(--panel);
  border:1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow);
  padding:22px 22px 18px;
}
.h-title{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;flex-wrap:wrap}
h1{font-size:22px;margin:0 0 6px;letter-spacing:.2px}
.meta{color:var(--muted);font-size:13px}
.theme-toggle{
  border:1px solid var(--line);
  background:var(--panel);
  color:var(--text);
  border-radius:999px;
  padding:8px 14px;
  font-size:13px;
  font-weight:700;
  cursor:pointer;
  margin-bottom:10px;
}
.theme-toggle:hover{filter:brightness(1.05)}
.badge{
  display:inline-flex;align-items:center;gap:10px;
  padding:10px 12px;border-radius:999px;border:1px solid var(--line);
  background: var(--panel-soft); font-weight:700;
}
.badge .grade{font-size:13px;color:var(--muted);font-weight:600}
.badge .value{font-size:15px}
.badge.Critical{background:var(--critical-bg);color:var(--critical-text)}
.badge.High{background:var(--high-bg);color:var(--high-text)}
.badge.Medium{background:var(--medium-bg);color:var(--medium-text)}
.badge.Low{background:var(--low-bg);color:var(--low-text)}
.badge.Information{background:var(--info-bg);color:var(--info-text)}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;margin-top:14px}
.card{
  background: var(--panel);
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
.sev-Critical{background:var(--critical-bg);color:var(--critical-text)}
.sev-High{background:var(--high-bg);color:var(--high-text)}
.sev-Medium{background:var(--medium-bg);color:var(--medium-text)}
.sev-Low{background:var(--low-bg);color:var(--low-text)}
.sev-Information{background:var(--info-bg);color:var(--info-text)}
.section{margin-top:18px} .section h2{margin:0 0 10px;font-size:16px}
.callout{border:1px solid var(--line);border-radius: var(--radius);padding:14px;background: var(--panel)}
.callout p{margin:0;line-height:1.4} .callout ul{margin:10px 0 0 18px} .callout li{margin:6px 0}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between;margin:10px 0}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
select,input{
  background: var(--panel);
  color:var(--text);
  border:1px solid var(--line);
  border-radius:10px;
  padding:8px 10px;
  outline:none;
}
input{min-width:240px}
small{color:var(--muted)}
select option{ background: var(--panel); color: var(--text); }
table{width:100%;border-collapse:collapse;border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;background: var(--panel)}
th,td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em;background: var(--panel-soft);cursor:pointer;user-select:none}
tr:hover td{background: var(--panel-soft)}
td.score{font-weight:800} td.title{font-weight:700}
.mono{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace}
td.source .mono{font-size:12px;color:var(--link)}
pre{white-space:pre-wrap;background: var(--pre-bg);border:1px solid var(--line);border-radius: var(--radius);padding:12px;color: var(--pre-text);overflow:auto}
.footer{margin-top:16px;color:var(--muted);font-size:12px}
.matrix-wrap{margin-top:10px}
table.matrix{ table-layout:fixed; }
table.matrix th, table.matrix td{ padding:14px 18px; }
table.matrix th{ cursor:default; }
table.matrix th:nth-child(1), table.matrix td:nth-child(1){ width:18%; padding-left:22px; }
table.matrix th:nth-child(2), table.matrix td:nth-child(2){ width:18%; text-align:center; }
table.matrix th:nth-child(3), table.matrix td:nth-child(3){ width:64%; padding-left:22px; }
.matrix-row.active td{background: var(--panel-soft)}
</style>
"@

    $js = @"
<script>
(function(){
  function q(sel){return document.querySelector(sel);}
  function qa(sel){return Array.prototype.slice.call(document.querySelectorAll(sel));}
  function rows(){return qa('#findings-body tr');}

  // Theme handling: if the user has explicitly toggled in the past we honour
  // their stored choice; otherwise we follow the OS prefers-color-scheme so
  // light-OS users get a light report and dark-OS users get a dark report.
  // The CSS handles both via :root / @media / html[data-theme=...] rules.
  function currentTheme(){
    var stored = null;
    try { stored = localStorage.getItem('adaudit-theme'); } catch(e){}
    if (stored === 'light' || stored === 'dark') return stored;
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark';
    return 'light';
  }
  function applyTheme(t){
    document.documentElement.setAttribute('data-theme', t);
    var btn = q('#themeToggle');
    if (btn){
      btn.innerText = (t === 'dark') ? 'Light mode' : 'Dark mode';
      btn.setAttribute('aria-pressed', (t === 'dark') ? 'true' : 'false');
    }
  }
  // Persist ONLY on explicit user choice, so the initial auto-detect does not
  // pin the theme and disable the follow-OS handler below.
  function setTheme(t){
    applyTheme(t);
    try { localStorage.setItem('adaudit-theme', t); } catch(e){}
  }
  applyTheme(currentTheme());
  var tBtn = q('#themeToggle');
  if (tBtn){
    tBtn.addEventListener('click', function(){
      var next = (document.documentElement.getAttribute('data-theme') === 'dark') ? 'light' : 'dark';
      setTheme(next);
    });
  }
  // React to OS theme changes only when the user has not picked a theme.
  if (window.matchMedia){
    var mq = window.matchMedia('(prefers-color-scheme: dark)');
    var handler = function(e){
      var stored = null;
      try { stored = localStorage.getItem('adaudit-theme'); } catch(_){}
      if (stored !== 'light' && stored !== 'dark'){
        applyTheme(e.matches ? 'dark' : 'light');
      }
    };
    if (mq.addEventListener){ mq.addEventListener('change', handler); }
    else if (mq.addListener){ mq.addListener(handler); }
  }

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
  var order = ['Critical','High','Medium','Low','Information'];

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
  sortBy('score'); sortBy('score');
})();
</script>
"@

    $primaryNav = Get-ADAuditPrimaryNav -Active 'risk'

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AD Audit - Risk Report</title>
$css
</head>
<body>
<div class="container">
$primaryNav
  <div class="header">
    <div class="h-title">
      <div>
        <h1>Active Directory Audit - Risk Report</h1>
        <div class="meta">Target: <span class="mono">$(HtmlEncode $computerName)</span> | Generated: $(HtmlEncode $now) | <a href="$(HtmlAttrEncode ([System.IO.Path]::GetFileName($AuditHtml)))">Detailed audit report</a></div>
        <div class="meta" style="margin-top:4px">Script: <span class="mono">$versionnum</span> | Run by: <span class="mono">$(HtmlEncode "$env:USERDOMAIN\$env:USERNAME")</span> | Start: $(HtmlEncode "$starttime") | End: $(HtmlEncode "$endtime")</div>
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:10px">
        <button id="themeToggle" type="button" class="theme-toggle" aria-pressed="false">Toggle theme</button>
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

      <div class="footer">Note: This score is an index based on the findings included in this report and the collected audit data embedded into the generated HTML reports. Validate scope and collection completeness.</div>
    </div>
  </div>

  <div class="section">
    <h2>Findings by Category</h2>
    <table style="width:100%;border-collapse:collapse;margin-bottom:18px">
      <thead><tr><th style="text-align:left;padding:6px 10px;border-bottom:1px solid var(--line)">Category</th><th style="text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)">Critical</th><th style="text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)">High</th><th style="text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)">Medium</th><th style="text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)">Low</th><th style="text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)">Total</th></tr></thead>
      <tbody>
$(
    $catGroups = $Findings | ForEach-Object { [pscustomobject]@{ Category = (Get-FindingCategory $_.Title); Severity = (Normalize-Severity $_.Severity) } } | Group-Object Category | Sort-Object @{Expression={($_.Group | Where-Object { $_.Severity -eq 'Critical' } | Measure-Object).Count};Descending=$true}, @{Expression={($_.Group | Where-Object { $_.Severity -eq 'High' } | Measure-Object).Count};Descending=$true}, Name
    foreach ($cg in $catGroups) {
        $cc = ($cg.Group | Where-Object { $_.Severity -eq 'Critical' } | Measure-Object).Count
        $ch = ($cg.Group | Where-Object { $_.Severity -eq 'High' } | Measure-Object).Count
        $cm = ($cg.Group | Where-Object { $_.Severity -eq 'Medium' } | Measure-Object).Count
        $cl = ($cg.Group | Where-Object { $_.Severity -eq 'Low' } | Measure-Object).Count
        $ct = $cg.Count
        "<tr><td style='padding:6px 10px;border-bottom:1px solid var(--line)'>$(HtmlEncode $cg.Name)</td><td style='text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)'>$(if($cc -gt 0){"<span class='pill sev-Critical'>$cc</span>"}else{'-'})</td><td style='text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)'>$(if($ch -gt 0){"<span class='pill sev-High'>$ch</span>"}else{'-'})</td><td style='text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)'>$(if($cm -gt 0){"<span class='pill sev-Medium'>$cm</span>"}else{'-'})</td><td style='text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)'>$(if($cl -gt 0){"<span class='pill sev-Low'>$cl</span>"}else{'-'})</td><td style='text-align:center;padding:6px 10px;border-bottom:1px solid var(--line);font-weight:700'>$ct</td></tr>"
    }
)
      </tbody>
    </table>
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
            <option>Information</option>
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
          <th>Details</th>
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
    Generated by the Risk Report script. Review the linked ADAudit-Results.html findings for remediation actions.<br>
    This report summarizes configuration and baseline observations. It should be reviewed alongside operational context and existing compensating controls.
  </div>
</div>

$js
</body>
</html>
"@

    Set-Content -LiteralPath $OutputHtml -Value $html -Encoding UTF8

    if ($OutputTxt) {
        # ---------------------------
        # Optional TXT output
        # ---------------------------
        $top = ($Findings | Sort-Object -Property @{Expression='Score';Descending=$true}) | Select-Object -First $TopFindings

        $txt = @()
        $txt += "Active Directory Audit - Risk Report"
        $txt += "Target: $computerName"
        $txt += "Generated: $now"
        $txt += "Overall risk level: $OverallLevel (Score=$TotalScore)"
        $txt += "Score matrix: " + (($ScoreBands | ForEach-Object { "$($_.Level)=$($_.Range)" }) -join '; ')
        if ($UsersCount)  { $txt += "Users: $UsersCount" }
        if ($GroupsCount) { $txt += "Groups: $GroupsCount" }
        if ($OUsCount)    { $txt += "OUs: $OUsCount" }
        $txt += ""
        $txt += "Top findings:"
        foreach ($f in $top) { $txt += "- [$($f.Severity)] $($f.Title) - $($f.Evidence) (source: $($f.Link))" }
        $txt += ""
        $txt += "See HTML report for linked detailed findings."

        Set-Content -LiteralPath $OutputTxt -Value ($txt -join "`r`n") -Encoding UTF8
        Write-Host "[+] Executive TXT summary written:" (Get-RelPath $OutputTxt)
    }

    Write-Host "[+] Audit results written:" (Get-RelPath $AuditHtml)
    Write-Host "[+] Risk report written:" (Get-RelPath $OutputHtml)
}

function Get-RelativeReportHref {
    [CmdletBinding()]
    param(
        [string]$FromFile,
        [string]$ToPath
    )

    if ([string]::IsNullOrWhiteSpace($FromFile) -or [string]::IsNullOrWhiteSpace($ToPath)) { return '' }

    try {
        $fromDir = Split-Path -Path $FromFile -Parent
        $fromAbs = [System.IO.Path]::GetFullPath($fromDir)
        $targetAbs = [System.IO.Path]::GetFullPath($ToPath)

        $baseUri = New-Object System.Uri(($fromAbs.TrimEnd('\') + '\'))
        $targetUri = New-Object System.Uri($targetAbs)
        return ([System.Uri]::UnescapeDataString($baseUri.MakeRelativeUri($targetUri).ToString()) -replace '\\','/')
    } catch {
        return [System.IO.Path]::GetFileName($ToPath)
    }
}

function Get-CompanionHtmlReportTitle {
    [CmdletBinding()]
    param([string]$FileName)

    switch -Regex ($FileName) {
        '^GPOReport\.html$'                     { return 'Group Policy report' }
        '^overlapping_group_memberships\.html$' { return 'Overlapping group membership report' }
        '^multiple_nested_paths\.html$'        { return 'Multiple nested paths report' }
        '^dangerousACLs\.html$'                { return 'Dangerous ACL report' }
        '^ad_high_risk_baseline_index\.html$'  { return 'High-risk baseline report' }
        '^Lateral-Movement\.html$'             { return 'Lateral movement map' }
        '^index\.html$'                        { return 'Delegated permissions report' }
        '^DNSAudit-.*\.html$'                  { return 'DNS audit report' }
        '^DNS-Recommendations-.*\.html$'       { return 'DNS recommendations report' }
        default                                { return ($FileName -replace '\.html$','' -replace '[-_]+',' ') }
    }
}

function Get-CompanionHtmlShellCandidates {
    [CmdletBinding()]
    param([string]$Root)

    $items = New-Object 'System.Collections.Generic.List[System.IO.FileInfo]'
    $seen  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    function Add-File([System.IO.FileInfo]$File) {
        if (-not $File) { return }
        $full = $null
        try { $full = [System.IO.Path]::GetFullPath($File.FullName) } catch { $full = $File.FullName }
        if ($seen.Add($full)) { $items.Add($File) | Out-Null }
    }

    # Reports that ALREADY ship with the shared primary-nav and standalone
    # design - they should NOT be wrapped in the companion shell, since that
    # would double up navigation and theme toggles.
    $skipWrap = @(
        'Risk-Report.html'
        'ADAudit-Results.html'
        'AD_Health.html'
        'overlapping_group_memberships.html'
        'multiple_nested_paths.html'
        'Lateral-Movement.html'
    )

    $htmlRoot = Get-HtmlReportsDir -BaseRoot $Root
    if (Test-Path -LiteralPath $htmlRoot) {
        foreach ($file in (Get-ChildItem -LiteralPath $htmlRoot -File -Filter '*.html' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin $skipWrap -and $_.Name -notmatch '\.source\.html$' })) {
            Add-File $file
        }
    }

    foreach ($file in (Get-ChildItem -Path (Join-Path (Get-RawDataDir -BaseRoot $Root) 'DelegatedPermissions') -Recurse -File -Filter 'index.html' -ErrorAction SilentlyContinue)) {
        Add-File $file
    }

    foreach ($file in (Get-ChildItem -Path $Root -Recurse -File -Include 'DNSAudit-*.html','DNS-Recommendations-*.html' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\.source\.html$' })) {
        Add-File $file
    }

    return $items.ToArray()
}

function Update-CompanionHtmlReports {
    [CmdletBinding()]
    param([string]$Root)

    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root)) { return }

    $auditPath = Join-Path (Get-HtmlReportsDir -BaseRoot $Root) 'ADAudit-Results.html'

    foreach ($file in (Get-CompanionHtmlShellCandidates -Root $Root)) {
        $targetPath = $file.FullName
        $rawHtml = ''
        try { $rawHtml = Get-Content -LiteralPath $targetPath -Raw -ErrorAction Stop } catch { continue }
        if ([string]::IsNullOrWhiteSpace($rawHtml)) { continue }
        if ($rawHtml -match 'adaudit-companion-wrapper') { continue }

        $bodyHtml = $rawHtml
        if ($rawHtml -match '(?is)<body[^>]*>(?<body>.*)</body>') {
            $bodyHtml = $matches['body']
        }

        $styleBlocks = @(
            [regex]::Matches($rawHtml, '(?is)<style[^>]*>.*?</style>') |
            ForEach-Object { $_.Value }
        )

        # Carry over head-scoped <script> blocks too: reports like GPOReport.html
        # (Get-GPOReport) define their expand/collapse functions in <head>, and
        # dropping them breaks every onclick handler in the wrapped body.
        $headHtml = ''
        if ($rawHtml -match '(?is)<head[^>]*>(?<head>.*?)</head>') {
            $headHtml = $matches['head']
        }
        $headScriptBlocks = @(
            [regex]::Matches($headHtml, '(?is)<script[^>]*>.*?</script>') |
            ForEach-Object { $_.Value }
        )

        # The wrapper embeds the complete original (body, styles and head scripts), so
        # the original is replaced in place - no '<name>.source.html' duplicate is kept.
        # Any stray copy from an earlier version is removed.
        $sourcePath = Join-Path $file.DirectoryName (([System.IO.Path]::GetFileNameWithoutExtension($file.Name)) + '.source.html')
        if (Test-Path -LiteralPath $sourcePath) {
            Remove-Item -LiteralPath $sourcePath -Force -ErrorAction SilentlyContinue
        }

        $title = Get-CompanionHtmlReportTitle -FileName $file.Name
        $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'
        $auditHref = if (Test-Path -LiteralPath $auditPath) { Get-RelativeReportHref -FromFile $targetPath -ToPath $auditPath } else { '' }

        # Companion-report wrapper now ships with full dark-mode support
        # (OS preference + manual toggle + localStorage) so wrapped GPO and
        # other companion HTML reports match the rest of the suite. Earlier
        # the wrapper was light-only and looked out of place when the user
        # had toggled the main ADAudit-Results report to dark.
        $wrapper = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="adaudit-companion-wrapper" content="1">
<title>ADAudit - $title</title>
$($styleBlocks -join "`n")
$($headScriptBlocks -join "`n")
<style>
:root{
  --bg:#f5f7fb;
  --panel:#ffffff;
  --panel-soft:#f8fafc;
  --panel-softer:#fafcff;
  --th-bg:#eef2f7;
  --code-bg:#f3f4f6;
  --text:#1b2430;
  --muted:#5f6b7a;
  --line:#d9e0ea;
  --shadow:0 10px 24px rgba(15,23,42,.08);
  --link:#0f5cb8;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#0f172a;
    --panel:#1e293b;
    --panel-soft:#0b1220;
    --panel-softer:#111827;
    --th-bg:#1e293b;
    --code-bg:rgba(255,255,255,.06);
    --text:#e2e8f0;
    --muted:#94a3b8;
    --line:#334155;
    --shadow:0 10px 24px rgba(0,0,0,.4);
    --link:#93c5fd;
  }
}
html[data-theme="light"]{
  --bg:#f5f7fb;
  --panel:#ffffff;
  --panel-soft:#f8fafc;
  --panel-softer:#fafcff;
  --th-bg:#eef2f7;
  --code-bg:#f3f4f6;
  --text:#1b2430;
  --muted:#5f6b7a;
  --line:#d9e0ea;
  --shadow:0 10px 24px rgba(15,23,42,.08);
  --link:#0f5cb8;
}
html[data-theme="dark"]{
  --bg:#0f172a;
  --panel:#1e293b;
  --panel-soft:#0b1220;
  --panel-softer:#111827;
  --th-bg:#1e293b;
  --code-bg:rgba(255,255,255,.06);
  --text:#e2e8f0;
  --muted:#94a3b8;
  --line:#334155;
  --shadow:0 10px 24px rgba(0,0,0,.4);
  --link:#93c5fd;
}
*{box-sizing:border-box}
body{
  margin:0;
  font-family:Segoe UI,Arial,sans-serif;
  background:var(--bg);
  color:var(--text);
}
a{color:var(--link);text-decoration:none}
a:hover{text-decoration:underline}
.container{max-width:1280px;margin:0 auto;padding:28px 22px 48px}
.hero,.panel{
  background:var(--panel);
  border:1px solid var(--line);
  border-radius:18px;
  box-shadow:var(--shadow);
}
.hero{padding:24px}
.panel{padding:22px;margin-top:20px}
.hero-top{display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap;align-items:flex-start}
.meta{color:var(--muted);font-size:14px;line-height:1.6}
.actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.btn,.theme-toggle{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-height:40px;
  padding:10px 14px;
  border-radius:10px;
  border:1px solid var(--line);
  background:var(--panel);
  color:var(--text);
  font-weight:700;
  cursor:pointer;
}
.theme-toggle{border-radius:999px;font-size:13px}
.embedded-report{margin-top:8px}
.embedded-report table{border-collapse:collapse;width:100%}
.embedded-report th,.embedded-report td{border:1px solid var(--line);padding:8px 10px;vertical-align:top;text-align:left}
.embedded-report th{background:var(--th-bg);color:var(--text)}
.embedded-report pre{
  white-space:pre-wrap;
  word-break:break-word;
  background:var(--panel-soft);
  color:var(--text);
  border:1px solid var(--line);
  border-radius:12px;
  padding:14px;
}
.embedded-report code{
  font-family:Consolas,Menlo,Monaco,monospace;
  background:var(--code-bg);
  color:var(--text);
  padding:2px 4px;
  border-radius:4px;
}
.embedded-report details{
  border:1px solid var(--line);
  border-radius:12px;
  padding:12px;
  margin:12px 0;
  background:var(--panel-softer);
  color:var(--text);
}
.embedded-report summary{cursor:pointer;font-weight:700}
.embedded-report h1,.embedded-report h2,.embedded-report h3,.embedded-report h4{margin-top:0;color:var(--text)}
</style>
<script>
(function(){
  function osPrefersDark(){
    return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  }
  function currentTheme(){
    var s=null; try { s=localStorage.getItem('adaudit-theme'); } catch(_){}
    if (s==='light'||s==='dark') return s;
    return osPrefersDark() ? 'dark' : 'light';
  }
  function applyTheme(t){
    document.documentElement.setAttribute('data-theme', t);
    var btn=document.getElementById('wrapperThemeToggle');
    if (btn){
      btn.innerText = (t==='dark') ? 'Light mode' : 'Dark mode';
      btn.setAttribute('aria-pressed', (t==='dark') ? 'true' : 'false');
    }
  }
  function setTheme(t){ applyTheme(t); try { localStorage.setItem('adaudit-theme', t); } catch(_){} }
  document.addEventListener('DOMContentLoaded', function(){
    applyTheme(currentTheme());
    var btn=document.getElementById('wrapperThemeToggle');
    if (btn){
      btn.addEventListener('click', function(){
        var next = (document.documentElement.getAttribute('data-theme')==='dark') ? 'light' : 'dark';
        setTheme(next);
      });
    }
    if (window.matchMedia){
      var mq = window.matchMedia('(prefers-color-scheme: dark)');
      var handler = function(e){
        var s=null; try { s=localStorage.getItem('adaudit-theme'); } catch(_){}
        if (s !== 'light' && s !== 'dark') applyTheme(e.matches ? 'dark' : 'light');
      };
      if (mq.addEventListener){ mq.addEventListener('change', handler); }
      else if (mq.addListener){ mq.addListener(handler); }
    }
  });
})();
</script>
</head>
<body>
<div class="container">
  <section class="hero">
    <div class="hero-top">
      <div>
        <h1>$title</h1>
        <div class="meta">
          Companion HTML report generated by ADAudit.<br>
          Generated wrapper: $generated
        </div>
      </div>
      <div class="actions">
        <button id="wrapperThemeToggle" type="button" class="theme-toggle" aria-pressed="false">Toggle theme</button>
        $(if ($auditHref) { "<a class='btn' href='$auditHref'>Back to ADAudit-Results</a>" } else { '' })
      </div>
    </div>
  </section>

  <section class="panel">
    <div class="embedded-report">
      $bodyHtml
    </div>
  </section>
</div>
</body>
</html>
"@

        Set-Content -LiteralPath $targetPath -Value $wrapper -Encoding UTF8
    }
}

function Get-LegacyArtifactCandidates {
    [CmdletBinding()]
    param(
        [string]$Root
    )

    $items = New-Object 'System.Collections.Generic.List[System.IO.FileInfo]'
    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root)) { return @() }

    $rootExts = @('.txt','.csv','.xml','.json','.nessus')
    $highRiskExts = @('.txt','.csv','.json')

    foreach ($file in (Get-ChildItem -LiteralPath $Root -File -ErrorAction SilentlyContinue | Where-Object { $rootExts -contains $_.Extension.ToLowerInvariant() })) {
        $items.Add($file) | Out-Null
    }

    $highRiskDir = Join-Path $Root 'HighRisk'
    if (Test-Path -LiteralPath $highRiskDir) {
        foreach ($file in (Get-ChildItem -LiteralPath $highRiskDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $highRiskExts -contains $_.Extension.ToLowerInvariant() })) {
            $items.Add($file) | Out-Null
        }
    }

    return @($items | Sort-Object FullName -Unique)
}

function Remove-EmptyAuditDirectories {
    [CmdletBinding()]
    param(
        [string]$Root,
        [string[]]$Exclude = @()
    )

    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root)) { return }

    $excludeMap = @{}
    foreach ($path in $Exclude) {
        if (-not [string]::IsNullOrWhiteSpace($path)) {
            try { $excludeMap[[System.IO.Path]::GetFullPath($path)] = $true } catch { }
        }
    }

    foreach ($dir in (Get-ChildItem -Path $Root -Recurse -Directory -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)) {
        $full = $null
        try { $full = [System.IO.Path]::GetFullPath($dir.FullName) } catch { $full = $dir.FullName }
        if ($excludeMap.ContainsKey($full)) { continue }

        try {
            if (-not (Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue)) {
                Remove-Item -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue
            }
        } catch { }
    }
}

function Remove-LegacyAuditArtifacts {
    [CmdletBinding()]
    param(
        [string]$Root
    )

    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root)) { return }

    $removed = 0
    foreach ($file in (Get-LegacyArtifactCandidates -Root $Root)) {
        try {
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            $removed++
        } catch { }
    }

    Remove-EmptyAuditDirectories -Root $Root -Exclude @((Get-HtmlReportsDir -BaseRoot $Root), (Get-RawDataDir -BaseRoot $Root))

    if ($removed -gt 0) {
        Write-Host "[+] Removed raw TXT/CSV/XML/JSON/NESSUS audit artifacts from the output tree."
    }
}

function Move-LegacyAuditArtifacts {
    [CmdletBinding()]
    param(
        [string]$Root,
        [string]$ArchiveRoot
    )

    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root)) { return }
    if ([string]::IsNullOrWhiteSpace($ArchiveRoot)) { $ArchiveRoot = Get-RawSourceDataDir -BaseRoot $Root }

    if (-not (Test-Path -LiteralPath $ArchiveRoot)) {
        New-Item -ItemType Directory -Path $ArchiveRoot -Force | Out-Null
    }

    $rootAbs = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $moved = 0

    foreach ($file in (Get-LegacyArtifactCandidates -Root $Root)) {
        try {
            $full = [System.IO.Path]::GetFullPath($file.FullName)
            $relative = $full.Substring($rootAbs.Length).TrimStart('\','/')
            $destination = Join-Path $ArchiveRoot $relative
            $destinationDir = Split-Path -Path $destination -Parent
            if ($destinationDir -and -not (Test-Path -LiteralPath $destinationDir)) {
                New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
            }

            Move-Item -LiteralPath $file.FullName -Destination $destination -Force -ErrorAction Stop
            $moved++
        } catch { }
    }

    Remove-EmptyAuditDirectories -Root $Root -Exclude @((Get-HtmlReportsDir -BaseRoot $Root), $ArchiveRoot)

    if ($moved -gt 0) {
        Write-Host "[+] Moved raw TXT/CSV/XML/JSON/NESSUS audit artifacts to:" $ArchiveRoot
    }
}

function Move-RootHtmlReports {
    [CmdletBinding()]
    param(
        [string]$Root,
        [string]$Destination
    )

    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root)) { return }
    if ([string]::IsNullOrWhiteSpace($Destination)) { $Destination = Get-HtmlReportsDir -BaseRoot $Root }

    if (-not (Test-Path -LiteralPath $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    foreach ($file in (Get-ChildItem -LiteralPath $Root -File -Filter '*.html' -ErrorAction SilentlyContinue)) {
        $destFile = Join-Path $Destination $file.Name
        try {
            $srcFull = [System.IO.Path]::GetFullPath($file.FullName)
            $destFull = [System.IO.Path]::GetFullPath($destFile)
            if ($srcFull -ieq $destFull) { continue }
            # Legacy migration only: never overwrite a report this run just
            # generated in the destination with a stale root-level file.
            if (Test-Path -LiteralPath $destFile) {
                $existing = Get-Item -LiteralPath $destFile -ErrorAction SilentlyContinue
                if ($existing -and $existing.LastWriteTimeUtc -ge $file.LastWriteTimeUtc) { continue }
            }
            Move-Item -LiteralPath $file.FullName -Destination $destFile -Force -ErrorAction Stop
        } catch { }
    }
}

function Invoke-ADAuditFinalReports {
    <#
    .SYNOPSIS
        End-of-run report assembly: legacy artifact migration, management + audit HTML,
        companion wrapping and the HTML Reports cleanup. Called once by AdAudit-PS7.ps1.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)

    Move-RootHtmlReports -Root $Root -Destination (Get-HtmlReportsDir -BaseRoot $Root)
    Move-LegacyAuditArtifacts -Root $Root -ArchiveRoot (Get-RawSourceDataDir -BaseRoot $Root)
    Invoke-ManagementReport -InputRoot $Root -OutputHtml (Join-Path (Get-HtmlReportsDir -BaseRoot $Root) 'Risk-Report.html') -AuditHtml (Join-Path (Get-HtmlReportsDir -BaseRoot $Root) 'ADAudit-Results.html')
    Update-CompanionHtmlReports -Root $Root

    # <<< add cleanup here (absolute last action) >>>
    # Keep the primary HTML reports PLUS the companion reports that ADAudit-Results.html
    # links to (its "Open Report" buttons and the companion list). Only genuinely orphaned
    # HTML (nothing links to it) is removed, and every '*.source.html' duplicate left by an
    # earlier version is deleted (the wrapper now contains the full original).
    $__htmlReportsDir = Get-HtmlReportsDir -BaseRoot $Root
    $__keep = @(
        'overlapping_group_memberships.html'
        'Risk-Report.html'
        'multiple_nested_paths.html'
        'ADAudit-Results.html'
        'AD_Health.html'
        'Lateral-Movement.html'
        # Companion reports linked from ADAudit-Results.html:
        'GPOReport.html'
        'dangerousACLs.html'
        'ad_high_risk_baseline_index.html'
    )
    if (Test-Path -LiteralPath $__htmlReportsDir) {
        foreach ($f in (Get-ChildItem -LiteralPath $__htmlReportsDir -File -Filter '*.html' -ErrorAction SilentlyContinue)) {
            if ($f.Name -notlike '*.source.html' -and ($__keep -contains $f.Name)) { continue }
            try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop } catch { }
        }
    }
    # Companion reports under Raw Data (DNS audit, delegated permissions) are wrapped in
    # place too; drop their '*.source.html' duplicates as well.
    foreach ($f in (Get-ChildItem -Path $Root -Recurse -File -Filter '*.source.html' -ErrorAction SilentlyContinue)) {
        try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop } catch { }
    }
}