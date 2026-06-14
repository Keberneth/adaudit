<#
    .NOTES
        Author       : phillips321.co.uk
        updated and modified by Keberneth
        Creation Date: 16/08/2018
        Script Name  : ADAudit.ps1
    .SYNOPSIS
        PowerShell Script to perform a quick AD audit
    .DESCRIPTION
        o Compatibility :
            * PowerShell 7.x on Windows (with conditional Windows PowerShell compatibility only for legacy modules that still require it)
            * Target platform: Windows Server 2025 and supported RSAT-equipped Windows management hosts
            * All languages (you may need to adjust $AdministratorTranslation variable)
        o Requirements :
            * ActiveDirectory PowerShell module (installed with RSAT tools)
            * DnsServer PowerShell module (installed with DNS Server role)
            * Windows LAPS PowerShell module (LAPS) for Windows LAPS estates, or AdmPwd.PS for legacy Microsoft LAPS
            * DSInternals and NuGet PowerShell module, installed by script if -installdeps switch is used)
              Offline installation help using ADAudit-run.ps1 script
        o Changelog :
            [X] Version 8.8 - 08/05/2026
                Added Get-ADHealth (-adhealth / -ad-health / -health). New AD platform
                    health check covering replication health, DC diagnostics (dcdiag),
                    SYSVOL/DFSR backlog, NTDS database, time synchronization, core AD
                    services, event-log scrape (last 72h), sites and subnets, AD
                    Recycle Bin posture, and group hygiene (total / empty / built-in
                    primaryGroupID-backed). Each test produces an evidence file under
                    Raw Data\Source\.
                Added DC interconnect probe inside Get-ADHealth. For every DC in AD
                    probes DNS A-record, TCP 389 (LDAP), TCP 445 (SMB) and replication
                    freshness via Get-ADReplicationPartnerMetadata. A DC that exists
                    in AD but cannot be reached on LDAP+SMB is flagged "isolated"
                    (cloned VM on isolated network, firewalled-off DC, decommissioned
                    but not removed, etc.). Severity scales with how much redundancy
                    is left:
                        2 DCs total, 1 isolated  -> Critical (no failover)
                        3 DCs total, 1 isolated  -> High
                        4+ DCs total, 1 isolated -> Medium
                        multiple isolated, < 2 reachable -> Critical
                        multiple isolated, < 3 reachable -> High
                        multiple isolated, 3+ reachable  -> Medium
                    Each isolated DC also gets its own per-DC Critical finding
                    because replication with that specific peer is dead regardless
                    of how many other DCs the rest of the forest can reach.
                Generates AD_Health.html with a hero, semicircle SVG risk gauge with
                    colour-graded arc and needle, counts row, "Tests Performed"
                    status grid, severity-bucketed findings tables, and a "Test
                    Details" section at the bottom - one collapsible card per test
                    with what-it-checks summary, why-it-matters, what-to-look-for
                    (Warn/Fail only), how-to-fix (Warn/Fail only), source-link to the
                    evidence file, and a copy-paste rerun command.
                KPSSVC (Kerberos Key Distribution Proxy) reclassified from High to
                    Information. KPSSVC is optional and frequently left stopped on
                    purpose; it was raising false High findings on every run. The
                    audit still records its state in the evidence file; only the
                    severity is reduced.
                Added Get-DomainAdminScaledRisk (KB427) and Built-in domain
                    Administrator (RID-500) hygiene check (KB428). Walks Domain
                    Admins recursively, classifies every member (BuiltinAdmin500 /
                    NormalUser / Service / Computer / gMSA / NestedGroup), counts
                    enabled human users as the denominator, and applies a size-
                    adjusted severity ladder:
                        any high-risk principal in DA (service / computer / gMSA /
                          nested / stale / disabled-but-member)        -> Critical
                        effective permanent count > hard cap (10)      -> High
                        effective permanent count > size-adjusted limit -> High
                        effective permanent count > static benchmark (5) -> Medium
                        effective permanent count > recommended target -> Low
                    Hard cap at 10 - scaling never normalises Domain Admins sprawl.
                    Built-in RID-500 is excluded from the count but checked
                    separately for password age (>180d), SPN attachment, disabled
                    state, and Protected Users membership. Evidence file folds in
                    Administrators / Enterprise Admins / Schema Admins / Backup
                    Operators / Account Operators / Server Operators / Print
                    Operators / Group Policy Creator Owners / Cert Publishers as
                    an "Other privileged groups" sub-table for one-stop review.
                    Get-PrivilegedGroupAccounts is unchanged; the new check runs
                    alongside it and produces two separate findings.
                Shared four-tab primary navigation injected into all five primary
                    HTML reports (ADAudit-Results.html, Risk-Report.html,
                    AD_Health.html, overlapping_group_memberships.html,
                    multiple_nested_paths.html). Tabs: Audit Results, Risk Report,
                    AD Health, Overlapping Groups. The "Operations" tab is gone
                    (Operations is not part of the audit). The active tab is
                    highlighted on the page that owns it.
                HTML Reports cleanup: only the five primary reports above survive
                    in the output folder. Companion wrappers, GPOReport.html,
                    dangerousACLs.html, ad_high_risk_baseline_index.html, DNS
                    audit / recommendations and *.source.html files are removed
                    at the end of the run.
                Modern flat theme for ADAudit-GUI.ps1 mirroring the HTML report
                    colour tokens (light + dark, accent #3b82f6 / #60a5fa, panel,
                    border, muted, mono variants). Card-based layout, rounded flat
                    buttons (Region-clipped), themed checkboxes / textboxes,
                    monospaced command preview block. Theme toggle in the top-right
                    persists the choice to %APPDATA%\ADAudit-GUI\theme.txt so it
                    survives close/reopen and follows the user's HTML report
                    preference.
                Bug fixes:
                    - Fixed repadmin /replsummary regex: the previous version
                      captured the trailing percentage column instead of the fails
                      column, so even fully-partitioned environments showed zero
                      replication failures. Now captures the actual fails value.
                    - Fixed AD_Health gauge needle on non-English locales: the SVG
                      line coordinates were emitted with the current culture's
                      decimal separator, so on Swedish / German / French / etc.
                      the values came out as '120,98' which the SVG parser cannot
                      read - the line was drawn to (0,0) and looked like a giant
                      stray pointer. Now uses [CultureInfo]::InvariantCulture so
                      SVG always sees a period decimal.
                    - Fixed shared CSS mojibake in summary::before and
                      ul.link-list li::before content rules. The original literal
                      Unicode glyphs got UTF-8 -> Latin-1 corrupted in the source
                      and rendered as 'a-' and similar gibberish. Replaced with
                      ASCII-safe CSS unicode escapes (\25B8 and \1F4C4).
                    - Fixed shared summary::before chevron leaking into AD_Health
                      Test Details cards. The td-item summary now overrides the
                      shared rule and uses a real <span class='td-chev'> element
                      with flex layout instead of display:grid (which broke title
                      display when the browser injected its disclosure marker as
                      a grid item, leaving only icons + chevron visible).
            [ ] Version 8.7 - 01/05/2026
                Fixed Get-ADAuditFunctionalLevelRank table: it only knew about 2016+ DFLs,
                    so any check using Test-ADAuditFunctionalLevelAtLeast against a minimum
                    of Windows2012R2Domain (or 2008R2, 2012, 2003 etc) returned $false even
                    on 2016/2019/2022 estates. The Protected Users / Authentication Policies
                    checks added in v8.6 silently failed because of this. Rank table now
                    covers Windows 2000 through 2025 (Domain + Forest variants).
                Get-ADAuditFunctionalLevelMode similarly extended.
                Test-DCPortConnectivity now DNS-resolves each DC name first; if a DC name
                    does not resolve we emit ONE "DC unreachable (DNS resolution failed)"
                    finding instead of fourteen "CLOSED (No such host is known)" rows. The
                    cross-DC WinRM matrix also skips unresolvable targets so the noise
                    does not propagate. Real findings still surface as before.
                Dark mode coverage across every HTML report:
                    - Risk-Report.html was hard-coded dark only with no light mode and no
                      toggle; rewritten to support light + dark with prefers-color-scheme
                      OS auto-detect, a header toggle button, and localStorage persistence.
                    - ADAudit-Results.html had a manual toggle but defaulted to light no
                      matter what the OS preference was; now follows OS prefers-color-scheme
                      on first load and reacts to OS theme changes if the user has not
                      explicitly toggled.
                    - Companion-report wrapper (used to wrap GPO/DNS/Delegated reports
                      with a back-link header) was light-only; now matches the rest of
                      the suite with full light/dark + OS auto-detect + toggle.
                    - DNS audit, DNS recommendations, Delegated Permissions, high-risk
                      baseline, overlapping group memberships and multiple-nested-paths
                      reports were already prefers-color-scheme aware; verified end-to-end.
            [ ] Version 8.6 - 01/05/2026
                Added Test-DCPortConnectivity (-portconnectivity / -dcports / -dc-ports / -portcheck).
                    Probes every DC from this host on the canonical AD port set
                    (DNS 53, Kerberos 88, RPC EPM 135, LDAP 389, SMB 445, kpasswd 464,
                    LDAPS 636, GC 3268, GC-TLS 3269, ADWS 9389, WinRM 5985/5986,
                    NetBIOS 139, sample of dynamic RPC 49152). Each DC also runs a
                    cross-DC TCP probe via WinRM if WinRM is reachable; if WinRM is
                    not reachable the cross-DC matrix is SKIPPED with a clear "why"
                    note in the output and the rest of the check still runs.
                    Output: dc_port_connectivity.txt (severity-grouped findings with
                    WHY / FIX / source-target details + LDAP/LDAPS posture summary)
                    and dc_port_connectivity.csv (per-row machine readable). Closed
                    ports surface as one finding per port name in the HTML report;
                    LDAPS-not-reachable also gets its own dedicated High-severity
                    finding ("LDAP traffic forced to plaintext").
                Fixed Get-ProtectedUsers and Get-AuthenticationPoliciesAndSilos: both
                    were gated on Windows2019Domain functional level, but Microsoft's
                    actual requirement is Windows2012R2Domain. The previous gate
                    silently skipped the check on every 2012R2/2016 estate. Now
                    correctly evaluates from 2012R2+.
                Both functions now write a structured evidence file with WHY this
                    matters / HOW to fix / consequences if NOT fixed / consequences
                    AFTER fixing - even when the check is skipped (DFL too low) or
                    when the group/policy is empty. The user previously got a one-
                    line "skipping" message with no remediation context.
                Help text and -all / -select / -exclude all updated to know about the
                    new portconnectivity switch.
            [ ] Version 8.5 - 01/05/2026
                Resilient per-check error handling: each audit step is now wrapped in
                    Invoke-AuditCheck / Invoke-AuditStep. A failure in one step (DNS
                    server unreachable, RPC blocked, missing module, AD lookup error)
                    is logged and the script continues with all remaining checks
                    instead of aborting. The customer-reported case where a single
                    DNS connectivity error stopped the entire audit no longer happens.
                Connection-failure summary: every captured failure is written to
                    connection_failures.txt + connection_failures.csv with timestamp,
                    check name, switch, error type and message, classification of
                    whether the failure looks like a connectivity / RPC / auth issue,
                    the suspected target server parsed from the error message, and -
                    if reachable - which FSMO roles that server holds (so the operator
                    knows which DC needs attention). Also surfaced as a Nessus finding
                    (KB1300).
                DNS audit report rewrite: replaced the flat "Top Findings" mini-table
                    with a "Findings by Issue" section. Each distinct issue is now
                    one collapsible row with a severity badge, a clear "why this
                    matters" explanation, the recommended fix, and the list of
                    affected zones. The huge per-zone table was demoted to a
                    collapsed "Zone Details (raw)" reference at the bottom.
                Delegated Permissions report rewrite: Risk Assessment is now grouped
                    by severity (CRITICAL > HIGH > MEDIUM > LOW), and each finding
                    has a Why / Fix / Sample-trustees block. Removed the 73+ per-OU
                    .txt files that duplicated the matching .csv content, and
                    replaced them with a single ADAudit_PerScopeSummary.txt for
                    human reading. The HTML index now leads with severity-bucketed
                    findings; the raw scope list is collapsed.
                DNS check no longer throws: missing DnsServer module, undetectable
                    DNS server, and unreachable target are now Write-Warning + throw
                    inside the resilient wrapper, which catches them. Earlier the
                    throws aborted every later check.
            [ ] Version 8.4 - 01/05/2026
                Fixed rc4_only_accounts.txt being created with only the explanation header
                    when zero RC4-only accounts were found. The function now buffers all
                    evidence text and only writes the file if at least one at-risk account
                    is detected (matching the rc4_authentication_events.txt pattern).
                Fixed Get-OverlappingGroupMemberships dispatch ignoring -exclude and -select.
                    Previously "$all -or $accounts -or $overlappinggroups" forced the check
                    to run even with -exclude overlappinggroups, and -select overlappinggroups
                    standalone did not trigger it. Now follows the same pattern as every
                    other check.
                Added five missing password-quality categories to the HTML risk report:
                    duplicate passwords (with same-NTLM-hash + pass-the-hash risk explanation),
                    historical dictionary passwords, Kerberos pre-auth disabled, password
                    never expires, and Kerberoastable accounts. Files were already split
                    and reported via .nessus, but never surfaced in the HTML report body.
                Added "WHY THIS MATTERS" explanatory block to pq_duplicate_passwords.txt
                    clarifying that accounts grouped together share the IDENTICAL NTLM hash
                    (and therefore the same plaintext password), with pass-the-hash and
                    lateral-movement risk context.
            [ ] Version 8.3 - 08/04/2026
                Added Get-RC4OnlyAccounts function (KB1205) to detect AD accounts whose
                    msDS-SupportedEncryptionTypes lacks AES128/AES256 support and are therefore
                    affected by Microsoft's CVE-2026-20833 Kerberos RC4 hardening update.
                    Generates rc4_only_accounts.txt (with remediation guidance and CVE links),
                    rc4_only_accounts.csv, and best-effort rc4_authentication_events.txt that
                    parses DC Security log events 4768/4769 for RC4 ticket exchanges in the
                    last 7 days. Hooked into the accounts audit and the management report.
            [ ] Version 8.2 - 05/04/2026
                Fixed KRBTGT password age scoring: no longer adds risk points when age is within 180-day baseline
                Fixed password quality account counts: header/footer lines in pq_*.txt files were inflating counts
                    (added Get-PqAccountLines helper to extract only DOMAIN\account entries)
                Improved no-password check: cross-references with Users.csv to differentiate enabled vs disabled accounts
                    Enabled accounts with no password remain Critical; all-disabled accounts downgraded to Low severity
                Improved KRBTGT age parsing to handle Observed column format when AgeDays column is absent
            [ ] Version 8.1 - 02/04/2026
                Added Get-KerberosUnconstrainedDelegation function to detect non-DC accounts with unconstrained delegation
                Added Get-GMSAStatus function to identify service accounts not using Group Managed Service Accounts
                Added Get-TombstoneLifetime function to check AD tombstone lifetime configuration
                Added Get-PrintSpoolerOnDCs function to detect Print Spooler running on domain controllers
                Added Get-SMBSigningStatus function to check SMB signing enforcement on domain controllers
                Added audit metadata to Management Report (script version, running account, start/end time)
                Added Findings by Category breakdown table to Management Report
                Evidence files now written directly to Raw Data\Source instead of root output directory
                Removed duplicate nessus file output (sanitization now in-place)
                Added finding definitions, context, and recommendations for all new checks
                Added new report categories: Delegation and service accounts, DC hardening
                Multiple bug fixes: broken string interpolation, wrong NTLM variable, duplicate encryption type,
                    typo in web_enrollment variable, erroneous @ prefix in DN strings, duplicate code and comments
                Added Split-PasswordQualityReport function to split password_quality.txt into category files:
                    pq_reversible_encryption.txt, pq_lm_hashes.txt, pq_no_password.txt,
                    pq_dictionary_passwords.txt, pq_historical_dictionary.txt, pq_duplicate_passwords.txt,
                    pq_default_computer_passwords.txt, pq_missing_aes_keys.txt, pq_no_preauth.txt,
                    pq_des_only.txt, pq_admin_delegation.txt, pq_password_never_expires.txt,
                    pq_password_not_required.txt, pq_kerberoastable.txt
                Each split password quality category now generates its own finding in both reports with
                    appropriate severity scoring (LM hashes, no password, dictionary, DES-only = Critical;
                    default computer passwords, admin delegation, password not required = High;
                    missing AES keys = Medium)
                Added finding definitions (category, why-it-matters, recommendation) for all new findings
                Original password_quality.txt is retained alongside the split files
            [ ] Version 8.0 - 22/03/2026
                Converted AdAudit.ps1 to PowerShell 7
                Windows LAPS + legacy Microsoft LAPS support
                CIM/DCOM remote compatibility and Windows Server 2025 functional-level awareness
            [ ] Version 7.2 - 03/03/2026
                All reports have been remade
            [ ] Version 7.1.6 - 21/01/2026
                Added function for checking overlapping group memberships.
            [ ] Version 7.1.5 - 21/01/2026
                Management report added to the script
                Minor fixes to multiple functions
            [ ] Version 7.1.4 - 28/12/2025
                Removed ntds export function.
                Fixed bug with Win32 FileTime
            [ ] Version 7.1.3 - 28/12/2025
                Added check for tier overlapping accounts in privileged groups.
            [ ] Version 7.1.2 - 26/12/2025
                Added inactive computers report.
            [ ] Version 7.1.1 - 25/12/2025
                Added Windows Update audit for high risk missing updates.
            [ ] Version 7.1.0 - 24/12/2025
                Added Get-DNSZoneInsecure function to check for DNS zones allowing insecure updates.
                Added DNS zone report.
                Added deligated permissions report.
                Improved reporting
            [] Version 7.0.1 - 20/11/2025
                Added explination for "These accounts are susceptible to the Kerberoasting attack"
            [ ] Version 7.0 - 20/11/2025
                Added offline installation of DSInternals and NuGet.
                Added comments for Password audit files and kerberos and ciphers checks.
                Added Audit reports for delegated permissions as separate script.
                Now posible to run Audit from an other server with RSAT tools installed. (Need to run powershell using domain admin account)
            [ ] Version 6.0 - 22/12/2023
                * Fix "BUILTIN\$Administrators" quoting, in order to use $Administrators variable when script enumerates Default Domain Controllers Policy
                * Fix RDP logon policy check in the same function above
            [ ] Version 5.9 - 20/12/2023
                * Contempled all cases of DCs with weak Kerberos algorithm and saves finding according to them
                * Fix "Cannot get time source for DC" as a warning
            [ ] Version 5.8 - 27/03/2023
                * Updated switches, users can now select functions, or run -all with exclusions
                * Added LDAP security checks 
            [ ] Version 5.7 - 11/03/2023
                * Added ACL Checks
            [ ] Version 5.6 - 09/03/2023
                * Added kerberoasting checks
                * Added ASREProasting Checks
            [ ] Version 5.5 - 08/03/2023
                * ADCS vulnerabilities added, checks for ESC1,2,3,4 and 8.
            [ ] Version 5.4 - 16/08/2022
                * Added nessus output tags for LAPS
                * Added nessus output for GPO issues
            [ ] Version 5.3 - 07/03/2022
                * Added SamAccountName to Get-PrivilegedGroupMembership output
                * Swapped some write-host to write-both so it's captured in the consolelog.txt
            [ ] Version 5.2 - 28/01/2022
                * Enhanced Get-LAPSStatus
                * Added news checks (AD services + Windows Update + NTP source + Computer/User container + RODC + Locked accounts + Password Quality + SYSVOL & NETLOGON share presence)
                * Added support for WS 2022
                * Fix OS version difference check for WS 2008
                * Fix Write-Progress not disappearing when done
            [ ] Version 5.1
                * Added check for newly created users and groups
                * Added check for replication mechanism
                * Added check for Recycle Bin
                * Fix ProtectedUsers for WS 2008
            [ ] Version 5.0
                * Make the script compatible with other language than English
                * Fix the cpassword search in GPO
                * Fix Get-ACL bad syntax error
                * Fix Get-DNSZoneInsecure for WS 2008
            [ ] Version 4.9
                * Bug fix in checking password comlexity
            [ ] Version 4.8
                * Added checks for vista, win7 and 2008 old operating systems
                * Added insecure DNS zone checks
            [ ] Version 4.7
                * Added powershel-v2 suport and fixed array issue
            [ ] Version 4.6
                * Fixed potential division by zero
            [ ] Version 4.5
                * PR to resolve count issue when count = 1
            [ ] Version 4.4
                * Reinstated nessus fix and put output in a list for findings
                * Changed Get-AdminSDHolders with Get-PrivilegedGroupAccounts
            [ ] Version 4.3
                * Temp fix with nessus output
            [ ] Version 4.2
                * Bug fix on cpassword count
            [ ] Version 4.1
                * Loads of fixes
                * Works with Powershellv2 again now
                * Filtered out disabled accounts
                * Improved domain trusts checking
                * OUperms improvements and filtering
                * Check for w2k
                * Fixed typos/spelling and various other fixes
            [ ] Version 4.0
                * Added XML output for import to CheckSecCanopy
            [ ] Version 3.5
                * Added KB more references for internal use
            [ ] Version 3.4
                * Added KB references for internal use
            [ ] Version 3.3
                * Added a greater level of accuracy to Inactive Accounts (thanks exceedio)
            [ ] Version 3.2
                * Added search for DCs not owned by Domain Admins group
            [ ] Version 3.1
                * Added progress to functions that have count
                * Added check for transitive trusts
            [ ] Version 3.0
                * Added ability to choose functions before runtime
                * Cleaned up get-ouperms output
            [ ] Version 2.5
                * Bug fixes to version check for 2012R2 or greater specific checks
            [ ] Version 2.4
                * Forked project
                * Added Get-OUPerms, Get-LAPSStatus, Get-AdminSDHolders, Get-ProtectedUsers and Get-AuthenticationPoliciesAndSilos functions
                * Also added FineGrainedPasswordPolicies to Get-PasswordPolicy and changed order slightly
            [ ] Version 2.3
                * Added more useful user output to .txt files (Cheers DK)
            [ ] Version 2.2
                * Minor typo fix
            [ ] Version 2.1
                * Added check for null sessions
            [ ] Version 2.0
                * Multiple Additions and knocked off lots of the todo list
            [ ] Version 1.9
                * Fixed bug, that used Administrator account name instead of UID 500 and a bug with inactive accounts timespan
            [ ] Version 1.8
                * Added check for last time 'Administrator' account logged on
            [ ] Version 1.6
                * Added Get-FunctionalLevel and krbtgt password last changed check
            [ ] Version 1.5
                * Added Get-HostDetails to output simple info like username, hostname, etc...
            [ ] Version 1.4
                * Added Get-WinVersion version to assist with some checks (SMBv1 currently)
            [ ] Version 1.3
                * Added XML output for GPO (for offline processing using grouper https://github.com/l0ss/Grouper/blob/master/grouper.psm1)
            [ ] Version 1.2
                * Added check for modules
            [ ] Version 1.1
                * Fixed bug where SYSVOL research returns empty
            [ ] Version 1.0
                * First release
    .EXAMPLE
        PS> ADAudit.ps1 -installdeps -all
        Install external features and launch all checks
    .EXAMPLE
        PS> ADAudit.ps1 -all
        Launch all checks (but do not install external modules)
    .EXAMPLE
        PS> ADAudit.ps1 -installdeps
        Installs optionnal features (DSInternals)
    .EXAMPLE
        PS> ADAudit.ps1 -hostdetails -domainaudit
        Retrieves hostname and other useful audit info
        Retrieves information about the AD such as functional level
#>
[CmdletBinding()]
Param (
    [switch]$installdeps = $false,
    [switch]$hostdetails = $false,
    [switch]$domainaudit = $false,
    [switch]$trusts = $false,
    [switch]$accounts = $false,
    [switch]$InactiveComputers = $false,
    [switch]$passwordpolicy = $false,
    [switch]$oldboxes = $false,
    [switch]$gpo = $false,
    [switch]$ouperms = $false,
    [switch]$laps = $false,
    [switch]$authpolsilos = $false,
    [switch]$insecurednszone = $false,
    [Alias('dns-zone')][switch]$dnszone = $false,
    [string]$DnsZoneOutputRoot,
    [switch]$DnsIncludeRecordCounts = $false,
    [switch]$DnsIncludeSystemZones = $false,
    [switch]$recentchanges = $false,
    [switch]$adcs = $false,
    [switch]$spn = $false,
    [switch]$asrep = $false,
    [switch]$acl = $false,
    [switch]$ldapsecurity = $false,
    [switch]$dataextract = $false,
    [Alias('delegated-permissions','delegated')][switch]$delegatedpermissions = $false,
    [string]$DelegatedOutputRoot,
    [switch]$DelegIncludeSystemTrustees = $false,
    [switch]$DelegIncludeDeny = $false,
    [switch]$DelegIncludeInherited = $false,
    [string]$DelegServer,
    [switch]$highrisk = $false,
    [switch]$overlappinggroups = $false,
    [Alias('dcports','dc-ports','portcheck')][switch]$portconnectivity = $false,
    [Alias('ad-health','adhealthcheck','health')][switch]$adhealth = $false,
    [switch]$all = $false,
    [string[]]$exclude = @(),
    [string]$select,
    [switch]$KeepLegacyArtifacts = $false
)

$selectedChecks = @()
if ($select) { $selectedChecks = $select.Split(',') }

$versionnum = "v8.8"
$AdministratorTranslation = @("Administrator", "Administrateur", "Administrador")#If missing put the default Administrator name for your own language here

$script:ADAuditIsWindows = ($env:OS -eq 'Windows_NT')
$script:ADAuditIsPowerShell7Plus = ($PSVersionTable.PSVersion.Major -ge 7)

function Import-ADAuditModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$Required,

        [switch]$PreferWindowsPowerShell
    )

    $loaded = Get-Module -Name $Name | Select-Object -First 1
    if ($loaded) { return $loaded }

    $available = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending
    if (-not $available) {
        if ($Required) { throw "Module '$Name' is not available on this host." }
        return $null
    }

    $attempts = New-Object System.Collections.Generic.List[hashtable]
    if ($script:ADAuditIsPowerShell7Plus -and $PreferWindowsPowerShell) {
        $attempts.Add(@{ UseWindowsPowerShell = $true })
    }

    $attempts.Add(@{})

    if ($script:ADAuditIsPowerShell7Plus) {
        $attempts.Add(@{ SkipEditionCheck = $true })
    }

    if ($script:ADAuditIsPowerShell7Plus -and -not $PreferWindowsPowerShell) {
        $attempts.Add(@{ UseWindowsPowerShell = $true })
    }

    $lastError = $null
    foreach ($attempt in $attempts) {
        try {
            Import-Module -Name $Name @attempt -ErrorAction Stop | Out-Null
            return (Get-Module -Name $Name | Sort-Object Version -Descending | Select-Object -First 1)
        }
        catch {
            $lastError = $_
        }
    }

    if ($Required) {
        if ($lastError) {
            throw "Failed to import module '$Name'. $($lastError.Exception.Message)"
        }
        throw "Failed to import module '$Name'."
    }

    return $null
}

function Get-ADAuditCimInstance {
    [CmdletBinding(DefaultParameterSetName = 'ByClass')]
    param(
        [Parameter(ParameterSetName = 'ByClass', Mandatory = $true)]
        [string]$ClassName,

        [Parameter(ParameterSetName = 'ByQuery', Mandatory = $true)]
        [string]$Query,

        [string]$Namespace = 'root/cimv2',

        [string]$Filter,

        [string[]]$Property,

        [string]$ComputerName = $env:COMPUTERNAME,

        [switch]$UseWsmanFallback
    )

    if (-not $script:ADAuditIsWindows) {
        throw "Get-ADAuditCimInstance requires Windows."
    }

    $remoteTarget = $ComputerName -and $ComputerName -notin @('.', 'localhost', $env:COMPUTERNAME)
    $baseParams = @{ Namespace = $Namespace; ErrorAction = 'Stop' }

    if ($PSCmdlet.ParameterSetName -eq 'ByClass') {
        $baseParams.ClassName = $ClassName
        if ($Filter)   { $baseParams.Filter = $Filter }
        if ($Property) { $baseParams.Property = $Property }
    }
    else {
        $baseParams.Query = $Query
    }

    if (-not $remoteTarget) {
        return Get-CimInstance @baseParams
    }

    $session = $null
    try {
        $sessionOption = New-CimSessionOption -Protocol Dcom
        $session = New-CimSession -ComputerName $ComputerName -SessionOption $sessionOption -ErrorAction Stop
        $baseParams.CimSession = $session
        return Get-CimInstance @baseParams
    }
    catch {
        if ($UseWsmanFallback) {
            try {
                $fallbackParams = @{}
                foreach ($entry in $baseParams.GetEnumerator()) {
                    if ($entry.Key -ne 'CimSession') {
                        $fallbackParams[$entry.Key] = $entry.Value
                    }
                }
                $fallbackParams.ComputerName = $ComputerName
                return Get-CimInstance @fallbackParams
            }
            catch {
                throw
            }
        }

        throw
    }
    finally {
        if ($session) {
            $session | Remove-CimSession -ErrorAction SilentlyContinue
        }
    }
}

function Convert-ADAuditFileTime {
    param(
        [Parameter(ValueFromPipeline = $true)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return $null }

    $raw = [string]$Value
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

    try {
        return [datetime]::FromFileTimeUtc([int64]$raw).ToLocalTime()
    }
    catch {
        return $null
    }
}

function Get-ADAuditFunctionalLevelRank {
    param([string]$Mode)

    # Ranks cover every Domain/Forest mode the ActiveDirectory module emits,
    # going back to NT4 (rank 0) and forward to Server 2025 (rank 10). Earlier
    # versions of this table only covered 2016+, which made
    # Test-ADAuditFunctionalLevelAtLeast return $false whenever the minimum
    # mode was Windows2003/2008/2008R2/2012/2012R2 because $minimumRank ended
    # up $null - which broke the Protected Users / Authentication Policies
    # checks on every estate at or above DFL 2008R2.
    switch ($Mode) {
        'Windows2000Domain'        { return 0 }
        'Windows2000Forest'        { return 0 }
        'Windows2003InterimDomain' { return 1 }
        'Windows2003InterimForest' { return 1 }
        'Windows2003Domain'        { return 2 }
        'Windows2003Forest'        { return 2 }
        'Windows2008Domain'        { return 3 }
        'Windows2008Forest'        { return 3 }
        'Windows2008R2Domain'      { return 4 }
        'Windows2008R2Forest'      { return 4 }
        'Windows2012Domain'        { return 5 }
        'Windows2012Forest'        { return 5 }
        'Windows2012R2Domain'      { return 6 }
        'Windows2012R2Forest'      { return 6 }
        'Windows2016Domain'        { return 7 }
        'Windows2016Forest'        { return 7 }
        'WinThreshold'             { return 7 }
        'Windows2019Domain'        { return 8 }
        'Windows2019Forest'        { return 8 }
        'Windows2022Domain'        { return 9 }
        'Windows2022Forest'        { return 9 }
        'Windows2025Domain'        { return 10 }
        'Windows2025Forest'        { return 10 }
        default                    { return $null }
    }
}

function Get-ADAuditFunctionalLevelMode {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Rank,

        [ValidateSet('Domain','Forest')]
        [string]$Scope = 'Domain'
    )

    switch ($Rank) {
        0  { return "Windows2000$Scope" }
        2  { return "Windows2003$Scope" }
        3  { return "Windows2008$Scope" }
        4  { return "Windows2008R2$Scope" }
        5  { return "Windows2012$Scope" }
        6  { return "Windows2012R2$Scope" }
        7  { return "Windows2016$Scope" }
        8  { return "Windows2019$Scope" }
        9  { return "Windows2022$Scope" }
        10 { return "Windows2025$Scope" }
        default { return $null }
    }
}

function Test-ADAuditFunctionalLevelAtLeast {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mode,

        [Parameter(Mandatory = $true)]
        [string]$MinimumMode
    )

    $modeRank = Get-ADAuditFunctionalLevelRank -Mode $Mode
    $minimumRank = Get-ADAuditFunctionalLevelRank -Mode $MinimumMode

    if ($null -eq $modeRank -or $null -eq $minimumRank) {
        return $false
    }

    return ($modeRank -ge $minimumRank)
}

function Get-ADAuditDcFunctionalLevelCapRank {
    param(
        [Parameter(Mandatory = $true)]
        $DomainController
    )

    $operatingSystem = [string]$DomainController.OperatingSystem
    $version = [string]$DomainController.OperatingSystemVersion

    if ($operatingSystem -match '2025') { return 10 }
    if ($operatingSystem -match '2022') { return 9 }
    if ($operatingSystem -match '2019') { return 8 }
    if ($operatingSystem -match '2016') { return 7 }

    try {
        $parsedVersion = [version]$version
        if ($parsedVersion.Major -eq 10 -and $parsedVersion.Build -ge 26000) { return 10 }
        if ($parsedVersion.Major -eq 10 -and $parsedVersion.Build -ge 20348) { return 9 }
        if ($parsedVersion.Major -eq 10 -and $parsedVersion.Build -ge 17763) { return 8 }
        if ($parsedVersion.Major -eq 10) { return 7 }
    }
    catch { }

    return $null
}


Function Get-Variables() {
    #Retrieve group names and OS version
    $script:OSVersion = (Get-Itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
    $script:Administrators = (Get-ADGroup -Identity S-1-5-32-544).SamAccountName
    $script:Users = (Get-ADGroup -Identity S-1-5-32-545).SamAccountName
    $script:DomainAdminsSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-512"
    $script:DomainUsersSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-513"
    $script:DomainControllersSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-516"
    $script:SchemaAdminsSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-518"
    $script:EnterpriseAdminsSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-519"
    $script:EveryOneSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
    $script:EntrepriseDomainControllersSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-9"
    $script:AuthenticatedUsersSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-11"
    $script:SystemSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-18"
    $script:LocalServiceSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-19"
    $script:DomainAdmins = (Get-ADGroup -Identity $DomainAdminsSID).SamAccountName
    $script:DomainUsers = (Get-ADGroup -Identity $DomainUsersSID).SamAccountName
    $script:DomainControllers = (Get-ADGroup -Identity $DomainControllersSID).SamAccountName
    $script:SchemaAdmins = (Get-ADGroup -Identity $SchemaAdminsSID).SamAccountName
    $script:EnterpriseAdmins = (Get-ADGroup -Identity $EnterpriseAdminsSID).SamAccountName
    $script:EveryOne = $EveryOneSID.Translate([System.Security.Principal.NTAccount]).Value
    $script:EntrepriseDomainControllers = $EntrepriseDomainControllersSID.Translate([System.Security.Principal.NTAccount]).Value
    $script:AuthenticatedUsers = $AuthenticatedUsersSID.Translate([System.Security.Principal.NTAccount]).Value
    $script:System = $SystemSID.Translate([System.Security.Principal.NTAccount]).Value
    $script:LocalService = $LocalServiceSID.Translate([System.Security.Principal.NTAccount]).Value
    Write-Both "    [+] Administrators               : $Administrators"
    Write-Both "    [+] Users                        : $Users"
    Write-Both "    [+] Domain Admins                : $DomainAdmins"
    Write-Both "    [+] Domain Users                 : $DomainUsers"
    Write-Both "    [+] Domain Controllers           : $DomainControllers"
    Write-Both "    [+] Schema Admins                : $SchemaAdmins"
    Write-Both "    [+] Enterprise Admins            : $EnterpriseAdmins"
    Write-Both "    [+] Every One                    : $EveryOne"
    Write-Both "    [+] Entreprise Domain Controllers: $EntrepriseDomainControllers"
    Write-Both "    [+] Authenticated Users          : $AuthenticatedUsers"
    Write-Both "    [+] System                       : $System"
    Write-Both "    [+] Local Service                : $LocalService"
}
Function Write-Both() {
    #Writes to console only. Findings are rendered into the HTML audit and management reports.
    Write-Host "$args"
}
Function Get-HtmlReportsDir {
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    if ([string]::IsNullOrWhiteSpace($BaseRoot)) {
        $BaseRoot = Join-Path (Get-Location) $env:COMPUTERNAME
    }

    $path = if ($script:HtmlReportsDir) { $script:HtmlReportsDir } else { Join-Path $BaseRoot 'HTML Reports' }
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    return $path
}
Function Get-RawDataDir {
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    if ([string]::IsNullOrWhiteSpace($BaseRoot)) {
        $BaseRoot = Join-Path (Get-Location) $env:COMPUTERNAME
    }

    $path = if ($script:EvidenceFilesDir) { $script:EvidenceFilesDir } else { Join-Path $BaseRoot 'Raw Data' }
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    return $path
}
Function Get-RawSourceDataDir {
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    $path = if ($script:LegacyArtifactsDir) { $script:LegacyArtifactsDir } else { Join-Path (Get-RawDataDir -BaseRoot $BaseRoot) 'Source' }
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    return $path
}
Function Get-PreparedDataDir {
    # Merged into Source - all output now goes to the same folder to eliminate duplication
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    return (Get-RawSourceDataDir -BaseRoot $BaseRoot)
}
Function Get-HtmlDownloadsDir {
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    return (Get-PreparedDataDir -BaseRoot $BaseRoot)
}
Function Get-ADAuditReportCss {
    <#
    .SYNOPSIS
        Returns the shared CSS style block used by all companion HTML reports.
        Matches the design language of ADAudit-Results.html (light default + dark mode).
    #>
    return @'
<style>
:root {
  --bg:#f5f7fb; --panel:#ffffff; --text:#1b2430; --muted:#5f6b7a;
  --line:#d9e0ea; --shadow:0 10px 24px rgba(15,23,42,.08); --radius:14px;
  --accent:#3b82f6; --accent-soft:#dbeafe;
  --critical:#c62828; --critical-soft:#fdecec;
  --high:#ef6c00;    --high-soft:#fff2e5;
  --medium:#0277bd;  --medium-soft:#e8f4fd;
  --low:#2e7d32;     --low-soft:#edf8ee;
  --info:#6c757d;    --info-soft:#f2f4f6;
}
@media(prefers-color-scheme:dark){
  :root {
    --bg:#0f172a; --panel:#1e293b; --text:#e2e8f0; --muted:#94a3b8;
    --line:#334155; --shadow:0 10px 24px rgba(0,0,0,.4);
    --accent:#60a5fa; --accent-soft:rgba(96,165,250,.15);
    --critical:#f87171; --critical-soft:rgba(248,113,113,.15);
    --high:#fb923c;    --high-soft:rgba(251,146,60,.15);
    --medium:#60a5fa;  --medium-soft:rgba(96,165,250,.15);
    --low:#4ade80;     --low-soft:rgba(74,222,128,.15);
    --info:#94a3b8;    --info-soft:rgba(148,163,184,.15);
  }
}
*,*::before,*::after{box-sizing:border-box}
body{margin:0;padding:32px 24px;font-family:'Segoe UI',system-ui,-apple-system,Arial,sans-serif;
  background:var(--bg);color:var(--text);line-height:1.6;-webkit-font-smoothing:antialiased}
.container{max-width:1280px;margin:0 auto}
.hero{background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);
  padding:32px 36px;margin-bottom:28px}
.hero h1{margin:0 0 4px;font-size:1.65rem;font-weight:700}
.hero .meta{color:var(--muted);font-size:.88rem}
.mono{font-family:Consolas,Menlo,Monaco,monospace;font-size:.92em}
h2{font-size:1.25rem;font-weight:600;margin:28px 0 14px;padding-bottom:8px;border-bottom:2px solid var(--line)}
h3{font-size:1.05rem;font-weight:600;margin:20px 0 10px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
code{font-family:Consolas,Menlo,Monaco,monospace;font-size:.9em;background:var(--accent-soft);
  padding:2px 7px;border-radius:5px}
pre{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  padding:16px 20px;overflow-x:auto;font-size:.88rem;font-family:Consolas,Menlo,Monaco,monospace}

/* Tables */
table{width:100%;border-collapse:separate;border-spacing:0;margin:12px 0 20px;
  background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}
thead th{background:var(--accent-soft);color:var(--text);font-weight:600;font-size:.85rem;
  text-transform:uppercase;letter-spacing:.04em;padding:12px 14px;text-align:left;
  position:sticky;top:0;z-index:1;border-bottom:2px solid var(--line)}
tbody td{padding:10px 14px;border-bottom:1px solid var(--line);font-size:.92rem;vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--accent-soft)}

/* Severity badges */
.badge{display:inline-block;padding:3px 12px;border-radius:999px;font-size:.82rem;font-weight:600;letter-spacing:.02em}
.badge-critical{background:var(--critical-soft);color:var(--critical)}
.badge-high{background:var(--high-soft);color:var(--high)}
.badge-medium{background:var(--medium-soft);color:var(--medium)}
.badge-low{background:var(--low-soft);color:var(--low)}
.badge-info{background:var(--info-soft);color:var(--info)}

/* Stat cards */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin:16px 0 24px}
.stat{background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);
  padding:18px 20px;text-align:center}
.stat .val{font-size:1.8rem;font-weight:700;line-height:1.1}
.stat .lbl{font-size:.82rem;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.04em}

/* Details/Accordion */
details{background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);
  margin:10px 0;border-left:5px solid var(--accent)}
details[open]{border-left-color:var(--accent)}
summary{cursor:pointer;padding:14px 20px;font-weight:600;font-size:.95rem;list-style:none;
  display:flex;align-items:center;gap:10px}
summary::-webkit-details-marker{display:none}
summary::before{content:'\25B8';font-size:1rem;transition:transform .15s ease;display:inline-block}
details[open]>summary::before{transform:rotate(90deg)}
details>div,details>.detail-body{padding:0 20px 16px}
details table{box-shadow:none;margin:0}

/* List styling */
ul.link-list{list-style:none;padding:0}
ul.link-list li{padding:8px 14px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:8px}
ul.link-list li:last-child{border-bottom:none}
ul.link-list li::before{content:'\1F4C4';font-size:1rem}

/* Footer */
.footer{margin-top:36px;padding-top:16px;border-top:1px solid var(--line);
  color:var(--muted);font-size:.82rem;text-align:center}

/* Responsive */
@media(max-width:768px){
  body{padding:16px 12px}
  .hero{padding:20px}
  .stats{grid-template-columns:repeat(auto-fit,minmax(120px,1fr))}
  table{display:block;overflow-x:auto}
}
</style>
'@
}
Function Get-ADAuditReportHeader {
    <#
    .SYNOPSIS
        Returns the HTML header/doctype block for companion reports.
    #>
    param([string]$Title = 'AD Audit Report')
    $css = Get-ADAuditReportCss
    return @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>$Title</title>
$css
</head>
<body>
<div class="container">
"@
}
Function Get-ADAuditReportFooter {
    <#
    .SYNOPSIS
        Returns the HTML footer block for companion reports.
    #>
    return @"
<div class="footer">Generated by AD Audit &mdash; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
</div>
</body>
</html>
"@
}
Function Get-ADAuditPrimaryNav {
    <#
    .SYNOPSIS
        Returns the shared CSS + <nav> block linking the four primary HTML reports.
        The Operations tab is intentionally not included - it is not part of the audit.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('audit','risk','health','overlap','none')]
        [string]$Active = 'none'
    )
    $links = @(
        [pscustomobject]@{ Key='audit';   Href='ADAudit-Results.html';            Label='Audit Results' }
        [pscustomobject]@{ Key='risk';    Href='Risk-Report.html';                Label='Risk Report' }
        [pscustomobject]@{ Key='health';  Href='AD_Health.html';                  Label='AD Health' }
        [pscustomobject]@{ Key='overlap'; Href='overlapping_group_memberships.html'; Label='Overlapping Groups' }
    )
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine(@'
<style>
.primary-nav{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 20px;padding:10px 14px;background:var(--panel,#fff);border:1px solid var(--line,#d9e0ea);border-radius:12px;box-shadow:var(--shadow,0 10px 24px rgba(15,23,42,.08))}
.primary-nav-link{padding:6px 12px;border-radius:999px;font-size:.85rem;font-weight:600;text-decoration:none;color:var(--text,#1b2430);border:1px solid transparent}
.primary-nav-link:hover{background:var(--accent-soft,#dbeafe);text-decoration:none}
.primary-nav-link.active{background:var(--accent,#3b82f6);color:#fff;border-color:var(--accent,#3b82f6)}
</style>
'@)
    [void]$sb.Append("<nav class='primary-nav'>")
    foreach ($link in $links) {
        $cls = if ($link.Key -eq $Active) { 'primary-nav-link active' } else { 'primary-nav-link' }
        [void]$sb.Append("<a class='$cls' href='$($link.Href)'>$($link.Label)</a>")
    }
    [void]$sb.AppendLine("</nav>")
    return $sb.ToString()
}
Function Get-EvidencePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )
    $dir = Get-RawSourceDataDir
    return (Join-Path $dir $FileName)
}

# ---------------------------------------------------------------------------
# Audit check resilience: per-check try/catch wrapper + FSMO context lookup
# Lets a single failing check (DNS, Delegated Permissions, etc.) be logged
# without stopping the entire script. A separate connection_failures.txt /
# .csv summarises every failure, the error, the suspected target server, and
# - if reachable - the FSMO roles that server holds, so the operator knows
# exactly which checks were skipped and why.
# ---------------------------------------------------------------------------
$script:CheckFailures = New-Object System.Collections.Generic.List[object]

Function Get-FsmoRolesForServer {
    [CmdletBinding()]
    param([string]$ServerHostnameOrFqdn)

    if ([string]::IsNullOrWhiteSpace($ServerHostnameOrFqdn)) { return @() }
    $needle = $ServerHostnameOrFqdn.Trim().TrimEnd('.').ToLowerInvariant()
    $shortNeedle = ($needle -split '\.')[0]

    $roles = @()
    try {
        $forest = Get-ADForest -ErrorAction Stop
        if ($forest) {
            foreach ($pair in @(
                @{ N='SchemaMaster';        V=$forest.SchemaMaster },
                @{ N='DomainNamingMaster';  V=$forest.DomainNamingMaster }
            )) {
                if ($pair.V) {
                    $v = $pair.V.ToString().ToLowerInvariant().TrimEnd('.')
                    $vShort = ($v -split '\.')[0]
                    if ($v -eq $needle -or $vShort -eq $shortNeedle) { $roles += $pair.N }
                }
            }
        }
    } catch { }
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        if ($domain) {
            foreach ($pair in @(
                @{ N='PDCEmulator';          V=$domain.PDCEmulator },
                @{ N='RIDMaster';            V=$domain.RIDMaster },
                @{ N='InfrastructureMaster'; V=$domain.InfrastructureMaster }
            )) {
                if ($pair.V) {
                    $v = $pair.V.ToString().ToLowerInvariant().TrimEnd('.')
                    $vShort = ($v -split '\.')[0]
                    if ($v -eq $needle -or $vShort -eq $shortNeedle) { $roles += $pair.N }
                }
            }
        }
    } catch { }
    return ,$roles
}

Function Resolve-ServerHintFromError {
    [CmdletBinding()]
    param([string]$ErrorMessage)

    if ([string]::IsNullOrWhiteSpace($ErrorMessage)) { return @() }
    $hints = New-Object System.Collections.Generic.List[string]

    foreach ($pat in @(
        "(?i)server\s+'([^']+)'",
        '(?i)server\s+"([^"]+)"',
        '(?i)on\s+server\s+([A-Za-z0-9_\-\.]+)',
        '(?i)from\s+server\s+([A-Za-z0-9_\-\.]+)',
        '(?i)computer\s+''([^'']+)''',
        '(?i)host\s+([A-Za-z0-9_\-\.]+)',
        '(?i)\\\\([A-Za-z0-9_\-\.]+)\\',
        '(?i)to\s+([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-\.]+)'
    )) {
        foreach ($m in [regex]::Matches($ErrorMessage, $pat)) {
            if ($m.Groups.Count -gt 1) {
                $val = $m.Groups[1].Value.Trim()
                if ($val -and $val -notmatch '^\s*$') { $hints.Add($val) | Out-Null }
            }
        }
    }
    return ,(@($hints | Sort-Object -Unique))
}

Function Test-IsConnectionError {
    [CmdletBinding()]
    param([string]$ErrorMessage, [string]$ErrorType)
    if (-not $ErrorMessage) { return $false }
    if ($ErrorMessage -match '(?i)\b(rpc|the rpc server is unavailable|cannot find|could not contact|server is not operational|cannot connect|connection (refused|timed out|reset|failed)|network path was not found|firewall|unreachable|0x80004005|access (is )?denied|no logon servers|target principal name is incorrect)\b') { return $true }
    if ($ErrorType -match '(?i)CimException|RpcException|RemoteException|DirectoryServerDownException|ActiveDirectoryServerDownException|EndpointNotFound') { return $true }
    return $false
}

Function Register-AuditFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord,
        [Parameter(Mandatory)][string]$Name,
        [string]$Description,
        [string]$Switch,
        [string]$Prefix = '    [!] STEP FAILED'
    )

    $errMsg  = $ErrorRecord.Exception.Message
    $errType = $ErrorRecord.Exception.GetType().FullName
    $isConn  = Test-IsConnectionError -ErrorMessage $errMsg -ErrorType $errType

    $serverHints = Resolve-ServerHintFromError -ErrorMessage $errMsg
    $fsmoEntries = New-Object System.Collections.Generic.List[string]
    foreach ($hint in $serverHints) {
        $rolesForHost = Get-FsmoRolesForServer -ServerHostnameOrFqdn $hint
        if ($rolesForHost.Count -gt 0) {
            $fsmoEntries.Add("$hint = [$($rolesForHost -join ', ')]") | Out-Null
        }
    }

    $script:CheckFailures.Add([pscustomobject]@{
        Time                = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        CheckName           = $Name
        Switch              = $Switch
        Description         = if ($Description) { $Description } else { $Name }
        ErrorType           = $errType
        ErrorMessage        = $errMsg
        IsConnectionIssue   = $isConn
        ServerHints         = ($serverHints -join ', ')
        FsmoOnFailedServers = ($fsmoEntries -join '; ')
        ScriptStackTrace    = ([string]$ErrorRecord.ScriptStackTrace)
    }) | Out-Null

    Write-Both ("{0} ({1}): {2}" -f $Prefix, $Name, $errMsg)
    if ($isConn) {
        Write-Both "    [!] Reason: connection / RPC / firewall / authentication issue with an AD or DNS server."
    }
    if ($serverHints.Count -gt 0) {
        Write-Both ("    [!] Suspected server(s) from error: {0}" -f ($serverHints -join ', '))
    }
    if ($fsmoEntries.Count -gt 0) {
        foreach ($entry in $fsmoEntries) {
            Write-Both "    [!] FSMO holder: $entry"
        }
    } elseif ($isConn -and $serverHints.Count -gt 0) {
        Write-Both "    [!] FSMO lookup: server(s) above do not appear to currently hold FSMO roles (or AD lookup also failed)."
    }
}

Function Invoke-AuditCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Body,
        [string]$Switch
    )

    Write-Both "[*] $Description"
    try {
        & $Body
    } catch {
        Register-AuditFailure -ErrorRecord $_ -Name $Name -Description $Description -Switch $Switch -Prefix '    [!] CHECK FAILED'
        Write-Both "    [*] Continuing with remaining checks..."
    }
}

Function Invoke-AuditStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Body,
        [string]$Switch
    )

    try {
        & $Body
    } catch {
        Register-AuditFailure -ErrorRecord $_ -Name $Name -Switch $Switch -Prefix '    [!] STEP FAILED'
    }
}

Function Write-CheckFailuresReport {
    [CmdletBinding()]
    param([string]$BaseRoot)

    if (-not $script:CheckFailures -or $script:CheckFailures.Count -eq 0) { return }

    $rawDir = Get-RawSourceDataDir
    if (-not (Test-Path -LiteralPath $rawDir)) {
        New-Item -ItemType Directory -Path $rawDir -Force | Out-Null
    }
    $txtPath = Join-Path $rawDir 'connection_failures.txt'
    $csvPath = Join-Path $rawDir 'connection_failures.csv'

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(' AUDIT CHECK FAILURES (script continued past these)')
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(" Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine(" Total failures: $($script:CheckFailures.Count)")
    [void]$sb.AppendLine('---------------------------------------------------------------------')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('What this file means:')
    [void]$sb.AppendLine(' - One or more audit checks could not complete (typically because an AD')
    [void]$sb.AppendLine('   or DNS server was unreachable, RPC was blocked, the user lacked')
    [void]$sb.AppendLine('   permissions, or a required PowerShell module was missing).')
    [void]$sb.AppendLine(' - The script kept running and finished every other check. Anything that')
    [void]$sb.AppendLine('   appears below was SKIPPED, so the corresponding section of the HTML')
    [void]$sb.AppendLine('   report may be incomplete.')
    [void]$sb.AppendLine(' - For each failure we record the suspected target server (parsed from')
    [void]$sb.AppendLine('   the error message) and which FSMO role(s) that server holds, so you')
    [void]$sb.AppendLine('   can decide whether to retry from a different DC.')
    [void]$sb.AppendLine('')

    $i = 0
    foreach ($f in $script:CheckFailures) {
        $i++
        [void]$sb.AppendLine("[$i] $($f.CheckName)  ($($f.Time))")
        [void]$sb.AppendLine("    Description : $($f.Description)")
        if ($f.Switch) { [void]$sb.AppendLine("    Switch      : -$($f.Switch)") }
        [void]$sb.AppendLine("    Connection  : $(if($f.IsConnectionIssue){'YES (RPC / network / auth)'}else{'no - other error'})")
        [void]$sb.AppendLine("    Error type  : $($f.ErrorType)")
        [void]$sb.AppendLine("    Error       : $($f.ErrorMessage)")
        if ($f.ServerHints)         { [void]$sb.AppendLine("    Server hint : $($f.ServerHints)") }
        if ($f.FsmoOnFailedServers) { [void]$sb.AppendLine("    FSMO held   : $($f.FsmoOnFailedServers)") }
        [void]$sb.AppendLine("    Effect      : results for this check are MISSING from the report.")
        [void]$sb.AppendLine('')
    }

    Set-Content -LiteralPath $txtPath -Value $sb.ToString() -Encoding UTF8
    $script:CheckFailures | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    Write-Both ""
    Write-Both "[!] $($script:CheckFailures.Count) check(s) failed during this run - see connection_failures.txt"

    try {
        Write-Nessus-Finding "AuditCheckFailures" "KB1300" ([System.IO.File]::ReadAllText($txtPath))
    } catch {}
}

Function Write-Nessus-Header() {
    #Creates nessus XML file header
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<?xml version=`"1.0`" ?><AdAudit>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<Report name=`"$env:ComputerName`" xmlns:cm=`"http://www.nessus.org/cm`">"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<ReportHost name=`"$env:ComputerName`"><HostProperties></HostProperties>"
}
Function Write-Nessus-Finding( [string]$pluginname, [string]$pluginid, [string]$pluginexample) {
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<ReportItem port=`"0`" svc_name=`"`" protocol=`"`" severity=`"0`" pluginID=`"ADAudit_$pluginid`" pluginName=`"$pluginname`" pluginFamily=`"Windows`">"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<description>There's an issue with $pluginname</description>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<plugin_type>remote</plugin_type><risk_factor>Low</risk_factor>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<solution>CCS Recommends fixing the issues with $pluginname on the host</solution>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<synopsis>There's an issue with the $pluginname settings on the host</synopsis>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<plugin_output>$pluginexample</plugin_output></ReportItem>"
}
Function Write-Nessus-Footer() {
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "</ReportHost></Report></AdAudit>"
}
Function Get-DNSZoneInsecure {
    # Check DNS zones allowing insecure updates on all DNS servers in the domain

    try {
        Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null
        Import-ADAuditModule -Name DnsServer -Required | Out-Null
    }
    catch {
        Write-Both "    [!] Could not load required modules (ActiveDirectory/DnsServer). $_"
        return
    }

    # Get all domain controllers; we'll probe each one to see if DNS is installed
    try {
        $dcList = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    }
    catch {
        Write-Both "    [!] Failed to enumerate domain controllers from AD. $_"
        return
    }

    if (-not $dcList -or $dcList.Count -eq 0) {
        Write-Both "    [-] No domain controllers found."
        return
    }

    $globalInsecureZonesFile = Get-EvidencePath 'insecure_dns_zones.txt'
    if (Test-Path $globalInsecureZonesFile) {
        Remove-Item $globalInsecureZonesFile -Force
    }

    $totalcount = 0

    foreach ($dnsServer in $dcList) {

        Write-Both "    [*] Checking potential DNS server: $dnsServer"

        # Optional: check remote OS version to skip 2008 if needed
        $skipServer = $false
        try {
            $os = Get-ADAuditCimInstance -ClassName Win32_OperatingSystem -ComputerName $dnsServer -UseWsmanFallback
            $osCaption = $os.Caption
            if ($osCaption -like "Windows Server 2008*") {
                Write-Both "        [-] $dnsServer is Windows Server 2008, skipping Get-DNSZoneInsecure check on this server."
                $skipServer = $true
            }
        }
        catch {
            Write-Both "        [!] Could not determine OS version for $dnsServer, continuing anyway. $_"
        }

        if ($skipServer) { continue }

        # Try to query DNS zones; if DNS role is not installed, this will fail and we skip
        try {
            $insecurezones = Get-DnsServerZone -ComputerName $dnsServer -ErrorAction Stop |
                             Where-Object { $_.DynamicUpdate -like '*nonsecure*' }
        }
        catch {
            Write-Both "        [-] $dnsServer does not appear to have the DNS role (or access failed), skipping. $_"
            continue
        }

        if ($insecurezones) {
            foreach ($insecurezone in $insecurezones) {
                Add-Content -Path $globalInsecureZonesFile -Value (
"@The DNS Zone {0} on DNS server {1} allows insecure updates ({2})" -f `
                    $insecurezone.ZoneName, $dnsServer, $insecurezone.DynamicUpdate
                )
                $totalcount++
            }
        }
        else {
            Write-Both "        [-] No insecure DNS zones found on $dnsServer."
        }
    }

    if ($totalcount -gt 0) {
        Write-Both "    [!] There were $totalcount DNS zones configured to allow insecure updates (KB842) across all DNS servers."
        Write-Nessus-Finding "InsecureDNSZone" "KB842" ([System.IO.File]::ReadAllText($globalInsecureZonesFile))
    }
    else {
        Write-Both "    [-] No insecure DNS zones found on any discovered DNS server."
    }
}
Function Get-OUPerms {
    #Check for non-standard perms for authenticated users, domain users, users and everyone groups
    $count = 0
    $progresscount = 0
    $objects = (Get-ADObject -Filter *)
    $totalcount = ($objects | Measure-Object | Select-Object Count).count
    foreach ($object in $objects) {
        if ($totalcount -eq 0) { break }
        $progresscount++
        Write-Progress -Activity "Searching for non standard permissions for authenticated users..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount * 100)
        try {
            $output = (Get-Acl -Path "AD:$object" -ErrorAction Stop).Access | Where-Object { ($_.IdentityReference -eq "$AuthenticatedUsers") -or ($_.IdentityReference -eq "$EveryOne") -or ($_.IdentityReference -like "*\$DomainUsers") -or ($_.IdentityReference -eq "BUILTIN\$Users") } | Where-Object { ($_.ActiveDirectoryRights -ne 'GenericRead') -and ($_.ActiveDirectoryRights -ne 'GenericExecute') -and ($_.ActiveDirectoryRights -ne 'ExtendedRight') -and ($_.ActiveDirectoryRights -ne 'ReadControl') -and ($_.ActiveDirectoryRights -ne 'ReadProperty') -and ($_.ActiveDirectoryRights -ne 'ListObject') -and ($_.ActiveDirectoryRights -ne 'ListChildren') -and ($_.ActiveDirectoryRights -ne 'ListChildren, ReadProperty, ListObject') -and ($_.ActiveDirectoryRights -ne 'ReadProperty, GenericExecute') -and ($_.AccessControlType -ne 'Deny') }
        } catch {
            $output = $null
        }
        if ($output -ne $null) {
            $count++
            Add-Content -Path (Get-EvidencePath 'ou_permissions.txt') -Value "OU: $object"
            Add-Content -Path (Get-EvidencePath 'ou_permissions.txt') -Value "[!] Rights: $($output.IdentityReference) $($output.ActiveDirectoryRights) $($output.AccessControlType)"
        }
    }
    Write-Progress -Activity "Searching for non standard permissions for authenticated users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] Issue identified, see $outputdir\ou_permissions.txt"
        Write-Nessus-Finding "OUPermissions" "KB551" ([System.IO.File]::ReadAllText((Get-EvidencePath 'ou_permissions.txt')))
    }
}
Function Get-LAPSStatus {
    #Check for presence of Windows LAPS and/or legacy Microsoft LAPS in the forest
    $schemaNC = (Get-ADRootDSE).SchemaNamingContext
    $legacySchema = $null
    $windowsSchema = $null

    try {
        $legacySchema = Get-ADObject -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwd)' -SearchBase $schemaNC -ErrorAction Stop
    }
    catch { }

    try {
        $windowsSchema = Get-ADObject -LDAPFilter '(lDAPDisplayName=msLAPS-PasswordExpirationTime)' -SearchBase $schemaNC -ErrorAction Stop
    }
    catch { }

    $legacyDetected = ($null -ne $legacySchema)
    $windowsDetected = ($null -ne $windowsSchema)

    if (-not $legacyDetected -and -not $windowsDetected) {
        Write-Both "    [!] LAPS Not Installed in domain (KB258)"
        Write-Nessus-Finding "LAPSMissing" "KB258" "LAPS Not Installed in domain"
        return
    }

    if ($windowsDetected) {
        Write-Both "    [+] Windows LAPS schema detected in the forest"
    }
    if ($legacyDetected) {
        Write-Both "    [+] Legacy Microsoft LAPS schema detected in the forest"
    }

    $missingPath = Get-EvidencePath 'laps_missing-computers.txt'
    $expiredPath = Get-EvidencePath 'laps_expired-passwords.txt'
    $rightsPath  = Get-EvidencePath 'laps_read-extendedrights.txt'

    Remove-Item -LiteralPath $missingPath,$expiredPath,$rightsPath -Force -ErrorAction SilentlyContinue

    if ($windowsDetected) {
        $lapsModule = Import-ADAuditModule -Name LAPS
        if ($lapsModule) {
            $missingComputers = @(Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(!(msLAPS-PasswordExpirationTime=*)))' -Properties msLAPS-PasswordExpirationTime | Select-Object -ExpandProperty Name)
            if ($missingComputers.Count -gt 0) {
                foreach ($name in $missingComputers) {
                    Add-Content -Path $missingPath -Value "[Windows LAPS] $name"
                }
                Write-Both "    [!] Some computers/servers don't have Windows LAPS password expiration data set, see $missingPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($missingPath))
            }

            $windowsComputers = @(Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(msLAPS-PasswordExpirationTime=*))' -Properties msLAPS-PasswordExpirationTime)
            foreach ($computer in $windowsComputers) {
                $expiration = Convert-ADAuditFileTime $computer.'msLAPS-PasswordExpirationTime'
                if ($expiration -and $expiration -lt (Get-Date)) {
                    Add-Content -Path $expiredPath -Value "[Windows LAPS] $($computer.Name) password is expired since $expiration"
                }
            }
            if (Test-Path -LiteralPath $expiredPath) {
                Write-Both "    [!] Some computers/servers have Windows LAPS password expired, see $expiredPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($expiredPath))
            }

            Get-ADOrganizationalUnit -Filter * | Find-LapsADExtendedRights -PipelineVariable OU | ForEach-Object {
                foreach ($holder in $_.ExtendedRightHolders) {
                    if ($holder -and $holder -ne $System) {
                        Add-Content -Path $rightsPath -Value "[Windows LAPS] $holder can read password attribute of $($_.ObjectDN)"
                    }
                }
            }
            if (Test-Path -LiteralPath $rightsPath) {
                Write-Both "    [!] Windows LAPS extended rights exported, see $rightsPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($rightsPath))
            }

            $DomainLevel = (Get-ADDomain).DomainMode
            if (-not (Test-ADAuditFunctionalLevelAtLeast -Mode $DomainLevel -MinimumMode 'Windows2016Domain')) {
                Write-Both "    [*] Windows LAPS is present, but domain functional level is below Windows Server 2016; encryption and DSRM management features may be limited."
            }
        }
        else {
            Write-Both "    [!] Windows LAPS schema detected, but the LAPS PowerShell module is not available on this host."
        }
    }

    if ($legacyDetected) {
        $legacyModule = Import-ADAuditModule -Name 'AdmPwd.PS' -PreferWindowsPowerShell
        if ($legacyModule) {
            $missingComputers = @(Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(!(ms-Mcs-AdmPwd=*)))' -Properties ms-Mcs-AdmPwd | Select-Object -ExpandProperty Name)
            if ($missingComputers.Count -gt 0) {
                foreach ($name in $missingComputers) {
                    Add-Content -Path $missingPath -Value "[Legacy LAPS] $name"
                }
                Write-Both "    [!] Some computers/servers don't have legacy LAPS password set, see $missingPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($missingPath))
            }

            $legacyComputers = @(Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))' -Properties ms-Mcs-AdmPwdExpirationTime)
            foreach ($computer in $legacyComputers) {
                $expiration = Convert-ADAuditFileTime $computer.'ms-Mcs-AdmPwdExpirationTime'
                if ($expiration -and $expiration -lt (Get-Date)) {
                    Add-Content -Path $expiredPath -Value "[Legacy LAPS] $($computer.Name) password is expired since $expiration"
                }
            }
            if (Test-Path -LiteralPath $expiredPath) {
                Write-Both "    [!] Some computers/servers have legacy LAPS password expired, see $expiredPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($expiredPath))
            }

            Get-ADOrganizationalUnit -Filter * | Find-AdmPwdExtendedRights -PipelineVariable OU | ForEach-Object {
                foreach ($holder in $_.ExtendedRightHolders) {
                    if ($holder -and $holder -ne $System) {
                        Add-Content -Path $rightsPath -Value "[Legacy LAPS] $holder can read password attribute of $($OU.ObjectDN)"
                    }
                }
            }
            if (Test-Path -LiteralPath $rightsPath) {
                Write-Both "    [!] Legacy LAPS extended rights exported, see $rightsPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($rightsPath))
            }
        }
        else {
            Write-Both "    [!] Legacy Microsoft LAPS schema detected, but the AdmPwd.PS module is not available on this host."
        }
    }
}
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
        Write-Progress -Activity "Searching for users who are in privileged groups..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path (Get-EvidencePath 'accounts_userPrivileged.txt') -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    Write-Progress -Activity "Searching for users who are in privileged groups..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] There are $count accounts in privileged groups, see accounts_userPrivileged.txt (KB426)"
        Write-Nessus-Finding "AdminSDHolders" "KB426" ([System.IO.File]::ReadAllText((Get-EvidencePath 'accounts_userPrivileged.txt')))
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
        try {
            $obj = Get-ADObject -Identity $m.distinguishedName -Properties SamAccountName, Enabled, lastLogonTimestamp, servicePrincipalName, objectClass, sIDHistory -ErrorAction Stop
        } catch {
            $obj = $m
        }
        $kind = Get-PrincipalKindForDA -Member $obj -DomainSid $domainSid
        $enabled = $true
        try { if ($obj.PSObject.Properties['Enabled']) { $enabled = [bool]$obj.Enabled } } catch { }
        $stale = $false
        try {
            if ($obj.lastLogonTimestamp) {
                $llt = [DateTime]::FromFileTime([long]$obj.lastLogonTimestamp)
                if ($llt -lt (Get-Date).AddDays(-90)) { $stale = $true }
            } else {
                $stale = $true   # never logged on
            }
        } catch { }
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
            try { $obj = Get-ADObject -Identity $m.distinguishedName -Properties SamAccountName, objectClass, servicePrincipalName -ErrorAction Stop } catch { }
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

    Write-Nessus-Finding "DomainAdminsSizeAdjustedReview" "KB427" ([System.IO.File]::ReadAllText((Get-EvidencePath 'domain_admins_scaled.txt')))

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
        if (-not $rid500.Enabled) { $issues += 'account is DISABLED' }
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
        Write-Nessus-Finding "BuiltinDomainAdminRid500" "KB428" ([System.IO.File]::ReadAllText((Get-EvidencePath 'domain_admin_builtin_rid500.txt')))
    } catch {
        Write-Both "    [!] Could not inspect RID-500 account: $($_.Exception.Message)"
    }
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
        $tests.Add([pscustomobject]@{
            Title        = $Title
            Subtitle     = $Subtitle
            Status       = $Status
            Detail       = $Detail
            EvidencePath = $EvidencePath
        }) | Out-Null
    }

    try {
        Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null
    } catch {
        Write-Both "    [!] AD Health check skipped: ActiveDirectory module not available."
        return
    }

    try {
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop | Sort-Object Name)
    } catch {
        Write-Both "    [!] AD Health check skipped: could not enumerate DCs ($($_.Exception.Message))."
        return
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
    [void]$replSb.AppendLine('=== repadmin /replsummary ===')
    try {
        $replSummary = (repadmin /replsummary 2>&1) | Out-String
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
        foreach ($line in ($replSummary -split "`r?`n")) {
            if ($line -match '^\s*\S+\s+.+?(\d+)\s*/\s*\d+\s+\d+(\s|$)') {
                $f = [int]$matches[1]
                if ($f -gt 0) { $replFailed += $f }
            }
        }
    } catch { [void]$replSb.AppendLine("repadmin /replsummary failed: $($_.Exception.Message)") }

    [void]$replSb.AppendLine('')
    [void]$replSb.AppendLine('=== repadmin /showrepl /csv (per-DC, may be truncated) ===')
    try {
        $showrepl = (repadmin /showrepl /csv 2>&1) | Out-String
        if ($showrepl.Length -gt 32000) { $showrepl = $showrepl.Substring(0,32000) + "`n... (truncated) ..." }
        [void]$replSb.AppendLine($showrepl)
    } catch { [void]$replSb.AppendLine("repadmin /showrepl failed: $($_.Exception.Message)") }

    [void]$replSb.AppendLine('')
    [void]$replSb.AppendLine('=== repadmin /queue (per-DC) ===')
    foreach ($dc in $dcs) {
        try {
            $q = (repadmin /queue $dc.HostName 2>&1) | Out-String
            [void]$replSb.AppendLine("--- $($dc.HostName) ---")
            [void]$replSb.AppendLine($q)
        } catch { [void]$replSb.AppendLine("$($dc.HostName): $($_.Exception.Message)") }
    }

    [void]$replSb.AppendLine('')
    [void]$replSb.AppendLine('=== repadmin /removelingeringobjects (advisory; dry-run not supported here) ===')
    try {
        # Advisory-only: many environments do not have a configured reference DC, so this often errors.
        $linger = (repadmin /showrepl /errorsonly 2>&1) | Out-String
        [void]$replSb.AppendLine($linger)
        if ($LASTEXITCODE -ne 0) { $replLingeringErr = $true }
    } catch { $replLingeringErr = $true; [void]$replSb.AppendLine($_.Exception.Message) }

    Set-Content -LiteralPath $replPath -Value $replSb.ToString() -Encoding UTF8

    if ($replFailed -gt 0) {
        _Add-HFinding -Category 'Replication' -Severity 'High' -Title 'Replication failures detected' -Evidence "Total replication failures across DCs: $replFailed" -Source $replPath
        _Add-HTest -Title 'Replication health' -Subtitle 'repadmin /replsummary, /showrepl, /queue, lingering objects' -Status 'Fail' -Detail "$replFailed failure(s)" -EvidencePath $replPath
    } elseif ($replLingeringErr) {
        _Add-HFinding -Category 'Replication' -Severity 'Low' -Title 'Lingering-object advisory scan could not complete' -Evidence 'repadmin advisory probe errored out (often DNS lookup or RPC reachability). Lingering state is unverified, not necessarily present.' -Source $replPath
        _Add-HTest -Title 'Replication health' -Subtitle 'repadmin /replsummary, /showrepl, /queue, lingering objects' -Status 'Pass' -Detail '1 Low (advisory only)' -EvidencePath $replPath
    } else {
        _Add-HTest -Title 'Replication health' -Subtitle 'repadmin /replsummary, /showrepl, /queue, lingering objects' -Status 'Pass' -Detail 'No issues' -EvidencePath $replPath
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
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $tcp.BeginConnect($Target, $Port, $null, $null)
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
    [void]$icSb.AppendLine('A DC is flagged "Isolated" when it is NOT this host AND both LDAP+SMB probes fail.')
    [void]$icSb.AppendLine('')

    $dcReachRows = @()
    foreach ($dc in $dcs) {
        $dcHost = $dc.HostName
        $isLocalDC = ($dcHost.ToLowerInvariant() -eq $localFqdn) -or ($dcHost.ToLowerInvariant().Split('.')[0] -eq $env:COMPUTERNAME.ToLowerInvariant())

        $dnsOk = $false
        try { if (Resolve-DnsName -Name $dcHost -Type A -ErrorAction Stop) { $dnsOk = $true } } catch { }

        $ldapOk = $false; $smbOk = $false
        if ($dnsOk -or $isLocalDC) {
            $ldapOk = _Test-DCTcp -Target $dcHost -Port 389
            $smbOk  = _Test-DCTcp -Target $dcHost -Port 445
        }

        $replOk = $null
        $lastRepl = $null
        try {
            $partners = Get-ADReplicationPartnerMetadata -Target $dcHost -Scope Server -ErrorAction Stop
            if ($partners) {
                $stale = $false
                foreach ($p in $partners) {
                    $lastRepl = $p.LastReplicationSuccess
                    if (-not $lastRepl -or $lastRepl -lt (Get-Date).AddDays(-1)) { $stale = $true }
                }
                $replOk = -not $stale
            }
        } catch { $replOk = $false }

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

    # Severity scaling
    $icSeverity = 'Pass'
    $icDetail = "All $totalDCs DC(s) reachable"
    $icOverallSev = $null
    if ($isolatedCount -gt 0) {
        if ($totalDCs -le 1) {
            $icDetail = "Only 1 DC; nothing to partition"
        } elseif ($totalDCs -eq 2) {
            $icOverallSev = 'Critical'
            $icSeverity = 'Fail'
            $icDetail = "$isolatedCount/$totalDCs DC(s) isolated - Critical (no redundancy)"
        } elseif ($totalDCs -eq 3 -and $isolatedCount -eq 1) {
            $icOverallSev = 'High'
            $icSeverity = 'Fail'
            $icDetail = "1/$totalDCs DC isolated - High"
        } elseif ($totalDCs -ge 4 -and $isolatedCount -eq 1) {
            $icOverallSev = 'Medium'
            $icSeverity = 'Warn'
            $icDetail = "1/$totalDCs DC isolated - Medium"
        } else {
            # Multiple isolated - severity scales by remaining redundancy
            if ($reachableCount -lt 2) {
                $icOverallSev = 'Critical'; $icSeverity = 'Fail'
            } elseif ($reachableCount -lt 3) {
                $icOverallSev = 'High'; $icSeverity = 'Fail'
            } else {
                $icOverallSev = 'Medium'; $icSeverity = 'Warn'
            }
            $icDetail = "$isolatedCount/$totalDCs DC(s) isolated - $icOverallSev"
        }
    }

    if ($icOverallSev) {
        $title = if ($isolatedCount -eq 1) { 'Domain controller cannot reach replication partners' }
                 else                       { 'Multiple domain controllers cannot reach replication partners' }
        $isolatedNames = ($isolatedRows | ForEach-Object { $_.Host }) -join ', '
        $evidenceText = "$isolatedCount of $totalDCs DC(s) isolated ($reachableCount reachable). Unreachable DC(s) from $env:COMPUTERNAME: $isolatedNames"
        _Add-HFinding -Category 'DC Interconnect' -Severity $icOverallSev -Title $title -Evidence $evidenceText -Source $icPath

        # Each isolated DC is itself in Critical state (its replication is dead
        # from this host's perspective, regardless of how many DCs the rest of
        # the forest can still talk to).
        foreach ($iso in $isolatedRows) {
            _Add-HFinding -Category 'DC Interconnect' -Severity 'Critical' -Title 'DC unreachable - replication broken with this peer' -Evidence "DC $($iso.Host) is unreachable on LDAP (389) and SMB (445) from $env:COMPUTERNAME. Replication with this DC is not happening - directory state will diverge. Possible causes: powered off, network partition, firewall, cloned VM on isolated network, decommissioned but not removed from AD." -Source $icPath
        }
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
            try {
                $out = (dcdiag /s:$dcHost /test:$t 2>&1) | Out-String
                [void]$dcdiagSb.AppendLine($out)
                if ($out -match '(?im)^\s*\.+\s+\S+\s+failed\s+test\s+') {
                    $dcdiagFailedTests++
                    if (-not $dcdiagBreakdown.ContainsKey($dcHost)) { $dcdiagBreakdown[$dcHost] = 0 }
                    $dcdiagBreakdown[$dcHost] = $dcdiagBreakdown[$dcHost] + 1
                }
            } catch {
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
        _Add-HTest -Title 'DC diagnostics (dcdiag)' -Subtitle 'Services, Replications, Advertising, FsmoCheck, KCCEvent, NetLogons, SysVolCheck, RidManager, DFSREvent, Intersite' -Status 'Pass' -Detail 'No issues' -EvidencePath $dcdiagPath
    }

    # ============================================================
    # 3) SYSVOL / DFSR backlog
    # ============================================================
    $sysvolPath = Join-Path $rawDir 'health_sysvol_dfsr.txt'
    $sysvolSb   = New-Object System.Text.StringBuilder
    $sysvolBacklog = 0
    foreach ($dc in $dcs) {
        $dcHost = $dc.HostName
        [void]$sysvolSb.AppendLine("--- $dcHost ---")
        try {
            $share = "\\$dcHost\SYSVOL"
            if (Test-Path -LiteralPath $share) {
                [void]$sysvolSb.AppendLine("SYSVOL share reachable: $share")
            } else {
                [void]$sysvolSb.AppendLine("SYSVOL share NOT reachable: $share")
                $sysvolBacklog++
            }
        } catch {
            [void]$sysvolSb.AppendLine("Could not reach SYSVOL on ${dcHost}: $($_.Exception.Message)")
            $sysvolBacklog++
        }
        try {
            $dfsr = Get-ADAuditCimInstance -ClassName Win32_Service -ComputerName $dcHost -Filter "Name='DFSR'" -ErrorAction SilentlyContinue
            if ($dfsr) {
                [void]$sysvolSb.AppendLine("DFSR state: $($dfsr.State) / start: $($dfsr.StartMode)")
                if ($dfsr.State -ne 'Running') { $sysvolBacklog++ }
            }
        } catch { }
    }
    Set-Content -LiteralPath $sysvolPath -Value $sysvolSb.ToString() -Encoding UTF8
    if ($sysvolBacklog -gt 0) {
        _Add-HFinding -Category 'SYSVOL/DFSR' -Severity 'Medium' -Title 'SYSVOL or DFSR issue detected' -Evidence "DCs with SYSVOL/DFSR concerns: $sysvolBacklog" -Source $sysvolPath
        _Add-HTest -Title 'SYSVOL / DFSR backlog' -Subtitle 'DFSR backlog and content consistency between DCs' -Status 'Warn' -Detail "$sysvolBacklog issue(s)" -EvidencePath $sysvolPath
    } else {
        _Add-HTest -Title 'SYSVOL / DFSR backlog' -Subtitle 'DFSR backlog and content consistency between DCs' -Status 'Pass' -Detail 'No issues' -EvidencePath $sysvolPath
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
    [void]$fsmoSb.AppendLine('A role is flagged when its holder is missing, unresolvable in DNS, an')
    [void]$fsmoSb.AppendLine('RODC, unreachable on LDAP/ADWS, not replicating, or (forest-root PDC)')
    [void]$fsmoSb.AppendLine('has no authoritative external time source.')
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
                $fsmoDom = Get-ADDomain -Server $domName -ErrorAction Stop
                if ($domName -eq $rootDomainName) { $forestRootPdc = [string]$fsmoDom.PDCEmulator }
                $fsmoRoles.Add([pscustomobject]@{ Scope=$domName; Role='PDCEmulator';          Holder=[string]$fsmoDom.PDCEmulator })          | Out-Null
                $fsmoRoles.Add([pscustomobject]@{ Scope=$domName; Role='RIDMaster';            Holder=[string]$fsmoDom.RIDMaster })            | Out-Null
                $fsmoRoles.Add([pscustomobject]@{ Scope=$domName; Role='InfrastructureMaster'; Holder=[string]$fsmoDom.InfrastructureMaster }) | Out-Null
            } catch {
                [void]$fsmoSb.AppendLine("[!] Could not query domain '$domName' (PDC/RID/Infrastructure not validated): $($_.Exception.Message)")
                _Add-HFinding -Category 'FSMO' -Severity 'Medium' -Title 'Per-domain FSMO holders could not be determined' -Evidence "Get-ADDomain -Server $domName failed: $($_.Exception.Message). PDC/RID/Infrastructure roles for this domain were not validated." -Source $fsmoPath
                $fsmoWarn++
            }
        }
        $fsmoEnumerated = $true
    } catch {
        [void]$fsmoSb.AppendLine("[!] Could not query the forest for FSMO holders: $($_.Exception.Message)")
        _Add-HFinding -Category 'FSMO' -Severity 'Medium' -Title 'FSMO role holders could not be enumerated' -Evidence "Get-ADForest failed: $($_.Exception.Message). FSMO inventory and validation were skipped - run from a domain-joined host with AD reachable." -Source $fsmoPath
        $fsmoWarn++
    }

    if ($fsmoEnumerated -and $fsmoRoles.Count -gt 0) {
        # --- Probe each unique holder once (a single DC can hold several roles) ---
        $holderProbe = @{}
        foreach ($h in (@($fsmoRoles | ForEach-Object { $_.Holder } | Where-Object { $_ } | Sort-Object -Unique))) {
            $hKey = $h.ToLowerInvariant()
            $found = $false; $isRodc = $null; $site = $null; $ipv4 = $null
            try {
                $hdc = Get-ADDomainController -Identity $h -ErrorAction Stop
                $found = $true; $isRodc = [bool]$hdc.IsReadOnly; $site = [string]$hdc.Site; $ipv4 = [string]$hdc.IPv4Address
            } catch {
                try {
                    $hdc = Get-ADDomainController -Identity $h -Server $h -ErrorAction Stop
                    $found = $true; $isRodc = [bool]$hdc.IsReadOnly; $site = [string]$hdc.Site; $ipv4 = [string]$hdc.IPv4Address
                } catch { }
            }
            $dnsOk = $false
            try { if (Resolve-DnsName -Name $h -Type A -ErrorAction Stop) { $dnsOk = $true } } catch { }
            $ldapOk = $false; $adwsOk = $false
            if ($dnsOk -or $found) {
                $ldapOk = _Test-DCTcp -Target $h -Port 389
                $adwsOk = _Test-DCTcp -Target $h -Port 9389
            }
            # $replOk: $true = fresh, $false = CONFIRMED stale (partners returned but
            # older than 24h), $null = could NOT verify (single DC with no partners,
            # or a cross-domain/RPC-restricted holder we cannot query). Only the
            # confirmed-stale ($false) case raises a finding, so a healthy holder we
            # simply cannot reach for metadata is never falsely flagged.
            $replOk = $null; $lastRepl = $null
            try {
                $rp = Get-ADReplicationPartnerMetadata -Target $h -Scope Server -ErrorAction Stop
                if ($rp) {
                    $stale = $false
                    foreach ($p in $rp) { $lastRepl = $p.LastReplicationSuccess; if (-not $lastRepl -or $lastRepl -lt (Get-Date).AddDays(-1)) { $stale = $true } }
                    $replOk = -not $stale
                }
            } catch { $replOk = $null }
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
            # Reachability impact: PDC and RID are the highest-impact operations
            # masters (password/lockout/time, and SID-pool issuance). The others
            # degrade to Warning when unreachable.
            $reachSev = if ($role -in @('PDCEmulator','RIDMaster')) { 'Critical' } else { 'Medium' }

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

                if (-not $pr.DNS) {
                    _Add-HFinding -Category 'FSMO' -Severity $reachSev -Title "FSMO holder does not resolve in DNS" -Evidence "The $role holder '$holder' ($($fr.Scope)) has no A record / DNS resolution failed. DCs and clients locate the role owner via DNS; an unresolvable holder makes $role unreachable. Common causes: the holder was decommissioned without transferring the role, or its DNS record was removed." -Source $fsmoPath
                    if ($reachSev -eq 'Critical') { $fsmoCritical++ } else { $fsmoWarn++ }
                } elseif (-not $pr.LDAP) {
                    _Add-HFinding -Category 'FSMO' -Severity $reachSev -Title "FSMO holder unreachable on LDAP (389)" -Evidence "The $role holder '$holder' resolves in DNS but is not reachable on TCP 389 (LDAP) from $env:COMPUTERNAME. An offline/firewalled operations master blocks role-dependent operations (PDC: password changes, lockouts, GPO targeting, forest time; RID: new-object SID pools)." -Source $fsmoPath
                    if ($reachSev -eq 'Critical') { $fsmoCritical++ } else { $fsmoWarn++ }
                }
                if ($pr.DNS -and -not $pr.ADWS) {
                    _Add-HFinding -Category 'FSMO' -Severity 'Medium' -Title "FSMO holder unreachable on ADWS (9389)" -Evidence "The $role holder '$holder' is not reachable on TCP 9389 (Active Directory Web Services). FSMO operations themselves do not require ADWS, but PowerShell/RSAT management of this DC and discovery tooling will fail against it." -Source $fsmoPath
                    $fsmoWarn++
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
                $pdcSource = (w32tm /query /source /computer:$forestRootPdc 2>&1 | Out-String).Trim()
                [void]$fsmoSb.AppendLine("  w32tm source   : $pdcSource")
                if ($pdcSource -match '(?i)0x800706BA|error|RPC server is unavailable') {
                    _Add-HFinding -Category 'FSMO' -Severity 'Medium' -Title 'Forest-root PDC time source could not be queried' -Evidence "w32tm /query /source against the forest-root PDC emulator '$forestRootPdc' failed ($pdcSource). The forest-root PDC is the authoritative time source for the entire forest - confirm W32Time and RPC are reachable on it." -Source $fsmoPath
                    $fsmoWarn++
                } elseif ($pdcSource -match '(?i)Local CMOS Clock|Free-running System Clock') {
                    _Add-HFinding -Category 'FSMO' -Severity 'High' -Title 'Forest-root PDC has no authoritative external time source' -Evidence "The forest-root PDC emulator '$forestRootPdc' is syncing from '$pdcSource' rather than an external/hardware NTP source. Every clock in the forest chains to this PDC; with no real upstream source the whole forest can drift and break Kerberos (auth fails at >5 min skew)." -Source $fsmoPath
                    $fsmoWarn++
                } else {
                    [void]$fsmoSb.AppendLine('  Assessment     : external/upstream time source present (OK)')
                }
            } catch {
                [void]$fsmoSb.AppendLine("  w32tm source   : query failed ($($_.Exception.Message))")
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
        _Add-HTest -Title 'FSMO role holders' -Subtitle $fsmoSubtitle -Status 'Pass' -Detail 'All FSMO holders healthy' -EvidencePath $fsmoPath
    }

    # ============================================================
    # 5) NTDS database
    # ============================================================
    $ntdsPath = Join-Path $rawDir 'health_ntds.txt'
    $ntdsSb   = New-Object System.Text.StringBuilder
    $ntdsIssues = 0
    foreach ($dc in $dcs) {
        $dcHost = $dc.HostName
        [void]$ntdsSb.AppendLine("--- $dcHost ---")
        try {
            $ntdsParams = Invoke-Command -ComputerName $dcHost -ScriptBlock {
                $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            } -ErrorAction Stop
            $ditPath = $ntdsParams.'DSA Database file'
            $logPath = $ntdsParams.'Database log files path'
            [void]$ntdsSb.AppendLine("ntds.dit: $ditPath")
            [void]$ntdsSb.AppendLine("logs:     $logPath")

            $dbInfo = Invoke-Command -ComputerName $dcHost -ScriptBlock {
                param($p) if ($p -and (Test-Path -LiteralPath $p)) { (Get-Item -LiteralPath $p).Length } else { -1 }
            } -ArgumentList $ditPath -ErrorAction SilentlyContinue
            $logVolFree = Invoke-Command -ComputerName $dcHost -ScriptBlock {
                param($p) if ($p) { $drv = (Split-Path -Path $p -Qualifier); if ($drv) { (Get-PSDrive -Name $drv.TrimEnd(':') -ErrorAction SilentlyContinue).Free } else { -1 } } else { -1 }
            } -ArgumentList $logPath -ErrorAction SilentlyContinue

            if ($dbInfo -ge 0)     { [void]$ntdsSb.AppendLine(("ntds.dit size: {0:N0} bytes" -f $dbInfo)) }
            if ($logVolFree -ge 0) { [void]$ntdsSb.AppendLine(("log volume free: {0:N0} bytes" -f $logVolFree)) }
            if ($logVolFree -ge 0 -and $logVolFree -lt (1GB)) {
                $ntdsIssues++
                [void]$ntdsSb.AppendLine("  [!] log volume has < 1 GB free")
            }
        } catch {
            [void]$ntdsSb.AppendLine("Could not read NTDS info via remoting on ${dcHost}: $($_.Exception.Message)")
        }
    }
    Set-Content -LiteralPath $ntdsPath -Value $ntdsSb.ToString() -Encoding UTF8
    if ($ntdsIssues -gt 0) {
        _Add-HFinding -Category 'NTDS Database' -Severity 'High' -Title 'NTDS database log volume low on free space' -Evidence "$ntdsIssues DC(s) with low free space on the database log volume" -Source $ntdsPath
        _Add-HTest -Title 'NTDS database' -Subtitle 'ntds.dit size, log volume free space, fragmentation' -Status 'Fail' -Detail "$ntdsIssues issue(s)" -EvidencePath $ntdsPath
    } else {
        _Add-HTest -Title 'NTDS database' -Subtitle 'ntds.dit size, log volume free space, fragmentation' -Status 'Pass' -Detail 'No issues' -EvidencePath $ntdsPath
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
        try {
            $nowUtc = Invoke-Command -ComputerName $dcHost -ScriptBlock { (Get-Date).ToUniversalTime() } -ErrorAction Stop
            $samples += [pscustomobject]@{ Host = $dcHost; Time = $nowUtc }
            [void]$timeSb.AppendLine("$dcHost UTC: $nowUtc")
        } catch {
            [void]$timeSb.AppendLine("$dcHost UTC: unavailable ($($_.Exception.Message))")
        }
    }
    if ($samples.Count -ge 2) {
        for ($i = 0; $i -lt $samples.Count; $i++) {
            for ($j = $i + 1; $j -lt $samples.Count; $j++) {
                $skew = [math]::Abs(($samples[$i].Time - $samples[$j].Time).TotalSeconds)
                [void]$timeSb.AppendLine(("Skew {0} <-> {1}: {2:N1} sec" -f $samples[$i].Host, $samples[$j].Host, $skew))
                if ($skew -gt 300) { $timeIssues++ }
            }
        }
    }
    Set-Content -LiteralPath $timePath -Value $timeSb.ToString() -Encoding UTF8
    if ($timeIssues -gt 0) {
        _Add-HFinding -Category 'Time Sync' -Severity 'High' -Title 'DC clock skew greater than 5 minutes (Kerberos breaks)' -Evidence "Skewed pairs: $timeIssues" -Source $timePath
        _Add-HTest -Title 'Time synchronization' -Subtitle 'Pairwise skew between DCs (Kerberos breaks at >5 min skew)' -Status 'Fail' -Detail "$timeIssues skewed pair(s)" -EvidencePath $timePath
    } else {
        _Add-HTest -Title 'Time synchronization' -Subtitle 'Pairwise skew between DCs (Kerberos breaks at >5 min skew)' -Status 'Pass' -Detail 'No issues' -EvidencePath $timePath
    }

    # ============================================================
    # 7) Core AD services
    # KPSSVC (Kerberos Key Distribution Proxy / KDC Proxy) is OPTIONAL.
    # Many AD deployments leave it Stopped intentionally. We still record
    # its state but classify it as Information, not High/Critical.
    # ============================================================
    $svcPath = Join-Path $rawDir 'health_dc_services.txt'
    $svcSb   = New-Object System.Text.StringBuilder
    $svcCritical = @('NTDS','Netlogon','KDC','DNS','DFSR','ADWS','W32Time')
    $svcOptional = @('KPSSVC')
    $svcAllNames = $svcCritical + $svcOptional
    $svcCriticalIssues = 0
    $svcInfoIssues     = 0
    foreach ($dc in $dcs) {
        $dcHost = $dc.HostName
        [void]$svcSb.AppendLine("--- $dcHost ---")
        foreach ($s in $svcAllNames) {
            try {
                $svc = Get-ADAuditCimInstance -ClassName Win32_Service -ComputerName $dcHost -Filter "Name='$s'" -ErrorAction SilentlyContinue
                if (-not $svc) {
                    [void]$svcSb.AppendLine("  $s : NOT INSTALLED")
                    if ($s -in $svcCritical) {
                        # DFSR may be replaced by NTFRS on legacy domains; tolerate that case
                        if ($s -ne 'DFSR') { $svcCriticalIssues++ }
                    }
                    continue
                }
                $state = [string]$svc.State
                [void]$svcSb.AppendLine("  $s : $state")
                if ($state -ne 'Running') {
                    if ($s -in $svcOptional) {
                        $svcInfoIssues++
                        _Add-HFinding -Category 'DC Services' -Severity 'Info' -Title 'Optional AD service not running (informational)' -Evidence "DC $dcHost service $s state: $state - $s is optional and frequently left stopped." -Source $svcPath
                    } else {
                        $svcCriticalIssues++
                        _Add-HFinding -Category 'DC Services' -Severity 'High' -Title 'Critical AD service not running' -Evidence "DC $dcHost service $s state: $state" -Source $svcPath
                    }
                }
            } catch {
                [void]$svcSb.AppendLine("  $s : check failed - $($_.Exception.Message)")
            }
        }
    }
    Set-Content -LiteralPath $svcPath -Value $svcSb.ToString() -Encoding UTF8
    if ($svcCriticalIssues -gt 0) {
        _Add-HTest -Title 'Core AD services' -Subtitle 'NTDS, Netlogon, KDC, DNS, DFSR, ADWS, W32Time, KPSSVC' -Status 'Fail' -Detail "$svcCriticalIssues High" -EvidencePath $svcPath
    } elseif ($svcInfoIssues -gt 0) {
        _Add-HTest -Title 'Core AD services' -Subtitle 'NTDS, Netlogon, KDC, DNS, DFSR, ADWS, W32Time, KPSSVC' -Status 'Pass' -Detail 'No critical issues (KPSSVC info only)' -EvidencePath $svcPath
    } else {
        _Add-HTest -Title 'Core AD services' -Subtitle 'NTDS, Netlogon, KDC, DNS, DFSR, ADWS, W32Time, KPSSVC' -Status 'Pass' -Detail 'No issues' -EvidencePath $svcPath
    }

    # ============================================================
    # 8) Event log scrape (72h)
    # ============================================================
    $evtPath = Join-Path $rawDir 'health_events_72h.txt'
    $evtSb   = New-Object System.Text.StringBuilder
    $evtIssues = 0
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
            $ids = $badIds[$logName]
            try {
                $hits = Get-WinEvent -ComputerName $dcHost -FilterHashtable @{ LogName = $logName; Id = $ids; StartTime = $cutoff } -ErrorAction Stop
                if ($hits) {
                    [void]$evtSb.AppendLine("  ${logName}: $($hits.Count) bad event(s)")
                    $evtIssues += $hits.Count
                    foreach ($h in ($hits | Select-Object -First 5)) {
                        [void]$evtSb.AppendLine("    [$($h.Id)] $($h.TimeCreated) $($h.LevelDisplayName)")
                    }
                }
            } catch {
                # Logs may simply have no matching events; that's fine.
            }
        }
    }
    Set-Content -LiteralPath $evtPath -Value $evtSb.ToString() -Encoding UTF8
    if ($evtIssues -gt 0) {
        _Add-HFinding -Category 'Event Logs' -Severity 'Medium' -Title 'Known bad event IDs found in DC logs (last 72h)' -Evidence "Events: $evtIssues" -Source $evtPath
        _Add-HTest -Title 'Event log scrape (72h)' -Subtitle 'Directory Service / DNS / DFSR / System logs, known bad IDs' -Status 'Warn' -Detail "$evtIssues event(s)" -EvidencePath $evtPath
    } else {
        _Add-HTest -Title 'Event log scrape (72h)' -Subtitle 'Directory Service / DNS / DFSR / System logs, known bad IDs' -Status 'Pass' -Detail 'No issues' -EvidencePath $evtPath
    }

    # ============================================================
    # 9) Sites and subnets
    # ============================================================
    $sitePath = Join-Path $rawDir 'health_sites_subnets.txt'
    $siteSb   = New-Object System.Text.StringBuilder
    $siteIssues = 0
    try {
        $sites = Get-ADReplicationSite -Filter * -ErrorAction Stop
        foreach ($site in $sites) {
            $gcs = $dcs | Where-Object { $_.IsGlobalCatalog -and $_.Site -eq $site.Name }
            if (-not $gcs) {
                [void]$siteSb.AppendLine("Site $($site.Name): NO GC present")
                $siteIssues++
            } else {
                [void]$siteSb.AppendLine("Site $($site.Name): $($gcs.Count) GC(s)")
            }
        }
    } catch { [void]$siteSb.AppendLine("Site enumeration failed: $($_.Exception.Message)") }
    Set-Content -LiteralPath $sitePath -Value $siteSb.ToString() -Encoding UTF8
    if ($siteIssues -gt 0) {
        _Add-HFinding -Category 'Sites/Subnets' -Severity 'Medium' -Title 'Site without a Global Catalog' -Evidence "Sites lacking GC: $siteIssues" -Source $sitePath
        _Add-HTest -Title 'Sites and subnets' -Subtitle 'GC placement, NETLOGON.log unmapped subnets' -Status 'Warn' -Detail "$siteIssues site(s)" -EvidencePath $sitePath
    } else {
        _Add-HTest -Title 'Sites and subnets' -Subtitle 'GC placement, NETLOGON.log unmapped subnets' -Status 'Pass' -Detail 'No issues' -EvidencePath $sitePath
    }

    # ============================================================
    # 10) AD Recycle Bin
    # ============================================================
    $rbPath = Join-Path $rawDir 'health_recyclebin.txt'
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
    }
    Set-Content -LiteralPath $rbPath -Value $rbSb.ToString() -Encoding UTF8
    if ($rbIssue) {
        _Add-HFinding -Category 'Recycle Bin' -Severity 'Low' -Title 'AD Recycle Bin not enabled' -Evidence 'Restoring deleted AD objects with full attributes will not be possible.' -Source $rbPath
        _Add-HTest -Title 'AD Recycle Bin' -Subtitle 'Lifetime alignment, recoverable backlog' -Status 'Warn' -Detail '1 Low' -EvidencePath $rbPath
    } else {
        _Add-HTest -Title 'AD Recycle Bin' -Subtitle 'Lifetime alignment, recoverable backlog' -Status 'Pass' -Detail 'No issues' -EvidencePath $rbPath
    }

    # ============================================================
    # 11) Group Hygiene
    # ============================================================
    $ghPath = Join-Path $rawDir 'health_group_hygiene.txt'
    $ghSb   = New-Object System.Text.StringBuilder
    $ghTotal = 0
    $ghEmpty = 0
    $ghBuiltinPg = 0
    [void]$ghSb.AppendLine('Group Hygiene')
    [void]$ghSb.AppendLine(("Generated: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ssZ')))
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
    }
    Set-Content -LiteralPath $ghPath -Value $ghSb.ToString() -Encoding UTF8
    if ($ghEmpty -gt 0) {
        $sev = if ($ghEmpty -gt 100) { 'Medium' } else { 'Low' }
        _Add-HFinding -Category 'Group Hygiene' -Severity $sev -Title 'Empty security groups detected' -Evidence "Total groups: $ghTotal | Empty: $ghEmpty | Excluded built-in primaryGroupID-backed: $ghBuiltinPg" -Source $ghPath
        _Add-HTest -Title 'Group hygiene' -Subtitle 'Empty groups, primaryGroupID-backed exclusion' -Status 'Warn' -Detail "$ghEmpty empty" -EvidencePath $ghPath
    } else {
        _Add-HTest -Title 'Group hygiene' -Subtitle 'Empty groups, primaryGroupID-backed exclusion' -Status 'Pass' -Detail 'No empty groups' -EvidencePath $ghPath
    }

    # ============================================================
    # Build AD_Health.html
    # ============================================================
    $htmlPath = Join-Path $htmlDir 'AD_Health.html'
    Write-ADHealthReport -OutputPath $htmlPath -Findings $findings -Tests $tests -Domain $domain -RunBy $runBy
    Write-Both "    [+] AD Health report saved to HTML Reports\AD_Health.html"
}

Function Write-ADHealthReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [Parameter(Mandatory=$true)][System.Collections.Generic.List[object]]$Findings,
        [Parameter(Mandatory=$true)][System.Collections.Generic.List[object]]$Tests,
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
    $cInfo = ($Findings | Where-Object { $_.Severity -eq 'Info' }).Count
    $totalFindings = $cCrit + $cHigh + $cMed + $cLow

    $score = (25 * $cCrit) + (12 * $cHigh) + (5 * $cMed) + (1 * $cLow)
    if ($score -gt 100) { $score = 100 }
    $totalScore = 100 - $score   # higher is better display

    $bandLabel = 'Healthy'
    $bandColor = '#2e7d32'
    $bandText  = 'No major operational issues detected from this run.'
    if ($cCrit -gt 0) {
        $bandLabel = 'Critical'; $bandColor = '#c62828'; $bandText = 'Critical issues detected - act now.'
    } elseif ($cHigh -gt 0 -or $score -ge 60) {
        $bandLabel = 'High'; $bandColor = '#ea580c'; $bandText = 'High-priority issues - prioritize remediation.'
    } elseif ($cMed -gt 0 -or $score -ge 25) {
        $bandLabel = 'Medium'; $bandColor = '#d97706'; $bandText = 'Some configuration drift or operational warnings - plan remediation.'
    } elseif ($cLow -gt 0) {
        $bandLabel = 'Low'; $bandColor = '#65a30d'; $bandText = 'Minor advisories only - address during routine maintenance.'
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

    # Pass/Warn/Fail counts
    $tPass = ($Tests | Where-Object { $_.Status -eq 'Pass' }).Count
    $tWarn = ($Tests | Where-Object { $_.Status -eq 'Warn' }).Count
    $tFail = ($Tests | Where-Object { $_.Status -eq 'Fail' }).Count
    $tSkip = ($Tests | Where-Object { $_.Status -eq 'Skipped' }).Count
    $tNone = ($Tests | Where-Object { $_.Status -eq 'NotRun' }).Count
    $tTotal = $Tests.Count

    $css = Get-ADAuditReportCss
    $nav = Get-ADAuditPrimaryNav -Active 'health'

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
    try { localStorage.setItem('adaudit-theme', t); } catch(_){}
  }
  document.addEventListener('DOMContentLoaded', function(){
    applyTheme(currentTheme());
    var b = document.getElementById('adAuditThemeToggle');
    if (b){ b.addEventListener('click', function(){ applyTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark'); }); }
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
    <text class='hg-tick' x='42'  y='205' text-anchor='middle'>Healthy</text>
    <text class='hg-tick' x='200' y='34'  text-anchor='middle'>Medium</text>
    <text class='hg-tick' x='358' y='205' text-anchor='middle'>Critical</text>
    <line class='hg-needle' x1='200' y1='180' x2='$nxStr' y2='$nyStr'/>
    <circle class='hg-hub' cx='200' cy='180' r='9'/>
    <text class='hg-score'  x='200' y='148'>$score</text>
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
      Score = <code>min(100, 25*Critical + 12*High + 5*Medium + 1*Low)</code>. Computed across $tTotal Health checks. Information findings are excluded.
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
            WhyMatters = 'A DC that exists in AD but is not reachable on the wire is a partition: cloned/restored to an isolated network, firewalled off, powered off, or decommissioned without being removed from AD. Replication silently diverges, password changes go missing, FSMO transfers fail, and clients in different segments authenticate against different copies of the directory. Severity scales with how much redundancy is left - a 2-DC domain with one DC isolated has zero failover and is Critical; a 4-DC domain with one isolated is Medium for the domain but still Critical for that specific DC.'
            LookFor    = 'In the evidence file, look at the "Isolated: True" lines and the "Replication fresh" column. An isolated DC has both LDAP and SMB unreachable. A reachable DC with stale replication (LastReplicationSuccess > 1 day) is also a problem, just a different one.'
            HowToFix   = 'For each isolated DC: 1) Verify the DC is supposed to exist - if it was decommissioned, demote it cleanly with `dcpromo /forceremoval` (last resort) or use `ntdsutil "metadata cleanup"` to remove the AD record from a healthy DC. 2) If it should be online, restore network reachability (firewall rules, routing, VPN, VLAN), then verify with `Test-NetConnection <DC> -Port 389/445` from each remaining DC. 3) Once reachable, force convergence with `repadmin /syncall /AdePq`. 4) For cloned VMs put on isolated networks: do not let them rejoin the production domain - clones must be either properly demoted or fully isolated (different domain), otherwise USN rollback can corrupt the directory.'
            RerunCmd   = 'foreach ($dc in (Get-ADDomainController -Filter *)) { [pscustomobject]@{ DC=$dc.HostName; LDAP=(Test-NetConnection $dc.HostName -Port 389 -InformationLevel Quiet); SMB=(Test-NetConnection $dc.HostName -Port 445 -InformationLevel Quiet) } }'
        }
        'DC diagnostics (dcdiag)' = @{
            Summary    = 'Runs the dcdiag test suite (Services, Replications, Advertising, FsmoCheck, KCCEvent, NetLogons, SysVolCheck, RidManager, DFSREvent, Intersite) against every DC.'
            WhyMatters = 'dcdiag exposes operational issues that are invisible at the directory level - missing SRV records, NetLogon stopped, FSMO unreachable, KCC errors, advertising failures.'
            LookFor    = 'In the evidence file, search for `failed test` lines. The DC name is on the line above; the test name is on the failed-test line.'
            HowToFix   = 'Each test has its own remediation. Common patterns: missing SRV records (re-register with `nltest /dsregdns`), Netlogon/Kdc stopped (`Start-Service Netlogon,Kdc`), FSMO holder offline (transfer or seize roles), DNS not resolving the DC FQDN, or > 5 min time skew (see Time synchronization).'
            RerunCmd   = 'dcdiag /v /s:<DC-FQDN> /test:Replications /test:Advertising /test:FsmoCheck /test:NetLogons /test:SysVolCheck'
        }
        'SYSVOL / DFSR backlog' = @{
            Summary    = 'Verifies the SYSVOL share is reachable on each DC and the DFSR (or NTFRS) replication service is running.'
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
            RerunCmd   = 'Invoke-Command -ComputerName <DC> -ScriptBlock { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"; Get-PSDrive | Where-Object Free -lt 1GB }'
        }
        'Time synchronization' = @{
            Summary    = 'Compares wall-clock UTC across all DCs and reports any pair drifted more than 5 minutes.'
            WhyMatters = 'Kerberos ticket validation requires < 5 min skew between client and KDC. Once a DC drifts past that window, clients silently fail to authenticate and authentication failures get blamed on credentials.'
            LookFor    = 'In the evidence file: "Skew ... > 300 sec" lines and DCs that returned "unavailable" (likely WinRM blocked).'
            HowToFix   = 'On the PDC emulator, point W32Time at an external authoritative source: `w32tm /config /manualpeerlist:"time.windows.com,0x9" /syncfromflags:manual /reliable:yes /update; Restart-Service W32Time`. On other DCs, force resync: `w32tm /resync /rediscover`.'
            RerunCmd   = 'Invoke-Command -ComputerName <each-DC> -ScriptBlock { (Get-Date).ToUniversalTime() }; w32tm /monitor'
        }
        'Core AD services' = @{
            Summary    = 'Verifies NTDS, Netlogon, KDC, DNS, DFSR, ADWS, W32Time and KPSSVC on every DC. KPSSVC is reported as informational only - it is optional and frequently left stopped on purpose.'
            WhyMatters = 'Each service maps to a discrete capability: NTDS = directory engine, Netlogon = domain auth + secure channels, KDC = Kerberos issuer, DNS = name resolution that AD itself depends on, DFSR = SYSVOL replication, ADWS = PowerShell/RSAT module endpoint, W32Time = Kerberos clock.'
            LookFor    = "In the evidence file: lines that read '`<service>` : Stopped' or '`<service>` : NOT INSTALLED' (DFSR vs NTFRS migration is OK; missing NTDS/Netlogon/KDC/DNS/ADWS is not)."
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
        'Sites and subnets' = @{
            Summary    = 'Walks every AD replication site and confirms at least one Global Catalog DC is present. Sites without a GC are flagged.'
            WhyMatters = 'Universal-group expansion at logon, cross-domain searches and Exchange/Outlook lookups all require a GC. Without a local GC, that traffic falls back across site links and adds latency to every authentication.'
            LookFor    = 'In the evidence file: lines that read "Site `<name>`: NO GC present". Cross-check with subnet coverage (NETLOGON.log on a DC tells you which subnets have no site mapping).'
            HowToFix   = 'Promote a DC at the affected site to GC: `Set-ADDomainController -Identity <DC> -GlobalCatalog $true`. Add any unmapped subnets to AD Sites and Services.'
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

function Get-OverlappingGroupMemberships {
    [CmdletBinding()]
    param(
        [string]$OutputDir = $(if ($script:outputdir) { $script:outputdir } else { $outputdir }),

        [string]$UserLdapFilter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",

        [ValidateRange(1,100)]
        [int]$MaxDepth = 15,

        [switch]$IncludeHtml = $true,

        [ValidateRange(0,1000000)]
        [int]$ProgressEvery = 250
    )

    $ErrorActionPreference = 'Stop'

    function Write-Log {
        param([string]$Message)
        if (Get-Command Write-Both -ErrorAction SilentlyContinue) { Write-Both $Message } else { Write-Host $Message }
    }

    Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null

    if (-not $OutputDir) {
        throw "OutputDir is empty. Ensure `$outputdir is set by the main script, or pass -OutputDir."
    }
    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $csvPath  = Join-Path $OutputDir "overlapping_group_memberships.csv"
    $htmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $OutputDir) "overlapping_group_memberships.html"

    $nestedCsvPath  = Join-Path $OutputDir "multiple_nested_paths.csv"
    $nestedHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $OutputDir) "multiple_nested_paths.html"

    # Cache groups by DN to reduce LDAP calls
    $groupCache = @{}

    function Get-CachedGroup {
        param([Parameter(Mandatory)][string]$DistinguishedName)

        if ($groupCache.ContainsKey($DistinguishedName)) { return $groupCache[$DistinguishedName] }

        try {
            $g = Get-ADGroup -Identity $DistinguishedName -Properties memberOf, name, samAccountName -ErrorAction Stop
        } catch {
            return $null
        }

        $obj = [pscustomobject]@{
            DN       = $g.DistinguishedName
            Name     = $g.Name
            Sam      = $g.SamAccountName
            MemberOf = @($g.memberOf)
        }

        $groupCache[$DistinguishedName] = $obj
        return $obj
    }

    function Add-Path {
        param(
            [Parameter(Mandatory)][hashtable]$PathsByDn,
            [Parameter(Mandatory)][string]$TargetDn,
            [Parameter(Mandatory)][string]$PathString,
            [Parameter(Mandatory)][string]$StartGroup
        )

        if (-not $PathsByDn.ContainsKey($TargetDn)) { $PathsByDn[$TargetDn] = @() }

        $PathsByDn[$TargetDn] += [pscustomobject]@{
            Path  = $PathString
            Start = $StartGroup
            Len   = ($PathString -split '\s->\s').Count
        }
    }

    Write-Log "    [*] Overlapping group membership routes (domain-wide)"

    $users = Get-ADUser -LDAPFilter $UserLdapFilter -Properties displayName, distinguishedName, samAccountName, memberOf `
        -ResultPageSize 2000 -ResultSetSize $null

    $total = ($users | Measure-Object).Count
    Write-Log ("    [*] Users to process: {0}" -f $total)

    $overlapResults    = New-Object System.Collections.Generic.List[object]
    $nestedPathResults = New-Object System.Collections.Generic.List[object]

    $i = 0
    foreach ($u in $users) {
        $i++
        if ($ProgressEvery -gt 0 -and ($i % $ProgressEvery) -eq 0) {
            Write-Log ("    [*] Processed {0}/{1} users..." -f $i, $total)
        }

        # DIRECT groups from memberOf
        $directGroupDns = @($u.memberOf)
        if (-not $directGroupDns -or $directGroupDns.Count -eq 0) { continue }

        # Resolve direct groups to names
        $directGroups = foreach ($gdn in $directGroupDns) {
            $g = Get-CachedGroup -DistinguishedName $gdn
            if ($g) { [pscustomobject]@{ Name = $g.Name; DN = $g.DN } }
        }
        $directGroups = @($directGroups | Where-Object { $_ })
        if ($directGroups.Count -eq 0) { continue }

        # targetGroupDN -> list of path objects
        $pathsByDn = @{}

        foreach ($dg in $directGroups) {
            $startName = [string]$dg.Name
            $startDn   = [string]$dg.DN

            $stack = New-Object System.Collections.ArrayList
            [void]$stack.Add([pscustomobject]@{
                Dn      = $startDn
                Path    = @($startName)
                PathDns = @($startDn)
                Depth   = 0
            })

            while ($stack.Count -gt 0) {
                $node = $stack[$stack.Count - 1]
                $stack.RemoveAt($stack.Count - 1)

                $currentDn  = $node.Dn
                $currentStr = ($node.Path -join ' -> ')

                Add-Path -PathsByDn $pathsByDn -TargetDn $currentDn -PathString $currentStr -StartGroup $startName

                if ($node.Depth -ge $MaxDepth) { continue }

                $g = Get-CachedGroup -DistinguishedName $currentDn
                if (-not $g) { continue }

                foreach ($parentDn in @($g.MemberOf)) {
                    if (-not $parentDn) { continue }
                    if ($node.PathDns -contains $parentDn) { continue } # loop guard

                    $parent = Get-CachedGroup -DistinguishedName $parentDn
                    if (-not $parent) { continue }

                    [void]$stack.Add([pscustomobject]@{
                        Dn      = $parent.DN
                        Path    = @($node.Path + @($parent.Name))
                        PathDns = @($node.PathDns + @($parent.DN))
                        Depth   = ($node.Depth + 1)
                    })
                }
            }
        }

        foreach ($targetDn in $pathsByDn.Keys) {
            $pathObjs = $pathsByDn[$targetDn]
            if (-not $pathObjs -or $pathObjs.Count -lt 2) { continue }

            $uniquePaths = @($pathObjs | Select-Object -ExpandProperty Path -Unique)
            if ($uniquePaths.Count -le 1) { continue }

            $targetGroup = Get-CachedGroup -DistinguishedName $targetDn
            $targetName  = if ($targetGroup) { $targetGroup.Name } else { $targetDn }

            # Path arrays
            $pathArrays = @()
            foreach ($p in $uniquePaths) {
                $arr = @($p -split '\s->\s' | Where-Object { $_ })
                if ($arr.Count -gt 0) { $pathArrays += ,$arr }
            }
            if ($pathArrays.Count -lt 2) { continue }

            # Direct entry groups
            $directEntryGroups = @($pathArrays | ForEach-Object { $_[0] } | Sort-Object -Unique)

            # Union contributing groups (excluding target)
            $allGroups = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
            foreach ($arr in $pathArrays) {
                foreach ($gName in $arr) {
                    if ($gName -and ($gName -ne $targetName)) { [void]$allGroups.Add($gName) }
                }
            }
            $contribUnion = @($allGroups | Sort-Object)

            # Intersection common groups (excluding target)
            $common = $null
            foreach ($arr in $pathArrays) {
                $set = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
                foreach ($gName in $arr) {
                    if ($gName -and ($gName -ne $targetName)) { [void]$set.Add($gName) }
                }

                if ($null -eq $common) { $common = $set }
                else { $common.IntersectWith($set) }
            }
            $commonGroups = if ($common) { @($common | Sort-Object) } else { @() }

            # ContributingGroups output: direct entry + other contributing (dedup)
            $entrySet = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
            foreach ($e in $directEntryGroups) { [void]$entrySet.Add($e) }

            $nonEntryContrib = @()
            foreach ($g in $contribUnion) {
                if (-not $entrySet.Contains($g)) { $nonEntryContrib += $g }
            }

            $hasDirect = $false
            $hasIndirect = $false
            foreach ($p in $pathObjs) {
                if ($p.Len -eq 1) { $hasDirect = $true } else { $hasIndirect = $true }
            }

            $overlapType =
                if ($hasDirect -and $hasIndirect) { "Direct+Indirect" }
                elseif ($directEntryGroups.Count -gt 1) { "MultipleDirectGroups" }
                else { "MultiplePaths" }

            $resultObj = [pscustomobject]@{
                UserSamAccountName = $u.SamAccountName
                UserDisplayName    = $u.DisplayName
                UserDN             = $u.DistinguishedName

                TargetGroup        = $targetName
                TargetGroupDN      = $targetDn

                OverlapType        = $overlapType
                PathCount          = $uniquePaths.Count

                DirectEntryGroups  = ($directEntryGroups -join '; ')
                ContributingGroups = (($directEntryGroups + $nonEntryContrib) | Sort-Object -Unique) -join '; '
                CommonGroups       = ($commonGroups -join '; ')

                Paths              = ($uniquePaths -join ' | ')
            }

            if ($overlapType -eq 'MultiplePaths') {
                $nestedPathResults.Add($resultObj) | Out-Null
            } else {
                $overlapResults.Add($resultObj) | Out-Null
            }
        }
    }

    # --- Overlapping Group Memberships (MultipleDirectGroups / Direct+Indirect) ---
    if (Test-Path -LiteralPath $csvPath) { Remove-Item -LiteralPath $csvPath -Force }
    $overlapResults | Sort-Object UserSamAccountName, TargetGroup | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    if ($IncludeHtml) {
        if (Test-Path -LiteralPath $htmlPath) { Remove-Item -LiteralPath $htmlPath -Force }

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine((Get-ADAuditReportHeader -Title 'Overlapping Group Memberships'))
        [void]$sb.AppendLine((Get-ADAuditPrimaryNav -Active 'overlap'))
        [void]$sb.AppendLine("<div class='hero'><h1>Overlapping Group Memberships</h1>")
        [void]$sb.AppendLine("<div class='meta'>Users who reach the same target group via multiple direct group memberships.</div></div>")

        $userCount = ($overlapResults | Select-Object -Property UserSamAccountName -Unique).Count
        [void]$sb.AppendLine("<div class='stats'>")
        [void]$sb.AppendLine("<div class='stat'><div class='val'>$($overlapResults.Count)</div><div class='lbl'>Total Findings</div></div>")
        [void]$sb.AppendLine("<div class='stat'><div class='val'>$userCount</div><div class='lbl'>Affected Users</div></div>")
        [void]$sb.AppendLine("</div>")

        $byUser = $overlapResults | Group-Object UserSamAccountName
        foreach ($ug in $byUser) {
            $userRows = $ug.Group
            $dn   = ($userRows | Select-Object -First 1).UserDN
            $disp = ($userRows | Select-Object -First 1).UserDisplayName

            [void]$sb.AppendLine("<details>")
            [void]$sb.AppendLine("<summary>$($ug.Name) &mdash; $disp ($($userRows.Count) target group(s) with overlap)</summary>")
            [void]$sb.AppendLine("<div class='detail-body'><p><code>$dn</code></p>")
            [void]$sb.AppendLine("<table><thead><tr><th>Target Group</th><th>Overlap Type</th><th>Direct Entry Groups</th><th>Contributing Groups</th><th>Common Groups</th><th>Paths</th></tr></thead><tbody>")

            foreach ($r in ($userRows | Sort-Object TargetGroup)) {
                $pathsHtml = ($r.Paths -split '\s\|\s' | ForEach-Object { "<div><code>$($_)</code></div>" }) -join ''
                [void]$sb.AppendLine("<tr><td>$($r.TargetGroup)</td><td>$($r.OverlapType)</td><td>$($r.DirectEntryGroups)</td><td>$($r.ContributingGroups)</td><td>$($r.CommonGroups)</td><td>$pathsHtml</td></tr>")
            }

            [void]$sb.AppendLine("</tbody></table></div></details>")
        }

        [void]$sb.AppendLine((Get-ADAuditReportFooter))
        [System.IO.File]::WriteAllText($htmlPath, $sb.ToString(), [System.Text.Encoding]::UTF8)
    }

    # --- Multiple Nested Paths (MultiplePaths) ---
    if (Test-Path -LiteralPath $nestedCsvPath) { Remove-Item -LiteralPath $nestedCsvPath -Force }
    $nestedPathResults | Sort-Object UserSamAccountName, TargetGroup | Export-Csv -LiteralPath $nestedCsvPath -NoTypeInformation -Encoding UTF8

    if ($IncludeHtml) {
        if (Test-Path -LiteralPath $nestedHtmlPath) { Remove-Item -LiteralPath $nestedHtmlPath -Force }

        $sb2 = New-Object System.Text.StringBuilder
        [void]$sb2.AppendLine((Get-ADAuditReportHeader -Title 'Multiple Nested Paths'))
        [void]$sb2.AppendLine((Get-ADAuditPrimaryNav -Active 'overlap'))
        [void]$sb2.AppendLine("<div class='hero'><h1>Multiple Nested Paths</h1>")
        [void]$sb2.AppendLine("<div class='meta'>Users who reach the same target group via multiple nesting chains from a single direct group membership. These represent group nesting complexity, not necessarily duplicate effective permissions.</div></div>")

        $nestedUserCount = ($nestedPathResults | Select-Object -Property UserSamAccountName -Unique).Count
        [void]$sb2.AppendLine("<div class='stats'>")
        [void]$sb2.AppendLine("<div class='stat'><div class='val'>$($nestedPathResults.Count)</div><div class='lbl'>Total Findings</div></div>")
        [void]$sb2.AppendLine("<div class='stat'><div class='val'>$nestedUserCount</div><div class='lbl'>Affected Users</div></div>")
        [void]$sb2.AppendLine("</div>")

        $byUser2 = $nestedPathResults | Group-Object UserSamAccountName
        foreach ($ug in $byUser2) {
            $userRows = $ug.Group
            $dn   = ($userRows | Select-Object -First 1).UserDN
            $disp = ($userRows | Select-Object -First 1).UserDisplayName

            [void]$sb2.AppendLine("<details>")
            [void]$sb2.AppendLine("<summary>$($ug.Name) &mdash; $disp ($($userRows.Count) target group(s) with multiple paths)</summary>")
            [void]$sb2.AppendLine("<div class='detail-body'><p><code>$dn</code></p>")
            [void]$sb2.AppendLine("<table><thead><tr><th>Target Group</th><th>Overlap Type</th><th>Direct Entry Groups</th><th>Contributing Groups</th><th>Common Groups</th><th>Paths</th></tr></thead><tbody>")

            foreach ($r in ($userRows | Sort-Object TargetGroup)) {
                $pathsHtml = ($r.Paths -split '\s\|\s' | ForEach-Object { "<div><code>$($_)</code></div>" }) -join ''
                [void]$sb2.AppendLine("<tr><td>$($r.TargetGroup)</td><td>$($r.OverlapType)</td><td>$($r.DirectEntryGroups)</td><td>$($r.ContributingGroups)</td><td>$($r.CommonGroups)</td><td>$pathsHtml</td></tr>")
            }

            [void]$sb2.AppendLine("</tbody></table></div></details>")
        }

        [void]$sb2.AppendLine((Get-ADAuditReportFooter))
        [System.IO.File]::WriteAllText($nestedHtmlPath, $sb2.ToString(), [System.Text.Encoding]::UTF8)
    }

    # --- Log output ---
    if ($overlapResults.Count -gt 0) {
        Write-Log "    [!] Overlapping membership findings: $($overlapResults.Count) row(s)."
        Write-Log "        - CSV: $(Split-Path -Leaf $csvPath)"
        if ($IncludeHtml) { Write-Log "        - HTML: $(Split-Path -Leaf $htmlPath)" }
    } else {
        Write-Log "    [+] No overlapping group membership routes found."
        Write-Log "        - CSV (empty): $(Split-Path -Leaf $csvPath)"
        if ($IncludeHtml) { Write-Log "        - HTML: $(Split-Path -Leaf $htmlPath)" }
    }

    if ($nestedPathResults.Count -gt 0) {
        Write-Log "    [!] Multiple nested path findings: $($nestedPathResults.Count) row(s)."
        Write-Log "        - CSV: $(Split-Path -Leaf $nestedCsvPath)"
        if ($IncludeHtml) { Write-Log "        - HTML: $(Split-Path -Leaf $nestedHtmlPath)" }
    } else {
        Write-Log "    [+] No multiple nested path findings."
        Write-Log "        - CSV (empty): $(Split-Path -Leaf $nestedCsvPath)"
        if ($IncludeHtml) { Write-Log "        - HTML: $(Split-Path -Leaf $nestedHtmlPath)" }
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
            Write-Progress -Activity "Searching for protected users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
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
Function Get-AuthenticationPoliciesAndSilos {
    # Authentication Policies and Silos require Domain Functional Level
    # Windows Server 2012 R2 (the AD schema features and KDC enforcement
    # ship at that DFL). Forest level is NOT required - only the domain.
    # Earlier versions of this script gated on Windows2019Domain, which
    # incorrectly skipped the check on perfectly capable estates.
    $DomainLevel = (Get-ADDomain).DomainMode
    $evPath = Get-EvidencePath 'auth_policies_silos.txt'

    if (Test-ADAuditFunctionalLevelAtLeast -Mode $DomainLevel -MinimumMode 'Windows2012R2Domain') {
        try {
            $policies = @(Get-ADAuthenticationPolicy -Filter *)
            $silos    = @(Get-ADAuthenticationPolicySilo -Filter *)
        } catch {
            Write-Both "    [!] Could not enumerate Authentication Policies / Silos: $($_.Exception.Message)"
            return
        }

        foreach ($policy in $policies)   { Write-Both "    [+] Found Authentication Policy: $($policy.Name)" }
        foreach ($silo   in $silos)      { Write-Both "    [+] Found Authentication Policy Silo: $($silo.Name)" }

        if ($policies.Count -eq 0 -and $silos.Count -eq 0) {
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine('No Authentication Policies and no Authentication Policy Silos exist in this domain.')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("Domain functional level: $DomainLevel (>= Windows2012R2Domain - the feature is supported).")
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('Why this matters:')
            [void]$sb.AppendLine(' - Authentication Silos let you fence off Tier0 (Domain Admins, KRBTGT, the')
            [void]$sb.AppendLine('   forest root) so those accounts can ONLY sign in to a small, controlled set')
            [void]$sb.AppendLine('   of jump hosts and DCs. Combined with Protected Users, this is the strongest')
            [void]$sb.AppendLine('   "no admin creds on workstations" control Microsoft ships out of the box.')
            [void]$sb.AppendLine(' - Without silos, an attacker who phishes any admin can use that ticket from')
            [void]$sb.AppendLine('   any compromised endpoint - there is no policy preventing it.')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('How to fix:')
            [void]$sb.AppendLine(' - Plan a Tier0 silo containing your DCs and a small number of PAW jump hosts.')
            [void]$sb.AppendLine(' - Create a policy + silo in audit mode first, monitor for breakage, then enforce.')
            [void]$sb.AppendLine('   Reference: https://learn.microsoft.com/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('Consequences if NOT fixed:')
            [void]$sb.AppendLine(' - Admins can interactively log on to any workstation. Their tickets can be')
            [void]$sb.AppendLine('   stolen and reused (golden ticket / silver ticket / ticket reuse paths).')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('Consequences AFTER you implement (test before enforcing):')
            [void]$sb.AppendLine(' - Accounts assigned to the silo can no longer sign in to systems outside it.')
            [void]$sb.AppendLine('   If the silo is misconfigured admins can lock themselves out of every system,')
            [void]$sb.AppendLine('   including the silo members. Always pilot in audit mode first.')
            [void]$sb.AppendLine(' - Service accounts that need to authenticate from many sources usually do NOT')
            [void]$sb.AppendLine('   belong in a Tier0 silo - put them in a separate silo or leave them out.')
            Set-Content -LiteralPath $evPath -Value $sb.ToString() -Encoding UTF8
            Write-Both "    [!] No Authentication Policies / Silos defined - Tier0 isolation is not enforced. See auth_policies_silos.txt for context, fix, and trade-offs."
            Write-Nessus-Finding "AuthPoliciesSilosMissing" "KB549" ([System.IO.File]::ReadAllText($evPath))
        }
    }
    else {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("Authentication Policies / Silos check SKIPPED - Domain Functional Level ($DomainLevel) is below Windows2012R2Domain.")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Why this matters:')
        [void]$sb.AppendLine(' - Authentication Policies and Silos let you fence Tier0 admins to specific,')
        [void]$sb.AppendLine('   controlled hosts. They require DFL 2012R2 - they simply do not exist below.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('How to fix:')
        [void]$sb.AppendLine(' - Raise the Domain Functional Level (see the ProtectedUsers finding for the')
        [void]$sb.AppendLine('   exact PowerShell). Then plan a Tier0 silo (DCs + PAW jump hosts only).')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Consequences if NOT fixed:')
        [void]$sb.AppendLine(' - No mechanism to restrict where Tier0 accounts can sign in. Pass-the-hash and')
        [void]$sb.AppendLine('   ticket-reuse attacks against admins are not contained at the policy layer.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Consequences AFTER raising DFL (review before doing it):')
        [void]$sb.AppendLine(' - DFL is one-way - cannot be lowered. Remove all DCs running an OS below the')
        [void]$sb.AppendLine('   target DFL BEFORE raising. Inventory legacy clients and apps for compatibility.')
        Set-Content -LiteralPath $evPath -Value $sb.ToString() -Encoding UTF8
        Write-Both "    [!] Authentication Policies / Silos check skipped - DFL is $DomainLevel (need Windows2012R2Domain). See auth_policies_silos.txt for context, fix, and trade-offs."
        Write-Nessus-Finding "AuthPoliciesSilosDflTooLow" "KB549" ([System.IO.File]::ReadAllText($evPath))
    }
}
Function Get-MachineAccountQuota {
    #Get number of machines a user can add to a domain
    $MachineAccountQuota = (Get-ADDomain | select -ExpandProperty DistinguishedName | Get-ADObject -Property 'ms-DS-MachineAccountQuota' | select -ExpandProperty ms-DS-MachineAccountQuota)
    if ($MachineAccountQuota -gt 0) {
        Write-Both "    [!] Domain users can add $MachineAccountQuota devices to the domain! (KB251)"
        Write-Nessus-Finding "DomainAccountQuota" "KB251" "Domain users can add $MachineAccountQuota devices to the domain"
    }
}
Function Get-InactiveComputerObjects {
    $count = 0
    $DaysAgo = (Get-Date).AddDays(-90)

    $ReportPath = Get-EvidencePath 'computers_inactive_90days.txt'
    Remove-Item -Path $ReportPath -ErrorAction SilentlyContinue

    $inactiveComputers = Get-ADComputer -Filter { LastLogonTimeStamp -lt $DaysAgo -and Enabled -eq "true" } -Properties LastLogonTimeStamp, DNSHostName, OperatingSystem
    $totalcount = ($inactiveComputers | Measure-Object | Select-Object Count).count

    foreach ($computer in $inactiveComputers) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for inactive computer objects (>90 days)..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)

        $datelastlogon = if ($computer.LastLogonTimeStamp) { [DateTime]::FromFileTime($computer.LastLogonTimeStamp) } else { "Never" }

        Add-Content -Path $ReportPath -Value "Computer $($computer.Name) ($($computer.DNSHostName)) OS: $($computer.OperatingSystem) last logon: $datelastlogon"
        $count++
    }

    Write-Progress -Activity "Searching for inactive computer objects (>90 days)..." -Status "Ready" -Completed

    if ($count -gt 0) {
        Write-Both "    [!] $count enabled computer objects inactive for >90 days, see computers_inactive_90days.txt (KB###)"
        Write-Nessus-Finding "InactiveComputers90Days" "KB###" ([System.IO.File]::ReadAllText($ReportPath))
    }
}

Function Get-PasswordPolicy {
    Write-Both "    [+] Checking default password policy"
    if (!(Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled) {
        Write-Both "    [!] Password Complexity not enabled (KB262)"
        Write-Nessus-Finding "PasswordComplexity" "KB262" "Password Complexity not enabled"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold -lt 5) {
        Write-Both "    [!] Lockout threshold is less than 5, currently set to $((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold) (KB263)"
        Write-Nessus-Finding "LockoutThreshold" "KB263" "Lockout threshold is less than 5, currently set to $((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold)"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength -lt 14) {
        Write-Both "    [!] Minimum password length is less than 14, currently set to $((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength) (KB262)"
        Write-Nessus-Finding "PasswordLength" "KB262" "Minimum password length is less than 14, currently set to $((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength)"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).ReversibleEncryptionEnabled) {
        Write-Both "    [!] Reversible encryption is enabled"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge -eq "00:00:00") {
        Write-Both "    [!] Passwords do not expire (KB254)"
        Write-Nessus-Finding "PasswordsDoNotExpire" "KB254" "Passwords do not expire"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount -lt 12) {
        Write-Both "    [!] Passwords history is less than 12, currently set to $((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount) (KB262)"
        Write-Nessus-Finding "PasswordHistory" "KB262" "Passwords history is less than 12, currently set to $((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount)"
    }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).NoLmHash -eq 0) {
        Write-Both "    [!] LM Hashes are stored! (KB510)"
        Write-Nessus-Finding "LMHashesAreStored" "KB510" "LM Hashes are stored"
    }
    Write-Both "    [-] Finished checking default password policy"
    Write-Both "    [+] Checking fine-grained password policies if they exist"
    foreach ($finegrainedpolicy in Get-ADFineGrainedPasswordPolicy -Filter *) {
        $finegrainedpolicyappliesto = $finegrainedpolicy.AppliesTo
        Write-Both "    [!] Policy: $finegrainedpolicy"
        Write-Both "    [!] AppliesTo: $($finegrainedpolicyappliesto)"
        if (!($finegrainedpolicy).PasswordComplexity) {
            Write-Both "    [!] Password Complexity not enabled (KB262)"
            Write-Nessus-Finding "PasswordComplexity" "KB262" "Password Complexity not enabled for $finegrainedpolicy"
        }
        if (($finegrainedpolicy).LockoutThreshold -lt 5) {
            Write-Both "    [!] Lockout threshold is less than 5, currently set to $(($finegrainedpolicy).LockoutThreshold) (KB263)"
            Write-Nessus-Finding "LockoutThreshold" "KB263" " Lockout threshold for $finegrainedpolicy is less than 5, currently set to $(($finegrainedpolicy).LockoutThreshold)"
        }
        if (($finegrainedpolicy).MinPasswordLength -lt 14) {
            Write-Both "    [!] Minimum password length is less than 14, currently set to $(($finegrainedpolicy).MinPasswordLength) (KB262)"
            Write-Nessus-Finding "PasswordLength" "KB262" "Minimum password length for $finegrainedpolicy is less than 14, currently set to $(($finegrainedpolicy).MinPasswordLength)"
        }
        if (($finegrainedpolicy).ReversibleEncryptionEnabled) {
            Write-Both "    [!] Reversible encryption is enabled"
        }
        if (($finegrainedpolicy).MaxPasswordAge -eq "00:00:00") {
            Write-Both "    [!] Passwords do not expire (KB254)"
        }
        if (($finegrainedpolicy).PasswordHistoryCount -lt 12) {
            Write-Both "    [!] Passwords history is less than 12, currently set to $(($finegrainedpolicy).PasswordHistoryCount) (KB262)"
            Write-Nessus-Finding "PasswordHistory" "KB262" "Passwords history for $finegrainedpolicy is less than 12, currently set to $(($finegrainedpolicy).PasswordHistoryCount)"
        }
    }
    Write-Both "    [-] Finished checking fine-grained password policy"
}
Function Get-NULLSessions {
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RestrictAnonymous -eq 0) {
        Write-Both "    [!] RestrictAnonymous is set to 0! (KB81)"
        Write-Nessus-Finding "NullSessions" "KB81" " RestrictAnonymous is set to 0"
    }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RestrictAnonymousSam -eq 0) {
        Write-Both "    [!] RestrictAnonymousSam is set to 0! (KB81)"
        Write-Nessus-Finding "NullSessions" "KB81" " RestrictAnonymous is set to 0"
    }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).everyoneincludesanonymous -eq 1) {
        Write-Both "    [!] EveryoneIncludesAnonymous is set to 1! (KB81)"
        Write-Nessus-Finding "NullSessions" "KB81" "EveryoneIncludesAnonymous is set to 1"
    }
}
Function Get-DomainTrusts {
    #Lists domain trusts if they are bad
    foreach ($trust in (Get-ADObject -Filter { objectClass -eq "trustedDomain" } -Properties TrustPartner, TrustDirection, trustType, trustAttributes)) {
        if ($trust.TrustDirection -eq 2) {
            if ($trust.TrustAttributes -eq 1 -or $trust.TrustAttributes -eq 4) {
                #1 means trust is non-transitive, 4 is external so we check for anything but that
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain."
            }
            else {
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive!"
            }
        }
        if ($trust.TrustDirection -eq 3) {
            if ($trust.TrustAttributes -eq 1 -or $trust.TrustAttributes -eq 4) {
                #1 means trust is non-transitive, 4 is external so we check for anything but that
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain."
            }
            else {
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive!"
            }
        }
    }
}
Function Get-WinVersion {
    $WinVersion = [single]([string][environment]::OSVersion.Version.Major + "." + [string][environment]::OSVersion.Version.Minor)
    return [single]$WinVersion
}
Function Get-SMB1Support {
    #Check if server supports SMBv1
    if ([single](Get-WinVersion) -le [single]6.1) {
        #NT6.1 or less detected so checking reg key
        if (!(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters).SMB1 -eq 0) {
            Write-Both "    [!] SMBv1 is not disabled (KB290)"
            Write-Nessus-Finding "SMBv1Support" "KB290" "SMBv1 is enabled"
        }
    }
    elseif ([single](Get-WinVersion) -ge [single]6.2) {
        #NT6.2 or greater detected so using powershell function
        if ((Get-SmbServerConfiguration).EnableSMB1Protocol) {
            Write-Both "    [!] SMBv1 is enabled! (KB290)"
            Write-Nessus-Finding "SMBv1Support" "KB290" "SMBv1 is enabled"
        }
    }
}
Function Get-UserPasswordNotChangedRecently {
    #Reports users that haven't changed passwords in more than 90 days
    $count = 0
    $DaysAgo = (Get-Date).AddDays(-90)
    $accountsoldpasswords = Get-ADUser -Filter { PwdLastSet -lt $DaysAgo -and Enabled -eq "true" } -Properties PasswordLastSet
    $totalcount = ($accountsoldpasswords | Measure-Object | Select-Object Count).count
    foreach ($account in $accountsoldpasswords) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for passwords older than 90days..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        if ($account.PasswordLastSet) {
            $datelastchanged = $account.PasswordLastSet
        }
        else {
            $datelastchanged = "Never"
        }
        Add-Content -Path (Get-EvidencePath 'accounts_with_old_passwords.txt') -Value "User $($account.SamAccountName) ($($account.Name)) has not changed their password since $datelastchanged"
        $count++
    }
    Write-Progress -Activity "Searching for passwords older than 90days..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count accounts with passwords older than 90days, see accounts_with_old_passwords.txt (KB550)"
        Write-Nessus-Finding "AccountsWithOldPasswords" "KB550" ([System.IO.File]::ReadAllText((Get-EvidencePath 'accounts_with_old_passwords.txt')))
    }
    $krbtgtPasswordDate = (Get-ADUser -Filter { SamAccountName -eq "krbtgt" } -Properties PasswordLastSet).PasswordLastSet
    if ($krbtgtPasswordDate -lt (Get-Date).AddDays(-180)) {
        Write-Both "    [!] krbtgt password not changed since $krbtgtPasswordDate! (KB253)"
        Write-Nessus-Finding "krbtgtPasswordNotChanged" "KB253" "krbtgt password not changed since $krbtgtPasswordDate"
    }
}
Function Get-GPOtoFile {
    #Outputs complete GPO report
    $gpoHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $outputdir) 'GPOReport.html'
    if (Test-Path $gpoHtmlPath) { Remove-Item $gpoHtmlPath -Recurse }
    Get-GPOReport -All -ReportType HTML -Path $gpoHtmlPath
    Write-Both "    [+] GPO Report saved to HTML Reports\GPOReport.html"
    if (Test-Path "$outputdir\GPOReport.xml") { Remove-Item "$outputdir\GPOReport.xml" -Recurse }
    Get-GPOReport -All -ReportType XML -Path "$outputdir\GPOReport.xml"
    Write-Both "    [+] GPO Report saved to GPOReport.xml, now run Grouper offline using the following command (KB499)"
    Write-Both "    [+]     PS>Import-Module Grouper.psm1 ; Invoke-AuditGPOReport -Path C:\GPOReport.xml -Level 3"
}
Function Get-GPOsPerOU {
    #Lists all OUs and which GPOs apply to them
    $count = 0
    $ousgpos = @(Get-ADOrganizationalUnit -Filter *)
    $totalcount = ($ousgpos | Measure-Object | Select-Object Count).count
    foreach ($ouobject in $ousgpos) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Identifying which GPOs apply to which OUs..." -Status "Currently identifed $count OUs" -PercentComplete ($count / $totalcount * 100)
        $combinedgpos = ($(((Get-GPInheritance -Target $ouobject).InheritedGpoLinks) | select DisplayName) | ForEach-Object { $_.DisplayName }) -join ','
        Add-Content -Path (Get-EvidencePath 'ous_inheritedGPOs.txt') -Value "$($ouobject.Name) Inherits these GPOs: $combinedgpos"
        $count++
    }
    Write-Progress -Activity "Identifying which GPOs apply to which OUs..." -Status "Ready" -Completed
    Write-Both "    [+] Inherited GPOs saved to ous_inheritedGPOs.txt"
}
Function Get-SYSVOLXMLS {
    #Finds XML files in SYSVOL (thanks --> https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)
    $XMLFiles = Get-ChildItem -Path "\\$Env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml', 'Services.xml', 'Scheduledtasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml'
    $count = 0
    if ($XMLFiles) {
        $progresscount = 0
        $totalcount = ($XMLFiles | Measure-Object | Select-Object Count).count
        foreach ($File in $XMLFiles) {
            if ($totalcount -eq 0) { break }
            $progresscount++
            Write-Progress -Activity "Searching SYSVOL *.xmls for cpassword..." -Status "Currently searched through $count" -PercentComplete ($progresscount / $totalcount * 100)
            $Filename = Split-Path $File -Leaf
            $Distinguishedname = (Split-Path (Split-Path (Split-Path( Split-Path (Split-Path $File -Parent) -Parent ) -Parent ) -Parent) -Leaf).Substring(1).TrimEnd('}')
            [xml]$Xml = Get-Content ($File)
            if ($Xml.innerxml -like "*cpassword*" -and $Xml.innerxml -notlike '*cpassword=""*') {
                if (!(Test-Path "$outputdir\sysvol")) { New-Item -ItemType Directory -Path "$outputdir\sysvol" | Out-Null }
                Write-Both "    [!] cpassword found in file, copying to output folder (KB329)"
                Write-Both "        $File"
                Copy-Item -Path $File -Destination $outputdir\sysvol\$Distinguishedname.$Filename
                $count++
            }
        }
        Write-Progress -Activity "Searching SYSVOL *.xmls for cpassword..." -Status "Ready" -Completed
    }
    if ($count -eq 0) {
        Write-Both "    ...cpassword not found in the $($XMLFiles.count) XML files found."
    }
    else {
        $GPOxml = (Get-Content "$outputdir\sysvol\*.xml" -ErrorAction SilentlyContinue)
        $GPOxml = $GPOxml -Replace "<", "&lt;"
        $GPOxml = $GPOxml -Replace ">", "&gt;"
        Write-Nessus-Finding "GPOPasswordStorage" "KB329" "$GPOxml"
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
        "@Accounts inactive (no logon) for the past $InactiveDays days (based on lastLogonTimestamp)" |
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
    $AdministratorSAMAccountName = (Get-ADUser -Filter { SID -eq $AdministratorSID } -Properties SamAccountName).SamAccountName
    $AdministratorName = (Get-ADUser -Filter { SID -eq $AdministratorSID } -Properties SamAccountName).Name
    if ($AdministratorTranslation -contains $AdministratorSAMAccountName) {
        Write-Both "    [!] Local Administrator account (UID500) has not been renamed (KB309)"
        Write-Nessus-Finding "AdminAccountRenamed" "KB309" "Local Administrator account (UID500) has not been renamed"
    }
    else {
        $count = 0
        foreach ($AdminName in $AdministratorTranslation) {
            if ((Get-ADUser -Filter { SamAccountName -eq $AdminName })) { $count++ }
        }
        if ($count -eq 0) {
            Write-Both "    [!] Local Administrator account renamed to $AdministratorSAMAccountName ($($AdministratorName)), but a dummy account not made in it's place! (KB309)"
            Write-Nessus-Finding "AdminAccountRenamed" "KB309" "Local Admin account renamed to $AdministratorSAMAccountName ($($AdministratorName)), but a dummy account not made in it's place"
        }
    }
    $AdministratorLastLogonDate = (Get-ADUser -Filter { SID -eq $AdministratorSID } -Properties LastLogonDate).LastLogonDate
    if ($AdministratorLastLogonDate -gt (Get-Date).AddDays(-180)) {
        Write-Both "    [!] UID500 (LocalAdministrator) account is still used, last used $AdministratorLastLogonDate! (KB309)"
        Write-Nessus-Finding "AdminAccountRenamed" "KB309" "UID500 (LocalAdmini) account is still used, last used $AdministratorLastLogonDate"
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
            'Group Policy Creator Owners',
            'Protected Users',
            'Key Admins',
            'Enterprise Key Admins'
        ),

        # Tier-1 groups (membership by a DA should be considered overlap / tier mixing)
        [string[]]$Tier1Groups = @(
            'Account Operators',
            'Server Operators',
            'Backup Operators',
            'Print Operators',
            'DnsAdmins',
            'Certificate Publishers',
            'Remote Desktop Users'
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

    foreach ($m in $members) {
        try {
            $u = Get-ADUser -Identity $m.DistinguishedName -Properties Enabled,SamAccountName,Name,DistinguishedName -ErrorAction Stop

            # Effective group membership (includes nested groups)
            $groups = Get-ADPrincipalGroupMembership -Identity $u.DistinguishedName -ErrorAction Stop |
                Select-Object -ExpandProperty SamAccountName

            $groupsNorm = @($groups | Where-Object { $_ } | ForEach-Object { $_.ToString() })

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
        Set-Content -Encoding UTF8 -Path $txtPath -Value "@Disabled user accounts"
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
    $lockedAccounts = Get-ADUser -Filter * -Properties LockedOut | Where-Object { $_.LockedOut -eq $true }
    $count = 0
    $totalcount = ($lockedAccounts | Measure-Object | Select-Object Count).Count
    foreach ($account in $lockedAccounts) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for locked users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path (Get-EvidencePath 'accounts_locked.txt') -Value "Account $($account.SamAccountName) ($($account.Name)) is locked"
        $count++
    }
    Write-Progress -Activity "Searching for locked users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count locked user accounts, see accounts_locked.txt"
    }
}
Function Get-AccountPassDontExpire {
    #Lists accounts who's passwords dont expire
    $count = 0
    $nonexpiringpasswords = Search-ADAccount -PasswordNeverExpires -UsersOnly | Where-Object { $_.Enabled -eq $true }
    $totalcount = ($nonexpiringpasswords | Measure-Object | Select-Object Count).count
    foreach ($account in $nonexpiringpasswords) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for users with passwords that dont expire..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path (Get-EvidencePath 'accounts_passdontexpire.txt') -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    Write-Progress -Activity "Searching for users with passwords that dont expire..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] There are $count accounts that don't expire, see accounts_passdontexpire.txt (KB254)"
        Write-Nessus-Finding "AccountsThatDontExpire" "KB254" ([System.IO.File]::ReadAllText((Get-EvidencePath 'accounts_passdontexpire.txt')))
    }
}
Function Get-OldBoxes {
    #Lists machines running OS older than Windows Server 2019
    $count = 0
    $oldboxes = Get-ADComputer -Filter { Enabled -eq "true" -and (OperatingSystem -Like "*2016*" -or OperatingSystem -Like "*2012*" -or OperatingSystem -Like "*2008*" -or OperatingSystem -Like "*2003*" -or OperatingSystem -Like "*2000*" -or OperatingSystem -Like "*XP*" -or OperatingSystem -like '*Windows 7*' -or OperatingSystem -like '*Windows 8*' -or OperatingSystem -like '*Windows 10*' -or OperatingSystem -like '*vista*') } -Property OperatingSystem
    $totalcount = ($oldboxes | Measure-Object | Select-Object Count).count
    foreach ($machine in $oldboxes) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for unsupported OS devices joined to the domain..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path (Get-EvidencePath 'machines_old.txt') -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersion), $($machine.IPv4Address)"
        $count++
    }
    Write-Progress -Activity "Searching for unsupported OS devices joined to the domain..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] We found $count machines running an unsupported OS (older than Server 2019)! see machines_old.txt (KB3/37/38/KB259)"
        Write-Nessus-Finding "OldBoxes" "KB259" ([System.IO.File]::ReadAllText((Get-EvidencePath 'machines_old.txt')))
    }
}
if ($InactiveComputers -or ($all -and 'inactivecomputers' -notin $exclude) -or 'inactivecomputers' -in $selectedChecks) {
    $running = $true
    Write-Both "[*] Inactive Computer Objects Audit"
    Get-InactiveComputerObjects
}
Function Get-DCsNotOwnedByDA {
    #Searches for DC objects not owned by the Domain Admins group
    $count = 0
    $progresscount = 0
    $domaincontrollers = Get-ADComputer -Filter { PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 521 } -Property *
    $totalcount = ($domaincontrollers | Measure-Object | Select-Object Count).count
    if ($totalcount -gt 0) {
        foreach ($machine in $domaincontrollers) {
            $progresscount++
            Write-Progress -Activity "Searching for DCs not owned by Domain Admins group..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount * 100)
            if ($machine.ntsecuritydescriptor.Owner -ne "$env:UserDomain\$DomainAdmins") {
                Add-Content -Path (Get-EvidencePath 'dcs_not_owned_by_da.txt') -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersion), $($machine.IPv4Address), owned by $($machine.ntsecuritydescriptor.Owner)"
                $count++
            }
        }
        Write-Progress -Activity "Searching for DCs not owned by Domain Admins group..." -Status "Ready" -Completed
    }
    if ($count -gt 0) {
        Write-Both "    [!] We found $count DCs not owned by Domains Admins group! see dcs_not_owned_by_da.txt"
        Write-Nessus-Finding "DCsNotByDA" "KB547" ([System.IO.File]::ReadAllText((Get-EvidencePath 'dcs_not_owned_by_da.txt')))
    }
}
Function Get-HostDetails {
    #Gets basic information about the host
    Write-Both "    [+] Device Name:  $env:ComputerName"
    Write-Both "    [+] Domain Name:  $env:UserDomain"
    Write-Both "    [+] User Name  :  $env:UserName"
    Write-Both "    [+] NT Version :  $(Get-WinVersion)"
    Write-Both "    [+] PowerShell :  $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
    $IPAddresses = [net.dns]::GetHostAddresses("") | Select-Object -ExpandProperty IPAddressToString
    foreach ($ip in $IPAddresses) {
        if ($ip -ne "::1") {
            Write-Both "    [+] IP Address :  $ip"
        }
    }
}
Function Get-FunctionalLevel {
    #Gets the functional level for domain and forest using the current DC OS inventory
    $domain = Get-ADDomain
    $forest = Get-ADForest
    $dcs = @(Get-ADDomainController -Filter *)

    $domainLevel = [string]$domain.DomainMode
    $forestLevel = [string]$forest.ForestMode

    Write-Both "    [+] Domain functional level: $domainLevel"
    Write-Both "    [+] Forest functional level: $forestLevel"

    if (-not $dcs -or $dcs.Count -eq 0) {
        Write-Both "    [!] Unable to enumerate domain controllers to validate functional level posture."
        return
    }

    $dcCaps = @()
    foreach ($dc in $dcs) {
        $capRank = Get-ADAuditDcFunctionalLevelCapRank -DomainController $dc
        $dcCaps += [pscustomobject]@{
            Name             = $dc.HostName
            OperatingSystem  = $dc.OperatingSystem
            Version          = $dc.OperatingSystemVersion
            MaxRank          = $capRank
        }
    }

    $knownCaps = @($dcCaps | Where-Object { $null -ne $_.MaxRank })
    $unknownCaps = @($dcCaps | Where-Object { $null -eq $_.MaxRank })

    if ($unknownCaps.Count -gt 0) {
        foreach ($dc in $unknownCaps) {
            Write-Both "    [*] Unable to map DC functional-level capability from OS inventory: $($dc.Name) [$($dc.OperatingSystem)] [$($dc.Version)]"
        }
    }

    if ($knownCaps.Count -eq 0) {
        Write-Both "    [!] Unable to determine the maximum supported functional level from DC OS inventory."
        return
    }

    $supportedRank = ($knownCaps | Measure-Object -Property MaxRank -Minimum).Minimum
    $recommendedDomainMode = Get-ADAuditFunctionalLevelMode -Rank $supportedRank -Scope Domain
    $recommendedForestMode = Get-ADAuditFunctionalLevelMode -Rank $supportedRank -Scope Forest

    $domainRank = Get-ADAuditFunctionalLevelRank -Mode $domainLevel
    $forestRank = Get-ADAuditFunctionalLevelRank -Mode $forestLevel

    if ($null -ne $domainRank -and $domainRank -lt $supportedRank) {
        $message = "DomainLevel can be raised from $domainLevel to $recommendedDomainMode based on current domain controller operating systems."
        Write-Both "    [!] $message"
        Write-Nessus-Finding "FunctionalLevel" "KB546" $message
    }
    else {
        Write-Both "    [+] Domain functional level is aligned with the current domain controller operating systems."
    }

    if ($null -ne $forestRank -and $forestRank -lt $supportedRank) {
        $message = "ForestLevel can be raised from $forestLevel to $recommendedForestMode based on current domain controller operating systems."
        Write-Both "    [!] $message"
        Write-Nessus-Finding "FunctionalLevel" "KB546" $message
    }
    else {
        Write-Both "    [+] Forest functional level is aligned with the current domain controller operating systems."
    }

    if ($supportedRank -eq 10) {
        Write-Both "    [+] Domain controller inventory supports the Windows Server 2025 functional level."
    }
    elseif ($supportedRank -eq 9) {
        Write-Both "    [+] Domain controller inventory supports up to the Windows Server 2022 functional level."
    }
    elseif ($supportedRank -eq 8) {
        Write-Both "    [+] Domain controller inventory supports up to the Windows Server 2019 functional level."
    }
    elseif ($supportedRank -eq 7) {
        Write-Both "    [+] Domain controller inventory supports up to the Windows Server 2016 functional level."
    }
}
Function Get-GPOEnum {
    #Loops GPOs for some important domain-wide settings
    $AllowedJoin = @()
    $HardenNTLM = @()
    $DenyNTLM = @()
    $AuditNTLM = @()
    $NTLMAuthExceptions = @()
    $EncryptionTypesNotConfigured = $true
    $AdminLocalLogonAllowed = $true
    $AdminRPDLogonAllowed = $true
    $AdminNetworkLogonAllowed = $true
    $AllGPOs = Get-GPO -All | sort DisplayName
    foreach ($GPO in $AllGPOs) {
        $GPOreport = Get-GPOReport -Guid $GPO.Id -ReportType Xml
        #Look for GPO that allows join PC to domain
        $permissionindex = $GPOreport.IndexOf('<q1:Name>SeMachineAccountPrivilege</q1:Name>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeMachineAccountPrivilege' }).Member) ) {
                $obj = New-Object -TypeName PSObject
                $obj | Add-Member -MemberType NoteProperty -Name GPO  -Value $GPO.DisplayName
                $obj | Add-Member -MemberType NoteProperty -Name SID  -Value $member.Sid.'#text'
                $obj | Add-Member -MemberType NoteProperty -Name Name -Value $member.Name.'#text'
                $AllowedJoin += $obj
            }
        }
        #Look for GPO that hardens NTLM
        $permissionindex = $GPOreport.IndexOf('NoLMHash</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'NoLMHash' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "NoLMHash $($value.Display.DisplayBoolean)"
            $HardenNTLM += $obj
        }
        $permissionindex = $GPOreport.IndexOf('LmCompatibilityLevel</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'LmCompatibilityLevel' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "LmCompatibilityLevel $($value.Display.DisplayString)"
            $HardenNTLM += $obj
        }
        #Look for GPO that denies NTLM
        $permissionindex = $GPOreport.IndexOf('RestrictNTLMInDomain</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'RestrictNTLMInDomain' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "RestrictNTLMInDomain $($value.Display.DisplayString)"
            $DenyNTLM += $obj
        }
        #Look for GPO that audits NTLM
        $permissionindex = $GPOreport.IndexOf('AuditNTLMInDomain</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'AuditNTLMInDomain' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "AuditNTLMInDomain $($value.Display.DisplayString)"
            $AuditNTLM += $obj
        }
        $permissionindex = $GPOreport.IndexOf('AuditReceivingNTLMTraffic</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'AuditReceivingNTLMTraffic' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "AuditReceivingNTLMTraffic $($value.Display.DisplayString)"
            $AuditNTLM += $obj
        }
        #Look for GPO that allows NTLM exclusions
        $permissionindex = $GPOreport.IndexOf('DCAllowedNTLMServers</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'DCAllowedNTLMServers' }).SettingStrings.Value) ) {
                $NTLMAuthExceptions += $member
            }
        }
        #Validate Kerberos Encryption algorithm
        $permissionindex = $GPOreport.IndexOf('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes')
        if ($permissionindex -gt 0) {
            $EncryptionTypesNotConfigured = $false
            $xmlreport = [xml]$GPOreport
            $EncryptionTypes = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions.Display.DisplayFields.Field
            if (($EncryptionTypes     | Where-Object { $_.Name -eq 'DES_CBC_CRC' }             | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled DES_CBC_CRC for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'DES_CBC_MD5' }             | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled DES_CBC_MD5 for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'RC4_HMAC_MD5' }            | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled RC4_HMAC_MD5 for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'AES128_HMAC_SHA1' }        | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] AES128_HMAC_SHA1 not enabled for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'AES256_HMAC_SHA1' }        | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] AES256_HMAC_SHA1 not enabled for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'Future encryption types' } | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] Future encryption types not enabled for Kerberos!" }
        }
        #Validates Admins local logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyInteractiveLogonRight')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeDenyInteractiveLogonRight' }).Member)) {
                if ($member.Name.'#text' -match "$SchemaAdmins" -or $member.Name.'#text' -match "$DomainAdmins" -or $member.Name.'#text' -match "$EnterpriseAdmins") {
                    $AdminLocalLogonAllowed = $false
                    Add-Content -Path (Get-EvidencePath 'admin_logon_restrictions.txt') -Value "$($GPO.DisplayName) SeDenyInteractiveLogonRight $($member.Name.'#text')"
                }
            }
        }
        #Validates Admins RDP logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyRemoteInteractiveLogonRight')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeDenyRemoteInteractiveLogonRight' }).Member)) {
                if ($member.Name.'#text' -match "$SchemaAdmins" -or $member.Name.'#text' -match "$DomainAdmins" -or $member.Name.'#text' -match "$EnterpriseAdmins") {
                    $AdminRPDLogonAllowed = $false
                    Add-Content -Path (Get-EvidencePath 'admin_logon_restrictions.txt') -Value "$($GPO.DisplayName) SeDenyRemoteInteractiveLogonRight $($member.Name.'#text')"
                }
            }
        }
        #Validates Admins network logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyNetworkLogonRight')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeDenyNetworkLogonRight' }).Member)) {
                if ($member.Name.'#text' -match "$SchemaAdmins" -or $member.Name.'#text' -match "$DomainAdmins" -or $member.Name.'#text' -match "$EnterpriseAdmins") {
                    $AdminNetworkLogonAllowed = $false
                    Add-Content -Path (Get-EvidencePath 'admin_logon_restrictions.txt') -Value "$($GPO.DisplayName) SeDenyNetworkLogonRight $($member.Name.'#text')"
                }
            }
        }
    }
    #Output for join PC to domain
    foreach ($record in $AllowedJoin) {
        Write-Both "    [+] GPO [$($record.GPO)] allows [$($record.Name)] to join computers to domain"
    }
    #Output for Admins local logon restrictions
    if ($AdminLocalLogonAllowed) {
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise local logon across domain!!!"
        Write-Nessus-Finding "AdminLogon" "KB479" "No GPO restricts Domain, Schema and Enterprise local logon across domain!"
    }
    #Output for Admins RDP logon restrictions
    if ($AdminRPDLogonAllowed) {
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise RDP logon across domain!!!"
        Write-Nessus-Finding "AdminLogon" "KB479" "No GPO restricts Domain, Schema and Enterprise RDP logon across domain!"
    }
    #Output for Admins network logon restrictions
    if ($AdminNetworkLogonAllowed) {
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise network logon across domain!!!"
        Write-Nessus-Finding "AdminLogon" "KB479" "No GPO restricts Domain, Schema and Enterprise network logon across domain!"
    }
    #Output for Validate Kerberos Encryption algorithm
    if ($EncryptionTypesNotConfigured) {
        Write-Both "    [!] RC4_HMAC_MD5 enabled for Kerberos across domain!!!"
    }
    #Output for deny NTLM
    if ($DenyNTLM.count -eq 0) {
        if ($HardenNTLM.count -eq 0) {
            Write-Both "    [!] No GPO denies NTLM authentication!"
            Write-Both "    [!] No GPO explicitely restricts LM or NTLMv1!"
        }
        else {
            Write-Both "    [+] NTLM authentication hardening implemented, but NTLM not denied"
            foreach ($record in $HardenNTLM) {
                Write-Both "        [-] $($record.value)"
                Add-Content -Path (Get-EvidencePath 'ntlm_restrictions.txt') -Value "NTLM restricted by GPO [$($record.gpo)] with value [$($record.value)]"
            }
        }
    }
    else {
        foreach ($record in $DenyNTLM) {
            Add-Content -Path (Get-EvidencePath 'ntlm_restrictions.txt') -Value "NTLM restricted by GPO [$($record.gpo)] with value [$($record.value)]"
        }
    }
    #Output for NTLM exceptions
    if ($NTLMAuthExceptions.count -ne 0) {
        foreach ($record in $NTLMAuthExceptions) {
            Add-Content -Path (Get-EvidencePath 'ntlm_restrictions.txt') -Value "NTLM auth exceptions $($record)"
        }
    }
    #Output for NTLM audit
    if ($AuditNTLM.count -eq 0) {
        Write-Both "    [!] No GPO enables NTLM audit authentication!"
    }
    else {
        foreach ($record in $AuditNTLM) {
            Add-Content -Path (Get-EvidencePath 'ntlm_restrictions.txt') -Value "NTLM audit GPO [$($record.gpo)] with value [$($record.value)]"
        }
    }
}
Function Get-PrivilegedGroupMembership {
    #List Domain Admins, Enterprise Admins and Schema Admins members
    $SchemaMembers = Get-ADGroup $SchemaAdmins     | Get-ADGroupMember
    $EnterpriseMembers = Get-ADGroup $EnterpriseAdmins | Get-ADGroupMember
    $DomainAdminsMembers = Get-ADGroup $DomainAdmins     | Get-ADGroupMember
    if (($SchemaMembers | measure).count -ne 0) {
        Write-Both "    [!] Schema Admins not empty!!!"
        foreach ($member in $SchemaMembers) {
            Add-Content -Path (Get-EvidencePath 'schema_admins.txt') -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
        }
    }
    if (($EnterpriseMembers | measure).count -ne 0) {
        Write-Both "    [!] Enterprise Admins not empty!!!"
        foreach ($member in $EnterpriseMembers) {
            Add-Content -Path (Get-EvidencePath 'enterprise_admins.txt') -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
        }
    }
    foreach ($member in $DomainAdminsMembers) {
        Add-Content -Path (Get-EvidencePath 'domain_admins.txt') -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
    }
}
Function Get-DCEval {
    #Basic validation of all DCs in forest
    #Collect all DCs in forest
    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $ADs = Get-ADDomainController -Filter { Site -like "*" }
    #Validate OS version of DCs
    $osList = @()
    $ADs | ForEach-Object { $osList += $_.OperatingSystem }
    if (($osList | sort -Unique | measure).Count -eq 1) {
        Write-Both "    [+] All DCs are the same OS version of $($osList | sort -Unique)"
    }
    else {
        Write-Both "    [!] Operating system differs across DCs!!!"
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2019' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2019"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2019' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2022' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2022"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2022' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2025' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2025"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2025' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
    }
    #Validate DCs hotfix level
    if ( (( $ADs | Select-Object OperatingSystemHotfix -Unique ) | measure).count -eq 1 -or ( $ADs | Select-Object OperatingSystemHotfix -Unique ) -eq $null ) {
        Write-Both "    [+] All DCs have the same hotfix of [$($ADs | Select-Object OperatingSystemHotFix -Unique | ForEach-Object {$_.OperatingSystemHotfix})]"
    }
    else {
        Write-Both "    [!] Hotfix level differs across DCs!!!"
        $ADs | ForEach-Object {
            Write-Both "        [-] DC $($_.Name) hotfix [$($_.OperatingSystemHotfix)]"
        }
    }
    #Validate DCs Service Pack level
    if ((($ADs | Select-Object OperatingSystemServicePack -Unique) | measure).count -eq 1 -or ($ADs | Select-Object OperatingSystemServicePack -Unique) -eq $null) {
        Write-Both "    [+] All DCs have the same Service Pack of [$($ADs | Select-Object OperatingSystemServicePack -Unique | ForEach-Object {$_.OperatingSystemServicePack})]"
    }
    else {
        Write-Both "    [!] Service Pack level differs across DCs!!!"
        $ADs | ForEach-Object {
            Write-Both "        [-] DC $($_.Name) Service Pack [$($_.OperatingSystemServicePack)]"
        }
    }
    #Validate DCs OS Version
    if ((($ADs | Select-Object OperatingSystemVersion -Unique ) | measure).count -eq 1 -or ($ADs | Select-Object OperatingSystemVersion -Unique) -eq $null) {
        Write-Both "    [+] All DCs have the same OS Version of [$($ADs | Select-Object OperatingSystemVersion -Unique | ForEach-Object {$_.OperatingSystemVersion})]"
    }
    else {
        Write-Both "    [!] OS Version differs across DCs!!!"
        $ADs | ForEach-Object {
            Write-Both "        [-] DC $($_.Name) OS Version [$($_.OperatingSystemVersion)]"
        }
    }
    #List sites without GC
    $SitesWithNoGC = $false
    foreach ($Site in $Forest.Sites) {
        if (($ADs | Where-Object { $_.Site -eq $Site.Name } | Where-Object { $_.IsGlobalCatalog -eq $true }) -eq $null) {
            $SitesWithNoGC = $true
            Add-Content -Path (Get-EvidencePath 'sites_no_gc.txt') -Value "$($Site.Name)"
        }
    }
    if ($SitesWithNoGC -eq $true) {
        Write-Both "    [!] You have sites with no Global Catalog!"
    }
    #FSMO role placement. Co-location (one DC holding all roles) is normal and
    #supported, so this is informational only - not a warning. The -adhealth
    #check ('FSMO role holders') validates each holder's writability, DNS,
    #reachability, replication and the forest-root PDC time source.
    $fsmoHolders = @($ADs | Where-Object { @($_.OperationMasterRoles).Count -gt 0 })
    if ($fsmoHolders.Count -eq 1) {
        Write-Both "    [i] All FSMO roles are held by a single DC ($($fsmoHolders[0].Hostname)). Normal/supported in a single-domain forest; noted for documentation and DR. Run -adhealth to validate each FSMO holder."
    }
    #DCs with weak Kerberos algorithm (*CH* Changed below to look for msDS-SupportedEncryptionTypes to work with 2008R2)
$ADcomputers = $ADs | ForEach-Object { Get-ADComputer $_.Name -Properties msDS-SupportedEncryptionTypes }
$WeakKerberos = $false

# Mapping of encryption types
$encryptionTypes = @{
    0  = "Not defined - defaults to RC4_HMAC_MD5"
    1  = "DES_CBC_CRC"
    2  = "DES_CBC_MD5"
    3  = "DES_CBC_CRC, DES_CBC_MD5"
    4  = "RC4"
    5  = "DES_CBC_CRC, RC4"
    6  = "DES_CBC_MD5, RC4"
    7  = "DES_CBC_CRC, DES_CBC_MD5, RC4"
    8  = "AES 128"
    9  = "DES_CBC_CRC, AES 128"
    10 = "DES_CBC_MD5, AES 128"
    11 = "DES_CBC_CRC, DES_CBC_MD5, AES 128"
    12 = "RC4, AES 128"
    13 = "DES_CBC_CRC, RC4, AES 128"
    14 = "DES_CBC_MD5, RC4, AES 128"
    15 = "DES_CBC_CRC, DES_CBC_MD5, RC4, AES 128"
    16 = "AES 256"
    17 = "DES_CBC_CRC, AES 256"
    18 = "DES_CBC_MD5, AES 256"
    19 = "DES_CBC_CRC, DES_CBC_MD5, AES 256"
    20 = "RC4, AES 256"
    21 = "DES_CBC_CRC, RC4, AES 256"
    22 = "DES_CBC_MD5, RC4, AES 256"
    23 = "DES_CBC_CRC, DES_CBC_MD5, RC4, AES 256"
    24 = "AES 128, AES 256"
    25 = "DES_CBC_CRC, AES 128, AES 256"
    26 = "DES_CBC_MD5, AES 128, AES 256"
    27 = "DES_CBC_CRC, DES_CBC_MD5, AES 128, AES 256"
    28 = "RC4, AES 128, AES 256"
    29 = "DES_CBC_CRC, RC4, AES 128, AES 256"
    30 = "DES_CBC_MD5, RC4, AES 128, AES 256"
    31 = "DES_CBC_CRC, DES_CBC_MD5, RC4-HMAC, AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96"
}

foreach ($DC in $ADcomputers) {
    $encType = $DC."msDS-SupportedEncryptionTypes"
    if ($encType -ne 8 -and $encType -ne 16 -and $encType -ne 24) {
        $WeakKerberos = $true
        $hexValue = "0x{0:X}" -f $encType
        $supportedTypes = $encryptionTypes[$encType]
        Add-Content -Path (Get-EvidencePath 'dcs_weak_kerberos_ciphersuite.txt') -Value "$($DC.DNSHostName)`nDecimal Value: $encType`nHex Value: $hexValue`nSupported Encryption Types: $supportedTypes`n"
    }
}

if ($WeakKerberos) {
    Add-Content -Path (Get-EvidencePath 'dcs_weak_kerberos_ciphersuite.txt') -Value "`nLink: https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/decrypting-the-selection-of-supported-kerberos-encryption-types/1628797`n"
    Write-Both "    [!] You have DCs with RC4 or DES allowed for Kerberos!!!"
    Write-Nessus-Finding "WeakKerberosEncryption" "KB995" ([System.IO.File]::ReadAllText((Get-EvidencePath 'dcs_weak_kerberos_ciphersuite.txt')))
}
    #Check where newly joined computers go
    $newComputers = (Get-ADDomain).ComputersContainer
    $newUsers = (Get-ADDomain).UsersContainer
    Write-Both "    [+] New joined computers are stored in $newComputers"
    Write-Both "    [+] New users are stored in $newUsers"
}
Function Get-DefaultDomainControllersPolicy {
    #Enumerates Default Domain Controllers Policy for default unsecure and excessive options
    $ExcessiveDCInteractiveLogon = $false
    $ExcessiveDCBackupPermissions = $false
    $ExcessiveDCRestorePermissions = $false
    $ExcessiveDCDriverPermissions = $false
    $ExcessiveDCLocalShutdownPermissions = $false
    $ExcessiveDCRemoteShutdownPermissions = $false
    $ExcessiveDCTimePermissions = $false
    $ExcessiveDCBatchLogonPermissions = $false
    $ExcessiveDCRDPLogonPermissions = $false
    $GPO = Get-GPO 'Default Domain Controllers Policy'
    $GPOreport = Get-GPOReport -Guid $GPO.Id -ReportType Xml
    #Interactive local logon
    $permissionindex = $GPOreport.IndexOf('SeInteractiveLogonRight')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeInteractiveLogonRight' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators" -and $member.Name.'#text' -ne "$EntrepriseDomainControllers") {
                $ExcessiveDCInteractiveLogon = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeInteractiveLogonRight $($member.Name.'#text')"
            }
        }
    }
    #Batch logon
    $permissionindex = $GPOreport.IndexOf('SeBatchLogonRight')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeBatchLogonRight' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCBatchLogonPermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeBatchLogonRight $($member.Name.'#text')"
            }
        }
    }
    #RDP logon
    $permissionindex = $GPOreport.IndexOf('SeRemoteInteractiveLogonRight')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeRemoteInteractiveLogonRight' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators" -and $member.Name.'#text' -ne "$EntrepriseDomainControllers") {
                $ExcessiveDCRDPLogonPermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeRemoteInteractiveLogonRight $($member.Name.'#text')"
            }
        }
    }
    #Backup
    $permissionindex = $GPOreport.IndexOf('SeBackupPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeBackupPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCBackupPermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeBackupPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Restore
    $permissionindex = $GPOreport.IndexOf('SeRestorePrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeRestorePrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCRestorePermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeRestorePrivilege $($member.Name.'#text')"
            }
        }
    }
    #Load driver
    $permissionindex = $GPOreport.IndexOf('SeLoadDriverPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeLoadDriverPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCDriverPermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeLoadDriverPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Local shutdown
    $permissionindex = $GPOreport.IndexOf('SeShutdownPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeShutdownPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCLocalShutdownPermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeShutdownPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Remote shutdown
    $permissionindex = $GPOreport.IndexOf('SeRemoteShutdownPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeRemoteShutdownPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCRemoteShutdownPermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeRemoteShutdownPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Change time
    $permissionindex = $GPOreport.IndexOf('SeSystemTimePrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeSystemTimePrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators" -and $member.Name.'#text' -ne "$LocalService") {
                $ExcessiveDCTimePermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeSystemTimePrivilege $($member.Name.'#text')"
            }
        }
    }
    #Output for Default Domain Controllers Policy
    if ($ExcessiveDCInteractiveLogon -or $ExcessiveDCBackupPermissions -or $ExcessiveDCRestorePermissions -or $ExcessiveDCDriverPermissions -or $ExcessiveDCLocalShutdownPermissions -or $ExcessiveDCRemoteShutdownPermissions -or $ExcessiveDCTimePermissions -or $ExcessiveDCBatchLogonPermissions -or $ExcessiveDCRDPLogonPermissions) {
        Write-Both "    [!] Excessive permissions in Default Domain Controllers Policy detected!"
    }
}
Function Get-RecentChanges() {
    #Retrieve users and groups that have been created during last 30 days
    $DateCutOff = ((Get-Date).AddDays(-30)).Date
    $newUsers = Get-ADUser  -Filter { whenCreated -ge $DateCutOff } -Properties whenCreated | select whenCreated, SamAccountName
    $newGroups = Get-ADGroup -Filter { whenCreated -ge $DateCutOff } -Properties whenCreated | select whenCreated, SamAccountName
    $countUsers = 0
    $countGroups = 0
    $progresscountUsers = 0
    $progresscountGroups = 0
    $totalcountUsers = ($newUsers  | Measure-Object | Select-Object Count).count
    $totalcountGroups = ($newGroups | Measure-Object | Select-Object Count).count
    if ($totalcountUsers -gt 0) {
        # Add header line (overwrite any existing file)
"@User Created within the last 30 days" | Set-Content -Path (Get-EvidencePath 'new_users.txt')
        foreach ($newUser in $newUsers ) { Add-Content -Path (Get-EvidencePath 'new_users.txt') -Value "Account $($newUser.SamAccountName) was created $($newUser.whenCreated)" }
        Write-Both "    [!] $totalcountUsers new users were created last 30 days, see $outputdir\new_users.txt"
    }
    if ($totalcountGroups -gt 0) {
        foreach ($newGroup in $newGroups ) { Add-Content -Path (Get-EvidencePath 'new_groups.txt') -Value "Group $($newGroup.SamAccountName) was created $($newGroup.whenCreated)" }
        Write-Both "    [!] $totalcountGroups new groups were created last 30 days, see $outputdir\new_groups.txt"
    }
}
Function Get-ReplicationType {
    #Retrieve replication mechanism (FRS or DFSR)
    $objectName = "DFSR-GlobalSettings"
    $searcher = [ADSISearcher] "(objectClass=msDFSR-GlobalSettings)"
    $objectExists = $searcher.FindOne() -ne $null
    if ($objectExists) {
        $DFSRFlags = (Get-ADObject -Identity "CN=DFSR-GlobalSettings,$((Get-ADDomain).systemscontainer)" -Properties msDFSR-Flags).'msDFSR-Flags'
        switch ($DFSRFlags) {
            0 { Write-Both "    [!] Migration from FRS to DFSR is not finished. Current state: started!" }
            16 { Write-Both "    [!] Migration from FRS to DFSR is not finished. Current state: prepared!" }
            32 { Write-Both "    [!] Migration from FRS to DFSR is not finished. Current state: redirected!" }
            48 { Write-Both "    [+] DFSR mechanism is used to replicate across domain controllers." }
        }
    }
    else {
        Write-Both "    [!] FRS mechanism is still used to replicate across domain controllers, you should migrate to DFSR!"
    }
}
Function Get-RecycleBinState {
    #Check if recycle bin is enabled
    if ((Get-ADOptionalFeature -Filter 'Name -eq "Recycle Bin Feature"').EnabledScopes) {
        Write-Both "    [+] Recycle Bin is enabled in the domain"
    }
    else {
        Write-Both "    [!] Recycle Bin is disabled in the domain, you should consider enabling it!"
    }
}
Function Get-CriticalServicesStatus {
    #Check AD services status
    Write-Both "    [+] Checking services on all DCs"
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    $searcher = [ADSISearcher] "(objectClass=msDFSR-GlobalSettings)"
    $objectExists = $searcher.FindOne() -ne $null
    if ($objectExists) {
        $services = @("dns", "netlogon", "kdc", "w32time", "dfsr")
    }
    else {
        $services = @("dns", "netlogon", "kdc", "w32time", "ntfrs")
    }

    foreach ($DC in $dcList) {
        foreach ($service in $services) {
            try {
                $checkService = Get-ADAuditCimInstance -ClassName Win32_Service -ComputerName $DC -Filter "Name='$service'"
                if (-not $checkService) {
                    Write-Both "        [!] Service $service cannot be checked on $DC!"
                    continue
                }

                $serviceStatus = [string]$checkService.State
                if (-not $serviceStatus) {
                    Write-Both "        [!] Service $service cannot be checked on $DC!"
                }
                elseif ($serviceStatus -ne "Running") {
                    Write-Both "        [!] Service $service is not running on $DC!"
                }
            }
            catch {
                Write-Both "        [!] Service $service cannot be checked on $DC!"
            }
        }
    }
}
Function Get-LastWUDate {
    #Check Windows update status and last install date
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    $lastMonth = (Get-Date).AddDays(-30)
    Write-Both "    [+] Checking Windows Update"
    foreach ($DC in $dcList) {
        try {
            $wuService = Get-ADAuditCimInstance -ClassName Win32_Service -ComputerName $DC -Filter "Name='wuauserv'"
            $startMode = $wuService.StartMode
            if (-not $startMode) {
                Write-Both "        [!] Windows Update service cannot be checked on $DC!"
            }
            elseif ($startMode -eq "Disabled") {
                Write-Both "        [!] Windows Update service is disabled on $DC!"
            }
        }
        catch {
            Write-Both "        [!] Windows Update service cannot be checked on $DC!"
        }
    }

    $progresscount = 0
    $totalcount = ($dcList | Measure-Object | Select-Object -ExpandProperty Count)
    foreach ($DC in $dcList) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for last Windows Update installation on all DCs..." -Status "Currently searching on $DC" -PercentComplete ($progresscount / $totalcount * 100)
        try {
            $lastHotfix = (Get-HotFix -ComputerName $DC | Where-Object { $_.InstalledOn -ne $null } | Sort-Object -Descending InstalledOn | Select-Object -First 1).InstalledOn
            if ($lastHotfix -lt $lastMonth) {
                Write-Both "        [!] Windows is not up to date on $DC, last install: $lastHotfix"
            }
            else {
                Write-Both "        [+] Windows is up to date on $DC, last install: $lastHotfix"
            }
        }
        catch {
            Write-Both "        [!] Cannot check last update date on $DC"
        }
        $progresscount++
    }
    Write-Progress -Activity "Searching for last Windows Update installation on all DCs..." -Status "Ready" -Completed
}
Function Get-TimeSource {
    #Get NTP sync source
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    Write-Both "    [+] Checking NTP configuration"
    foreach ($DC in $dcList) {
        $ntpSource = w32tm /query /source /computer:$DC
        if ($ntpSource -like '*0x800706BA*') {
            Write-Both "        [!] Cannot get time source for $DC"
        }
        else {
            Write-Both "        [+] $DC is syncing time from $ntpSource"
        }
    }
}
Function Get-RODC {
    #Check for RODC
    Write-Both "    [+] Checking for Read Only DCs"
    $ADs = Get-ADDomainController -Filter { Site -like "*" }
    $ADs | ForEach-Object {
        if ($_.IsReadOnly) {
            Write-Both "        [+] DC $($_.Name) is a RODC server!"
        }
    }
}
Function Install-Dependencies {
    #Install optional dependency modules for the audit
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch { }

    Write-Both "    [+] Preparing optional dependency installation"

    try {
        if (Get-Command Install-PSResource -ErrorAction SilentlyContinue) {
            $repo = Get-PSResourceRepository -Name PSGallery -ErrorAction SilentlyContinue
            if ($repo -and -not $repo.Trusted) {
                Set-PSResourceRepository -Name PSGallery -Trusted -ErrorAction Stop
            }

            if (-not (Get-Module -ListAvailable -Name DSInternals)) {
                Install-PSResource -Name DSInternals -Scope CurrentUser -TrustRepository -ErrorAction Stop
            }
        }
        elseif (Get-Command Install-Module -ErrorAction SilentlyContinue) {
            $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
            if ($repo -and $repo.InstallationPolicy -eq 'Untrusted') {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            }

            if (-not (Get-Module -ListAvailable -Name DSInternals)) {
                Install-Module -Name DSInternals -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            }
        }
        else {
            Write-Both "    [!] No supported PowerShell package manager was found. Install DSInternals manually."
            return
        }

        if (Import-ADAuditModule -Name DSInternals) {
            Write-Both "    [+] DSInternals module is available."
        }
        else {
            Write-Both "    [!] DSInternals installation completed, but the module could not be imported in the current session."
        }

        if (Get-Module -ListAvailable -Name LAPS) {
            Write-Both "    [+] Windows LAPS module is available on this host."
        }
        elseif (Get-Module -ListAvailable -Name 'AdmPwd.PS') {
            Write-Both "    [+] Legacy Microsoft LAPS module (AdmPwd.PS) is available on this host."
        }
        else {
            Write-Both "    [*] No LAPS module was found. Windows LAPS ships with supported Windows builds; legacy Microsoft LAPS uses AdmPwd.PS."
        }
    }
    catch {
        Write-Both "    [!] Failed to install optional dependencies. $($_.Exception.Message)"
    }
}
Function Remove-StringLatinCharacters {
    #Removes latin characters
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
}

function Add-KerberoastExplanationToPasswordQualityReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportPath,
        [Parameter(Mandatory = $false)]
        [string]$DomainController
    )

    if (-not (Test-Path -LiteralPath $ReportPath)) { return }

    $lines = Get-Content -LiteralPath $ReportPath
    $header = 'These accounts are susceptible to the Kerberoasting attack:'

    # Find the simple list block under the header
    $headerIndex = [array]::IndexOf($lines, $header)
    if ($headerIndex -lt 0) { return }

    # Collect the simple list items that follow the header (until a blank line)
    $simpleList = @()
    for ($i = $headerIndex + 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()
        if (-not $line) { break }
        $simpleList += $lines[$i]
    }

    if ($simpleList.Count -eq 0) { return }

    # Normalize SAM names
    $kerberoastAccounts = @()
    foreach ($l in $simpleList) {
        $trimmed = $l.Trim()
        if ($trimmed) { $kerberoastAccounts += $trimmed }
    }

    # Split into krbtgt vs service accounts
    $krbtgtAccounts  = @()
    $serviceAccounts = @()
    foreach ($acct in $kerberoastAccounts) {
        $sam = $acct
        if ($acct -like '*\*') {
            $parts = $acct.Split('\', 2)
            $sam   = $parts[1]
        }
        if ($sam -ieq 'krbtgt') { $krbtgtAccounts += $acct } else { $serviceAccounts += $acct }
    }

    # Optional: krbtgt details
    $krbtgtInfo = $null
    if ($krbtgtAccounts.Count -gt 0 -and $DomainController) {
        try {
            $krbtgtInfo = Get-ADUser -Server $DomainController -Filter { SamAccountName -eq 'krbtgt' } -Properties PasswordLastSet -ErrorAction Stop
        } catch { }
    }

    # Build replacement
    $replacement = New-Object System.Collections.Generic.List[string]
    $replacement.Add($header)

    if ($krbtgtAccounts.Count -gt 0) {
        $replacement.Add('  Password not changed in at least 180 days for the built-in krbtgt account (Golden Ticket / ticket-forgery risk):')
        foreach ($acct in $krbtgtAccounts) { $replacement.Add(("    {0}" -f $acct)) }
        $replacement.Add('  Reference: Microsoft guidance "Reset the krbtgt account password".')
        $replacement.Add('')
    }

    if ($serviceAccounts.Count -gt 0) {
        $replacement.Add('  The account is a user or service account with a password that could be weak / brute-forceable (Kerberoastable due to SPN / service ticket exposure):')
        foreach ($acct in $serviceAccounts) { $replacement.Add(("    {0}" -f $acct)) }
        $replacement.Add('  Reference: Microsoft security guidance on mitigating Kerberoasting.')
        $replacement.Add('')
    }

    # Splice into file
    $endOfBlock = $headerIndex + 1 + $simpleList.Count
    $newContent = @()
    if ($headerIndex -gt 0) { $newContent += $lines[0..($headerIndex-1)] }
    $newContent += $replacement
    if ($endOfBlock -lt $lines.Count) { $newContent += $lines[$endOfBlock..($lines.Count-1)] }

    Set-Content -LiteralPath $ReportPath -Value $newContent
}

Function Get-PasswordQuality {
    # Use DSInternals to evaluate password quality (supports remote execution)
    # Output is split into category-specific files for easier consumption and reporting.
    if (Import-ADAuditModule -Name DSInternals) {
        try {
            $cfgNC = (Get-ADRootDSE).ConfigurationNamingContext

            $sites = Get-ADObject `
                -LDAPFilter '(objectClass=site)' `
                -SearchBase $cfgNC `
                -ErrorAction Stop

            $totalSite = ($sites | Measure-Object).Count
            $count = 0

            foreach ($site in $sites) {
                if ($site.Name -eq (Remove-StringLatinCharacters $site.Name)) {
                    $count++
                }
            }

            if ($count -ne $totalSite) {
                Write-Both "    [!] One or more sites have illegal characters in their name, can't get password quality!"
                return
            }
        }
        catch {
            Write-Both "    [!] Failed to enumerate AD sites for password quality test: $($_.Exception.Message)"
            return
        }

        # Determine a single DC to query (fallback chain to ensure we get a plain string)
        $dcObj = Get-ADDomainController -Discover
        $dc = $dcObj.DNSHostName
        if (-not $dc) { $dc = $dcObj.HostName }
        if (-not $dc) { $dc = $dcObj.Name }
        if (-not $dc -or [string]::IsNullOrWhiteSpace($dc)) {
            Write-Both "    [!] Could not determine a domain controller hostname for password quality test."
            return
        }
        $dc = [string]$dc

        try {
            $domain = Get-ADDomain
            $domainDN = $domain.DistinguishedName

            $accounts = Get-ADReplAccount `
                -All `
                -Server $dc `
                -NamingContext $domainDN `
                -ErrorAction Stop

            if ($accounts) {
                # Run DSInternals password quality test and capture the full report
                $passwordQualityPath = Get-EvidencePath 'password_quality.txt'

                $accounts |
                    Test-PasswordQuality -IncludeDisabledAccounts |
                    Out-File -FilePath $passwordQualityPath

                if (Test-Path $passwordQualityPath) {
                    Write-Both "    [!] Password quality test done, see password_quality.txt"

                    # Post-process the DSInternals report to clarify why accounts are marked as Kerberoastable
                    try {
                        Add-KerberoastExplanationToPasswordQualityReport `
                            -ReportPath $passwordQualityPath `
                            -DomainController $dc
                    }
                    catch {
                        Write-Both "    [*] Failed to append Kerberoast clarification to password quality report: $($_.Exception.Message)"
                    }

                    # Split the combined report into category-specific files
                    try {
                        Split-PasswordQualityReport -ReportPath $passwordQualityPath
                    }
                    catch {
                        Write-Both "    [*] Failed to split password quality report into category files: $($_.Exception.Message)"
                    }
                }
                else {
                    Write-Both "    [!] Password quality test ran but output file was not created."
                }
            }
            else {
                Write-Both "    [!] No replication accounts retrieved from DC $dc; skipping password quality test."
            }
        }
        catch {
            # Delimit $dc to avoid $dc: being parsed as an (invalid) scope qualifier
            Write-Both "    [!] Failed password quality test on DC ${dc}: $($_.Exception.Message)"
        }
    }
    else {
        Write-Both "    [!] DSInternals module not available; skipping password quality test."
    }
}

function Split-PasswordQualityReport {
    # Parses the combined password_quality.txt from DSInternals Test-PasswordQuality and writes
    # each section into a dedicated evidence file.  The original combined file is kept intact.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportPath
    )

    if (-not (Test-Path -LiteralPath $ReportPath)) { return }

    $allLines = @(Get-Content -LiteralPath $ReportPath -ErrorAction Stop)
    if ($allLines.Count -eq 0) { return }

    # Map each DSInternals section header to a target evidence file name and a nessus KB id
    $sectionMap = [ordered]@{
        'Passwords of these accounts are stored using reversible encryption:'                    = @{ File = 'pq_reversible_encryption.txt';       KB = 'KB997';  Severity = 'Critical'; Label = 'reversible encryption' }
        'LM hashes of passwords of these accounts are present:'                                 = @{ File = 'pq_lm_hashes.txt';                   KB = 'KB998';  Severity = 'Critical'; Label = 'LM hashes present' }
        'These accounts have no password set:'                                                  = @{ File = 'pq_no_password.txt';                 KB = 'KB999';  Severity = 'Critical'; Label = 'no password set' }
        'Passwords of these accounts have been found in the dictionary:'                        = @{ File = 'pq_dictionary_passwords.txt';        KB = 'KB1000'; Severity = 'Critical'; Label = 'dictionary passwords' }
        'Historical passwords of these accounts have been found in the dictionary:'             = @{ File = 'pq_historical_dictionary.txt';       KB = 'KB1001'; Severity = 'Medium';   Label = 'historical dictionary passwords' }
        'These groups of accounts have the same passwords:'                                     = @{ File = 'pq_duplicate_passwords.txt';         KB = 'KB1002'; Severity = 'High';     Label = 'duplicate passwords' }
        'These computer accounts have default passwords:'                                       = @{ File = 'pq_default_computer_passwords.txt';  KB = 'KB1003'; Severity = 'High';     Label = 'default computer passwords' }
        'Kerberos AES keys are missing from these accounts:'                                    = @{ File = 'pq_missing_aes_keys.txt';            KB = 'KB1004'; Severity = 'Medium';   Label = 'missing Kerberos AES keys' }
        'Kerberos pre-authentication is not required for these accounts:'                       = @{ File = 'pq_no_preauth.txt';                  KB = 'KB1005'; Severity = 'High';     Label = 'Kerberos pre-auth not required' }
        'Only DES encryption is allowed to be used with these accounts:'                        = @{ File = 'pq_des_only.txt';                    KB = 'KB1006'; Severity = 'Critical'; Label = 'DES-only encryption' }
        'These administrative accounts are allowed to be delegated to a service:'               = @{ File = 'pq_admin_delegation.txt';            KB = 'KB1007'; Severity = 'High';     Label = 'admin accounts delegatable' }
        'Passwords of these accounts will never expire:'                                        = @{ File = 'pq_password_never_expires.txt';      KB = 'KB1008'; Severity = 'Medium';   Label = 'password never expires' }
        'These accounts are not required to have a password:'                                   = @{ File = 'pq_password_not_required.txt';       KB = 'KB1009'; Severity = 'High';     Label = 'password not required' }
        'These accounts are susceptible to the Kerberoasting attack:'                           = @{ File = 'pq_kerberoastable.txt';              KB = 'KB1010'; Severity = 'High';     Label = 'Kerberoastable accounts' }
    }

    # Build a list of known headers for quick lookup
    $knownHeaders = $sectionMap.Keys

    # Parse the file into sections
    $sections = [ordered]@{}
    $currentHeader = $null
    $currentLines  = New-Object 'System.Collections.Generic.List[string]'

    foreach ($line in $allLines) {
        $trimmed = $line.Trim()

        # Check if this line is a known section header
        $matchedHeader = $null
        foreach ($h in $knownHeaders) {
            if ($trimmed -eq $h) {
                $matchedHeader = $h
                break
            }
        }

        if ($matchedHeader) {
            # Save previous section if any
            if ($currentHeader) {
                $sections[$currentHeader] = $currentLines.ToArray()
            }
            $currentHeader = $matchedHeader
            $currentLines  = New-Object 'System.Collections.Generic.List[string]'
        }
        elseif ($currentHeader) {
            $currentLines.Add($line) | Out-Null
        }
    }
    # Save last section
    if ($currentHeader) {
        $sections[$currentHeader] = $currentLines.ToArray()
    }

    $filesWritten = 0

    foreach ($header in $sections.Keys) {
        $bodyLines = $sections[$header]
        # Strip leading/trailing blank lines and get account entries
        $accountEntries = @($bodyLines | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })

        if ($accountEntries.Count -eq 0) { continue }

        $meta = $sectionMap[$header]
        if (-not $meta) { continue }

        $targetPath = Get-EvidencePath $meta.File

        $fileContent = @"
=====================================================================
 PASSWORD QUALITY: $($meta.Label.ToUpper())
=====================================================================
 Source    : DSInternals Test-PasswordQuality
 Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
 Accounts  : $($accountEntries.Count)
---------------------------------------------------------------------

$header

"@
        # For "groups of accounts have the same passwords" the format is different (grouped)
        # so we write the raw block preserving structure, plus an explanatory note
        # about NTLM hash equality and the security risk it represents.
        if ($header -match 'groups of accounts have the same passwords') {
            $fileContent += @"
WHY THIS MATTERS
---------------------------------------------------------------------
DSInternals identified the accounts below by comparing NTLM password
hashes pulled from NTDS.dit. Every account listed in the same group
has the IDENTICAL NTLM hash, which means they share the EXACT SAME
plaintext password (NTLM is an unsalted MD4 over the UTF-16 password,
so equal hash <=> equal password).

Risk:
  - One credential compromise unlocks every account in the group at
    once. An attacker who obtains the NTLM hash from one account
    (Mimikatz, DCSync, kerberoasting, LSASS dump, etc.) can pass-the-
    hash to every other account that shares it - including across
    privilege tiers if a low-tier account happens to share a password
    with a high-tier one.
  - Service accounts and admin accounts that share a password with
    user accounts are an immediate lateral-movement path.
  - Password reuse across users defeats lockout, auditing per-user
    accountability, and any "rotate one account's password" response.

Each blank-line-separated block below is one group of accounts that
share the same NTLM hash (i.e. the same password):

---------------------------------------------------------------------

"@
            $fileContent += ($bodyLines -join "`n")
        }
        else {
            foreach ($entry in $accountEntries) {
                $fileContent += "  $entry`n"
            }
        }

        $fileContent += @"

---------------------------------------------------------------------
 Total accounts: $($accountEntries.Count)
=====================================================================
"@

        Set-Content -LiteralPath $targetPath -Value $fileContent -Encoding UTF8
        $filesWritten++

        Write-Both "    [+] Password quality category: $($meta.Label) - $($accountEntries.Count) accounts -> $($meta.File)"

        # Write nessus finding for each non-empty category
        Write-Nessus-Finding "PasswordQuality_$($meta.Label -replace '\s+','_')" $meta.KB $fileContent
    }

    if ($filesWritten -gt 0) {
        Write-Both "    [+] Password quality report split into $filesWritten category files"
    }
}


Function Check-Shares {
    #Check SYSVOL and NETLOGON share exists
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    Write-Both "    [+] Checking SYSVOL and NETLOGON shares on all DCs"
    foreach ($DC in $dcList) {
        try {
            $shareList = @(Get-ADAuditCimInstance -ClassName Win32_Share -ComputerName $DC)
        }
        catch {
            $shareList = @()
        }

        if (-not $shareList -or $shareList.Count -eq 0) {
            Write-Both "        [!] Cannot test shares on $DC!"
        }
        else {
            $sysvolShare = ($shareList | Where-Object { $_.Name -eq 'SYSVOL' } | Measure-Object).Count
            $netlogonShare = ($shareList | Where-Object { $_.Name -eq 'NETLOGON' } | Measure-Object).Count
            if ($sysvolShare -eq 0) { Write-Both "        [!] SYSVOL share is missing on $DC!" }
            if ($netlogonShare -eq 0) { Write-Both "        [!] NETLOGON share is missing on $DC!" }
        }
    }
}
Function Get-ADCSVulns {
    #Check for ADCS Vulnerabiltiies, ESC1,2,3,4 and 8. ESC8 will output to a different issues mapped to Nessus. 
    $certutil_output = certutil -v -template
    $certutil_lines = $certutil_output.Trim().Split("`n")
    $templates = @()
    $current_template = ""

    foreach ($line in $certutil_lines) {
        if ($line.StartsWith("Template[")) {
            if ($current_template) {
                $template_unparsed = $current_template.TrimEnd(",").Split(",")
                $SuppliesSubjectCheck = $false
                $ClientAuthCheck = $false
                $AllowEnrollCheck = $false
                $AnyPurposeCheck = $false
                $AllowWriteCheck = $false
                $AllowFullControl = $false
                $CertificateRequestAgentCheck = $false
                $TemplatePropCommonName = $null

                foreach ($detail in $template_unparsed) {
                    if ($detail -like "*TemplatePropCommonName =*") { $TemplatePropCommonName = $detail.Split("=")[1].Trim() }
                    if ($detail -like "*CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 1*") { $SuppliesSubjectCheck = $true }
                    if ($detail -like "*Client Authentication*") { $ClientAuthCheck = $true }
                    if ($detail -match "^\s*Allow Enroll\s+.*\\Authenticated Users\s*$|^\s*Allow Enroll\s+.*\\Domain Users\s*$") { $AllowEnrollCheck = $true }
                    if ($detail -like "2.5.29.37.0 Any Purpose") { $AnyPurposeCheck = $true }
                    if ($detail -match "^\s*Allow Write\s+.*\\Authenticated Users\s*$|^\s*Allow Write\s+.*\\Domain Users\s*$") { $AllowWriteCheck = $true }
                    if ($detail -match "^\s*Allow Full Control\s+.*\\Authenticated Users\s*$|^\s*Allow Full Control\s+.*\\Domain Users\s*$") { $AllowFullControl = $true }
                    if ($detail -like "Certificate Request Agent (1.3.6.1.4.1.311.20.2.1)") { $CertificateRequestAgentCheck = $true }
                }

                $templates += [pscustomobject]@{
                    SuppliesSubjectCheck         = $SuppliesSubjectCheck
                    ClientAuthCheck              = $ClientAuthCheck
                    AllowEnrollCheck             = $AllowEnrollCheck
                    AnyPurposeCheck              = $AnyPurposeCheck
                    AllowWriteCheck              = $AllowWriteCheck
                    AllowFullControl             = $AllowFullControl
                    TemplatePropCommonName       = $TemplatePropCommonName
                    CertificateRequestAgentCheck = $CertificateRequestAgentCheck
                }
            }
            $current_template = $line + ","
        } else {
            $current_template += $line + ","
        }
    }

    # Check for ESC1
    # ESC1 = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1 and  Client Authentication and ( enroll or full control )

    $ESC1 = @()
    $ESC1e = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowEnrollCheck }
    $ESC1f = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowFullControl }
    $ESC1w = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowWriteCheck }
    $ESC1 += $ESC1e
    $ESC1 += $ESC1f
    $ESC1 += $ESC1w
    # Remove duplicates
    $ESC1 = $ESC1 | Select-Object -Property TemplatePropCommonName -unique
    $ESC2 = $templates | Where-Object { $_.AnyPurposeCheck -and $_.AllowEnrollCheck }
    $ESC3 = $templates | Where-Object { $_.CertificateRequestAgentCheck -and $_.AllowEnrollCheck }
    $ESC4 = $templates | Where-Object { $_.AllowWriteCheck -or $_.AllowFullControl }

    $template_path = Get-EvidencePath 'vulnerable_templates.txt'
    $web_enrollment_path = Get-EvidencePath 'web_enrollment.txt'

    foreach ($template in $ESC1) {
        $ESC1line = "ESC1 Vulnerable Templates:" + $template.TemplatePropCommonName
        Add-Content -Path $template_path -Value $ESC1line
        Write-Both "    [!] $ESC1line"
    }
    foreach ($template in $ESC2) {
        $ESC2line = "ESC2 Vulnerable Templates:" + $template.TemplatePropCommonName
        Add-Content -Path $template_path -Value $ESC2line
        Write-Both "    [!] $ESC2line"
    }
    foreach ($template in $ESC3) {
        $ESC3line = "ESC3 Vulnerable Templates:" + $template.TemplatePropCommonName
        Add-Content -Path $template_path -Value $ESC3line
        Write-Both "    [!] $ESC3line"
    }
    foreach ($template in $ESC4) {
        $ESC4line = "ESC4 Vulnerable Templates:" + $template.TemplatePropCommonName
        Add-Content -Path $template_path -Value $ESC4line
        Write-Both "    [!] $ESC4line"
    }
    # ESC8 Check, If error 401 and response is unauthorized, then vulnerable
    try {
        $certInfo = & certutil
        $serverName = ($certInfo | Select-String 'Server:' | Select-Object -First 1).ToString().Split(':')[1].Trim().Replace('"', '')
        $response = Invoke-WebRequest -Uri ("http://$serverName/certsrv/") -ErrorAction Stop
        $response
    }
    catch {
        # If error and response is unauthorised, then vulnerable
        if ($_.Exception.Response.StatusCode -eq 401) {
            Add-Content -Path $web_enrollment_path -Value "ESC8 Vulnerable: Endpoint located at http://$serverName/certsrv/"
            Write-Both "    [!] ESC8 Vulnerable: Endpoint located at http://$serverName/certsrv/"
        }
        else {
            Write-Both "    [+] ESC8 not vulnerable"
        }
    }
    if (Test-Path (Get-EvidencePath 'web_enrollment.txt')) {
        Write-Nessus-Finding "Active Directory Certificate Service Web Enrollment Enabled in HTTP" "KB1095" ([System.IO.File]::ReadAllText((Get-EvidencePath 'web_enrollment.txt')))
    }
    if (Test-Path (Get-EvidencePath 'vulnerable_templates.txt')) {
        Write-Nessus-Finding "Active Directory Certificate Service Vulnerable Templates" "KB1096" ([System.IO.File]::ReadAllText((Get-EvidencePath 'vulnerable_templates.txt')))
    }
}

Function Get-SPNs {
    [CmdletBinding()]
    param(
        # Optional: explicitly target a DC when running from a jump server
        [string]$Server
    )

    # Ensure AD module is available (required on JUMP/RSAT host)
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        throw "The ActiveDirectory module is not available. Install RSAT / AD DS tools on this host."
    }

    Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null

    # If no DC specified, let AD pick one
    if (-not $Server) {
        try {
            $Server = (Get-ADDomainController -Discover -ErrorAction Stop).HostName
        }
        catch {
            throw "Unable to discover a domain controller. Specify -Server explicitly or check network/credentials."
        }
    }

    Write-Both "    [+] Using domain controller: $Server"

    # Default/high-value groups we care about
    $default_groups = @(
        # Core AD Tier 0
        "Enterprise Admins",
        "Domain Admins",
        "Schema Admins",
        "Administrators",
    
        # Domain Controllers / AD control plane
        "Domain Controllers",
        "Read-only Domain Controllers",
        "Group Policy Creator Owners",
    
        # Built-in privileged operator groups (often overlooked Tier 0)
        "Account Operators",
        "Server Operators",
        "Backup Operators",
        "Print Operators",
    
        # Privilege escalation vectors
        "DnsAdmins",
        "Cryptographic Operators",
    
        # Exchange (only if Exchange on-prem exists)
        "Exchange Servers",
        "Exchange Trusted Subsystem",
        "Organization Management"
    )

    $base_groups = @()

    foreach ($group in $default_groups) {
        try {
            $ADGrp = Get-ADGroup -Identity $group -Server $Server -ErrorAction Stop
            if ($ADGrp) {
                $base_groups += $ADGrp.Name
            }
        }
        catch {
            # Ignore missing groups in this environment
            Write-Both "    [*] Skipping non-existent group '$group' on $Server."
        }
    }

    $all_groups = @()
    $all_groups += $base_groups

    # Single-level nested groups
    foreach ($group in $base_groups) {
        try {
            $ADGrp = Get-ADGroup -Identity $group -Server $Server -ErrorAction Stop
            $QueryResult = Get-ADGroup -LDAPFilter "(&(objectCategory=group)(memberof=$($ADGrp.DistinguishedName)))" -Server $Server
            foreach ($result in $QueryResult) {
                if ($all_groups -notcontains $result.Name) {
                    $all_groups += $result.Name
                }
            }
        }
        catch {
            # Non-fatal; just continue
        }
    }

    # Recursively walk nested groups
    while ($base_groups.Count -gt 0) {
        $new_groups = @()
        foreach ($group in $base_groups) {
            try {
                $ADGrp = Get-ADGroup -Identity $group -Server $Server -ErrorAction Stop
                $QueryResult = Get-ADGroup -LDAPFilter "(&(objectCategory=group)(memberof=$($ADGrp.DistinguishedName)))" -Server $Server
                foreach ($result in $QueryResult) {
                    if ($all_groups -notcontains $result.Name) {
                        $all_groups += $result.Name
                        $new_groups += $result.Name
                    }
                }
            }
            catch {
                # Ignore failures
            }
        }
        $base_groups = $new_groups
    }

    # Prepare output file on *local* machine (DC or jump host)
    $spnFile = Get-EvidencePath 'SPNs.txt'
    New-Item -Path $spnFile -ItemType File -Force | Out-Null
    Clear-Content -Path $spnFile -ErrorAction SilentlyContinue

    Write-Both "    [+] Enumerating SPN-bearing user accounts from DC: $Server"

    # Get all objects with SPNs, restrict to users
    $SPNs = Get-ADObject -Server $Server -Filter { serviceprincipalname -like "*" } -Properties MemberOf,objectClass |
            Where-Object { $_.ObjectClass -eq "user" } |
            ForEach-Object {
                $groups = @()
                if ($_.MemberOf) {
                    $groups = $_.MemberOf | Get-ADObject -Server $Server | Where-Object { $_.ObjectClass -eq "group" }
                }
                $_ | Select-Object Name, @{
                    Name       = "Groups"
                    Expression = { $groups.Name -join ',' }
                }
            }

    $high_value_users = @()

    foreach ($spn in $SPNs) {
        if (-not $spn.Groups) {
            continue
        }

        $spn_groups = $spn.Groups.Split(',') | Where-Object { $_ -and $_.Trim() -ne "" }
        $name = $spn.Name

        foreach ($spn_group in $spn_groups) {
            if ($all_groups -contains $spn_group) {
                if ($high_value_users.Name -notcontains $name) {
                    $user = [PSCustomObject]@{
                        Name  = $name
                        Group = $spn_group
                    }
                    $high_value_users += $user
                }
            }
        }
    }

    if ($high_value_users.Count -eq 0) {
        Write-Both "    [+] No high value kerberoastable user accounts identified."
        Add-Content -Path $spnFile -Value "No high value kerberoastable user accounts identified."
    }
    else {
        foreach ($user in $high_value_users) {
            $kerbuser = '    [!]' + $user.Name + ' in groups: ' + $user.Group
            Write-Both $kerbuser
            Add-Content -Path $spnFile -Value $user.Name
        }
    }

    # Safe ReadAllText regardless of DC vs jump server
    $spnContent = [System.IO.File]::ReadAllText($spnFile)
    Write-Nessus-Finding "Kerberoast Attack - Services Configured With a Weak Password" "KB611" $spnContent
}

function Get-ADUsersWithoutPreAuth {
    try {
        $asrepUsers = Get-ADUser -Filter 'DoesNotRequirePreAuth -eq True -and Enabled -eq True' `
                                 -Properties SamAccountName, Name, userAccountControl
    }
    catch {
        $asrepUsers = @()
    }

    if (-not $asrepUsers -or $asrepUsers.Count -eq 0) {
        $asrepUsers = Get-ADUser -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
                                 -Properties SamAccountName, Name, userAccountControl
    }

    $asrepUsers = $asrepUsers | Select-Object SamAccountName, Name, userAccountControl

    if (-not $asrepUsers -or $asrepUsers.Count -eq 0) {
        Write-Both "    [+] No ASREP Accounts"
        return
    }

    $asrepPath = Get-EvidencePath 'ASREP.txt'
    $header = @(
        'AS-REP Roastable accounts detected (DONT_REQ_PREAUTH set).',
        '',
        'To list all vulnerable accounts:',
        "  Get-ADUser -Filter 'DoesNotRequirePreAuth -eq True -and Enabled -eq True' | Select SamAccountName, Enabled",
        '  # Or LDAP bitwise (server-side):',
        "  Get-ADUser -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' | Select SamAccountName, Enabled",
        '',
        'Mitigate (clear DONT_REQ_PREAUTH bit 0x00400000):',
        '  $u = Get-ADUser <username> -Properties userAccountControl',
        '  Set-ADUser <username> -Replace @{userAccountControl = ($u.userAccountControl -band (-bnot 0x00400000))}',
        '',
        'Force password reset (must meet domain policy):',
        '  Set-ADAccountPassword -Identity <username> -Reset -NewPassword (Read-Host -AsSecureString)',
        '',
        '------------------------------------------------------------',
        '',
        'Accounts (Display Name (sAMAccountName)) with per-account commands:'
    )
    $header | Set-Content -LiteralPath $asrepPath -Encoding UTF8

    foreach ($user in $asrepUsers) {
        $display = ("{0} ({1})" -f $user.Name, $user.SamAccountName)
        Write-Both ("    [!] AS-REP Roastable user: {0}" -f $display)

        @(
            $display,
            '      # Verify vulnerable bit (non-zero means vulnerable):',
            "      (Get-ADUser '$($user.SamAccountName)' -Properties userAccountControl).userAccountControl -band 0x00400000",
            '      # Mitigate (clear bit 0x00400000):',
            "      `$u = Get-ADUser '$($user.SamAccountName)' -Properties userAccountControl",
            "      Set-ADUser '$($user.SamAccountName)' -Replace @{userAccountControl = (`$u.userAccountControl -band (-bnot 0x00400000))}",
            '      # Optional: force password reset (use compliant password):',
            "      Set-ADAccountPassword -Identity '$($user.SamAccountName)' -Reset -NewPassword (Read-Host -AsSecureString)",
            ''
        ) | Add-Content -LiteralPath $asrepPath -Encoding UTF8
    }

    Write-Nessus-Finding "AS-REP Roasting Attack" "KB720" ([System.IO.File]::ReadAllText($asrepPath))
}

function Get-LDAPSecurity {
    # Check if LDAP signing is enabled
    $computerName = $env:COMPUTERNAME
    
    # Check if LDAP signing is enabled
    try {
        $ldapSigning = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters -Name "LDAPServerIntegrity" -ErrorAction Stop).LDAPServerIntegrity

        if ($ldapSigning -eq 2) {
            Write-Both "    [+] LDAP signing is enabled on $computerName"
        }
        else {
            Write-Both "    [!] Issue identified LDAP signing is not enabled on $computerName, the registry value is currently set to $ldapSigning."
            Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "LDAP signing is not enabled on $computerName, the registry key does not exist"
            Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP signing is not enabled on $computerName, the registry key does not exist"
        }
    }
    catch {
        Write-Both "    [!] Issue identified LDAP signing is not enabled on $computerName, the registry key does not exist."
        Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "LDAP signing is not enabled on $computerName, the registry key does not exist"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP signing is not enabled on $computerName, the registry key does not exist"
    }

    # Check if LDAPS is configured
    $serverAuthOid = '1.3.6.1.5.5.7.3.1'
    $ldapsCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
        $_.Extensions -like "System.Security.Cryptography.Oid*" -and
        $_.Extensions.Oid.Value -eq $serverAuthOid
    }

    if ($ldapsCert) {
        Write-Both "    [+] LDAPS is configured on $computerName"
    }
    else {
        Write-Both "    [!] Issue identified LDAPS is not configured on $computerName, LDAPs certificates are not configured"
        Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "LDAPS is not configured on $computerName, LDAPs certificates are not configured"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAPS is not configured on $computerName, LDAPs certificates are not configured"
    }


    # Check if LDAPS Channel binding is enabled
    try {
        $ldapsBinding = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction Stop).LdapEnforceChannelBinding

        if ($ldapsBinding -eq 2) {
            Write-Both "    [+] LDAPS channel binding is enabled on $computerName"
        }
        else {
            Write-Both "    [!] Issue identified LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
            Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
            Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
        }
    }
    catch {
        Write-Both "    [!] Issue identified LDAPS channel binding is not enabled on $computerName, the registry key does not exist"
        Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "LDAPS channel binding is not enabled on $computerName, the registry key does not exist"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAPS channel binding is not enabled on $computerName, the registry key does not exist"
    }


    # Check for LDAP null sessions
    $Server = (Get-ADDomainController -Discover).HostName
    $Port = 389

    try {
        # Load required assemblies
        Add-Type -AssemblyName System.DirectoryServices.Protocols

        # Create LDAP connection
        $ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection("$Server`:$Port")

        # Set connection timeout
        $ldapConnection.Timeout = [System.TimeSpan]::FromSeconds(5)

        # Create an empty NetworkCredential for anonymous bind
        $anonymousCredential = New-Object System.Net.NetworkCredential("", "")

        # Bind to the LDAP server anonymously
        $ldapConnection.Bind($anonymousCredential)

        Write-Both "    [!] Issue identified LDAP null session allowed on server $Server`:$Port"
        Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "null session allowed on server $Server`:$Port"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP null session allowed on server $Server`:$Port"
    }
    catch [System.DirectoryServices.Protocols.LdapException] {
        Write-Both "    [+] LDAP null session not allowed on server $Server`:$Port"
    }
    catch {
        Write-Both "Error occurred: $_"
    }
}

function Get-ADObjectAclSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DistinguishedName,
        [string]$Server
    )
    # Prefer AD: provider; fall back to ADSI if DN contains characters the AD provider struggles with.
    try {
        if (-not (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
            Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null | Out-Null
            try { New-PSDrive -Name AD -PSProvider ActiveDirectory -Root "//RootDSE/" -ErrorAction Stop | Out-Null } catch {}
        }
        return Get-Acl -Path ("AD:\" + $DistinguishedName) -ErrorAction Stop
    } catch {
        try {
            $ldapPath = if ($Server) { "LDAP://$Server/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
            $entry = [ADSI]$ldapPath
            return $entry.psbase.ObjectSecurity
        } catch {
            throw $_
        }
    }
}

function Find-DangerousACLPermissions {
    #Specify the ACLs and Groups to check against
    $dangerousAces = @('GenericAll', 'GenericWrite', 'ForceChangePassword', 'WriteDacl', 'WriteOwner', 'Delete')
    $groupsToCheck = @('NT AUTHORITY\Authenticated Users', 'DOMAIN\Domain Users', 'Everyone')

    # Find dangerous permissions on Computers
    $computers = Get-ADObject -Filter { objectClass -eq 'computer' -and objectCategory -eq 'computer' } -Properties *
    $computerResults = foreach ($computer in $computers) {
        try {
            $acl = Get-ADObjectAclSafe -DistinguishedName $computer.DistinguishedName
        }
        catch {
            Write-Warning "Could not retrieve ACL for computer '$computer': $_"
            continue
        }

        $dangerousRules = $acl.Access | Where-Object { $_.ActiveDirectoryRights -in $dangerousAces -and $_.IdentityReference -in $groupsToCheck }

        if ($dangerousRules) {
            foreach ($rule in $dangerousRules) {
                [PSCustomObject]@{
                    ObjectType            = 'Computer'
                    ObjectName            = $computer
                    IdentityReference     = $rule.IdentityReference
                    AccessControlType     = $rule.AccessControlType
                    ActiveDirectoryRights = $rule.ActiveDirectoryRights
                }
            }
        }
        Write-Progress -Activity "Searching for dangerous ACL permissions on computers" -Status "Computers searched: $($computers.IndexOf($computer) + 1)/$($computers.Count)" -PercentComplete (($computers.IndexOf($computer) + 1) / $computers.Count * 100)
    }

    # Find dangerous permissions on groups
    $groups = Get-ADObject -Filter { objectClass -eq 'group' -and objectCategory -eq 'group' } -Properties *
    $groupResults = foreach ($group in $groups) {
        try {
            $acl = Get-ADObjectAclSafe -DistinguishedName $group.DistinguishedName
        }
        catch {
            Write-Warning "Could not retrieve ACL for group '$group': $_"
            continue
        }

        $dangerousRules = $acl.Access | Where-Object { $_.ActiveDirectoryRights -in $dangerousAces -and $_.IdentityReference -in $groupsToCheck }

        if ($dangerousRules) {
            foreach ($rule in $dangerousRules) {
                [PSCustomObject]@{
                    ObjectType            = 'Group'
                    ObjectName            = $group
                    IdentityReference     = $rule.IdentityReference
                    AccessControlType     = $rule.AccessControlType
                    ActiveDirectoryRights = $rule.ActiveDirectoryRights
                }
            }
        }
        Write-Progress -Activity "Searching for dangerous ACL permissions on groups" -Status "Groups searched: $($groups.IndexOf($group) + 1)/$($groups.Count)" -PercentComplete (($groups.IndexOf($group) + 1) / $groups.Count * 100)
    }
    # Find dangerous permissions on users
    $users = Get-ADObject -Filter { objectClass -eq 'user' -and objectCategory -eq 'person' } -Properties *

    $userResults = foreach ($user in $users) {
        $acl = $null
        $acl = Get-ADObjectAclSafe -DistinguishedName $user.DistinguishedName
        if ($acl) {
            $dangerousRules = $acl.Access | Where-Object { $_.ActiveDirectoryRights -in $dangerousAces -and $_.IdentityReference -in $groupsToCheck }
            if ($dangerousRules) {
                foreach ($rule in $dangerousRules) {
                    [PSCustomObject]@{
                        ObjectType            = 'User'
                        ObjectName            = $user
                        IdentityReference     = $rule.IdentityReference
                        AccessControlType     = $rule.AccessControlType
                        ActiveDirectoryRights = $rule.ActiveDirectoryRights
                    }
                }
            }
            Write-Progress -Activity "Searching for dangerous ACL permissions on users" -Status "Users searched: $($users.IndexOf($user) + 1)/$($users.Count)" -PercentComplete (($users.IndexOf($user) + 1) / $users.Count * 100)
        }
    }

    # Output results
    $dangerousAclHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $outputdir) 'dangerousACLs.html'
    $hasAnyAcl = $false

    if ($computerResults) {
        $hasAnyAcl = $true
        $computerResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType | Out-File (Get-EvidencePath 'dangerousACL_Computer.txt') -Encoding UTF8
        Write-Both "    [!] Issue identified, vulnerable ACL on Computer, see $outputdir\dangerousACL_Computer.txt"
        Write-Nessus-Finding "Weak Computer Permissions" "KB551" ([System.IO.File]::ReadAllText((Get-EvidencePath 'dangerousACL_Computer.txt')))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any computer."
    }

    if ($groupResults) {
        $hasAnyAcl = $true
        $groupResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType, ActiveDirectoryRights | Out-File (Get-EvidencePath 'dangerousACL_Groups.txt')
        Write-Both "    [!] Issue identified, vulnerable ACL on Group, see $outputdir\dangerousACL_Groups.txt"
        Write-Nessus-Finding "Weak Group Permissions" "KB551" ([System.IO.File]::ReadAllText((Get-EvidencePath 'dangerousACL_Groups.txt')))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any group."
    }
    if ($userResults) {
        $hasAnyAcl = $true
        $userResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType, ActiveDirectoryRights | Out-File (Get-EvidencePath 'dangerousACLUsers.txt')
        Write-Both "    [!] Issue identified, vulnerable ACL on User, see $outputdir\dangerousACLUsers.txt"
        Write-Nessus-Finding "Weak User Permissions" "KB551" ([System.IO.File]::ReadAllText((Get-EvidencePath 'dangerousACLUsers.txt')))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any user."
    }

    # Build consolidated modern HTML report
    if ($hasAnyAcl) {
        $aclSb = New-Object System.Text.StringBuilder
        [void]$aclSb.AppendLine((Get-ADAuditReportHeader -Title 'Dangerous ACL Permissions'))
        [void]$aclSb.AppendLine("<div class='hero'><h1>Dangerous ACL Permissions</h1>")
        [void]$aclSb.AppendLine("<div class='meta'>Objects with potentially dangerous access control entries that could allow privilege escalation.</div></div>")

        $compCount = if ($computerResults) { $computerResults.Count } else { 0 }
        $grpCount  = if ($groupResults) { $groupResults.Count } else { 0 }
        $usrCount  = if ($userResults) { $userResults.Count } else { 0 }
        [void]$aclSb.AppendLine("<div class='stats'>")
        [void]$aclSb.AppendLine("<div class='stat'><div class='val'>$($compCount + $grpCount + $usrCount)</div><div class='lbl'>Total Findings</div></div>")
        [void]$aclSb.AppendLine("<div class='stat'><div class='val'>$compCount</div><div class='lbl'>Computer ACLs</div></div>")
        [void]$aclSb.AppendLine("<div class='stat'><div class='val'>$grpCount</div><div class='lbl'>Group ACLs</div></div>")
        [void]$aclSb.AppendLine("<div class='stat'><div class='val'>$usrCount</div><div class='lbl'>User ACLs</div></div>")
        [void]$aclSb.AppendLine("</div>")

        function Write-AclTable($sb, $title, $results, $nameLabel) {
            if (-not $results -or $results.Count -eq 0) { return }
            [void]$sb.AppendLine("<h2>$title ($($results.Count))</h2>")
            [void]$sb.AppendLine("<table><thead><tr><th>Type</th><th>$nameLabel</th><th>Allowed Group</th><th>Access Control</th><th>AD Rights</th></tr></thead><tbody>")
            foreach ($r in $results) {
                [void]$sb.AppendLine("<tr><td><span class='badge badge-high'>$title</span></td><td><code>$($r.ObjectName)</code></td><td>$($r.IdentityReference)</td><td>$($r.AccessControlType)</td><td>$($r.ActiveDirectoryRights)</td></tr>")
            }
            [void]$sb.AppendLine("</tbody></table>")
        }

        Write-AclTable $aclSb 'Computer' $computerResults 'Computer Name'
        Write-AclTable $aclSb 'Group' $groupResults 'Group Name'
        Write-AclTable $aclSb 'User' $userResults 'User Name'

        [void]$aclSb.AppendLine((Get-ADAuditReportFooter))
        [System.IO.File]::WriteAllText($dangerousAclHtmlPath, $aclSb.ToString(), [System.Text.Encoding]::UTF8)
    }
}
#region AD raw data extract (Get-ADAuditData style)
function New-ZipFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateScript({ Test-Path $_ -PathType 'Container' })]
        [string]$Source
    )

    try {
        if (Test-Path -LiteralPath $Path) {
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }

        [System.IO.Compression.ZipFile]::CreateFromDirectory(
            $Source,
            $Path,
            [System.IO.Compression.CompressionLevel]::Optimal,
            $true
        )

        return $true
    }
    catch {
        try {
            Compress-Archive -Path $Source -DestinationPath $Path -CompressionLevel Optimal -Force -ErrorAction Stop
            return $true
        }
        catch {
            Write-Both "    [!] Failed to create ZIP file '$Path'. $($_.Exception.Message)"
            return $false
        }
    }
}
function Remove-InvalidFileNameChars {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [AllowEmptyString()]
        [string]$Name
    )
    $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
    return ($Name -replace $re,'#')
}

function ConvertFrom-UAC {
    param([Parameter(ValueFromPipeline=$true)]$Value)
    $uacOptions = @{
        512='Enabled';514='Disabled';528='Enabled - Locked Out';530='Disabled - Locked Out'
        4096='Enabled - Workstation Trust Account';4098='Disabled - Workstation Trust Account'
        8192='Enabled - Server Trust Account';8194='Disabled - Server Trust Account'
        66048='Enabled - Password Does Not Expire';66050='Disabled - Password Does Not Expire'
        1049088='Enabled - Not Delegated';1049090='Disabled - Not Delegated'
        2097664='Enabled - Use DES Key Only';4194816='Enabled - PreAuthorization Not Required'
        16781312='Enabled - Workstation Trust Account - Trusted to Authenticate For Delegation'
    }
    if ($null -eq $Value) { return "Unknown User Account Type - No Value Available" }
    if ($uacOptions.ContainsKey([int]$Value)) { return [string]$uacOptions[[int]$Value] }
    return "Unknown User Account Type - $Value"
}

function ConvertFrom-UACComputed {
    param([Parameter(ValueFromPipeline=$true)]$Value)
    $uacComputed = @{
        0='Refer to userAccountControl Field';16='Locked Out';8388608='Password Expired'
        8388624='Locked Out - Password Expired';67108864='Partial Secrets Account';2147483648='Use AES Keys'
    }
    if ($null -eq $Value) { return "Unknown User Account Type - No Value Available" }
    if ($uacComputed.ContainsKey([int64]$Value)) { return [string]$uacComputed[[int64]$Value] }
    return "Unknown User Account Type - $Value"
}

function ConvertFrom-PasswordExpiration {
    param([Parameter(ValueFromPipeline=$true)]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -eq 0 -or $Value -ge 922337203685477000) { return '' }
    try { return ([datetime]::FromFileTime([int64]$Value)).ToString("M/d/yyyy h:mm:ss tt") } catch { return '' }
}

function ConvertFrom-trustDirection {
    param([Parameter(ValueFromPipeline=$true)]$Value)
    $trustDirect = @{
        0='Disabled (Trust exists but disabled)'
        1='Inbound (One-Way Trust) (TrustING Domain)'
        2='Outbound (One-Way Trust) (TrustED Domain)'
        3='Bidirectional (Two-Way Trust)'
    }
    if ($null -eq $Value) { return "Unknown Trust Direction - No Value Available" }
    if ($trustDirect.ContainsKey([int]$Value)) { return $trustDirect[[int]$Value] }
    return "Unknown Trust Direction - $Value"
}

function ConvertFrom-trustType {
    param([Parameter(ValueFromPipeline=$true)]$Value)
    $trustType = @{
        1='Downlevel Trust (Windows NT / External)'
        2='Uplevel Trust (Windows 2000+ / AD)'
        3='MIT Kerberos v5 Realm'
        4='DCE Realm'
    }
    if ($null -eq $Value) { return "Unknown Trust Type - No Value Available" }
    if ($trustType.ContainsKey([int]$Value)) { return [string]$trustType[[int]$Value] }
    return "Unknown Trust Type - $Value"
}

function ConvertFrom-trustAttribute {
    param([Parameter(Mandatory=$true, ValueFromPipeline=$true)]$Value)
    $trustAttribute = @{
        0='Non-Verifiable Trust'
        1='Non-Transitive Trust'
        2='Up-level Trust'
        4='Quarantined Domain External Trust (SID Filtering Enabled)'
        8='Forest Transitive Trust'
        16='Selective Authentication'
        20='Intra-Forest Trust'
        32='Forest-Internal'
        64='SIDHistory enabled'
        80='Uses RC4 Encryption'
        400='PIM Trust'
    }
    if ($null -eq $Value) { return "Unknown Trust Attribute - No Value Available" }
    if ($trustAttribute.ContainsKey([int]$Value)) { return [string]$trustAttribute[[int]$Value] }
    return "Unknown Trust Attribute - $Value"
}

function Export-ADAuditDataExtract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateScript({ Test-Path $_ -PathType 'Container' })]
        [string]$Path = (Join-Path (Get-RawDataDir -BaseRoot $outputdir) 'ADExtract'),

        [Parameter(Mandatory=$false)]
        [string]$SearchBase = (Get-ADRootDSE | Select-Object -ExpandProperty defaultNamingContext)
    )

    try { Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null } catch { Write-Both "    [!] ActiveDirectory module missing. $_"; return }
    try { Import-ADAuditModule -Name GroupPolicy -Required -PreferWindowsPowerShell | Out-Null } catch { Write-Both "    [!] GroupPolicy module missing. $_"; return }

    $domainInfo = Get-ADDomain -Current LocalComputer
    $domainDN   = $domainInfo.DistinguishedName
    $outRoot    = Join-Path $Path $domainDN

    if (Test-Path $outRoot) { Remove-Item $outRoot -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $outRoot -Force | Out-Null

    $log = Join-Path $outRoot 'consoleOutput.txt'
    "@Starting AD data extract at $(Get-Date -Format G)" | Out-File -FilePath $log -Encoding utf8
    "@Path parameter: '$outRoot'"                        | Out-File -FilePath $log -Append -Encoding utf8
    "@SearchBase parameter: '$SearchBase'"               | Out-File -FilePath $log -Append -Encoding utf8

    # OS info
    $sysInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $PSVersionTable | Out-File -FilePath (Join-Path $outRoot "$env:COMPUTERNAME-sysinfo.txt") -Append -Encoding utf8
    $sysInfo | Select-Object BuildNumber,Caption,InstallDate,LastBootUpTime,LocalDateTime,OSArchitecture,Version |
        Out-File -FilePath (Join-Path $outRoot "$env:COMPUTERNAME-sysinfo.txt") -Append -Encoding utf8

    # Domain / DC / Forest
    $domainInfo | Select-Object @{Name='ChildDomains';Expression={$_.ChildDomains -join ';'}},ComputersContainer,DeletedObjectsContainer,
        DistinguishedName,DNSRoot,DomainControllersContainer,DomainMode,DomainSID,Forest,InfrastructureMaster,Name,NetBIOSName,
        ParentDomain,PDCEmulator,RIDMaster,SystemsContainer,UsersContainer |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-Info.csv") -Append

    Get-ADDomainController -Filter * -Server $domainInfo.DnsRoot |
        Select-Object ComputerObjectDN,DefaultPartition,Domain,Enabled,Forest,HostName,IsGlobalCatalog,IsReadOnly,Name,
            OperatingSystem,OperatingSystemVersion,@{Name='OperationMasterRoles';Expression={$_.OperationMasterRoles -join ';'}},ServerObjectDN,Site |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-domainControllerInfo.csv") -Append

    Get-ADForest -Current LocalComputer |
        Select-Object DomainNamingMaster,@{Name='Domains';Expression={$_.Domains -join ';'}},ForestMode,
            @{Name='GlobalCatalogs';Expression={$_.GlobalCatalogs -join ';'}},Name,RootDomain,SchemaMaster,
            @{Name='UPNSuffixes';Expression={$_.UPNSuffixes -join ';'}} |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-ForestInfo.csv") -Append

    # -------------------------
    # Users (SAFE RAW LDAP EXPORT)
    # -------------------------
    $delimiter = '|'
    $eol = "`r`n"

    function _SafeFileTimeToString {
        param([object]$v)
        if ($null -eq $v) { return '' }
        try {
            $ft = [int64]$v
            if ($ft -le 0) { return '' }
            return [datetime]::FromFileTimeUtc($ft).ToString("o")
        } catch {
            return ''   # invalid/out-of-range FILETIME -> blank, do not fail export
        }
    }

    function _PropFirst {
        param($props, [string]$name)
        if ($props.Contains($name) -and $props[$name] -and $props[$name].Count -gt 0) { return $props[$name][0] }
        return $null
    }

    function _PropJoin {
        param($props, [string]$name, [string]$sep)
        if ($props.Contains($name) -and $props[$name] -and $props[$name].Count -gt 0) {
            return ($props[$name] | ForEach-Object { [string]$_ }) -join $sep
        }
        return ''
    }

    function _SidBytesToString {
        param([object]$sidObj)
        try {
            if ($sidObj -is [byte[]]) {
                return (New-Object System.Security.Principal.SecurityIdentifier($sidObj,0)).Value
            }
            if ($sidObj) { return [string]$sidObj }
            return ''
        } catch { return '' }
    }

    # Keep your original header list, but source values via LDAP safely
    $userProps = @(
        'accountExpirationDate','adminCount','canonicalName','cn','comment','company','department','description','displayName',
        'distinguishedName','employeeID','employeeNumber','employeeType','givenName','info','LastLogonDate','mail','managedObjects',
        'manager','memberOf','middleName','msDS-AllowedToDelegateTo','msDS-PSOApplied','msDS-ResultantPSO',
        'msDS-User-Account-Control-Computed','msDS-UserPasswordExpiryTimeComputed','name','objectSid','PasswordExpired',
        'PasswordLastSet','primaryGroupID','sAMAccountName','servicePrincipalName','sIDHistory','sn','title','uid','uidNumber',
        'userAccountControl','userWorkstations','whenChanged','whenCreated'
    )
    $userHeader = $userProps + @('relativeIdentifier')

    # LDAP properties to load (raw names)
    # - accountExpirationDate comes from accountExpires (FILETIME)
    # - PasswordLastSet comes from pwdLastSet (FILETIME)
    # - LastLogonDate comes from lastLogonTimestamp (FILETIME)
    $ldapLoad = @(
        'accountExpires','adminCount','canonicalName','cn','comment','company','department','description','displayName',
        'distinguishedName','employeeID','employeeNumber','employeeType','givenName','info','lastLogonTimestamp','mail','managedObjects',
        'manager','memberOf','middleName','msDS-AllowedToDelegateTo','msDS-PSOApplied','msDS-ResultantPSO',
        'msDS-User-Account-Control-Computed','msDS-UserPasswordExpiryTimeComputed','name','objectSid','primaryGroupID',
        'pwdLastSet','sAMAccountName','servicePrincipalName','sIDHistory','sn','title','uid','uidNumber',
        'userAccountControl','userWorkstations','whenChanged','whenCreated'
    )

    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$SearchBase")
        $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
        $ds.PageSize = 2000
        $ds.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $ds.Filter = '(&(objectCategory=person)(objectClass=user))'
        $ds.PropertiesToLoad.Clear()
        foreach ($p in $ldapLoad) { [void]$ds.PropertiesToLoad.Add($p) }

        $usersCsvPath = Join-Path $outRoot "$($domainInfo.DNSRoot)-Users.csv"
        $w = $null
        try {
            $w = [System.IO.StreamWriter]::new($usersCsvPath, $false, [System.Text.Encoding]::UTF8)
            $w.Write(($userHeader -join $delimiter) + $eol)

            foreach ($r in $ds.FindAll()) {
                $p = $r.Properties

                $managed = ''
                if ($p.Contains('managedobjects')) {
                    $managed = ($p['managedobjects'] | ForEach-Object { ((($_ -split ',')[0]) -replace '^CN=','') }) -join ', '
                }

                $memberof = ''
                if ($p.Contains('memberof')) {
                    $memberof = ($p['memberof'] | ForEach-Object { ((($_ -split ',')[0]) -replace '^CN=','') }) -join ', '
                }

                $psoApplied = (_PropJoin $p 'msds-psoapplied' ';')
                $psoRes     = (_PropJoin $p 'msds-resultantpso' ';')
                if ($psoApplied) { $psoApplied = ($psoApplied -replace ",CN=Password Settings Container,CN=System,$domainDN",'') -replace 'CN=','' }
                if ($psoRes)     { $psoRes     = ($psoRes     -replace ",CN=Password Settings Container,CN=System,$domainDN",'') -replace 'CN=','' }

                $sidStr = _SidBytesToString (_PropFirst $p 'objectsid')
                $rid = ''
                if ($sidStr -match '^(S-\d-\d+-.+)-(\d+)$') { $rid = $matches[2] }

                # Derive the fields that were previously auto-converted by AD cmdlets
                $accountExpirationDate = _SafeFileTimeToString (_PropFirst $p 'accountexpires')
                $passwordLastSet       = _SafeFileTimeToString (_PropFirst $p 'pwdlastset')
                $lastLogonDate         = _SafeFileTimeToString (_PropFirst $p 'lastlogontimestamp')
                $pwdExpiryComputed     = _SafeFileTimeToString (_PropFirst $p 'msds-userpasswordexpirytimecomputed')

                # PasswordExpired was previously from AD cmdlet; keep best-effort blank (or compute if you want later)
                $passwordExpired = ''

                $line = @(
                    [string]$accountExpirationDate
                    (_PropFirst $p 'admincount')
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'canonicalname')))
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'cn')))
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'comment')))
                    [string](_PropFirst $p 'company')
                    [string](_PropFirst $p 'department')
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'description')))
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'displayname')))
                    [string](_PropFirst $p 'distinguishedname')
                    [string](_PropFirst $p 'employeeid')
                    [string](_PropFirst $p 'employeenumber')
                    [string](_PropFirst $p 'employeetype')
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'givenname')))
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'info')))
                    [string]$lastLogonDate
                    [string](_PropFirst $p 'mail')
                    [string]$managed
                    [string](_PropFirst $p 'manager')
                    [string]$memberof
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'middlename')))
                    (_PropJoin $p 'msds-allowedtodelegateto' ';')
                    [string]$psoApplied
                    [string]$psoRes
                    (ConvertFrom-UACComputed (_PropFirst $p 'msds-user-account-control-computed'))
                    (ConvertFrom-PasswordExpiration (_PropFirst $p 'msds-userpasswordexpirytimecomputed'))
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'name')))
                    [string]$sidStr
                    [string]$passwordExpired
                    [string]$passwordLastSet
                    [string](_PropFirst $p 'primarygroupid')
                    [string](_PropFirst $p 'samaccountname')
                    (_PropJoin $p 'serviceprincipalname' ';')
                    (_PropJoin $p 'sidhistory' ';')
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'sn')))
                    [string](_PropFirst $p 'title')
                    (_PropJoin $p 'uid' ';')
                    [string](_PropFirst $p 'uidnumber')
                    (ConvertFrom-UAC (_PropFirst $p 'useraccountcontrol'))
                    [string](_PropFirst $p 'userworkstations')
                    [string](_PropFirst $p 'whenchanged')
                    [string](_PropFirst $p 'whencreated')
                    [string]$rid
                ) -join $delimiter

                $w.Write($line + $eol)
            }
        } finally {
            if ($w) { $w.Close() }
        }
    } catch {
        "@Problem exporting users (raw LDAP): $_" | Out-File -FilePath $log -Append -Encoding utf8
        Write-Both "    [!] Problem exporting users. See consoleOutput.txt"
    }

    # Groups
    $groupProps = @('CN','description','displayName','distinguishedName','GroupCategory','GroupScope','ManagedBy','memberOf','msDS-PSOApplied','name','objectSID','sAMAccountName','whenCreated','whenChanged')
    $groupHeader = $groupProps + @('relativeIdentifier')
    $groups = Get-ADGroup -SearchBase $SearchBase -Filter * -Properties $groupProps -ErrorAction SilentlyContinue

    $groupsCsvPath = Join-Path $outRoot "$($domainInfo.DNSRoot)-Groups.csv"
    $w = $null
    try {
        $w = [System.IO.StreamWriter]::new($groupsCsvPath, $false, [System.Text.Encoding]::UTF8)
        $w.Write(($groupHeader -join $delimiter) + $eol)
        foreach ($g in $groups) {
            $memberof = ($g.memberOf | ForEach-Object { ((($_ -split ',')[0]) -replace '^CN=','') }) -join ', '
            $pso = (($g.'msDS-PSOApplied' -join ';') -replace ",CN=Password Settings Container,CN=System,$domainDN",'') -replace 'CN=',''
            $line = @(
                (Remove-InvalidFileNameChars $g.CN)
                (Remove-InvalidFileNameChars $g.description)
                (Remove-InvalidFileNameChars $g.displayName)
                $g.distinguishedName
                $g.GroupCategory
                $g.GroupScope
                $g.ManagedBy
                $memberof
                $pso
                (Remove-InvalidFileNameChars $g.name)
                $g.objectSid
                $g.sAMAccountName
                [string]$g.whenCreated
                [string]$g.whenChanged
                (($g.SID.Value).Split('-')[-1])
            ) -join $delimiter
            $w.Write($line + $eol)
        }
    } finally {
        if ($w) { $w.Close() }
    }

    # Computers (keep as-is; if you later hit FileTime errors here, apply the same raw LDAP pattern)
    $computerProps = @('cn','description','displayName','distinguishedName','LastLogonDate','name','objectSid','operatingSystem','operatingSystemServicePack','operatingSystemVersion','primaryGroupID','PasswordLastSet','userAccountControl','whenCreated','whenChanged')
    $computers = Get-ADComputer -SearchBase $SearchBase -Filter * -Properties $computerProps -ErrorAction SilentlyContinue
    $computers | Select-Object $computerProps | ForEach-Object {
        $_.userAccountControl = ConvertFrom-UAC $_.userAccountControl
        $_
    } | ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-Computers.csv") -Append

    # OUs (unchanged)
    $ouProps = @('CanonicalName','Description','DisplayName','DistinguishedName','ManagedBy','Name','whenChanged','whenCreated')
    Get-ADOrganizationalUnit -SearchBase $SearchBase -Filter * -Properties $ouProps -ErrorAction SilentlyContinue |
        Select-Object CanonicalName,Description,DisplayName,DistinguishedName,ManagedBy,Name,whenChanged,whenCreated |
        ForEach-Object {
            $_.CanonicalName = Remove-InvalidFileNameChars $_.CanonicalName
            $_.Description   = Remove-InvalidFileNameChars $_.Description
            $_.DisplayName   = Remove-InvalidFileNameChars $_.DisplayName
            $_.Name          = Remove-InvalidFileNameChars $_.Name
            $_
        } | ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-OUs.csv") -Append

    # GPO Reports + inheritance (harden filenames + ensure dirs exist)
    $gpRoot = Join-Path $outRoot 'GroupPolicy'
    New-Item -ItemType Directory -Path $gpRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $gpRoot 'Reports') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $gpRoot 'Inheritance') -Force | Out-Null

    $gpos = Get-GPO -All -ErrorAction SilentlyContinue
    foreach ($gpo in $gpos) {
        $name = Remove-InvalidFileNameChars $gpo.DisplayName

        # Prevent path-too-long / weird names
        if ($name.Length -gt 150) { $name = $name.Substring(0,150) }

        $reportPath = Join-Path (Join-Path $gpRoot 'Reports') "$name.html"
        try {
            Get-GPOReport -Guid $gpo.Id -ReportType Html -Path $reportPath -ErrorAction Stop
        } catch {
            "@Problem exporting GPO report '$($gpo.DisplayName)' to '$reportPath': $_" | Out-File -FilePath $log -Append -Encoding utf8
        }
    }

    $domainGPI = Get-GPInheritance -Target $domainDN -ErrorAction SilentlyContinue
    $domainGPI | Select-Object Name,ContainerType,Path,GpoInheritanceBlocked | Format-List |
        Out-File -FilePath (Join-Path (Join-Path $gpRoot 'Inheritance') "$domainDN.txt")
    $domainGPI | Select-Object -ExpandProperty InheritedGpoLinks |
        Out-File -FilePath (Join-Path (Join-Path $gpRoot 'Inheritance') "$domainDN.txt") -Append

    $adOUs = Get-ADOrganizationalUnit -SearchBase $SearchBase -Filter * -ErrorAction SilentlyContinue
    foreach ($ou in $adOUs) {
        $fn = Remove-InvalidFileNameChars $ou.DistinguishedName
        if ($fn.Length -gt 150) { $fn = $fn.Substring(0,150) }

        $gpi = Get-GPInheritance -Target $ou.DistinguishedName -ErrorAction SilentlyContinue
        $gpi | Select-Object Name,ContainerType,Path,GpoInheritanceBlocked | Format-List |
            Out-File -FilePath (Join-Path (Join-Path $gpRoot 'Inheritance') "$fn.txt")
        $gpi | Select-Object -ExpandProperty InheritedGpoLinks |
            Out-File -FilePath (Join-Path (Join-Path $gpRoot 'Inheritance') "$fn.txt") -Append
    }

    # OU ACLs (unchanged)
    New-Item -ItemType Directory -Path (Join-Path $outRoot 'OU\ACLs') -Force | Out-Null
    $schemaIDGUID = @{}
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'SilentlyContinue'
    Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name,schemaIDGUID |
        ForEach-Object { $schemaIDGUID[[Guid]$_.schemaIDGUID] = $_.name }
    Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name,rightsGUID |
        ForEach-Object { $schemaIDGUID[[Guid]$_.rightsGUID] = $_.name }
    $ErrorActionPreference = $eap

    $ouDns = @()
    if ($SearchBase -eq (Get-ADRootDSE).defaultNamingContext) {
        $ouDns += (Get-ADDomain).DistinguishedName
        $ouDns += Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
        $ouDns += Get-ADObject -SearchBase (Get-ADDomain).DistinguishedName -SearchScope OneLevel -LDAPFilter '(objectClass=container)' | Select-Object -ExpandProperty DistinguishedName
    } else {
        $ouDns += Get-ADOrganizationalUnit -SearchBase $SearchBase -Filter * | Select-Object -ExpandProperty DistinguishedName
    }

    foreach ($ouDN in $ouDns) {
        $fn = Remove-InvalidFileNameChars $ouDN
        if ($fn.Length -gt 150) { $fn = $fn.Substring(0,150) }

        $csvPath = Join-Path (Join-Path $outRoot 'OU\ACLs') "$fn.csv"
        try {
            Get-Acl -Path "AD:$ouDN" -ErrorAction Stop |
                Select-Object -ExpandProperty Access |
                Select-Object @{n='organizationalUnit';e={$ouDN}},
                    @{n='objectTypeName';e={ if ($_.ObjectType -eq [Guid]::Empty) {'All'} else { $schemaIDGUID[$_.ObjectType] } }},
                    @{n='inheritedObjectTypeName';e={ $schemaIDGUID[$_.InheritedObjectType] }}, * |
                ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
                Out-File -FilePath $csvPath -Append
        } catch {
            "@Problem reading ACL for '$ouDN': $_" | Out-File -FilePath $log -Append -Encoding utf8
        }
    }

    # Confidentiality bit (unchanged)
    try {
        Get-ADObject -SearchBase "CN=Schema,CN=Configuration,$domainDN" -LDAPFilter '(searchFlags:1.2.840.113556.1.4.803:=128)' |
            Select-Object DistinguishedName,Name |
            ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
            Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-confidentialBit.csv") -Append
    } catch {
        "@Problem exporting confidentiality bit: $_" | Out-File -FilePath $log -Append -Encoding utf8
    }

    # Default password policy + FGPP (unchanged)
    Get-ADDefaultDomainPasswordPolicy |
        Select-Object ComplexityEnabled,DistinguishedName,LockoutDuration,LockoutObservationWindow,LockoutThreshold,MaxPasswordAge,
            MinPasswordAge,MinPasswordLength,PasswordHistoryCount,ReversibleEncryptionEnabled |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-defaultDomainPasswordPolicy.csv") -Append

    Get-ADFineGrainedPasswordPolicy -Filter * -Properties appliesTo |
        Select-Object ComplexityEnabled,DistinguishedName,LockoutDuration,LockoutObservationWindow,LockoutThreshold,MaxPasswordAge,
            MinPasswordAge,MinPasswordLength,
            @{Name='msDS-PSOAppliesTo';Expression={(($_.appliesTo -split "," | Select-String -AllMatches "CN=") -join ", ") -replace "CN=" }},
            Name,PasswordHistoryCount,Precedence,ReversibleEncryptionEnabled |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-fgppDetails.csv") -Append

    # Trusts (unchanged)
    if (Get-Command Get-ADTrust -ErrorAction SilentlyContinue) {
        Get-ADTrust -Filter * -Properties * |
            Select-Object CanonicalName,CN,Created,Deleted,Description,DisallowTransivity,DisplayName,DistinguishedName,flatName,
                ForestTransitive,IntraForest,Name,SelectiveAuthentication,Source,Target,TGTDelegation,
                @{Name='TrustAttributes';Expression={ConvertFrom-trustAttribute $_.TrustAttributes}},
                @{Name='trustDirection';Expression={ConvertFrom-trustDirection $_.trustDirection}},
                @{Name='TrustType';Expression={ConvertFrom-trustType $_.TrustType}},
                TrustingPolicy,trustPartner,UplevelOnly,UsesAESKeys,UsesRC4Encryption,whenChanged,whenCreated |
            ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
            Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-trustedDomains.csv") -Append
    } else {
        & netdom query trust > (Join-Path $outRoot "$($domainInfo.DNSRoot)-trustedDomains-netdom.txt")
    }

    "@Finished AD data extract at $(Get-Date -Format G)" | Out-File -FilePath $log -Append -Encoding utf8

    # Zip output (best-effort)
    $zip = Join-Path $Path ("$domainDN.zip")
    if (New-ZipFile -Path $zip -Source $outRoot) {
        "@Compressed output: $zip" | Out-File -FilePath $log -Append -Encoding utf8
    } else {
        "@.NET 4.5.2+ not detected - skipping zip" | Out-File -FilePath $log -Append -Encoding utf8
    }

    Write-Both "    [+] AD raw data export complete: $outRoot"
}

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

        $dnsIps[0]
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
    $css = Get-ADAuditReportCss

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

    # Fix ConvertTo-Html <table> to use <thead>/<tbody>
    $zonesHtml = $zonesHtml -replace '<table>\s*<tr><th','<table><thead><tr><th' -replace '</th></tr>\s*<tr><td','</th></tr></thead><tbody><tr><td' -replace '</td></tr>\s*</table>','</td></tr></tbody></table>'

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
            $zoneListHtml = ($g.Zones | Sort-Object | ForEach-Object { "<li><code>$_</code></li>" }) -join "`n"
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

#endregion DNS Zone Posture Report




#region Delegated Permissions Report (merged)
function Invoke-DelegatedPermissionsReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputRoot,
        [switch]$IncludeSystemTrustees,
        [switch]$IncludeDeny,
        [switch]$IncludeInherited,
        [string]$Server
    )

    # Embedded from Delegated_Permissions.ps1 (working version)
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null

    # System.Web is needed later for HtmlEncode in the HTML index. Loading
    # it once up front avoids a per-call Add-Type and keeps strict-mode happy.
    try { [void][System.Web.HttpUtility] } catch { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue }

    # Timestamped folders
    $ts   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $base = Join-Path $OutputRoot "ADAudit_Reports_$ts"
    $ouDir  = Join-Path $base 'OUs'
    $allDir = Join-Path $base 'All'
    New-Item -ItemType Directory -Path $base,$ouDir,$allDir -Force | Out-Null

    # Transcript
    $log = Join-Path $base "Transcript_$ts.txt"
    try { Start-Transcript -Path $log -ErrorAction SilentlyContinue | Out-Null } catch {}

    # RootDSE and NCs
    $rootDse  = if ($Server) { Get-ADRootDSE -Server $Server } else { Get-ADRootDSE }
    $domainNC = $rootDse.defaultNamingContext
    $schemaNC = $rootDse.schemaNamingContext
    $configNC = $rootDse.configurationNamingContext

    # Server-pinned ACL read to avoid referrals
    function Get-AclForDn {
      param([Parameter(Mandatory)][string]$Dn,[string]$Server)
      if ($Server) {
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$Dn")
        $de.RefreshCache()
        return $de.ObjectSecurity
      } else {
        return (Get-Acl -Path "AD:$Dn")
      }
    }

    # Simple retry wrapper
    function Invoke-Retry([scriptblock]$Script,[int]$Max=3,[int]$DelaySec=2){
      for($i=1;$i -le $Max;$i++){
        try { return & $Script } catch { if($i -eq $Max){ throw } Start-Sleep -Seconds $DelaySec }
      }
    }

    # GUID cache: attributes, classes, extended rights, property sets
    $guidCache = @{}

    # Schema objects
    $schemaObjects = if ($Server) {
      Get-ADObject -Server $Server -SearchBase $schemaNC -LDAPFilter '(|(objectClass=classSchema)(objectClass=attributeSchema))' -Properties lDAPDisplayName,schemaIDGUID
    } else {
      Get-ADObject -SearchBase $schemaNC -LDAPFilter '(|(objectClass=classSchema)(objectClass=attributeSchema))' -Properties lDAPDisplayName,schemaIDGUID
    }
    foreach ($s in $schemaObjects) {
      try { $g = [Guid]$s.schemaIDGUID; $guidCache[$g.Guid] = $s.lDAPDisplayName } catch {}
    }

    # Extended rights (controlAccessRight) in Configuration NC
    $carObjects = if ($Server) {
      Get-ADObject -Server $Server -SearchBase $configNC -LDAPFilter '(objectClass=controlAccessRight)' -Properties displayName,rightsGuid,cn
    } else {
      Get-ADObject -SearchBase $configNC -LDAPFilter '(objectClass=controlAccessRight)' -Properties displayName,rightsGuid,cn
    }
    foreach ($c in $carObjects) {
      try {
        $g = [Guid]$c.rightsGuid
        $friendly = if ($c.displayName) { $c.displayName } else { $c.cn }
        $guidCache[$g.Guid] = $friendly
      } catch {}
    }

    function Resolve-GuidName {
      param($GuidValue)
      if (-not $GuidValue -or $GuidValue -eq [Guid]::Empty) { return $null }
      try {
        $g = [Guid]$GuidValue
        if ($guidCache.ContainsKey($g.Guid)) { return $guidCache[$g.Guid] }
        return $g.Guid
      } catch {
        return $GuidValue.ToString()
      }
    }

    # Trustee classification
    function Get-PrincipalType {
      param([string]$Identity)
      try {
        $filter = "(|(sAMAccountName=$Identity)(distinguishedName=$Identity)(objectSid=$Identity))"
        $obj = if ($Server) {
          Get-ADObject -Server $Server -LDAPFilter $filter -Properties objectClass -ErrorAction Stop
        } else {
          Get-ADObject -LDAPFilter $filter -Properties objectClass -ErrorAction Stop
        }
        if ($obj.objectClass -contains 'group')     { return 'Group' }
        if ($obj.objectClass -contains 'user')      { return 'User' }
        if ($obj.objectClass -contains 'computer')  { return 'Computer' }
        if ($obj.objectClass -contains 'foreignSecurityPrincipal') { return 'FSP' }
      } catch {}
      if ($Identity -match '^S-\d-\d+') { return 'SID' }
      return 'WellKnownOrExternal'
    }

    # Canonical path helper
    function Get-Canonical {
      param([string]$Dn)
      try {
        $p = @{ Identity=$Dn; Properties='CanonicalName'; ErrorAction='Stop' }
        if ($Server) { $p['Server'] = $Server }
        (Get-ADObject @p).CanonicalName
      } catch { $null }
    }

    # Built-in trustees to optionally suppress
    $systemTrustees = @(
      'NT AUTHORITY\SELF',
      'NT AUTHORITY\Authenticated Users',
      'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
      'NT AUTHORITY\Everyone',
      'BUILTIN\Administrators',
      'NT AUTHORITY\SYSTEM'
    )

    # Scope discovery
    $ouParams = @{ Filter='*'; Properties=@('DistinguishedName','Name') }
    if ($Server) { $ouParams['Server'] = $Server }
    $OUs = Get-ADOrganizationalUnit @ouParams

    $scopes = New-Object 'System.Collections.Generic.List[string]'
    [void]$scopes.Add($domainNC)
    $OUs | ForEach-Object { [void]$scopes.Add($_.DistinguishedName) }

    $wellKnownContainers = @(
"CN=Users,$domainNC",
"CN=Computers,$domainNC",
"CN=System,$domainNC",
"CN=Managed Service Accounts,$domainNC"
    ) | Where-Object { Test-Path "AD:$_" }
    $wellKnownContainers | ForEach-Object { [void]$scopes.Add($_) }

    $adminSDHolder = "CN=AdminSDHolder,CN=System,$domainNC"
    if (Test-Path "AD:$adminSDHolder") { [void]$scopes.Add($adminSDHolder) }

    # Data store
    $records = New-Object System.Collections.Generic.List[object]

    # Iterate scopes and collect ACEs
    foreach ($dn in $scopes) {
      $scopeType = if ($dn -eq $domainNC) { 'Domain' }
                   elseif ($dn -eq $adminSDHolder) { 'AdminSDHolder' }
                   elseif ($wellKnownContainers -contains $dn) { 'Container' }
                   else { 'OU' }

      try {
        $acl = Invoke-Retry { Get-AclForDn -Dn $dn -Server $Server }
      } catch {
        Write-Warning "ACL read failed: $dn. $_"
        continue
      }

      foreach ($ace in $acl.Access) {
        if (-not $IncludeInherited -and $ace.IsInherited) { continue }
        if (-not $IncludeDeny -and $ace.AccessControlType -ne 'Allow') { continue }
        $trustee = $ace.IdentityReference.Value
        if (-not $IncludeSystemTrustees -and ($systemTrustees -contains $trustee)) { continue }

        $objTypeName      = Resolve-GuidName $ace.ObjectType
        $inheritedObjName = Resolve-GuidName $ace.InheritedObjectType

        [void]$records.Add([pscustomobject]@{
          ScopeDN               = $dn
          CanonicalScope        = Get-Canonical $dn
          ScopeType             = $scopeType
          Trustee               = $trustee
          TrusteeType           = Get-PrincipalType $trustee
          AccessControlType     = $ace.AccessControlType
          ActiveDirectoryRights = $ace.ActiveDirectoryRights
          InheritanceType       = $ace.InheritanceType
          AppliesToClass        = $inheritedObjName
          AppliesToProperty     = $objTypeName
          ObjectTypeGuid        = if ($ace.ObjectType -and $ace.ObjectType -ne [Guid]::Empty) { $ace.ObjectType } else { $null }
          InheritedObjectGuid   = if ($ace.InheritedObjectType -and $ace.InheritedObjectType -ne [Guid]::Empty) { $ace.InheritedObjectType } else { $null }
          IsInherited           = $ace.IsInherited
          PropagationFlags      = $ace.PropagationFlags
          InheritanceFlags      = $ace.InheritanceFlags
        })
      }
      # NOTE: Per-scope .txt files are no longer written here. They previously
      # duplicated the same data already in the per-scope .csv (and we ended up
      # with 73+ pairs of .txt/.csv files in OUs/, which made the report folder
      # hard to navigate). A single consolidated, sectioned summary is written
      # instead - see ADAudit_PerScopeSummary.txt later in this function.
    }

    # De-duplicate identical ACE rows to reduce noise
    $records = $records |
      Sort-Object ScopeDN,Trustee,AccessControlType,ActiveDirectoryRights,AppliesToClass,AppliesToProperty,InheritanceType,IsInherited,ObjectTypeGuid,InheritedObjectGuid -Unique

    # ------- Analytics and risk outputs (always generated) -------

    # Windows LAPS + legacy LAPS attributes
    $lapsAttributes = @('ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime','msLAPS-Password','msLAPS-PasswordExpirationTime')

    $overDelegations = $records | Where-Object {
      $_.ActiveDirectoryRights.ToString() -match 'GenericAll|WriteDacl|DeleteTree'
    }
    $accountOperators = $records | Where-Object { $_.Trustee -eq 'BUILTIN\Account Operators' }
    $printOperators   = $records | Where-Object { $_.Trustee -eq 'BUILTIN\Print Operators' }
    $exchangePattern  = 'Exchange Trusted Subsystem','Organization Management','Exchange Windows Permissions'
    $exchangeDelegations = $records | Where-Object { $_.Trustee -in $exchangePattern }
    $serviceAcctDelegations = $records | Where-Object {
      $_.Trustee -match '^(svc|SVC)[\-_]' -or $_.Trustee -match 'DomainJoin' -or $_.Trustee -match 'DJ\b'
    }
    $unknownSids = @($records | Where-Object { $_.TrusteeType -eq 'SID' } | Select-Object -Expand Trustee | Sort-Object -Unique)
    $membershipControl = $records | Where-Object {
      $_.ActiveDirectoryRights.ToString() -match 'WriteProperty' -and $_.AppliesToProperty -eq 'member'
    }
    $preWin2k  = $records | Where-Object { $_.Trustee -eq 'Pre-Windows 2000 Compatible Access' }
    $lapsRead  = $records | Where-Object {
      $_.AppliesToProperty -in $lapsAttributes -and $_.ActiveDirectoryRights.ToString() -match 'ReadProperty|ExtendedRight'
    }
    $computerCreate = $records | Where-Object {
      $_.ActiveDirectoryRights.ToString() -match 'CreateChild' -and ($_.AppliesToClass -match 'computer')
    }

    # Safe counts under StrictMode
    $cntOver            = ($overDelegations      | Measure-Object).Count
    $cntAcctOps         = ($accountOperators     | Measure-Object).Count
    $cntPrintOps        = ($printOperators       | Measure-Object).Count
    $cntExchange        = ($exchangeDelegations  | Measure-Object).Count
    $cntSvc             = ($serviceAcctDelegations | Measure-Object).Count
    $cntUnknownSids     = ($unknownSids          | Measure-Object).Count
    $cntMemberCtrl      = ($membershipControl    | Measure-Object).Count
    $cntPreWin2k        = ($preWin2k             | Measure-Object).Count
    $cntLaps            = ($lapsRead             | Measure-Object).Count
    $cntComputerCreate  = ($computerCreate       | Measure-Object).Count

    # High-risk CSV
    $highRisk = $records | Where-Object {
      $_.ActiveDirectoryRights.ToString() -match 'GenericAll|WriteDacl|DeleteTree' -or
      ($_.AppliesToProperty -in ($lapsAttributes + 'member') -and $_.ActiveDirectoryRights.ToString() -match 'WriteProperty|ReadProperty|ExtendedRight')
    }
    $highCsv = Join-Path -Path $allDir -ChildPath "ADAudit_HighRisk_$ts.csv"
    $highRisk | Export-Csv -NoTypeInformation -Path $highCsv -Encoding UTF8
    Write-Host "High-Risk CSV:  $highCsv"

    # ----------------------------
    # Risk Assessment - structured by SEVERITY so the operator can read top-down:
    # CRITICAL findings first (act now), HIGH next, MEDIUM/LOW after. Each
    # finding now carries: severity, what is wrong, why it matters (security
    # impact), how to fix it, and a sample of trustees / scopes to look at.
    # The old report listed nine numbered items with no severity grouping and
    # no "what to do" guidance per item, which made it hard to prioritise.
    # ----------------------------
    $findings = New-Object System.Collections.Generic.List[object]

    function _Add-Finding {
        param(
            [Parameter(Mandatory)][string]$Severity,
            [Parameter(Mandatory)][string]$Title,
            [Parameter(Mandatory)][int]$Count,
            [Parameter(Mandatory)][string]$Why,
            [Parameter(Mandatory)][string]$Fix,
            [string[]]$Samples = @()
        )
        $findings.Add([pscustomobject]@{
            Severity = $Severity
            Title    = $Title
            Count    = $Count
            Why      = $Why
            Fix      = $Fix
            Samples  = $Samples
        }) | Out-Null
    }

    if ($cntOver -gt 0) {
        $sev = if ($cntOver -gt 50) { 'CRITICAL' } elseif ($cntOver -gt 10) { 'HIGH' } else { 'MEDIUM' }
        $samples = @($overDelegations | Select-Object -ExpandProperty Trustee | Sort-Object -Unique | Select-Object -First 10)
        _Add-Finding -Severity $sev -Title 'Over-delegation: GenericAll / WriteDacl / DeleteTree' -Count $cntOver `
            -Why 'These rights let the trustee fully control or take ownership of the affected OU, which is equivalent to administrative access on every object below it. A single account or group with GenericAll on a Tier0 OU is a domain-takeover path.' `
            -Fix 'Replace these delegations with task-specific rights (e.g. ResetPassword, ReadPwdLastSet) scoped to the smallest necessary container. Document the business justification for any remaining GenericAll delegation.' `
            -Samples $samples
    }
    if ($cntMemberCtrl -gt 0) {
        $sev = if ($cntMemberCtrl -gt 40) { 'CRITICAL' } elseif ($cntMemberCtrl -gt 5) { 'HIGH' } else { 'MEDIUM' }
        $samples = @($membershipControl | Select-Object -ExpandProperty Trustee | Sort-Object -Unique | Select-Object -First 10)
        _Add-Finding -Severity $sev -Title 'Group membership modification rights (WriteProperty on member)' -Count $cntMemberCtrl `
            -Why 'Allows the trustee to add/remove accounts from arbitrary groups - a direct privilege-escalation vector if it leads to Tier0 groups (Domain/Enterprise Admins) via nested membership.' `
            -Fix 'Restrict member-write to controlled, audited group-admin roles. Never grant member-write on Tier0 groups except via JIT/PIM.' `
            -Samples $samples
    }
    if ($cntLaps -gt 0) {
        $samples = @($lapsRead | Select-Object -ExpandProperty Trustee | Sort-Object -Unique | Select-Object -First 10)
        _Add-Finding -Severity 'HIGH' -Title 'LAPS password read delegations' -Count $cntLaps `
            -Why 'Trustees with read access to ms-Mcs-AdmPwd / msLAPS-Password can recover the local-administrator password of every computer covered by the delegation. This is full local-admin on those endpoints.' `
            -Fix 'Limit LAPS read to a small, monitored helpdesk/Tier1 group. Audit each existing reader and remove anything outside that group. Monitor all reads.' `
            -Samples $samples
    }
    if ($cntComputerCreate -gt 0) {
        $samples = @($computerCreate | Select-Object -ExpandProperty Trustee | Sort-Object -Unique | Select-Object -First 10)
        _Add-Finding -Severity 'HIGH' -Title 'Computer object creation rights (CreateChild for computer class)' -Count $cntComputerCreate `
            -Why 'Trustees who can create computer objects can join arbitrary machines to the domain and chain that into Resource-Based Constrained Delegation (RBCD) attacks for privilege escalation.' `
            -Fix 'Constrain computer creation to a dedicated join service account with a low MachineAccountQuota (or 0). Never grant CreateChild=computer to broad groups.' `
            -Samples $samples
    }
    if ($cntAcctOps -gt 0) {
        _Add-Finding -Severity 'HIGH' -Title 'BUILTIN\Account Operators delegations present' -Count $cntAcctOps `
            -Why 'Account Operators can manage users/groups/computers in most of the domain - Microsoft explicitly recommends this group be empty. Membership and ACEs through it indirectly create privileged paths.' `
            -Fix 'Remove BUILTIN\Account Operators delegations from OUs unless explicitly required and reviewed. Replace with narrow, task-specific delegations.' `
            -Samples @()
    }
    if ($cntSvc -gt 0) {
        $sev = if ($cntSvc -gt 30) { 'HIGH' } else { 'MEDIUM' }
        $samples = @($serviceAcctDelegations | Select-Object -ExpandProperty Trustee | Sort-Object -Unique | Select-Object -First 10)
        _Add-Finding -Severity $sev -Title 'Service account elevated delegations' -Count $cntSvc `
            -Why 'Service accounts (svc-*, DJ-*, DomainJoin*) holding write/create rights are an attractive target - if compromised they can be used for SPN-based attacks (Kerberoasting), RBCD, and lateral movement.' `
            -Fix 'Apply least privilege per service account, rotate passwords, prefer Group Managed Service Accounts (gMSA), and tier them so they cannot reach Tier0 objects.' `
            -Samples $samples
    }
    if ($cntExchange -gt 0) {
        _Add-Finding -Severity 'MEDIUM' -Title 'Exchange security group delegations' -Count $cntExchange `
            -Why 'Exchange Trusted Subsystem / Organization Management / Exchange Windows Permissions traditionally hold rights well beyond mail scope. They have historically been a path to domain compromise (CVE-2019-0683 et al).' `
            -Fix 'Review these ACLs against Microsoft Exchange Split Permissions and remove anything not required by the current Exchange version. Replace any GenericAll with the documented minimum.' `
            -Samples @()
    }
    if ($cntUnknownSids -gt 0) {
        _Add-Finding -Severity 'MEDIUM' -Title 'Unknown / unresolved SIDs in ACLs' -Count $cntUnknownSids `
            -Why 'A SID that no longer resolves to a principal is usually orphaned (deleted account, deleted trust). Each one is dead weight in the ACL and complicates audits, but a foreign-domain SID could also indicate an unexpected trust relationship.' `
            -Fix 'For each SID, verify whether it belongs to a deleted local principal or a foreign domain, then remove the ACE. Do NOT bulk-delete without verification.' `
            -Samples @($unknownSids | Select-Object -First 10)
    }
    if ($cntPrintOps -gt 0) {
        _Add-Finding -Severity 'MEDIUM' -Title 'BUILTIN\Print Operators delegations present' -Count $cntPrintOps `
            -Why 'Print Operators can load device drivers and historically have been abused (e.g. PrintNightmare, SpoolSample). Microsoft recommends keeping the group empty.' `
            -Fix 'Remove Print Operators delegations from OUs unless required. Empty the group where possible; replace with explicit, scoped delegations.' `
            -Samples @()
    }
    if ($cntPreWin2k -gt 0) {
        _Add-Finding -Severity 'LOW' -Title 'Legacy Pre-Windows 2000 Compatible Access ACEs' -Count $cntPreWin2k `
            -Why 'Pre-Windows 2000 Compatible Access expands anonymous/legacy read scope. Modern environments should not need it.' `
            -Fix 'Decommission Pre-Windows 2000 Compatible Access ACEs if no legacy systems require them. Validate downstream impact in a maintenance window first.' `
            -Samples @()
    }

    # Sort findings by severity (CRITICAL > HIGH > MEDIUM > LOW > INFORMATIONAL)
    $sevRank = @{ 'CRITICAL'=0; 'HIGH'=1; 'MEDIUM'=2; 'LOW'=3; 'INFORMATIONAL'=4 }
    $findings = @($findings | Sort-Object @{Expression={$sevRank[$_.Severity]}}, @{Expression={-1 * $_.Count}}, Title)

    $criticalCount = @($findings | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
    $highCount     = @($findings | Where-Object { $_.Severity -eq 'HIGH' }).Count
    $medCount      = @($findings | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
    $lowCount      = @($findings | Where-Object { $_.Severity -eq 'LOW' }).Count

    $overallRisk = if ($criticalCount -gt 0) { 'CRITICAL' }
                   elseif ($highCount -gt 0) { 'HIGH' }
                   elseif ($medCount  -gt 0) { 'MEDIUM' }
                   elseif ($lowCount  -gt 0) { 'LOW' }
                   else { 'CLEAN' }

    $riskSb = New-Object System.Text.StringBuilder
    [void]$riskSb.AppendLine('=====================================================================')
    [void]$riskSb.AppendLine(' DELEGATED PERMISSIONS RISK ASSESSMENT')
    [void]$riskSb.AppendLine('=====================================================================')
    [void]$riskSb.AppendLine(" Generated         : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$riskSb.AppendLine(" Scopes analysed   : $(@($scopes).Count)")
    [void]$riskSb.AppendLine(" ACE records       : $($records.Count)")
    [void]$riskSb.AppendLine(" Overall risk      : $overallRisk")
    [void]$riskSb.AppendLine(" Findings (CRITICAL/HIGH/MEDIUM/LOW): $criticalCount / $highCount / $medCount / $lowCount")
    [void]$riskSb.AppendLine('---------------------------------------------------------------------')
    [void]$riskSb.AppendLine('')
    [void]$riskSb.AppendLine('How to read this file:')
    [void]$riskSb.AppendLine(' - Findings are sorted by severity. Work CRITICAL/HIGH first.')
    [void]$riskSb.AppendLine(' - Each finding has: WHY (the security impact) and FIX (the action).')
    [void]$riskSb.AppendLine(' - For the per-account/per-OU breakdown of any finding, open the')
    [void]$riskSb.AppendLine('   matching file in OUs/ (.csv) or All/ADAudit_HighRisk_*.csv.')
    [void]$riskSb.AppendLine('')

    if ($findings.Count -eq 0) {
        [void]$riskSb.AppendLine('No findings detected against the heuristic baseline. This does not')
        [void]$riskSb.AppendLine('replace a manual ACL review - it only means the patterns this')
        [void]$riskSb.AppendLine('script tests for were not present.')
        [void]$riskSb.AppendLine('')
    } else {
        $idx = 0
        foreach ($f in $findings) {
            $idx++
            [void]$riskSb.AppendLine(("[{0}/{1}] [{2}] {3}" -f $idx, $findings.Count, $f.Severity, $f.Title))
            [void]$riskSb.AppendLine("    Count : $($f.Count) ACE records")
            [void]$riskSb.AppendLine("    Why   : $($f.Why)")
            [void]$riskSb.AppendLine("    Fix   : $($f.Fix)")
            if ($f.Samples -and $f.Samples.Count -gt 0) {
                [void]$riskSb.AppendLine("    Sample: $((($f.Samples | Select-Object -First 10) -join ', '))")
            }
            [void]$riskSb.AppendLine('')
        }
    }

    $riskPath = Join-Path $base 'ADAudit_RiskAssessment.txt'
    Set-Content -LiteralPath $riskPath -Value $riskSb.ToString() -Encoding UTF8
    Write-Host "Wrote: $riskPath"

    # ----------------------------
    # Recommendations - keep the existing prioritized action list (it's the
    # generic playbook that maps to the findings above).
    # ----------------------------
    $rec = @()
    $rec += "Delegated Permissions Recommendations"
    $rec += ('=' * 80)
    $rec += "Prioritized Actions:"
    $rec += " 1. Remove unnecessary GenericAll / WriteDacl / DeleteTree delegations."
    $rec += " 2. Remove BUILTIN\Account Operators and Print Operators from OUs unless explicitly required."
    $rec += " 3. Review Exchange-related ACLs; align with Microsoft minimums; eliminate GenericAll."
    $rec += " 4. Resolve unknown SIDs; remove orphaned entries."
    $rec += " 5. Enforce least privilege for service accounts (scoped rights, rotation, tiering)."
    $rec += " 6. Restrict WriteProperty(member) to controlled group admins; isolate Tier0 groups."
    $rec += " 7. Decommission Pre-Windows 2000 Compatible Access if no legacy need."
    $rec += " 8. Harden Tier0 OUs: only Enterprise Admins / Domain Admins."
    $rec += " 9. Constrain computer account creation to a dedicated join group with quota."
    $rec += "10. Monitor ACL changes with auditing and alerts."
    $rec += ""
    $rec += "Microsoft Reference Links:"
    $rec += " - AD DS security best practices: https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices"
    $rec += " - AD partitions and naming contexts: https://learn.microsoft.com/windows/win32/ad/active-directory-partitions"
    $rec += " - Control access rights (rightsGuid): https://learn.microsoft.com/windows/win32/ad/control-access-rights"
    $rec += " - AdminSDHolder and protected groups: https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices#ad-protected-accounts-and-groups"
    $rec += " - Windows LAPS overview: https://learn.microsoft.com/windows-server/identity/laps/laps-overview"
    $rec += ""
    $rec += "Disclaimer: Automated heuristic assessment; verify before remediation."
    $recPath = Join-Path $base 'ADAudit_Recommendations.txt'
    $rec -join [Environment]::NewLine | Out-File -FilePath $recPath -Encoding UTF8
    Write-Host "Wrote: $recPath"

    # ----------------------------
    # Single consolidated per-scope summary that REPLACES the 73+ per-OU .txt
    # files we used to drop in OUs/. This is the human-readable companion to
    # the per-OU .csv files - one document, sorted by scope, grouped by
    # trustee, with rights inline. Use the .csv files when you need to filter
    # or pivot in Excel; this file is for reading top-down.
    # ----------------------------
    $perScopeSb = New-Object System.Text.StringBuilder
    [void]$perScopeSb.AppendLine('=====================================================================')
    [void]$perScopeSb.AppendLine(' DELEGATED PERMISSIONS - PER-SCOPE SUMMARY (HUMAN READABLE)')
    [void]$perScopeSb.AppendLine('=====================================================================')
    [void]$perScopeSb.AppendLine(" Generated  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$perScopeSb.AppendLine(" Scopes     : $(@($scopes).Count)")
    [void]$perScopeSb.AppendLine(" ACE records: $($records.Count)")
    [void]$perScopeSb.AppendLine('---------------------------------------------------------------------')
    [void]$perScopeSb.AppendLine(' For machine-readable output use OUs\ADAudit_*.csv (one per scope) or')
    [void]$perScopeSb.AppendLine(' All\ADAudit_AllScopes_*.csv (everything in one CSV).')
    [void]$perScopeSb.AppendLine('---------------------------------------------------------------------')
    [void]$perScopeSb.AppendLine('')

    $byScopeForTxt = $records | Group-Object ScopeDN | Sort-Object Name
    foreach ($g in $byScopeForTxt) {
        $first = $g.Group | Select-Object -First 1
        [void]$perScopeSb.AppendLine('=====================================================================')
        [void]$perScopeSb.AppendLine(" Scope      : $($g.Name)")
        [void]$perScopeSb.AppendLine(" Type       : $($first.ScopeType)")
        if ($first.CanonicalScope) {
            [void]$perScopeSb.AppendLine(" Canonical  : $($first.CanonicalScope)")
        }
        [void]$perScopeSb.AppendLine(" ACE count  : $($g.Count)")
        [void]$perScopeSb.AppendLine('---------------------------------------------------------------------')
        foreach ($trGrp in ($g.Group | Group-Object Trustee | Sort-Object Name)) {
            $tFirst = $trGrp.Group | Select-Object -First 1
            [void]$perScopeSb.AppendLine("  Trustee  : $($trGrp.Name)  [$($tFirst.TrusteeType)]")
            foreach ($r in $trGrp.Group) {
                $line = "    {0,-20} ({1}) class={2} prop={3} inh={4}" -f `
                    $r.ActiveDirectoryRights, $r.AccessControlType,
                    ($(if($r.AppliesToClass){$r.AppliesToClass}else{'-'})),
                    ($(if($r.AppliesToProperty){$r.AppliesToProperty}else{'-'})),
                    $r.InheritanceType
                [void]$perScopeSb.AppendLine($line)
            }
            [void]$perScopeSb.AppendLine('')
        }
        [void]$perScopeSb.AppendLine('')
    }

    $perScopePath = Join-Path $base 'ADAudit_PerScopeSummary.txt'
    Set-Content -LiteralPath $perScopePath -Value $perScopeSb.ToString() -Encoding UTF8
    Write-Host "Wrote: $perScopePath"

    # CSVs
    $masterCsv = Join-Path -Path $allDir -ChildPath "ADAudit_AllScopes_$ts.csv"
    $records | Sort-Object ScopeType,ScopeDN,Trustee | Export-Csv -NoTypeInformation -Path $masterCsv -Encoding UTF8

    $byScope = $records | Group-Object ScopeDN
    foreach ($g in $byScope) {
      $safeName = ($g.Name -replace '[=,]','_') -replace '[^\w\.-]','_'
      $csvPath = Join-Path -Path $ouDir -ChildPath "ADAudit_$safeName.csv"
      $g.Group | Export-Csv -NoTypeInformation -Path $csvPath -Encoding UTF8
    }

    # ----------------------------
    # HTML index - now leads with the structured Findings (severity, why, fix,
    # sample trustees) and demotes the raw scope list to a collapsed section
    # so the operator sees risk first, scopes second.
    # ----------------------------
    $sevToBadge = @{
        'CRITICAL'      = 'badge-critical'
        'HIGH'          = 'badge-high'
        'MEDIUM'        = 'badge-medium'
        'LOW'           = 'badge-low'
        'INFORMATIONAL' = 'badge-info'
    }

    $index = New-Object System.Collections.Generic.List[string]
    $index.Add((Get-ADAuditReportHeader -Title 'AD Delegated Permissions Report'))
    $index.Add("<div class='hero'><h1>AD Delegated Permissions Report</h1>")
    $index.Add("<div class='meta'>Generated: $(Get-Date -Format 'u') &mdash; Overall risk: <strong>$overallRisk</strong></div></div>")

    $index.Add("<div class='stats'>")
    $index.Add("<div class='stat'><div class='val'>$($scopes.Count)</div><div class='lbl'>Scopes Analyzed</div></div>")
    $index.Add("<div class='stat'><div class='val'>$($records.Count)</div><div class='lbl'>Total ACEs</div></div>")
    $index.Add("<div class='stat'><div class='val' style='color:var(--critical)'>$criticalCount</div><div class='lbl'>Critical</div></div>")
    $index.Add("<div class='stat'><div class='val' style='color:var(--high)'>$highCount</div><div class='lbl'>High</div></div>")
    $index.Add("<div class='stat'><div class='val' style='color:var(--medium)'>$medCount</div><div class='lbl'>Medium</div></div>")
    $index.Add("<div class='stat'><div class='val' style='color:var(--low)'>$lowCount</div><div class='lbl'>Low</div></div>")
    $index.Add("</div>")

    $index.Add('<h2>How to read this report</h2>')
    $index.Add('<p>Findings are sorted by severity. Each finding tells you <strong>what is wrong</strong>, <strong>why it matters</strong> (the actual security impact), and the <strong>recommended fix</strong>. Use the per-scope CSV files at the bottom to drill into specific OUs.</p>')

    $index.Add('<h2>Findings</h2>')
    if ($findings.Count -eq 0) {
        $index.Add('<p>No findings detected against the heuristic baseline.</p>')
    } else {
        foreach ($f in $findings) {
            $badge = $sevToBadge[$f.Severity]; if (-not $badge) { $badge = 'badge-info' }
            $titleEnc  = [System.Web.HttpUtility]::HtmlEncode($f.Title)
            $whyEnc    = [System.Web.HttpUtility]::HtmlEncode($f.Why)
            $fixEnc    = [System.Web.HttpUtility]::HtmlEncode($f.Fix)
            $sampleTxt = if ($f.Samples -and $f.Samples.Count -gt 0) {
                ($f.Samples | Select-Object -First 10 | ForEach-Object { "<li><code>$([System.Web.HttpUtility]::HtmlEncode([string]$_))</code></li>" }) -join ''
            } else { '' }
            $sampleBlock = if ($sampleTxt) {
                "<p><strong>Sample trustees / SIDs:</strong></p><ul>$sampleTxt</ul>"
            } else { '' }
            $index.Add(@"
<details>
<summary><span class="badge $badge">$($f.Severity)</span> &nbsp; $titleEnc &nbsp;&mdash;&nbsp; <strong>$($f.Count) ACE records</strong></summary>
<div class="detail-body">
<p><strong>Why this matters:</strong> $whyEnc</p>
<p><strong>How to fix:</strong> $fixEnc</p>
$sampleBlock
</div>
</details>
"@)
        }
    }

    try { [void][System.Web.HttpUtility] } catch { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue }

    $index.Add('<h2>Reference Files</h2><ul class="link-list">')
    $index.Add("<li><a href='ADAudit_RiskAssessment.txt'>Risk Assessment (severity-grouped, with WHY/FIX per finding)</a></li>")
    $index.Add("<li><a href='ADAudit_Recommendations.txt'>Recommendations (prioritised playbook)</a></li>")
    $index.Add("<li><a href='ADAudit_PerScopeSummary.txt'>Per-Scope Summary (one human-readable file, all scopes)</a></li>")
    $index.Add("<li><a href='All/ADAudit_AllScopes_$ts.csv'>Master CSV - all ACEs across all scopes</a></li>")
    $index.Add("<li><a href='All/ADAudit_HighRisk_$ts.csv'>High-Risk CSV - flagged ACEs only</a></li>")
    $index.Add('</ul>')

    $index.Add('<h2>Per-Scope CSV (drill-down)</h2>')
    $index.Add('<details><summary>Show all ' + (@($scopes).Count) + ' scope CSVs</summary><div class="detail-body"><ul class="link-list">')
    foreach ($dn in $scopes) {
        $safe = ($dn -replace '[=,]','_') -replace '[^\w\.-]','_'
        $dnEnc = [System.Web.HttpUtility]::HtmlEncode([string]$dn)
        $index.Add("<li><a href='OUs/ADAudit_$safe.csv'><code>$dnEnc</code></a></li>")
    }
    $index.Add('</ul></div></details>')
    $index.Add((Get-ADAuditReportFooter))
    $indexPath = Join-Path $base 'index.html'
    $index -join "`r`n" | Out-File -Encoding UTF8 -FilePath $indexPath
    Write-Host "Index: $indexPath"

    Write-Host "Reports folder: $base"
    Write-Host "Master CSV:     $masterCsv"

    # End transcript
    try { Stop-Transcript | Out-Null } catch {}
}

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
        try {
            $g = Get-ADGroup -Identity $Identity -ErrorAction Stop
            return @(Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop)
        } catch {
            return @()
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
    $privSamSet = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($gd in $groupDefs) {
        $members = _Get-GroupMembersBySidOrName -Identity $gd.Identity
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

$inactiveDetails = @()

# Enabled users (bitwise filter for "not disabled")
$enabledUsers = Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
    -Properties lastLogonTimestamp,whenCreated,SamAccountName,Name -ErrorAction SilentlyContinue

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
        $inactiveDetails += [pscustomobject]@{
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
        }
    }
}

$inactiveObj = [pscustomobject]@{
    RiskId='ACCT_INACTIVE'
    Category='Account Hygiene'
    Item="Enabled accounts inactive > $inactiveDays days"
    Severity='HIGH'
    Baseline="0 (disable if inactive > $inactiveDays days)"
    Observed=($inactiveDetails | Measure-Object).Count
    IsFinding=((($inactiveDetails | Measure-Object).Count) -gt 0)
    Recommendation='Disable or remove accounts that are no longer used; verify HR/offboarding; prioritize privileged and service accounts.'
}
    
    # Password never expires (enabled users)
    $pneUsers = Search-ADAccount -PasswordNeverExpires -UsersOnly -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
    $pneDetails = @()
    foreach ($u in $pneUsers) {
        $pneDetails += [pscustomobject]@{
            RiskId='PWD_NEVER_EXPIRES'
            SamAccountName=$u.SamAccountName
            Name=$u.Name
            Baseline='0 (humans); use gMSA/MSA for services'
            Severity= $(if ($privSamSet.Contains([string]$u.SamAccountName)) { 'CRITICAL' } else { 'HIGH' })
            IsPrivileged= $privSamSet.Contains([string]$u.SamAccountName)
        }
    }
    $pneObj = [pscustomobject]@{
        RiskId='PWD_NEVER_EXPIRES'
        Category='Credential Hygiene'
        Item='Enabled user accounts with PasswordNeverExpires'
        Severity='HIGH'
        Baseline='0 (humans); services should use gMSA/MSA'
        Observed=($pneDetails | Measure-Object).Count
        IsFinding=((($pneDetails | Measure-Object).Count) -gt 0)
        Recommendation='Eliminate non-expiring human passwords; migrate service accounts to gMSA; rotate credentials; enforce MFA for admins.'
    }

    # Disabled accounts stale (>180 days) based on whenChanged (best-effort)
    $disabledRetentionDays = 180
    $disabledOld = Get-ADUser -Filter { Enabled -eq $false } -Properties whenChanged,SamAccountName,Name -ErrorAction SilentlyContinue |
                   Where-Object { $_.whenChanged -lt (Get-Date).AddDays(-$disabledRetentionDays) }
    $disabledOldDetails = @()
    foreach ($u in $disabledOld) {
        $disabledOldDetails += [pscustomobject]@{
            RiskId='ACCT_DISABLED_STALE'
            SamAccountName=$u.SamAccountName
            Name=$u.Name
            whenChanged=$u.whenChanged
            Baseline="Review/remove if disabled > $disabledRetentionDays days"
            Severity='MEDIUM'
        }
    }
    $disabledOldObj = [pscustomobject]@{
        RiskId='ACCT_DISABLED_STALE'
        Category='Account Hygiene'
        Item="Disabled accounts not reviewed > $disabledRetentionDays days"
        Severity='MEDIUM'
        Baseline="0 (review/remove if disabled > $disabledRetentionDays days)"
        Observed=($disabledOldDetails | Measure-Object).Count
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

            $replAccounts = Get-ADReplAccount -All -Server $dc -NamingContext $domainDN -ErrorAction Stop
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

Function Get-KerberosUnconstrainedDelegation {
    # Finds accounts with unconstrained Kerberos delegation (excluding DCs which have it by design)
    # Unconstrained delegation allows an account to impersonate any user, making it a high-value attack target
    $count = 0
    $evidencePath = Get-EvidencePath 'unconstrained_delegation.txt'
    Remove-Item -LiteralPath $evidencePath -Force -ErrorAction SilentlyContinue

    # UserAccountControl flag 0x80000 = TRUSTED_FOR_DELEGATION (unconstrained)
    $filter = '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))'
    $results = Get-ADObject -LDAPFilter $filter -Properties Name, SamAccountName, ObjectClass, userAccountControl, DistinguishedName

    foreach ($obj in $results) {
        Add-Content -Path $evidencePath -Value "$($obj.ObjectClass) $($obj.SamAccountName) ($($obj.Name)) has unconstrained Kerberos delegation - DN: $($obj.DistinguishedName)"
        $count++
    }

    if ($count -gt 0) {
        Write-Both "    [!] $count non-DC account(s) with unconstrained Kerberos delegation found (KB1200)"
        Write-Both "    [!] These accounts can impersonate ANY user who authenticates to them - high-priority remediation target"
        Write-Nessus-Finding "UnconstrainedDelegation" "KB1200" ([System.IO.File]::ReadAllText($evidencePath))
    }
    else {
        Write-Both "    [+] No non-DC accounts with unconstrained Kerberos delegation found"
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

Function Get-TombstoneLifetime {
    # Checks the forest tombstone lifetime configuration
    # Low tombstone lifetime reduces the window for AD Recycle Bin recovery
    $configNC = (Get-ADRootDSE).configurationNamingContext
    $tombstoneObj = Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties tombstoneLifetime -ErrorAction SilentlyContinue
    $lifetime = $tombstoneObj.tombstoneLifetime

    if ($null -eq $lifetime) {
        $lifetime = 60  # Default if not explicitly set (Windows Server 2003+)
        Write-Both "    [!] Tombstone lifetime is not explicitly configured (defaults to 60 days). Consider setting to 180 days for better AD Recycle Bin retention (KB1202)"
        Write-Nessus-Finding "TombstoneLifetime" "KB1202" "Tombstone lifetime not explicitly set (defaults to 60 days)"
    }
    elseif ($lifetime -lt 180) {
        Write-Both "    [!] Tombstone lifetime is set to $lifetime days (recommended: 180 days minimum) (KB1202)"
        Write-Nessus-Finding "TombstoneLifetime" "KB1202" "Tombstone lifetime is $lifetime days (recommended minimum: 180)"
    }
    else {
        Write-Both "    [+] Tombstone lifetime is $lifetime days"
    }
}

Function Get-PrintSpoolerOnDCs {
    # Checks if Print Spooler service is running on domain controllers
    # PrintNightmare (CVE-2021-34527) and coercion attacks exploit the spooler service
    $count = 0
    $evidencePath = Get-EvidencePath 'dc_print_spooler.txt'
    Remove-Item -LiteralPath $evidencePath -Force -ErrorAction SilentlyContinue

    $dcList = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)

    foreach ($dc in $dcList) {
        try {
            $spooler = Get-ADAuditCimInstance -ClassName Win32_Service -Filter "Name='Spooler'" -ComputerName $dc -UseWsmanFallback
            if ($spooler -and $spooler.State -eq 'Running') {
                Add-Content -Path $evidencePath -Value "Print Spooler is RUNNING on DC: $dc (StartMode: $($spooler.StartMode))"
                $count++
            }
            elseif ($spooler) {
                Write-Both "    [+] Print Spooler is $($spooler.State) on DC: $dc"
            }
        }
        catch {
            Write-Both "    [!] Could not query Print Spooler status on DC: $dc - $_"
        }
    }

    if ($count -gt 0) {
        Write-Both "    [!] Print Spooler is running on $count domain controller(s) - disable to mitigate PrintNightmare and coercion attacks (KB1203)"
        Write-Nessus-Finding "PrintSpoolerOnDC" "KB1203" ([System.IO.File]::ReadAllText($evidencePath))
    }
    else {
        Write-Both "    [+] Print Spooler is not running on any domain controller"
    }
}

Function Get-SMBSigningStatus {
    # Checks SMB signing enforcement on domain controllers
    # Missing SMB signing enables NTLM relay attacks
    $count = 0
    $evidencePath = Get-EvidencePath 'dc_smb_signing.txt'
    Remove-Item -LiteralPath $evidencePath -Force -ErrorAction SilentlyContinue

    $dcList = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)

    foreach ($dc in $dcList) {
        try {
            $regParams = @{
                ClassName    = 'StdRegProv'
                Namespace    = 'root/default'
                ComputerName = $dc
            }

            # Check RequireSecuritySignature (EnableSecuritySignature is the weaker setting)
            $requireSigning = $null
            try {
                $result = Invoke-CimMethod -ClassName StdRegProv -Namespace 'root/default' -MethodName GetDWORDValue -Arguments @{
                    hDefKey     = [uint32]2147483650  # HKLM
                    sSubKeyName = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
                    sValueName  = 'RequireSecuritySignature'
                } -CimSession (New-CimSession -ComputerName $dc -ErrorAction Stop) -ErrorAction Stop
                $requireSigning = $result.uValue
            }
            catch {
                # Fallback: try Get-SmbServerConfiguration if available
                try {
                    $smbConfig = Invoke-Command -ComputerName $dc -ScriptBlock { (Get-SmbServerConfiguration).RequireSecuritySignature } -ErrorAction Stop
                    $requireSigning = if ($smbConfig) { 1 } else { 0 }
                }
                catch {
                    Write-Both "    [!] Could not query SMB signing status on DC: $dc - $_"
                    continue
                }
            }

            if ($null -ne $requireSigning -and $requireSigning -ne 1) {
                Add-Content -Path $evidencePath -Value "SMB signing is NOT required on DC: $dc (RequireSecuritySignature = $requireSigning)"
                $count++
            }
            else {
                Write-Both "    [+] SMB signing is required on DC: $dc"
            }
        }
        catch {
            Write-Both "    [!] Could not query SMB signing status on DC: $dc - $_"
        }
    }

    if ($count -gt 0) {
        Write-Both "    [!] SMB signing is not enforced on $count domain controller(s) - enables NTLM relay attacks (KB1204)"
        Write-Nessus-Finding "SMBSigningNotRequired" "KB1204" ([System.IO.File]::ReadAllText($evidencePath))
    }
    else {
        Write-Both "    [+] SMB signing is required on all domain controllers"
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
    try { Get-ADUser     -Filter * -Properties $props -ErrorAction SilentlyContinue | ForEach-Object { $allAccounts.Add($_) | Out-Null } } catch { }
    try { Get-ADComputer -Filter * -Properties $props -ErrorAction SilentlyContinue | ForEach-Object { $allAccounts.Add($_) | Out-Null } } catch { }

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
            $authLines.Add("# Could not query Security log on ${dc}: $($_.Exception.Message)") | Out-Null
            $authHasContent = $true
            continue
        }

        foreach ($evt in $events) {
            # TicketEncryptionType is exposed as an integer (UInt32) in event Properties.
            # 0x17 (23) = RC4-HMAC, 0x18 (24) = RC4-HMAC-EXP
            # 0x11 (17) = AES128, 0x12 (18) = AES256
            $encVal = $null
            try {
                # 4769: Properties index 5 = TicketEncryptionType ; 4768: index 8 (varies by OS)
                if ($evt.Id -eq 4769 -and $evt.Properties.Count -ge 6) {
                    $encVal = $evt.Properties[5].Value
                } elseif ($evt.Id -eq 4768 -and $evt.Properties.Count -ge 9) {
                    $encVal = $evt.Properties[8].Value
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

Function Test-DCPortConnectivity {
    <#
        Tests TCP connectivity from the running host (and, if WinRM is
        available, from each DC) to every DC on the standard set of ports an
        AD environment needs. Closed ports here directly limit AD
        functionality (replication, authentication, DNS, group policy, AD
        Web Services for the PowerShell module). LDAP/LDAPS are also flagged
        as risk findings because plaintext LDAP enables MITM/relay attacks.

        Output:
            dc_port_connectivity.txt  - human readable findings with WHY/FIX
            dc_port_connectivity.csv  - machine readable per-(source,target,port) rows
        Plus a Nessus finding (KB1310) and a CheckFailures entry for each DC
        that could not be reached at all.

        WinRM dependency: cross-DC tests REQUIRE WinRM 5985/5986 to be open
        from this host to each DC. If WinRM is unavailable we still run the
        local-host -> DC tests and clearly note that the cross-DC matrix was
        skipped (and why) in the output, rather than failing.
    #>
    [CmdletBinding()]
    param()

    $evidencePath = Get-EvidencePath 'dc_port_connectivity.txt'
    $csvPath      = Get-EvidencePath 'dc_port_connectivity.csv'
    Remove-Item -LiteralPath $evidencePath,$csvPath -Force -ErrorAction SilentlyContinue

    # Required port catalog. Each entry has a friendly name, a security
    # criticality (Critical / High / Medium / Low), and a short rationale.
    # The criticality drives both the severity in the report and how a
    # closed port is presented to the operator (some ports are advisory,
    # most are operationally required).
    $portCatalog = @(
        [pscustomobject]@{ Port=53;    Proto='tcp'; Name='DNS';                          Severity='Critical'; Why='DC must serve DNS for SRV/A records used by clients to find DCs.'; Required=$true }
        [pscustomobject]@{ Port=88;    Proto='tcp'; Name='Kerberos';                     Severity='Critical'; Why='Kerberos AS/TGS exchanges. If blocked, no Kerberos auth happens.'; Required=$true }
        [pscustomobject]@{ Port=135;   Proto='tcp'; Name='RPC endpoint mapper';          Severity='Critical'; Why='Endpoint mapper for AD replication, Netlogon, RPC over TCP. Without it most AD operations fail.'; Required=$true }
        [pscustomobject]@{ Port=389;   Proto='tcp'; Name='LDAP (plaintext)';             Severity='Medium';   Why='Plaintext LDAP; required for legacy clients but should NEVER be the only AD lookup path. Channel binding/LDAP signing must be enforced.'; Required=$true }
        [pscustomobject]@{ Port=445;   Proto='tcp'; Name='SMB';                          Severity='Critical'; Why='SYSVOL/NETLOGON shares, GPO download. Without it clients cannot apply Group Policy.'; Required=$true }
        [pscustomobject]@{ Port=464;   Proto='tcp'; Name='Kerberos password change';     Severity='High';     Why='kpasswd. Required for password changes through Kerberos (Set-ADAccountPassword, ALTER DOMAIN PASSWORD, etc).'; Required=$true }
        [pscustomobject]@{ Port=636;   Proto='tcp'; Name='LDAPS (LDAP over TLS)';        Severity='High';     Why='Encrypted LDAP. Required to protect bind credentials and search content. CLOSED = a real risk because plaintext LDAP can be intercepted/relayed.'; Required=$true }
        [pscustomobject]@{ Port=3268;  Proto='tcp'; Name='Global Catalog (LDAP)';        Severity='Critical'; Why='GC queries used by Exchange, multi-domain forest auth. Closed GC breaks login in multi-domain forests.'; Required=$true }
        [pscustomobject]@{ Port=3269;  Proto='tcp'; Name='Global Catalog (LDAPS)';       Severity='High';     Why='Encrypted GC. Same role as 3268 but over TLS. Should be open if 3268 is open.'; Required=$true }
        [pscustomobject]@{ Port=9389;  Proto='tcp'; Name='AD Web Services (ADWS)';       Severity='High';     Why='Used by the ActiveDirectory PowerShell module and Get-AD* cmdlets. Closed ADWS breaks every PowerShell-based admin tool.'; Required=$true }
        [pscustomobject]@{ Port=5985;  Proto='tcp'; Name='WinRM HTTP';                   Severity='Medium';   Why='Remote PowerShell. This audit script and many ops tools depend on it for cross-DC checks. Required for some cross-DC checks in THIS report.'; Required=$true }
        [pscustomobject]@{ Port=5986;  Proto='tcp'; Name='WinRM HTTPS';                  Severity='Low';      Why='Encrypted WinRM. Optional but recommended over 5985.'; Required=$false }
        [pscustomobject]@{ Port=139;   Proto='tcp'; Name='NetBIOS Session';              Severity='Low';      Why='Legacy NetBIOS. Modern clients use 445; can be closed if no down-level systems remain.'; Required=$false }
        [pscustomobject]@{ Port=49152; Proto='tcp'; Name='Dynamic RPC (sample)';         Severity='High';     Why='Sample of the dynamic RPC range (49152-65535) used for AD replication, DRS, FRS/DFSR. If 49152 is closed but the RPC firewall rule is open the actual replication may still be allowed; investigate before remediating.'; Required=$true }
    )

    # Discover DCs
    $dcs = @()
    try {
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop |
                 Sort-Object Name |
                 Select-Object Name,HostName,IPv4Address)
    } catch {
        Add-Content -Path $evidencePath -Value "ERROR: could not enumerate DCs via Get-ADDomainController: $($_.Exception.Message)"
        Write-Both "    [!] DC port check: could not enumerate DCs: $($_.Exception.Message)"
        return
    }
    if ($dcs.Count -eq 0) {
        Add-Content -Path $evidencePath -Value 'No domain controllers were returned by Get-ADDomainController.'
        Write-Both '    [!] DC port check: no DCs returned.'
        return
    }

    # Helper: TCP probe with short timeout
    function _Test-TcpPort {
        param([string]$Target, [int]$Port, [int]$TimeoutMs = 1500)
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $tcp.BeginConnect($Target, $Port, $null, $null)
            $ok = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
            if (-not $ok) { return [pscustomobject]@{ Open=$false; Error='timeout' } }
            try { $tcp.EndConnect($async) } catch { return [pscustomobject]@{ Open=$false; Error=$_.Exception.Message } }
            return [pscustomobject]@{ Open=$true; Error=$null }
        } catch {
            return [pscustomobject]@{ Open=$false; Error=$_.Exception.Message }
        } finally {
            try { $tcp.Close() } catch {}
        }
    }

    # Run local probes from this host to each DC. We DNS-resolve each DC name
    # first; if the name does not resolve we emit ONE "host unresolvable"
    # row instead of 14 noisy "CLOSED (No such host is known)" rows. The user
    # still gets a clear finding ("DC unreachable: name resolution failed")
    # and we skip the per-port probes for that DC. If the name resolves but
    # the host is down (e.g. firewall drops everything) the per-port loop
    # still runs and produces normal closed-port findings.
    function _Test-HostResolves {
        param([string]$Target)
        try {
            $null = [System.Net.Dns]::GetHostAddresses($Target)
            return $true
        } catch {
            return $false
        }
    }

    Write-Both ("    [+] Probing {0} DC(s) from this host on {1} required ports..." -f $dcs.Count, $portCatalog.Count)
    $rows           = New-Object System.Collections.Generic.List[object]
    $unresolvedDcs  = New-Object System.Collections.Generic.List[string]
    foreach ($dc in $dcs) {
        $tgt = if ($dc.HostName) { [string]$dc.HostName } else { [string]$dc.Name }
        if (-not (_Test-HostResolves -Target $tgt)) {
            $unresolvedDcs.Add($tgt) | Out-Null
            $rows.Add([pscustomobject]@{
                Source     = $env:COMPUTERNAME
                Target     = $tgt
                Port       = 0
                Proto      = '-'
                PortName   = 'DC unreachable (DNS resolution failed)'
                Severity   = 'Critical'
                Required   = $true
                Open       = $false
                Error      = "Name '$tgt' did not resolve via DNS from this host."
                Why        = 'Before any port test we resolve the DC FQDN. If resolution fails the DC cannot be queried at all - usually one of: the DNS server cannot be reached from this host, the DC is decommissioned but still listed in AD, or split-DNS is missing the record.'
                ProbeFrom  = 'this host'
            }) | Out-Null
            continue
        }
        foreach ($p in $portCatalog) {
            $r = _Test-TcpPort -Target $tgt -Port $p.Port
            $rows.Add([pscustomobject]@{
                Source     = $env:COMPUTERNAME
                Target     = $tgt
                Port       = $p.Port
                Proto      = $p.Proto
                PortName   = $p.Name
                Severity   = $p.Severity
                Required   = $p.Required
                Open       = $r.Open
                Error      = $r.Error
                Why        = $p.Why
                ProbeFrom  = 'this host'
            }) | Out-Null
        }
    }
    if ($unresolvedDcs.Count -gt 0) {
        Write-Both ("    [!] {0} DC(s) could not be resolved via DNS - per-port checks skipped: {1}" -f $unresolvedDcs.Count, ($unresolvedDcs -join ', '))
    }

    # Cross-DC tests via WinRM. If WinRM is unavailable, mark cross-DC as
    # skipped and continue (do NOT fail the whole check).
    $crossRows = New-Object System.Collections.Generic.List[object]
    $winrmSkippedReason = $null

    $winrmAvailableDcs = @()
    foreach ($dc in $dcs) {
        $tgt = if ($dc.HostName) { [string]$dc.HostName } else { [string]$dc.Name }
        $winrmRow = $rows | Where-Object { $_.Target -eq $tgt -and $_.Port -eq 5985 }
        if ($winrmRow -and $winrmRow.Open) { $winrmAvailableDcs += $tgt }
    }

    if ($winrmAvailableDcs.Count -eq 0) {
        $winrmSkippedReason = "WinRM (TCP 5985) is not reachable from this host to any DC, so we cannot run a cross-DC port matrix. Local-host probes above are still complete."
        Write-Both "    [!] WinRM is not reachable to any DC - skipping cross-DC port matrix. $winrmSkippedReason"
    } else {
        Write-Both ("    [+] WinRM reachable to {0} DC(s) - running cross-DC port matrix..." -f $winrmAvailableDcs.Count)
        # Run a probe FROM each WinRM-reachable DC TO every other DC. Drop any
        # DC that did not resolve via DNS from this host - the remote probe
        # would just emit "No such host is known" 14 times for it. The local
        # "DC unreachable" row for that target already surfaces it.
        $allTargets = @($dcs | ForEach-Object { if ($_.HostName) { [string]$_.HostName } else { [string]$_.Name } } | Where-Object { $unresolvedDcs -notcontains $_ })

        foreach ($srcDc in $winrmAvailableDcs) {
            try {
                $remoteResults = Invoke-Command -ComputerName $srcDc -ErrorAction Stop -ArgumentList $allTargets,$portCatalog -ScriptBlock {
                    param($Targets, $Catalog)
                    $local = $env:COMPUTERNAME
                    $out = New-Object System.Collections.Generic.List[object]
                    foreach ($t in $Targets) {
                        if ($t -eq $local -or $t -like "$local.*") { continue } # skip self
                        foreach ($p in $Catalog) {
                            $tcp = New-Object System.Net.Sockets.TcpClient
                            $open = $false; $err = $null
                            try {
                                $async = $tcp.BeginConnect($t, [int]$p.Port, $null, $null)
                                $ok = $async.AsyncWaitHandle.WaitOne(1500, $false)
                                if (-not $ok) { $err = 'timeout' }
                                else {
                                    try { $tcp.EndConnect($async); $open = $true }
                                    catch { $err = $_.Exception.Message }
                                }
                            } catch {
                                $err = $_.Exception.Message
                            } finally {
                                try { $tcp.Close() } catch {}
                            }
                            $out.Add([pscustomobject]@{
                                Source   = $local
                                Target   = $t
                                Port     = $p.Port
                                Proto    = $p.Proto
                                PortName = $p.Name
                                Severity = $p.Severity
                                Required = $p.Required
                                Open     = $open
                                Error    = $err
                                Why      = $p.Why
                                ProbeFrom = "DC '$local' (cross-DC via WinRM)"
                            }) | Out-Null
                        }
                    }
                    ,$out.ToArray()
                }
                if ($remoteResults) { foreach ($rr in $remoteResults) { $crossRows.Add($rr) | Out-Null } }
            } catch {
                Write-Both ("    [!] Cross-DC probe from {0} failed: {1}" -f $srcDc, $_.Exception.Message)
            }
        }
    }

    $allRows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows)      { $allRows.Add($r) | Out-Null }
    foreach ($r in $crossRows) { $allRows.Add($r) | Out-Null }

    # Persist machine-readable CSV
    if ($allRows.Count -gt 0) {
        $allRows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    }

    # Build the human-readable evidence file
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(' DOMAIN CONTROLLER PORT CONNECTIVITY')
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(" Generated      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine(" Probed from    : $env:COMPUTERNAME")
    [void]$sb.AppendLine(" DC count       : $($dcs.Count)")
    [void]$sb.AppendLine(" Ports per DC   : $($portCatalog.Count)")
    [void]$sb.AppendLine(" Cross-DC probe : $(if ($winrmAvailableDcs.Count -gt 0) { 'yes via WinRM from ' + ($winrmAvailableDcs -join ', ') } else { 'SKIPPED' })")
    if ($winrmSkippedReason) { [void]$sb.AppendLine("                  Reason: $winrmSkippedReason") }
    [void]$sb.AppendLine('---------------------------------------------------------------------')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('How to read this file:')
    [void]$sb.AppendLine(' - Each section below groups the closed-port findings by severity.')
    [void]$sb.AppendLine(' - "Closed" means the TCP probe could not establish a connection from')
    [void]$sb.AppendLine('   the named source to the named target on that port within 1.5s.')
    [void]$sb.AppendLine(' - LDAP (389) and LDAPS (636) are special: 389 OPEN is normal but a')
    [void]$sb.AppendLine('   risk if LDAP signing/channel-binding is not enforced; 636 CLOSED')
    [void]$sb.AppendLine('   is treated as a real finding because it forces all LDAP to plain.')
    [void]$sb.AppendLine('')

    # Closed-port findings, grouped by severity (highest first)
    $closed = @($allRows | Where-Object { -not $_.Open })
    $sevOrder = @{ 'Critical'=0; 'High'=1; 'Medium'=2; 'Low'=3 }
    $closedBySeverity = $closed | Group-Object Severity | Sort-Object @{Expression={$sevOrder[$_.Name]}}

    if ($closed.Count -eq 0) {
        [void]$sb.AppendLine('All probed ports were reachable from every probe source. No closed-port findings.')
        [void]$sb.AppendLine('')
    } else {
        foreach ($g in $closedBySeverity) {
            [void]$sb.AppendLine("[$($g.Name)] Closed ports - $($g.Count) finding(s)")
            [void]$sb.AppendLine('---------------------------------------------------------------------')
            $byPort = $g.Group | Group-Object PortName | Sort-Object Name
            foreach ($pg in $byPort) {
                $first = $pg.Group | Select-Object -First 1
                [void]$sb.AppendLine("  Port $($first.Port)/$($first.Proto) - $($first.PortName)")
                [void]$sb.AppendLine("    Why : $($first.Why)")
                $fix = switch -Regex ($first.PortName) {
                    'LDAPS' { 'Issue an LDAPS certificate to the DC (Server Authentication EKU, subject = DC FQDN), reload the DC schannel store (e.g. restart NTDS), and verify with `ldp.exe` to <DC>:636.' ; break }
                    'LDAP \(plaintext\)' { 'LDAP itself must be open (clients still use 389). The risk is unsigned/cleartext binds. Enforce LDAP signing (HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=2) and channel binding (LdapEnforceChannelBinding=2) - both should already be on per the LDAPSecurity check above.' ; break }
                    'WinRM HTTP|WinRM HTTPS' { 'Enable WinRM (`Enable-PSRemoting -Force`) or open TCP 5985/5986 on the DC firewall to the management subnet. Cross-DC checks in this audit need 5985 reachable from the audit host.' ; break }
                    'AD Web Services' { 'Verify the ADWS service is running on the DC (`Get-Service ADWS`). Open TCP 9389 from any host that uses the ActiveDirectory PowerShell module.' ; break }
                    'RPC endpoint' { 'Open TCP 135 from the source to the target. Most AD operations (replication, secure channel, Netlogon) start by hitting the RPC endpoint mapper here. Without it almost everything below fails.' ; break }
                    'Dynamic RPC' { 'Open the dynamic RPC range (TCP 49152-65535) or pin a static replication port via the RPC dynamic-port restriction registry value. Sampling 49152 alone is heuristic - one closed sample does not prove the entire range is blocked.' ; break }
                    'Kerberos password change' { 'Open TCP/UDP 464 between the DC and any host that does password changes (clients changing passwords, Set-ADAccountPassword from a remote DC).' ; break }
                    'Kerberos\b' { 'Open TCP/UDP 88 between the source and the DC. Kerberos auth fails completely without it.' ; break }
                    'Global Catalog' { "Open the GC port (3268 plain / 3269 TLS) from the source to the DC. Multi-domain forest logons and Exchange use GC; closed GC breaks them." ; break }
                    'DNS\b' { 'Open TCP/UDP 53 from clients to the DC. Without it clients cannot find DCs (no SRV records).' ; break }
                    'SMB\b' { 'Open TCP 445 between the source and the DC. SYSVOL, NETLOGON, GPO download all use SMB.' ; break }
                    'NetBIOS' { 'TCP 139 is legacy. If only modern clients exist this is fine to leave closed; otherwise open it.' ; break }
                    default { 'Open this port from the source to the target on the DC firewall and any path firewall.' }
                }
                [void]$sb.AppendLine("    Fix : $fix")
                foreach ($r in ($pg.Group | Sort-Object Source,Target)) {
                    $errTxt = if ($r.Error) { " ($($r.Error))" } else { '' }
                    [void]$sb.AppendLine("    -> [$($r.ProbeFrom)] $($r.Source) -> $($r.Target):$($r.Port)  CLOSED$errTxt")
                }
                [void]$sb.AppendLine('')
            }
            [void]$sb.AppendLine('')
        }
    }

    # LDAP / LDAPS posture summary - this is the question the user explicitly
    # asked about. Restate it as a dedicated, easy-to-find block.
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(' LDAP / LDAPS POSTURE')
    [void]$sb.AppendLine('=====================================================================')
    foreach ($dc in $dcs) {
        $tgt = if ($dc.HostName) { [string]$dc.HostName } else { [string]$dc.Name }
        $ldap  = $rows | Where-Object { $_.Target -eq $tgt -and $_.Port -eq 389 }
        $ldaps = $rows | Where-Object { $_.Target -eq $tgt -and $_.Port -eq 636 }
        $ldapState  = if ($ldap  -and $ldap.Open)  { 'OPEN' } else { 'CLOSED' }
        $ldapsState = if ($ldaps -and $ldaps.Open) { 'OPEN' } else { 'CLOSED' }
        $verdict =
            if ($ldapsState -eq 'OPEN' -and $ldapState -eq 'OPEN') { 'OK (both available - enforce LDAP signing + channel binding)' }
            elseif ($ldapsState -eq 'OPEN' -and $ldapState -eq 'CLOSED') { 'OK (LDAPS only, plaintext blocked - rare but ideal)' }
            elseif ($ldapsState -eq 'CLOSED' -and $ldapState -eq 'OPEN') { 'RISK: LDAPS not reachable - all LDAP traffic forced to plaintext on 389' }
            else { 'CRITICAL: neither LDAP nor LDAPS reachable - no AD lookups possible from this host' }
        [void]$sb.AppendLine(("  {0,-40} 389={1,-6} 636={2,-6}  =>  {3}" -f $tgt, $ldapState, $ldapsState, $verdict))
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Notes:')
    [void]$sb.AppendLine(' - LDAPS reachable but no certificate trusted = LDAPS effectively broken;')
    [void]$sb.AppendLine('   the Get-LDAPSecurity check earlier in this report verifies the cert side.')
    [void]$sb.AppendLine(' - LDAP signing + channel binding requirements live in the registry under')
    [void]$sb.AppendLine('   HKLM\System\CurrentControlSet\Services\NTDS\Parameters (LDAPServerIntegrity,')
    [void]$sb.AppendLine('   LdapEnforceChannelBinding). Both should be set to 2 (Required).')
    [void]$sb.AppendLine('')

    Set-Content -LiteralPath $evidencePath -Value $sb.ToString() -Encoding UTF8

    $closedReq = @($closed | Where-Object { $_.Required })
    if ($closedReq.Count -gt 0) {
        Write-Both ("    [!] {0} required port(s) are closed across the DC fleet - see dc_port_connectivity.txt" -f $closedReq.Count)
    } else {
        Write-Both '    [+] All required DC ports are reachable from this host (and any cross-DC sources tested).'
    }

    try {
        Write-Nessus-Finding "DCPortConnectivity" "KB1310" ([System.IO.File]::ReadAllText($evidencePath))
    } catch {}
}

$outputdir = Join-Path -Path (Get-Item -Path '.').FullName -ChildPath $env:COMPUTERNAME
$script:outputdir = $outputdir
$starttime = Get-Date
$scriptname = $MyInvocation.MyCommand.Name
if (!(Test-Path "$outputdir")) { New-Item -ItemType Directory -Path $outputdir | Out-Null }

$script:HtmlReportsDir = Join-Path $outputdir 'HTML Reports'
$script:EvidenceFilesDir = Join-Path $outputdir 'Raw Data'
$script:LegacyArtifactsDir = Join-Path $script:EvidenceFilesDir 'Source'
$script:ReportDownloadsDir = $script:LegacyArtifactsDir  # Merged: Prepared now points to Source
if (!(Test-Path $script:HtmlReportsDir)) { New-Item -ItemType Directory -Path $script:HtmlReportsDir -Force | Out-Null }
if (!(Test-Path $script:EvidenceFilesDir)) { New-Item -ItemType Directory -Path $script:EvidenceFilesDir -Force | Out-Null }
if (!(Test-Path $script:LegacyArtifactsDir)) { New-Item -ItemType Directory -Path $script:LegacyArtifactsDir -Force | Out-Null }
Write-Both " _____ ____     _____       _ _ _
|  _  |    \   |  _  |_ _ _| |_| |_
|     |  |  |  |     | | | . | |  _|
|__|__|____/   |__|__|___|___|_|_|
6.0                     by phillips321 (Legacy Script)
$versionnum                  Converted for Powershell 7 and extended by Keberneth
"
$running = $false
Write-Both "[*] Script start time $starttime"

if (-not $script:ADAuditIsWindows) {
    Write-Both "[!] This script requires Windows because it depends on Windows Server/RSAT management modules."
    exit 1
}

$needsActiveDirectory = (
    $domainaudit -or $trusts -or $accounts -or $InactiveComputers -or
    $passwordpolicy -or $oldboxes -or $gpo -or $ouperms -or $laps -or
    $authpolsilos -or $insecurednszone -or $recentchanges -or $adcs -or
    $spn -or $asrep -or $acl -or $ldapsecurity -or $dataextract -or
    $delegatedpermissions -or $highrisk -or $overlappinggroups -or $portconnectivity -or $adhealth -or
    (($all -and 'domainaudit' -notin $exclude) -or
     ($all -and 'trusts' -notin $exclude) -or
     ($all -and 'accounts' -notin $exclude) -or
     ($all -and 'inactivecomputers' -notin $exclude) -or
     ($all -and 'passwordpolicy' -notin $exclude) -or
     ($all -and 'oldboxes' -notin $exclude) -or
     ($all -and 'gpo' -notin $exclude) -or
     ($all -and 'ouperms' -notin $exclude) -or
     ($all -and 'laps' -notin $exclude) -or
     ($all -and 'authpolsilos' -notin $exclude) -or
     ($all -and 'insecurednszone' -notin $exclude) -or
     ($all -and 'recentchanges' -notin $exclude) -or
     ($all -and 'adcs' -notin $exclude) -or
     ($all -and 'spn' -notin $exclude) -or
     ($all -and 'asrep' -notin $exclude) -or
     ($all -and 'acl' -notin $exclude) -or
     ($all -and 'ldapsecurity' -notin $exclude) -or
     ($all -and 'dataextract' -notin $exclude) -or
     ($all -and 'delegatedpermissions' -notin $exclude) -or
     ($all -and 'highrisk' -notin $exclude) -or
     ($all -and 'overlappinggroups' -notin $exclude) -or
     ($all -and 'portconnectivity' -notin $exclude) -or
     ($all -and 'adhealth' -notin $exclude)) -or
    ('domainaudit' -in $selectedChecks) -or ('trusts' -in $selectedChecks) -or
    ('accounts' -in $selectedChecks) -or ('inactivecomputers' -in $selectedChecks) -or
    ('passwordpolicy' -in $selectedChecks) -or ('oldboxes' -in $selectedChecks) -or
    ('gpo' -in $selectedChecks) -or ('ouperms' -in $selectedChecks) -or
    ('laps' -in $selectedChecks) -or ('authpolsilos' -in $selectedChecks) -or
    ('insecurednszone' -in $selectedChecks) -or ('recentchanges' -in $selectedChecks) -or
    ('adcs' -in $selectedChecks) -or ('spn' -in $selectedChecks) -or
    ('asrep' -in $selectedChecks) -or ('acl' -in $selectedChecks) -or
    ('ldapsecurity' -in $selectedChecks) -or ('dataextract' -in $selectedChecks) -or
    ('delegatedpermissions' -in $selectedChecks) -or ('highrisk' -in $selectedChecks) -or
    ('overlappinggroups' -in $selectedChecks) -or ('portconnectivity' -in $selectedChecks) -or
    ('adhealth' -in $selectedChecks)
)

$needsGroupPolicy = (
    $domainaudit -or $gpo -or $dataextract -or
    (($all -and 'domainaudit' -notin $exclude) -or ($all -and 'gpo' -notin $exclude) -or ($all -and 'dataextract' -notin $exclude)) -or
    ('domainaudit' -in $selectedChecks) -or ('gpo' -in $selectedChecks) -or ('dataextract' -in $selectedChecks)
)

$needsDnsServer = (
    $dnszone -or $insecurednszone -or
    (($all -and 'dnszone' -notin $exclude) -or ($all -and 'insecurednszone' -notin $exclude)) -or
    ('dnszone' -in $selectedChecks) -or ('insecurednszone' -in $selectedChecks)
)

$needsDSInternals = (
    $passwordpolicy -or $highrisk -or
    (($all -and 'passwordpolicy' -notin $exclude) -or ($all -and 'highrisk' -notin $exclude)) -or
    ('passwordpolicy' -in $selectedChecks) -or ('highrisk' -in $selectedChecks)
)

if ($needsActiveDirectory) {
    try {
        Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null
    }
    catch {
        Write-Both "[!] ActiveDirectory module not installed or failed to load, exiting... $($_.Exception.Message)"
        exit 1
    }
}

if ($needsGroupPolicy) {
    try {
        Import-ADAuditModule -Name GroupPolicy -Required -PreferWindowsPowerShell | Out-Null
    }
    catch {
        Write-Both "[!] GroupPolicy module not available, GP-dependent checks will be skipped... $($_.Exception.Message)"
    }
}

if ($needsDnsServer) {
    try {
        Import-ADAuditModule -Name DnsServer -Required | Out-Null
    }
    catch {
        Write-Both "[!] DnsServer module not available, DNS-dependent checks will be skipped... $($_.Exception.Message)"
    }
}

if ($needsDSInternals) {
    if (-not (Import-ADAuditModule -Name DSInternals)) {
        Write-Both "[!] DSInternals module not installed, DSInternals-based checks will be skipped. Use -installdeps to install it."
    }
}

if (Test-Path "$outputdir\adaudit.nessus") { Remove-Item -LiteralPath "$outputdir\adaudit.nessus" -Force | Out-Null }
Write-Nessus-Header
Write-Both "[+] Outputting to $outputdir"
if ($needsActiveDirectory) {
    Write-Both "[*] Lang specific variables"
    Get-Variables
}
if ($installdeps) {
    $running = $true
    Invoke-AuditCheck -Name 'InstallDependencies' -Switch 'installdeps' -Description 'Installing optionnal features' -Body { Install-Dependencies }
}
if ($hostdetails -or ($all -and 'hostdetails' -notin $exclude) -or 'hostdetails' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'HostDetails' -Switch 'hostdetails' -Description 'Device Information' -Body { Get-HostDetails }
}
if ($domainaudit -or ($all -and 'domainaudit' -notin $exclude) -or 'domainaudit' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'DomainAudit' -Switch 'domainaudit' -Description 'Domain Audit' -Body {
        Invoke-AuditStep -Name 'Get-LastWUDate'                       -Switch 'domainaudit' -Body { Get-LastWUDate }
        Invoke-AuditStep -Name 'Get-DCEval'                           -Switch 'domainaudit' -Body { Get-DCEval }
        Invoke-AuditStep -Name 'Get-TimeSource'                       -Switch 'domainaudit' -Body { Get-TimeSource }
        Invoke-AuditStep -Name 'Get-PrivilegedGroupMembership'        -Switch 'domainaudit' -Body { Get-PrivilegedGroupMembership }
        Invoke-AuditStep -Name 'Get-MachineAccountQuota'              -Switch 'domainaudit' -Body { Get-MachineAccountQuota }
        Invoke-AuditStep -Name 'Get-DefaultDomainControllersPolicy'   -Switch 'domainaudit' -Body { Get-DefaultDomainControllersPolicy }
        Invoke-AuditStep -Name 'Get-SMB1Support'                      -Switch 'domainaudit' -Body { Get-SMB1Support }
        Invoke-AuditStep -Name 'Get-FunctionalLevel'                  -Switch 'domainaudit' -Body { Get-FunctionalLevel }
        Invoke-AuditStep -Name 'Get-DCsNotOwnedByDA'                  -Switch 'domainaudit' -Body { Get-DCsNotOwnedByDA }
        Invoke-AuditStep -Name 'Get-ReplicationType'                  -Switch 'domainaudit' -Body { Get-ReplicationType }
        Invoke-AuditStep -Name 'Check-Shares'                         -Switch 'domainaudit' -Body { Check-Shares }
        Invoke-AuditStep -Name 'Get-RecycleBinState'                  -Switch 'domainaudit' -Body { Get-RecycleBinState }
        Invoke-AuditStep -Name 'Get-CriticalServicesStatus'           -Switch 'domainaudit' -Body { Get-CriticalServicesStatus }
        Invoke-AuditStep -Name 'Get-RODC'                             -Switch 'domainaudit' -Body { Get-RODC }
        Invoke-AuditStep -Name 'Get-KerberosUnconstrainedDelegation'  -Switch 'domainaudit' -Body { Get-KerberosUnconstrainedDelegation }
        Invoke-AuditStep -Name 'Get-TombstoneLifetime'                -Switch 'domainaudit' -Body { Get-TombstoneLifetime }
        Invoke-AuditStep -Name 'Get-PrintSpoolerOnDCs'                -Switch 'domainaudit' -Body { Get-PrintSpoolerOnDCs }
        Invoke-AuditStep -Name 'Get-SMBSigningStatus'                 -Switch 'domainaudit' -Body { Get-SMBSigningStatus }
    }
}
if ($trusts -or ($all -and 'trusts' -notin $exclude) -or 'trusts' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'DomainTrusts' -Switch 'trusts' -Description 'Domain Trust Audit' -Body { Get-DomainTrusts }
}
if ($accounts -or ($all -and 'accounts' -notin $exclude) -or 'accounts' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'AccountsAudit' -Switch 'accounts' -Description 'Accounts Audit' -Body {
        Invoke-AuditStep -Name 'Get-InactiveAccounts'           -Switch 'accounts' -Body { Get-InactiveAccounts }
        Invoke-AuditStep -Name 'Get-DisabledAccounts'           -Switch 'accounts' -Body { Get-DisabledAccounts }
        Invoke-AuditStep -Name 'Get-LockedAccounts'             -Switch 'accounts' -Body { Get-LockedAccounts }
        Invoke-AuditStep -Name 'Get-AdminAccountChecks'         -Switch 'accounts' -Body { Get-AdminAccountChecks }
        Invoke-AuditStep -Name 'Get-NULLSessions'               -Switch 'accounts' -Body { Get-NULLSessions }
        Invoke-AuditStep -Name 'Get-PrivilegedGroupAccounts'    -Switch 'accounts' -Body { Get-PrivilegedGroupAccounts }
        Invoke-AuditStep -Name 'Get-DomainAdminScaledRisk'      -Switch 'accounts' -Body { Get-DomainAdminScaledRisk }
        Invoke-AuditStep -Name 'Get-ProtectedUsers'             -Switch 'accounts' -Body { Get-ProtectedUsers }
        Invoke-AuditStep -Name 'Get-DomainAdminsGroupOverlap'   -Switch 'accounts' -Body { Get-DomainAdminsGroupOverlap }
        Invoke-AuditStep -Name 'Get-GMSAStatus'                 -Switch 'accounts' -Body { Get-GMSAStatus }
        Invoke-AuditStep -Name 'Get-RC4OnlyAccounts'            -Switch 'accounts' -Body { Get-RC4OnlyAccounts }
    }
}
if ($passwordpolicy -or ($all -and 'passwordpolicy' -notin $exclude) -or 'passwordpolicy' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'PasswordPolicy' -Switch 'passwordpolicy' -Description 'Password Information Audit' -Body {
        Invoke-AuditStep -Name 'Get-AccountPassDontExpire'           -Switch 'passwordpolicy' -Body { Get-AccountPassDontExpire }
        Invoke-AuditStep -Name 'Get-UserPasswordNotChangedRecently'  -Switch 'passwordpolicy' -Body { Get-UserPasswordNotChangedRecently }
        Invoke-AuditStep -Name 'Get-PasswordPolicy'                  -Switch 'passwordpolicy' -Body { Get-PasswordPolicy }
        Invoke-AuditStep -Name 'Get-PasswordQuality'                 -Switch 'passwordpolicy' -Body { Get-PasswordQuality }
    }
}
if ($InactiveComputers -or ($all -and 'inactivecomputers' -notin $exclude) -or 'inactivecomputers' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'InactiveComputerObjects' -Switch 'inactivecomputers' -Description 'Inactive Computer Objects Audit' -Body { Get-InactiveComputerObjects }
}
if (
    $overlappinggroups -or
    ($all      -and 'overlappinggroups' -notin $exclude) -or
    ($accounts -and 'overlappinggroups' -notin $exclude) -or
    'overlappinggroups' -in $selectedChecks -or
    ('accounts' -in $selectedChecks -and 'overlappinggroups' -notin $exclude)
) {
    $running = $true
    Invoke-AuditCheck -Name 'OverlappingGroupMemberships' -Switch 'overlappinggroups' -Description 'Overlapping group membership analysis' -Body { Get-OverlappingGroupMemberships }
}
if ($highrisk -or ($all -and 'highrisk' -notin $exclude) -or 'highrisk' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'HighRiskBaseline' -Switch 'highrisk' -Description 'High-Risk AD Baseline Report' -Body { Get-HighRiskADBaselineReport }
}
if ($oldboxes -or ($all -and 'oldboxes' -notin $exclude) -or 'oldboxes' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'OldOSComputers' -Switch 'oldboxes' -Description 'Computer Objects Audit (legacy OS)' -Body { Get-OldBoxes }
}
if ($gpo -or ($all -and 'gpo' -notin $exclude) -or 'gpo' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'GPOAudit' -Switch 'gpo' -Description 'GPO audit (and checking SYSVOL for passwords)' -Body {
        Invoke-AuditStep -Name 'Get-GPOtoFile'   -Switch 'gpo' -Body { Get-GPOtoFile }
        Invoke-AuditStep -Name 'Get-GPOsPerOU'   -Switch 'gpo' -Body { Get-GPOsPerOU }
        Invoke-AuditStep -Name 'Get-SYSVOLXMLS'  -Switch 'gpo' -Body { Get-SYSVOLXMLS }
        Invoke-AuditStep -Name 'Get-GPOEnum'     -Switch 'gpo' -Body { Get-GPOEnum }
    }
}
if ($ouperms -or ($all -and 'ouperms' -notin $exclude) -or 'ouperms' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'OUPermissions' -Switch 'ouperms' -Description 'Check Generic Group AD Permissions' -Body { Get-OUPerms }
}
if ($laps -or ($all -and 'laps' -notin $exclude) -or 'laps' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'LAPSStatus' -Switch 'laps' -Description 'Check For Existence of LAPS in domain' -Body { Get-LAPSStatus }
}
if ($authpolsilos -or ($all -and 'authpolsilos' -notin $exclude) -or 'authpolsilos' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'AuthPoliciesAndSilos' -Switch 'authpolsilos' -Description 'Check For Existence of Authentication Polices and Silos' -Body { Get-AuthenticationPoliciesAndSilos }
}
if ($insecurednszone -or ($all -and 'insecurednszone' -notin $exclude) -or 'insecurednszone' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'InsecureDnsZones' -Switch 'insecurednszone' -Description 'Check For Existence DNS Zones allowing insecure updates' -Body { Get-DNSZoneInsecure }
}
if ($dnszone -or ($all -and 'dnszone' -notin $exclude) -or 'dnszone' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'DnsZoneReport' -Switch 'dnszone' -Description 'DNS Zone Report' -Body {
        Invoke-DNSZoneReport -OutputRoot $(if($DnsZoneOutputRoot){$DnsZoneOutputRoot}else{(Get-RawDataDir -BaseRoot $outputdir)}) -IncludeRecordCounts:$DnsIncludeRecordCounts -IncludeSystemZones:$DnsIncludeSystemZones
    }
}
if ($recentchanges -or ($all -and 'recentchanges' -notin $exclude) -or 'recentchanges' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'RecentChanges' -Switch 'recentchanges' -Description 'Check For newly created users and groups' -Body { Get-RecentChanges }
}
if ($spn -or ($all -and 'spn' -notin $exclude) -or 'spn' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'KerberoastableAccounts' -Switch 'spn' -Description 'Check high value kerberoastable user accounts' -Body { Get-SPNs }
}
if ($asrep -or ($all -and 'asrep' -notin $exclude) -or 'asrep' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'AsRepRoasting' -Switch 'asrep' -Description 'Check for accounts with kerberos pre-auth' -Body { Get-ADUsersWithoutPreAuth }
}
if ($acl -or ($all -and 'acl' -notin $exclude) -or 'acl' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'DangerousACLs' -Switch 'acl' -Description 'Check for dangerous ACL permissions on Computers, Users and Groups' -Body { Find-DangerousACLPermissions }
}
if ($adcs -or ($all -and 'adcs' -notin $exclude) -or 'adcs' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'ADCSVulnerabilities' -Switch 'adcs' -Description 'Check for ADCS Vulnerabilities' -Body { Get-ADCSVulns }
}
if ($ldapsecurity -or ($all -and 'ldapsecurity' -notin $exclude) -or 'ldapsecurity' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'LDAPSecurity' -Switch 'ldapsecurity' -Description 'Check for LDAP Security Issues' -Body { Get-LDAPSecurity }
}
if ($dataextract -or ($all -and 'dataextract' -notin $exclude) -or 'dataextract' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'AdDataExtract' -Switch 'dataextract' -Description 'AD Raw Data Extract' -Body { Export-ADAuditDataExtract }
}
if ($delegatedpermissions -or ($all -and 'delegatedpermissions' -notin $exclude) -or 'delegatedpermissions' -in $selectedChecks) {
    $running = $true
    if (-not $DelegatedOutputRoot) { $DelegatedOutputRoot = (Join-Path (Get-RawDataDir -BaseRoot $outputdir) 'DelegatedPermissions') }
    Invoke-AuditCheck -Name 'DelegatedPermissions' -Switch 'delegatedpermissions' -Description 'Delegated Permissions Report' -Body {
        Invoke-DelegatedPermissionsReport -OutputRoot $DelegatedOutputRoot -IncludeSystemTrustees:$DelegIncludeSystemTrustees -IncludeDeny:$DelegIncludeDeny -IncludeInherited:$DelegIncludeInherited -Server $DelegServer
    }
}
if ($portconnectivity -or ($all -and 'portconnectivity' -notin $exclude) -or 'portconnectivity' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'DCPortConnectivity' -Switch 'portconnectivity' -Description 'Domain Controller port connectivity check (RPC/LDAP/LDAPS/Kerberos/SMB/ADWS/WinRM/dynamic RPC)' -Body { Test-DCPortConnectivity }
}
if ($adhealth -or ($all -and 'adhealth' -notin $exclude) -or 'adhealth' -in $selectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name 'ADHealth' -Switch 'adhealth' -Description 'AD platform health check (replication, dcdiag, SYSVOL/DFSR, NTDS, time, services, events, sites, recycle bin, group hygiene)' -Body { Get-ADHealth }
}
if (!$running) {
    Write-Both "[!] No arguments selected"
    Write-Both "[!] Other options are as follows, they can be used in combination"
    Write-Both "    -installdeps installs optionnal features (DSInternals)"
    Write-Both "    -hostdetails retrieves hostname and other useful audit info"
    Write-Both "    -domainaudit retrieves information about the AD such as functional level, delegation, spooler, SMB signing, tombstone"
    Write-Both "    -trusts retrieves information about any doman trusts"
    Write-Both "    -accounts identifies account issues such as expired, disabled, gMSA status, etc..."
    Write-Both "    -passwordpolicy retrieves password policy information"
    Write-Both "    -oldboxes identifies outdated OSs like 2000/2003/XP/Vista/7/2008 joined to the domain"
    Write-Both "    -gpo dumps the GPOs in XML and HTML for later analysis"
    Write-Both "    -ouperms checks generic OU permission issues"
    Write-Both "    -laps checks if LAPS is installed"
    Write-Both "    -authpolsilos checks for existence of authentication policies and silos"
    Write-Both "    -insecurednszone checks for insecure DNS zones"
    Write-Both "    -dnszone generates a DNS zone posture report (HTML/CSV/JSON) (alias: -dns-zone)"
    Write-Both "        Optional: -DnsIncludeRecordCounts -DnsIncludeSystemZones -DnsZoneOutputRoot <path>"
    Write-Both "    -recentchanges checks for newly created users and groups (last 30 days)"
    Write-Both "    -spn checks for kerberoastable high value accounts"
    Write-Both "    -asrep checks for accounts with kerberos pre-auth"
    Write-Both "    -acl checks for dangerous ACL permissions on Computers, Users and Groups"
    Write-Both "    -ADCS checks for ESC1,2,3,4 and 8"
    Write-Both "    -ldapsecurity checks for multiple LDAP issues"
    Write-Both "    -dataextract exports raw AD audit data (users/groups/computers/OUs/GPO reports/OU ACLs/FGPP/trusts) to .\<COMPUTERNAME>\Raw Data\ADExtract"
    Write-Both "    -delegatedpermissions generates an AD delegated permissions report (alias: -delegated-permissions)"
    Write-Both "        Optional: -DelegIncludeSystemTrustees -DelegIncludeDeny -DelegIncludeInherited -DelegServer <dc> -DelegatedOutputRoot <path>"
    Write-Both "    -portconnectivity tests TCP ports DCs need (RPC/LDAP/LDAPS/Kerberos/SMB/ADWS/WinRM/dynamic RPC) from this host and (via WinRM) cross-DC. Aliases: -dcports, -dc-ports, -portcheck"
    Write-Both "    -adhealth runs AD platform health checks (replication, dcdiag, SYSVOL/DFSR, NTDS, time, services, events, sites, recycle bin, group hygiene) and writes AD_Health.html. Aliases: -ad-health, -health"
    Write-Both "    -all runs all checks, e.g. $scriptname -all"
    Write-Both "    -KeepLegacyArtifacts is retained for backward compatibility; raw data and evidence files are preserved in .\\<COMPUTERNAME>\\Raw Data by default"
}
Write-CheckFailuresReport -BaseRoot $outputdir
Write-Nessus-Footer

# Sanitize .nessus XML characters in-place (no duplicate file)
$nessusPath = "$outputdir\adaudit.nessus"
if (Test-Path $nessusPath) {
    $nessusContent = Get-Content $nessusPath
    $nessusContent = $nessusContent -Replace "&", "&amp;"
    $nessusContent = $nessusContent -Replace ([char]8220), "&quot;"
    $nessusContent = $nessusContent -Replace ([char]8221), "&quot;"
    $nessusContent = $nessusContent -Replace "`'", "&apos;"
    $nessusContent = $nessusContent -Replace ([char]252), "u"
    $nessusContent | Out-File $nessusPath -Force
}

$endtime = Get-Date
Write-Both "[*] Script end time $endtime"


$oldEap = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
try {

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
            'Duplicate passwords' {
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
            'inactive|disabled stale|Inactive computer' {
                return 'Inactive objects increase attack surface, complicate review, and often indicate weak lifecycle controls.'
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
            'LDAP security|NTLM' {
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
            'Duplicate passwords' {
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
            'inactive|disabled stale|Inactive computer' {
                return 'Review ownership, disable or remove stale accounts and computer objects, and enforce a documented lifecycle and exception process.'
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
            'LDAP security|NTLM' {
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
                return 'Set passwords on all affected accounts immediately. Review why these accounts were created without passwords and enforce the domain password policy.'
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

            '^NTLM restrictions require hardening$' {
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
            '^NTLM restrictions require hardening$' {
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
    try { localStorage.setItem('adaudit-theme', theme); } catch (e) {}
  }

  function applyFilters(){
    var sev = q('#severityFilter').value;
    var query = (q('#searchFilter').value || '').toLowerCase().trim();
    var visible = 0;

    findings().forEach(function(item){
      var itemSev = item.getAttribute('data-sev');
      var text = (item.innerText || '').toLowerCase();
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
      applyTheme(next);
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
    $baselineHasDAOverlap = $false

    $baselineHasInactive180 = $false
    $baselineHasPNE         = $false

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
                        $baselineHasDAOverlap = $true
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

        $dupRows = Get-CsvSafe $hrFiles.DUPLICATE_PASSWORDS
        if ($dupRows.Count -gt 0) {
            Add-FindingOnce 'Critical' 'Duplicate passwords detected' "Affected accounts in shared-password groups: $($dupRows.Count)" $hrFiles.DUPLICATE_PASSWORDS (Score-Scaled 'Critical' $dupRows.Count 100)
        }

        $krbtgt = Get-CsvSafe $hrFiles.KRBTGT
        if ($krbtgt.Count -gt 0) {
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

        $privRows = Get-CsvSafe $hrFiles.PRIVILEGED_GROUPS
        if ($privRows.Count -gt 0) {
            $sev = if ($privRows.Count -ge 20) { 'High' } elseif ($privRows.Count -ge 10) { 'Medium' } else { 'Low' }
            Add-FindingOnce $sev 'Large privileged group membership' "Rows: $($privRows.Count)" $hrFiles.PRIVILEGED_GROUPS (Score-Scaled $sev $privRows.Count)
        }

        # Keep ONLY baseline inactive >180 days (renamed), suppress HighRisk\INACTIVE_ACCOUNTS.csv
        if (-not $baselineHasInactive180) {
            $inactiveRows = Get-CsvSafe $hrFiles.INACTIVE_ACCOUNTS
            if ($inactiveRows.Count -gt 0) {
                $sev = if ($inactiveRows.Count -ge 200) { 'High' } elseif ($inactiveRows.Count -ge 50) { 'Medium' } else { 'Low' }
                Add-FindingOnce $sev 'Inactive enabled accounts' "Accounts inactive: $($inactiveRows.Count)" $hrFiles.INACTIVE_ACCOUNTS (Score-Scaled $sev $inactiveRows.Count)
            }
        }

        # Keep ONLY baseline PasswordNeverExpires, suppress HighRisk\PASSWORD_NEVER_EXPIRES.csv
        if (-not $baselineHasPNE) {
            $pneRows = Get-CsvSafe $hrFiles.PASSWORD_NEVER_EXPIRES
            if ($pneRows.Count -gt 0) {
                $sev = if ($pneRows.Count -ge 50) { 'High' } elseif ($pneRows.Count -ge 10) { 'Medium' } else { 'Low' }
                Add-FindingOnce $sev 'Passwords set to never expire' "Accounts: $($pneRows.Count)" $hrFiles.PASSWORD_NEVER_EXPIRES (Score-Scaled $sev $pneRows.Count)
            }
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

    # ---------------------------
    # Text-based checks
    # ---------------------------
    $weakKerbPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'dcs_weak_kerberos_ciphersuite.txt')
    $weakKerbLines = Get-NonHeaderLines $weakKerbPath
    if ($weakKerbLines.Count -gt 0) {
        Add-FindingOnce 'High' 'Domain controllers allow weak Kerberos ciphers' "DCs flagged: $($weakKerbLines.Count)" $weakKerbPath (Score-Scaled 'High' $weakKerbLines.Count)
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
    $revAccounts = @(Get-ReversibleEncryptionAccounts -Path $(if ($pqRevPath) { $pqRevPath } else { $pqPath }))
    if ($revAccounts.Count -eq 0 -and $pqRevPath -ne $pqPath) {
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
                    $allUserRows = Get-CsvSafe $uCsv.FullName
                    $noPwdSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($s in $noPwdSams) { $noPwdSet.Add($s) | Out-Null }
                    $enabledNoPwd = 0
                    foreach ($row in $allUserRows) {
                        $sam = $row.SamAccountName
                        if (-not $sam -or -not $noPwdSet.Contains($sam)) { continue }
                        $uac = 0
                        try { $uac = [int]$row.userAccountControl } catch {}
                        if (($uac -band 2) -eq 0) { $enabledNoPwd++ }
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

    # Kerberos pre-auth not required (DSInternals view, complements ASREP.txt)
    $pqNoPreauthPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_no_preauth.txt')
    $pqNoPreauthLines = Get-PqAccountLines $pqNoPreauthPath
    if ($pqNoPreauthLines.Count -gt 0) {
        $score = Score-BaselineZeroLog -Severity 'High' -Observed $pqNoPreauthLines.Count -MaxAdd 20 -K 8
        Add-FindingOnce 'High' 'Accounts with Kerberos pre-authentication disabled (AS-REP roastable)' "Accounts: $($pqNoPreauthLines.Count)" $pqNoPreauthPath $score
    }

    # Password never expires (DSInternals view, complements accounts_passdontexpire.txt)
    $pqPwdNeverExpPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_password_never_expires.txt')
    $pqPwdNeverExpLines = Get-PqAccountLines $pqPwdNeverExpPath
    if ($pqPwdNeverExpLines.Count -gt 0) {
        $sev = if ($pqPwdNeverExpLines.Count -ge 50) { 'High' } elseif ($pqPwdNeverExpLines.Count -ge 10) { 'Medium' } else { 'Low' }
        Add-FindingOnce $sev 'Accounts with PasswordNeverExpires set' "Accounts: $($pqPwdNeverExpLines.Count)" $pqPwdNeverExpPath (Score-Scaled $sev $pqPwdNeverExpLines.Count)
    }

    # Kerberoastable (DSInternals view, complements SPNs.txt)
    $pqKerbPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_kerberoastable.txt')
    $pqKerbLines = Get-PqAccountLines $pqKerbPath
    if ($pqKerbLines.Count -gt 0) {
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

    $spnPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'SPNs.txt')
    $spnLines = Get-NonHeaderLines $spnPath
    if ($spnLines.Count -gt 0) {
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

    # Suppress accounts_passdontexpire.txt when baseline already provides PasswordNeverExpires
    $pndePath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'accounts_passdontexpire.txt')
    if (-not $baselineHasPNE) {
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

    $ntlmRestrictPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'ntlm_restrictions.txt')
    if ((Get-NonHeaderLines $ntlmRestrictPath).Count -gt 0) {
        Add-FindingOnce 'Medium' 'NTLM restrictions require hardening' 'Review NTLM configuration and restrictions' $ntlmRestrictPath $SeverityScore.Medium
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
            Add-FindingOnce $sev "DC port closed: $($first.PortName) ($($first.Port)/$($first.Proto))" $detail $portTxtPath (Score-Scaled $sev $g.Count)
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
    $htmlReportsDirLocal = Get-HtmlReportsDir -BaseRoot $InputRoot
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
    try { localStorage.setItem('adaudit-theme', t); } catch(e){}
  }
  applyTheme(currentTheme());
  var tBtn = q('#themeToggle');
  if (tBtn){
    tBtn.addEventListener('click', function(){
      var next = (document.documentElement.getAttribute('data-theme') === 'dark') ? 'light' : 'dark';
      applyTheme(next);
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

        $sourcePath = Join-Path $file.DirectoryName (([System.IO.Path]::GetFileNameWithoutExtension($file.Name)) + '.source.html')
        if (Test-Path -LiteralPath $sourcePath) {
            Remove-Item -LiteralPath $sourcePath -Force -ErrorAction SilentlyContinue
        }

        Move-Item -LiteralPath $targetPath -Destination $sourcePath -Force -ErrorAction SilentlyContinue

        $title = Get-CompanionHtmlReportTitle -FileName $file.Name
        $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'
        $auditHref = if (Test-Path -LiteralPath $auditPath) { Get-RelativeReportHref -FromFile $targetPath -ToPath $auditPath } else { '' }
        $sourceHref = Get-RelativeReportHref -FromFile $targetPath -ToPath $sourcePath

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
    try { localStorage.setItem('adaudit-theme', t); } catch(_){}
  }
  document.addEventListener('DOMContentLoaded', function(){
    applyTheme(currentTheme());
    var btn=document.getElementById('wrapperThemeToggle');
    if (btn){
      btn.addEventListener('click', function(){
        var next = (document.documentElement.getAttribute('data-theme')==='dark') ? 'light' : 'dark';
        applyTheme(next);
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
        <a class="btn" href="$sourceHref" target="_blank" rel="noopener">Open original HTML</a>
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
            Move-Item -LiteralPath $file.FullName -Destination $destFile -Force -ErrorAction Stop
        } catch { }
    }
}

Move-RootHtmlReports -Root $outputdir -Destination (Get-HtmlReportsDir -BaseRoot $outputdir)
Move-LegacyAuditArtifacts -Root $outputdir -ArchiveRoot (Get-RawSourceDataDir -BaseRoot $outputdir)
Invoke-ManagementReport -InputRoot $outputdir -OutputHtml (Join-Path (Get-HtmlReportsDir -BaseRoot $outputdir) 'Risk-Report.html') -AuditHtml (Join-Path (Get-HtmlReportsDir -BaseRoot $outputdir) 'ADAudit-Results.html')
Update-CompanionHtmlReports -Root $outputdir

# <<< add cleanup here (absolute last action) >>>
# Keep only the five primary HTML reports the user wants surfaced. Anything
# else in HTML Reports (companion wrappers, GPOReport, dangerousACLs, DNS
# audit/recommendations, baseline index, .source.html files, etc.) is removed
# at the end of the run so the output folder stays focused.
$__htmlReportsDir = Get-HtmlReportsDir -BaseRoot $outputdir
$__keep = @(
    'overlapping_group_memberships.html'
    'Risk-Report.html'
    'multiple_nested_paths.html'
    'ADAudit-Results.html'
    'AD_Health.html'
)
if (Test-Path -LiteralPath $__htmlReportsDir) {
    foreach ($f in (Get-ChildItem -LiteralPath $__htmlReportsDir -File -Filter '*.html' -ErrorAction SilentlyContinue)) {
        if ($__keep -notcontains $f.Name) {
            try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop } catch { }
        }
    }
}
}
finally {
    $ErrorActionPreference = $oldEap
}
