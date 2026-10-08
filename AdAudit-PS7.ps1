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
            [X] Version 9.0 - 08/10/2026
                Added Invoke-LateralMovementCheck.ps1 (-lateralmovement / -lateral / -lm, also
                    part of -all, and selectable in the GUI). Separate companion script, dot-sourced
                    by this file, that builds the full member / memberOf graph of the domain and
                    reports lateral movement through group nesting:
                    - every nesting path into a Tier 0 / privileged built-in group and every
                      account that becomes Tier 0 through a chain (hidden privilege)
                    - AGDLP violations (role in role, resource in resource, users directly in
                      resource groups, groups that are both role and resource)
                    - broad "all employees" groups used as building blocks, circular nesting,
                      deep chains, dormant (empty) privileged paths, temporary / legacy groups
                    - hidden membership via primaryGroupID, computers / gMSAs / foreign and
                      cross-domain principals in privileged groups
                    - Tier 0 account hygiene (SPN, pre-auth, password age, Protected Users,
                      stale, daily-use looking accounts, memberships outside Tier 0)
                    - tier boundary crossings for groups/accounts tagged T0/T1/T2
                    - optional baseline diff of group-to-group edges (-LateralBaselinePath)
                    Severity per finding, per user and per group (Critical / High / Medium / Low /
                    Information) with why-it-matters and how-to-fix text. Writes lateral_movement.txt,
                    LateralMovement\*.csv (findings, users, groups, edges = next baseline, Tier 0
                    paths) and Lateral-Movement.html - an interactive, offline map (no external
                    libraries) with a privilege overview, hop-by-hop focus view, filters for
                    severity / scope / tier / OU / name, per-node details with paths to Tier 0,
                    sortable findings / accounts / groups / paths tables and a rules & guidance tab.
                    Findings feed ADAudit-Results.html / Risk-Report.html (one per rule) and the
                    Nessus export (KB1400-KB1421). Lateral-Movement.html joins the primary nav.
                Restructured the toolkit into a runner + library + one file per check:
                    AdAudit-PS7.ps1 keeps the parameters, the check table, the run lifecycle
                    and the usage text. Library\ADAudit.Common.ps1 holds the shared helpers and
                    run state (output folders, logging, failure / not-assessed tracking, Nessus
                    export, report CSS and navigation, module import, DSInternals cache,
                    -installdeps). Library\ADAudit.Report.ps1 holds the management report, the
                    companion-report wrapping and the end-of-run cleanup. Checks\Invoke-<Name>Check.ps1
                    holds the functions of each check plus its Invoke-<Name>Check entry point;
                    check files are dot-sourced (shared scope), were moved verbatim, and can be
                    started on their own (they forward to the runner with -select <check>).
                    Password Audit scripts renamed to Invoke-PwnedPasswordCheck.ps1 and
                    Invoke-SamePasswordCheck.ps1 and are launchable from the GUI, separate from
                    -all. Checks\Invoke-LateralMovementCheck.ps1 moved into the Checks folder.
            [X] Version 8.9 - 03/07/2026
                Code-review fix pass (correctness, duplication, efficiency, report/output clarity).
                Correctness fixes:
                    - Removed a stray top-level dispatch that ran the InactiveComputers check
                      TWICE, the first time before $outputdir existed (writing a rogue
                      \adaudit.nessus at the drive root) and outside the error wrapper.
                    - Get-DomainAdminScaledRisk hydrated members with Get-ADObject -Properties
                      Enabled, an invalid property that threw for every member, so KB427 always
                      reported Critical. Now derives enabled state from userAccountControl.
                    - Risk report: inverted NTLM logic (hardened domains were flagged, unhardened
                      passed) - collector now writes an explicit Status line and the finding keys
                      off "NotRestricted". MachineAccountQuota finding read a non-existent column
                      and always said "Quota: 10" / fired at MAQ=0 - now reads Observed + IsFinding.
                      SPNs.txt "no findings" sentinel counted as a Kerberoastable finding on clean
                      domains - now excluded. AS-REP / Kerberoast / duplicate-password /
                      PasswordNeverExpires / krbtgt / MAQ were each reported 2-3x under different
                      titles/severities - now de-duplicated to a single source.
                    - Nessus export: values are XML-escaped at write time (evidence containing
                      < > & no longer corrupts the file) and severity is tiered from the KB id
                      instead of every item being severity 0 / Low. Removed the broken post-hoc
                      sanitizer.
                    - Get-ADReplAccount -All (full-domain DCSync) ran twice per -all run; now
                      cached and replicated once. Privileged-group enumeration failure was
                      reported as an empty group (false all-clear); now recorded as Not Assessed.
                    - Delegated permissions: Exchange/svc-*/Pre-Win2000 trustee matches ignored
                      the DOMAIN\ prefix and never fired; computer-creation checked the wrong ACE
                      column; Get-PrincipalType built an invalid LDAP filter from DOMAIN\name.
                    - ConvertFrom-UACComputed always returned Unknown (int32 keys vs int64 lookup).
                    - Split-PasswordQualityReport parsed the injected Kerberoast prose as accounts
                      (now splits before annotating). repadmin /replsummary failure count was
                      doubled (Source + Destination tables). Time-sync reported WinRM latency as
                      clock skew (now offset vs the auditor clock). Get-ADAuditDcFunctionalLevelCapRank
                      returned null for pre-2016 DCs, giving wrong "raise DFL" advice.
                    - Theme toggle persisted the OS preference on first load in all HTML reports,
                      permanently disabling "follow OS". End-of-run cleanup deleted companion
                      reports that ADAudit-Results.html still linked to (now preserved).
                    - Get-DomainAdminsGroupOverlap used direct-only membership; now resolves
                      transitive membership via tokenGroups. Disabled built-in Administrator (RID-500)
                      no longer flagged as a finding.
                Efficiency: Get-PasswordPolicy queries the policy once (was 9x); Get-LockedAccounts
                    uses Search-ADAccount -LockedOut; Get-OUPerms scans OUs only (was every object).
                Clarity/output: fixed "identifed"/"optionnal" typos, KB### placeholder, stray '@'
                    file headers, admin-account terminology (RID 500, not "Local Administrator"),
                    trust-risk wording, and -select/-exclude trimming + usage docs. -KeepLegacyArtifacts
                    now clears prior-run evidence files at startup (fixes append-across-runs).
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
        Installs optional features (DSInternals)
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
    [Alias('lateral','lateral-movement','lm')][switch]$lateralmovement = $false,
    [string]$LateralBaselinePath,
    [string[]]$LateralTier0Groups = @(),
    [switch]$all = $false,
    [string[]]$exclude = @(),
    [string]$select,
    [switch]$KeepLegacyArtifacts = $false
)

$selectedChecks = @()
# Split on commas AND whitespace: unquoted '-select accounts,spn' binds to the
# [string] parameter as 'accounts spn' (space-joined array), which a plain
# comma split would turn into one unmatchable token.
if ($select) { $selectedChecks = @($select -split '[,\s]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
# Normalise -exclude too: accept "-exclude gpo,dnszone" and "-exclude 'gpo, dnszone'"
# alike by splitting on commas and trimming, so a stray space never silently
# defeats the match (e.g. ' dnszone' -notin the check names).
$exclude = @($exclude | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

$versionnum = "v9.0"
$AdministratorTranslation = @("Administrator", "Administrateur", "Administrador")#If missing put the default Administrator name for your own language here

$script:ADAuditIsWindows = ($env:OS -eq 'Windows_NT')
$script:ADAuditIsPowerShell7Plus = ($PSVersionTable.PSVersion.Major -ge 7)

# ---------------------------------------------------------------------------
# Layout (v9.0): this file is the runner. The shared helpers live in Library\,
# every check in its own Checks\Invoke-<Name>Check.ps1. All files are dot-sourced
# so they share this script scope (the helpers keep their state in $script:
# variables) - see Library\ADAudit.Common.ps1 for the rules check files follow.
# ---------------------------------------------------------------------------
$script:ADAuditRoot = $PSScriptRoot
foreach ($__lib in @('ADAudit.Common.ps1', 'ADAudit.Report.ps1')) {
    $__libPath = Join-Path (Join-Path $script:ADAuditRoot 'Library') $__lib
    if (-not (Test-Path -LiteralPath $__libPath)) {
        Write-Host "[!] Missing $__libPath - copy the whole ADAudit folder (AdAudit-PS7.ps1, Library\, Checks\), not only this file."
        exit 1
    }
    . $__libPath
}

# One row per check: the switch users type, the parameter variable, the name used in the
# failure / not-assessed reports, the file that implements it, the modules it needs and the
# entry function. Order = execution order. AlsoWith = checks that imply this one (unless
# excluded). Add a check by adding a row and a Checks\Invoke-<Name>Check.ps1 file.
$script:ADAuditChecks = @(
    [pscustomobject]@{ Switch = 'hostdetails'; Variable = 'hostdetails'; Name = 'HostDetails'; File = 'Invoke-HostDetailsCheck.ps1'; Load = $true; Modules = @(); AlsoWith = @(); Description = 'Device Information'; Run = { Invoke-HostDetailsCheck } }
    [pscustomobject]@{ Switch = 'domainaudit'; Variable = 'domainaudit'; Name = 'DomainAudit'; File = 'Invoke-DomainAuditCheck.ps1'; Load = $true; Modules = @('ActiveDirectory','GroupPolicy'); AlsoWith = @(); Description = 'Domain Audit'; Run = { Invoke-DomainAuditCheck } }
    [pscustomobject]@{ Switch = 'trusts'; Variable = 'trusts'; Name = 'DomainTrusts'; File = 'Invoke-TrustsCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Domain Trust Audit'; Run = { Invoke-TrustsCheck } }
    [pscustomobject]@{ Switch = 'accounts'; Variable = 'accounts'; Name = 'AccountsAudit'; File = 'Invoke-AccountsCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Accounts Audit'; Run = { Invoke-AccountsCheck } }
    [pscustomobject]@{ Switch = 'passwordpolicy'; Variable = 'passwordpolicy'; Name = 'PasswordPolicy'; File = 'Invoke-PasswordPolicyCheck.ps1'; Load = $true; Modules = @('ActiveDirectory','DSInternals'); AlsoWith = @(); Description = 'Password Information Audit'; Run = { Invoke-PasswordPolicyCheck } }
    [pscustomobject]@{ Switch = 'inactivecomputers'; Variable = 'InactiveComputers'; Name = 'InactiveComputerObjects'; File = 'Invoke-InactiveComputersCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Inactive Computer Objects Audit'; Run = { Invoke-InactiveComputersCheck } }
    [pscustomobject]@{ Switch = 'overlappinggroups'; Variable = 'overlappinggroups'; Name = 'OverlappingGroupMemberships'; File = 'Invoke-OverlappingGroupsCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @('accounts'); Description = 'Overlapping group membership analysis'; Run = { Invoke-OverlappingGroupsCheck } }
    [pscustomobject]@{ Switch = 'highrisk'; Variable = 'highrisk'; Name = 'HighRiskBaseline'; File = 'Invoke-HighRiskCheck.ps1'; Load = $true; Modules = @('ActiveDirectory','DSInternals'); AlsoWith = @(); Description = 'High-Risk AD Baseline Report'; Run = { Invoke-HighRiskCheck } }
    [pscustomobject]@{ Switch = 'oldboxes'; Variable = 'oldboxes'; Name = 'OldOSComputers'; File = 'Invoke-OldBoxesCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Computer Objects Audit (legacy OS)'; Run = { Invoke-OldBoxesCheck } }
    [pscustomobject]@{ Switch = 'gpo'; Variable = 'gpo'; Name = 'GPOAudit'; File = 'Invoke-GroupPolicyCheck.ps1'; Load = $true; Modules = @('ActiveDirectory','GroupPolicy'); AlsoWith = @(); Description = 'GPO audit (and checking SYSVOL for passwords)'; Run = { Invoke-GroupPolicyCheck } }
    [pscustomobject]@{ Switch = 'ouperms'; Variable = 'ouperms'; Name = 'OUPermissions'; File = 'Invoke-OUPermissionsCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Check Generic Group AD Permissions'; Run = { Invoke-OUPermissionsCheck } }
    [pscustomobject]@{ Switch = 'laps'; Variable = 'laps'; Name = 'LAPSStatus'; File = 'Invoke-LapsCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Check For Existence of LAPS in domain'; Run = { Invoke-LapsCheck } }
    [pscustomobject]@{ Switch = 'authpolsilos'; Variable = 'authpolsilos'; Name = 'AuthPoliciesAndSilos'; File = 'Invoke-AuthPoliciesCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Check For Existence of Authentication Polices and Silos'; Run = { Invoke-AuthPoliciesCheck } }
    [pscustomobject]@{ Switch = 'insecurednszone'; Variable = 'insecurednszone'; Name = 'InsecureDnsZones'; File = 'Invoke-InsecureDnsZonesCheck.ps1'; Load = $true; Modules = @('ActiveDirectory','DnsServer'); AlsoWith = @(); Description = 'Check For Existence DNS Zones allowing insecure updates'; Run = { Invoke-InsecureDnsZonesCheck } }
    [pscustomobject]@{ Switch = 'dnszone'; Variable = 'dnszone'; Name = 'DnsZoneReport'; File = 'Invoke-DnsZoneReportCheck.ps1'; Load = $true; Modules = @('DnsServer'); AlsoWith = @(); Description = 'DNS Zone Report'; Run = { Invoke-DnsZoneReportCheck } }
    [pscustomobject]@{ Switch = 'recentchanges'; Variable = 'recentchanges'; Name = 'RecentChanges'; File = 'Invoke-RecentChangesCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Check For newly created users and groups'; Run = { Invoke-RecentChangesCheck } }
    [pscustomobject]@{ Switch = 'spn'; Variable = 'spn'; Name = 'KerberoastableAccounts'; File = 'Invoke-KerberoastCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Check high value kerberoastable user accounts'; Run = { Invoke-KerberoastCheck } }
    [pscustomobject]@{ Switch = 'asrep'; Variable = 'asrep'; Name = 'AsRepRoasting'; File = 'Invoke-AsRepRoastCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Check for accounts with kerberos pre-auth'; Run = { Invoke-AsRepRoastCheck } }
    [pscustomobject]@{ Switch = 'acl'; Variable = 'acl'; Name = 'DangerousACLs'; File = 'Invoke-DangerousAclCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Check for dangerous ACL permissions on Computers, Users and Groups'; Run = { Invoke-DangerousAclCheck } }
    [pscustomobject]@{ Switch = 'adcs'; Variable = 'adcs'; Name = 'ADCSVulnerabilities'; File = 'Invoke-AdcsCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Check for ADCS Vulnerabilities'; Run = { Invoke-AdcsCheck } }
    [pscustomobject]@{ Switch = 'ldapsecurity'; Variable = 'ldapsecurity'; Name = 'LDAPSecurity'; File = 'Invoke-LdapSecurityCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Check for LDAP Security Issues'; Run = { Invoke-LdapSecurityCheck } }
    [pscustomobject]@{ Switch = 'dataextract'; Variable = 'dataextract'; Name = 'AdDataExtract'; File = 'Invoke-DataExtractCheck.ps1'; Load = $true; Modules = @('ActiveDirectory','GroupPolicy'); AlsoWith = @(); Description = 'AD Raw Data Extract'; Run = { Invoke-DataExtractCheck } }
    [pscustomobject]@{ Switch = 'delegatedpermissions'; Variable = 'delegatedpermissions'; Name = 'DelegatedPermissions'; File = 'Invoke-DelegatedPermissionsCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Delegated Permissions Report'; Run = { Invoke-DelegatedPermissionsCheck } }
    [pscustomobject]@{ Switch = 'portconnectivity'; Variable = 'portconnectivity'; Name = 'DCPortConnectivity'; File = 'Invoke-PortConnectivityCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Domain Controller port connectivity check (RPC/LDAP/LDAPS/Kerberos/SMB/ADWS/WinRM/dynamic RPC)'; Run = { Invoke-PortConnectivityCheck } }
    [pscustomobject]@{ Switch = 'adhealth'; Variable = 'adhealth'; Name = 'ADHealth'; File = 'Invoke-HealthCheck.ps1'; Load = $true; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'AD platform health check (replication, dcdiag, SYSVOL/DFSR, NTDS, time, services, events, sites, recycle bin, group hygiene)'; Run = { Invoke-HealthCheck } }
    [pscustomobject]@{ Switch = 'lateralmovement'; Variable = 'lateralmovement'; Name = 'LateralMovement'; File = 'Invoke-LateralMovementCheck.ps1'; Load = $false; Modules = @('ActiveDirectory'); AlsoWith = @(); Description = 'Lateral movement analysis (group nesting, hidden Tier 0 paths, AGDLP violations, per-user / per-group risk map)'; Run = {
        # Self-contained companion script with its own parameters: dot-sourced at run time
        # (not at load time) so it shares this script's scope - see the note in the table.
        $lmScriptPath = Join-Path (Join-Path $script:ADAuditRoot 'Checks') 'Invoke-LateralMovementCheck.ps1'
        if (-not (Test-Path -LiteralPath $lmScriptPath)) {
            Register-ADAuditNotAssessed -Name 'LateralMovement' -Switch 'lateralmovement' -Reason "Invoke-LateralMovementCheck.ps1 was not found ($lmScriptPath). Copy the whole ADAudit folder."
            return
        }
        $lmArgs = @{ OutputRoot = $outputdir }
        if ($LateralBaselinePath) { $lmArgs['BaselinePath'] = $LateralBaselinePath }
        if ($LateralTier0Groups -and @($LateralTier0Groups).Count -gt 0) { $lmArgs['Tier0Groups'] = @($LateralTier0Groups | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        . $lmScriptPath @lmArgs
    } }
)

foreach ($__chk in $script:ADAuditChecks) {
    if (-not $__chk.Load) { continue }
    $__chkPath = Join-Path (Join-Path $script:ADAuditRoot 'Checks') $__chk.File
    if (-not (Test-Path -LiteralPath $__chkPath)) {
        Write-Host "[!] Missing $__chkPath - copy the whole ADAudit folder (AdAudit-PS7.ps1, Library\, Checks\), not only this file."
        exit 1
    }
    . $__chkPath
}

function Test-ADAuditCheckSelected {
    # Mirrors the historical dispatch rule: the check's own switch, or -all without -exclude,
    # or -select, or (for AlsoWith) another selected check that implies it unless excluded.
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Check)
    $sw = [string]$Check.Switch
    $flag = $false
    try { $flag = [bool](Get-Variable -Name $Check.Variable -Scope Script -ValueOnly -ErrorAction Stop) } catch { $flag = $false }
    if ($flag) { return $true }
    if ($all -and ($sw -notin $exclude)) { return $true }
    if ($sw -in $selectedChecks) { return $true }
    foreach ($other in @($Check.AlsoWith)) {
        if (-not $other) { continue }
        $oflag = $false
        try { $oflag = [bool](Get-Variable -Name $other -Scope Script -ValueOnly -ErrorAction Stop) } catch { $oflag = $false }
        if (($oflag -or ($other -in $selectedChecks)) -and ($sw -notin $exclude)) { return $true }
    }
    return $false
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

# Clear the prior run's per-check evidence files so this run starts clean.
# Many checks append (Add-Content) rather than overwrite their evidence file;
# because the output folder is reused, without this the files accumulate stale
# lines across runs - duplicating Nessus findings and inflating the risk-report
# scores that are computed from line counts. -KeepLegacyArtifacts preserves them.
if (-not $KeepLegacyArtifacts) {
    # -Recurse: subfolders (e.g. HighRisk) hold per-run CSVs that would otherwise
    # be re-imported by the management report as current findings.
    Get-ChildItem -LiteralPath $script:LegacyArtifactsDir -File -Recurse -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
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

$script:ADAuditSelectedChecks = @($script:ADAuditChecks | Where-Object { Test-ADAuditCheckSelected -Check $_ })
$needsActiveDirectory = [bool]@($script:ADAuditSelectedChecks | Where-Object { 'ActiveDirectory' -in $_.Modules }).Count
$needsGroupPolicy     = [bool]@($script:ADAuditSelectedChecks | Where-Object { 'GroupPolicy'     -in $_.Modules }).Count
$needsDnsServer       = [bool]@($script:ADAuditSelectedChecks | Where-Object { 'DnsServer'       -in $_.Modules }).Count
$needsDSInternals     = [bool]@($script:ADAuditSelectedChecks | Where-Object { 'DSInternals'     -in $_.Modules }).Count

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

# Preflight: detect whether we are running ON a Domain Controller. Several checks read
# host-local settings (registry/SMB config) that are only meaningful on a DC, or must
# reach the DCs over remote PowerShell/CIM. When run from a member/Tier-0 jump server
# those checks degrade to "could not assess" (recorded, never scored) rather than
# auditing the wrong host or asserting a false all-clear.
if ($needsActiveDirectory) {
    if (Test-ADAuditIsDomainController) {
        Write-Both "[+] Host role: this host IS a Domain Controller - host-local DC checks read the local machine."
    }
    else {
        Write-Both "[~] Host role: this host is NOT a Domain Controller (member/Tier-0 jump server)."
        Write-Both "    Checks that need the DCs' registry/services/SMB/SYSVOL will use remote PowerShell/CIM"
        Write-Both "    (WinRM or DCOM) to each DC. Where that is unavailable, the affected check is recorded as"
        Write-Both "    'could not assess' in not_assessed.txt with the reason - this does NOT raise the risk score."
    }
}

if ($needsActiveDirectory) {
    Write-Both "[*] Lang specific variables"
    Get-Variables
}
if ($installdeps) {
    $running = $true
    Invoke-AuditCheck -Name 'InstallDependencies' -Switch 'installdeps' -Description 'Installing optional features' -Body { Install-Dependencies }
}
foreach ($__chk in $script:ADAuditSelectedChecks) {
    $running = $true
    Invoke-AuditCheck -Name $__chk.Name -Switch $__chk.Switch -Description $__chk.Description -Body $__chk.Run
}
if (!$running) {
    Write-Both "[!] No arguments selected"
    Write-Both "[!] Other options are as follows, they can be used in combination"
    Write-Both "    -installdeps installs optional features (DSInternals)"
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
    Write-Both "    -lateralmovement analyses group nesting for lateral movement (hidden Tier 0 paths, AGDLP violations, per-user / per-group risk) and writes Lateral-Movement.html. Aliases: -lateral, -lm"
    Write-Both "        Optional: -LateralBaselinePath <lateral_movement_edges.csv> -LateralTier0Groups <group[,group...]>"
    Write-Both "    -all runs all checks, e.g. $scriptname -all"
    Write-Both "    -exclude <check[,check...]> skips the named checks when running -all, e.g. $scriptname -all -exclude gpo,dnszone"
    Write-Both "    -select <check[,check...]> runs only the named checks (comma-separated), e.g. $scriptname -select accounts,spn"
    Write-Both "    -KeepLegacyArtifacts keeps the previous run's per-check evidence files instead of clearing them at startup (by default each run starts with a clean .\\<COMPUTERNAME>\\Raw Data\\Source folder)"
}
Write-CheckFailuresReport -BaseRoot $outputdir
Write-NotAssessedReport -BaseRoot $outputdir
Write-Nessus-Footer
# Note: .nessus content is XML-escaped at write time inside Write-Nessus-Finding
# (and the header/footer are static), so no post-hoc character sanitisation is
# needed. The previous whole-file pass could not escape < and > without
# corrupting the markup and has been removed.

$endtime = Get-Date
Write-Both "[*] Script end time $endtime"

$oldEap = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
try {
    Invoke-ADAuditFinalReports -Root $outputdir
}
finally {
    $ErrorActionPreference = $oldEap
}