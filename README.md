# ADAudit-PS7 - Active Directory Security Audit Tool

A comprehensive PowerShell 7 script for auditing Active Directory security configurations, policies, and vulnerabilities. Originally created by phillips321, converted to PowerShell 7 and extended by Keberneth.<br>
ADAudit-PS7 include health checks and improved reporting.

## Repository layout

```
ADAudit-GUI.ps1              GUI: pick checks, install dependencies, run the audit, run the Password Audit
AdAudit-PS7.ps1              Command-line runner: parameters, check table, run lifecycle (use this from scripts / scheduled tasks)
README.md
Library\ADAudit.Common.ps1   Shared helpers and run state (output folders, logging, failure / not-assessed tracking, Nessus export, report CSS and navigation, module import, -installdeps)
Library\ADAudit.Report.ps1   Management report (ADAudit-Results.html, Risk-Report.html), companion-report wrapping, end-of-run cleanup
Checks\Invoke-<Name>Check.ps1  Audit collectors, plus shared helpers loaded by their parent check
Checks\Invoke-DcShareSecurityCheck.ps1  DC SMB/share helper included in Domain Audit (no additional selection required)
Checks\Invoke-LateralMovementCheck.ps1  Lateral movement analysis (self-contained, also runs on its own)
Password Audit\             Invoke-PwnedPasswordCheck.ps1, Invoke-SamePasswordCheck.ps1, PasswordAuditCommon.psm1 (separate from the audit run)
```

Always copy the whole folder. The runner and the GUI refuse to start when `Library\` or `Checks\` are missing. Each standard audit writes to `<COMPUTERNAME>\yyyy-MM-dd_HH-mm-ss\` next to the scripts, using the audit host's local time (for example, `2026-10-25_11-28-24`). A collision adds `_02`, `_03`, etc.; existing evidence is never reused. The unique run ID, local time with UTC offset, UTC time, and time-zone ID are retained in the run metadata.

## Password Audit
Two separate scripts in `Password Audit\` check accounts with the same NTLM hash (same passwords) and check Active Directory account NTLM hashes against the
https://api.pwnedpasswords.com service using a k-anonymity range query. These scripts remain a **separate paid add-on**, never part of `-all`, with their own replication permissions and connectivity requirements. The existing DSInternals password-quality and duplicate-password checks remain in the standard audit and also require replication rights. Start the add-on from the GUI (section "Password Audit") or directly:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\Password` Audit\Invoke-PwnedPasswordCheck.ps1 [-Server dc01] [-IncludeComputers]
.\Password` Audit\Invoke-SamePasswordCheck.ps1  [-Server dc01] [-UsersOnly] [-Pwned]
```

See `Password Audit\README.md` for the details of the k-anonymity lookup.

## Quick Start

**From the GUI version you can install dependencies and choose what audits to run**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\AdAudit-GUI.ps1
```

**For the best and most complete results, run all checks:**

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\AdAudit-PS7.ps1 -all
```

This runs every available audit check and produces a full security report. It is the recommended way to use this tool.

The console shows how many checks were selected out of the available checks, how many were skipped, and the current check number. Overall progress counts completed checks; it is not an estimate of remaining time. Within a check, phases with known totals show counts and percentages. Directory requests and other operations without a known total show their current stage instead of a made-up percentage. While a remote call is waiting for an answer, both progress bars repeat the check number, phase, target and elapsed time about every five seconds (console lines are throttled); the percentage shown is the measured completed work and never advances just because time passes. Progress is cleared on success, failure or cancellation, and report generation has its own stages.

Each wrapped operation also records measured elapsed seconds and its completion/coverage status in `Raw Data\Source\audit_step_timings.csv`. Both main reports show the ten slowest operations and link to the complete CSV. Timings include waiting and nested work, so do not sum them to calculate total audit duration. Use them to identify the actual Accounts bottleneck before changing concurrency or queries.

### Focused domain controller security

`-domainaudit` (also in `-all` and the GUI's Domain Audit selection) includes DC SMB and share security. This is an AD security assessment, not the separate Windows Server audit or a Microsoft baseline/GPO comparison.

- `dc_smb_security.csv` records SMB1, server/client signing, insecure guest access, anonymous SMB restrictions/exception lists and available dialect configuration. Missing properties stay unknown; newer-server settings are not required on unsupported versions.
- `dc_share_security.csv` inventories SYSVOL, NETLOGON and additional disk shares, their encryption requirements and permission-review candidates. The encryption requirement combines server/share `EncryptData` with `RejectUnencryptedAccess`; a missing requirement is a review observation, not proof that all connections are unencrypted. An additional share alone is not a vulnerability.
- `dc_share_aces.csv` preserves share and NTFS root ACL evidence, including SIDs, allow/deny masks and inheritance. Broad authenticated read on SYSVOL/NETLOGON is normal. Unexpected broad write/control ACEs are unscored review candidates: confirm both authorization layers, deny/inheritance rules and trustee membership before remediation. Child-folder/file overrides and full effective-access token evaluation are outside this collection.
- `dc_smb_sessions.csv` summarizes observed session dialect/protection fields without client/account identities. No sessions is not proof that weak dialects are prohibited. Blank fields are unavailable evidence, not false values.
- `-ldapsecurity` records signing/channel-binding configuration separately from certificate-validated LDAPS/StartTLS and the bounded anonymous domain-object read. LDAP 389 may be protected; an open LDAPS port alone does not establish enforcement. Active unsigned/CBT enforcement, all directory subtrees, certificate revocation and GC TLS are not certified by these checks.
- `-accounts` preserves domain SID-500 naming/logon context. Renaming is limited defense in depth; a decoy is optional and a recent logon is not automatically misuse. The per-DC DSRM recovery account is separate. On an isolated host, SID-500 password age uses a supplied snapshot date; without one its age assessment remains unknown while independent risks are retained.

Both main HTML reports include a **Domain controller security evidence** section with positive, review, unavailable and excluded observations plus complete CSV downloads. Only explicit findings add risk points. Local/CIM/DCOM collection is preferred with the existing permitted WinRM fallback; missing access remains a coverage gap. Isolated-host mode excludes remote DCs before collection.

Reference guidance: [Microsoft LDAP protections](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), [SMB security](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security), and [default AD accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-default-user-accounts).

### Remote collection: deadlines, connection cache and parallel targets

Every remote operation against a domain controller (CIM over DCOM with optional WinRM fallback, remote event logs, remote PowerShell, SYSVOL access, replication metadata and the native `dcdiag`, `repadmin` and `w32tm` tools) runs as a cancellable worker with an end-to-end deadline that includes name resolution, connection setup, the operation and any transport fallback:

| Option | Default | Effect |
|---|---|---|
| `-TargetTimeoutSec <5-3600>` | 60 | Deadline per remote target operation. On expiry the worker is stopped (native tools and child processes are killed), the target is recorded as **not assessed (Timeout)**, results already collected are kept and the audit continues. |
| `-ConnectionCacheSec <0-86400>` | 300 | How long a target/protocol **connection** failure (unreachable or timeout) suppresses another attempt in the same run. Access denied and unsupported operations are never cached, and a DCOM failure does not prevent a permitted WinRM attempt. Every skipped operation is recorded with the reason and the time of the next allowed attempt. |
| `-MaxConcurrency <1-16>` | 2 | Parallel target workers inside a check (Domain Audit per-DC collectors and the DC port probes). `1` is the serial troubleshooting mode and produces the same findings and coverage. |

Every target is resolved once per run (5 s bound; the answer, a missing record, or "resolver did not answer" is cached) and probes connect to the resolved address. Before the first attempt on a transport, a 3-second TCP probe of the port that transport needs (135 for DCOM, RPC and event logs, 389 for dcdiag, 5985 for WinRM, 445 for SYSVOL, 9389 for replication metadata, 80/443 for AD CS web enrollment) replaces the protocol's own timeout: a host that is down is recorded as unreachable within seconds instead of after 15 to 40 s, and a DC whose LDAP port does not answer skips all ten dcdiag tests with one recorded reason. Short DC names and their domain FQDNs share one cache entry.

Coverage records (`not_assessed.csv`, the report's *Assessment scope and coverage* section) carry a collection outcome: `Timeout`, `Unreachable`, `AccessDenied`, `Unsupported`, `Excluded` (isolated-host scope) or `Unavailable`. Success means the collection succeeded, not that a control passed. CIM sessions are reused within a run and disposed at the end; the connection cache is reset between runs. `audit_run.json` records the settings, worker counts and transport failures of the run.

Transport preflight attempts all resolved IPv4/IPv6 addresses within one shared connect budget. One failed address cannot suppress a reachable alternate. A CIM provider/query timeout is recorded as `Timeout` and its session is discarded, but unrelated queries remain eligible. Only a connection-stage timeout or an explicit connection failure can create a negative CIM transport-cache entry; a timed-out query or method is not automatically retried.

Known limits: the DNS zone posture report (`-dnszone`) still uses the DnsServer module's own timeouts; a worker that ignores cancellation (rare, native RPC blocked inside a cmdlet) is abandoned after a five-second grace period, reported in the run metadata and console, and never reused.

### Auditing an isolated host (copy of a domain controller)

For an isolated copy of a domain controller, select **Isolated host (-IsolateHost)** in the GUI or run:

```powershell
.\AdAudit-PS7.ps1 -all -IsolateHost
# If the actual copy date is known, also supply -SnapshotDate yyyy-MM-dd.
```

`-IsolatedClone` remains accepted as an alias and behaves identically. This mode identifies the reports as an assessment of an isolated copy. It records remote DC operational probes as excluded before any connection is opened, skips production replication validation, retains local and directory-based checks, and records excluded coverage. It is not a network-disconnection mechanism: directory access and any separately selected password breach lookup still need their normal connectivity. `-SnapshotDate` is optional context (it must be a valid past or current date and requires `-IsolateHost`); it does not rewind the audit clock. On an old copy, inactivity, password age, recent changes, and other time-based observations may reflect the age of the copy. Verify them against production before remediation. These reports do not establish the current production environment's health or risk. Reports and metadata written by earlier versions (`AssessmentMode = IsolatedClone`) remain readable.

**Run a single check** either through the runner or by starting its file; both give the same output folders and reports:

```powershell
.\AdAudit-PS7.ps1 -select accounts,spn
.\Checks\Invoke-AccountsCheck.ps1            # same as .\AdAudit-PS7.ps1 -select accounts
.\Checks\Invoke-HealthCheck.ps1 -KeepLegacyArtifacts
```

To also install optional dependencies (DSInternals for password quality analysis):

```powershell
.\AdAudit-PS7.ps1 -installdeps -all
```

## Requirements

- **PowerShell 7.x** on Windows (`pwsh.exe`)
- **ActiveDirectory** PowerShell module (installed with RSAT tools)
- Use an audit identity with the permissions required by the selected checks: directory reads, applicable remote registry/event/service access, and replication rights for DSInternals password analysis. Missing access is reported as incomplete coverage.
- NuGet and DSInternals modules from PowerShell Gallery
<br>
https://www.powershellgallery.com/packages/NuGet/
<br>
https://www.powershellgallery.com/packages/DSInternals/
<br>
Choose Manual Download. You will get two .nupkg files. Place them in the ADAudit folder for offline installation.
<br>

### Optional Modules

| Module | Purpose | How to Get |
|---|---|---|
| GroupPolicy | GPO export and domain audit checks | Installed with RSAT Group Policy Management |
| DnsServer | DNS zone security checks | Installed with DNS Server role |
| LAPS / AdmPwd.PS | LAPS deployment verification | Windows LAPS or legacy Microsoft LAPS |
| DSInternals | Password quality analysis | `.\AdAudit-PS7.ps1 -installdeps` or manual install |

If an optional module is not available, those specific checks will be skipped and the rest of the audit will continue normally.

### Remote collection and WinRM

WinRM is optional for most collection. The audit reads its own host locally and uses CIM over DCOM, registry RPC, event-log RPC, or SMB where the particular check supports them. CIM collection can fall back to WSMan if available. These alternatives still require the relevant permissions, services, and firewall access; they do not bypass a blocked network.

Probing connectivity from another DC requires executing a probe on that DC, so the cross-DC port matrix still uses WinRM for remote origins. If that access is unavailable, the remote-origin portion is marked **Not assessed** while probes from the audit host remain available. An unavailable management interface alone is not treated as a security weakness. The script does not enable WinRM or alter firewall rules. In isolated-clone mode it avoids remote origins entirely.

## Output

Results are written under `<COMPUTERNAME>\<run date and time>\HTML Reports\` and `<COMPUTERNAME>\<run date and time>\Raw Data\`. Each report describes only its own run; the audit does not load previous reports or automatically label issues resolved. The six primary HTML reports share a navigation bar. Intermediate companion HTML is consolidated during final cleanup; source evidence remains in Raw Data. HTML reports, including the separate Password Audit reports, support offline dark/light themes with a saved preference and operating-system default.

Primary HTML reports (in `HTML Reports\`):

- **ADAudit-Results.html** - the main audit report. Severity-grouped findings (Critical / High / Medium / Low / Information), filterable, with per-finding "Why it matters" / "Recommended action" / source-link / result preview panels. Includes the new **Domain Admins membership review (size-adjusted)** and **Built-in domain Administrator (RID-500) hygiene** findings.
- **Risk-Report.html** - executive risk summary with overall score, score-band matrix, top findings, and links back into ADAudit-Results.html.
- **AD_Health.html** - replication, DC diagnostics (dcdiag), observed replication partners and reachability, SYSVOL/DFSR availability, NTDS file size/free space, time synchronization, services, recent event logs, site/GC placement, AD Recycle Bin enablement, and group hygiene. Collection gaps are visible per test; incomplete collection cannot produce a perfect health score. DFSR backlog, database fragmentation, and complete subnet mapping are not measured by these checks.
- **overlapping_group_memberships.html** - users who reach the same target group via multiple direct group memberships.
- **multiple_nested_paths.html** - users who reach the same target group via multiple nesting chains from a single direct group (group-nesting complexity, not necessarily duplicate effective permissions).
- **Lateral-Movement.html** - interactive, offline map of group nesting (member / memberOf). Privilege overview with Tier 0 groups on top and every group that reaches them below, hop-by-hop focus view for any user or group (who gets in / where it leads), filters for severity, scope, tier, OU and name, per-node details with every path to Tier 0, findings and fixes, plus sortable tables (findings, accounts, groups, Tier 0 paths) and a rules & guidance tab. Generated by `Invoke-LateralMovementCheck.ps1` (see below).

Other output:

- **Raw Data\report_findings.csv** - current finding register with rule ID, severity, evidence, score, and evidence-file reference.
- **Raw Data\report_summary.json** - current-run scope, coverage, methodology version, severity counts, and risk index for manual comparison.
- **Raw Data\ReportDownloads\** - derived tables used by report download links, kept separate so rendering a text preview can never overwrite a collected CSV with the same basename.
- **Raw Data\Source\audit_run.json** and **audit_check_status.csv** - run identity and selected, omitted, completed, partial, or failed checks. Completed means execution finished without recorded gaps; it does not mean every security control passed.
- **Nessus-compatible** XML file (`adaudit.nessus`)
- **Raw Data\Source\\** - per-check evidence files (more detail than the HTML reports), including `health_*.txt` for AD Health, `domain_admins_scaled.txt` / `domain_admin_builtin_rid500.txt` for the Domain Admins review and `lateral_movement.txt` + `LateralMovement\*.csv` (findings, users, groups, edges = baseline for the next run, Tier 0 paths) for the lateral movement analysis
- **Raw Data\GPOReports\\** - GPO XML/HTML exports when the GroupPolicy module is available; linked companion reports are retained by final cleanup.

## Audit Checks

| Switch | Description |
|---|---|
| `-hostdetails` | Retrieve hostname and useful audit information |
| `-domainaudit` | Audit AD functional level, delegation, spooler, SMB signing, tombstone |
| `-trusts` | Check domain trust relationships |
| `-accounts` | Identify account issues (expired, disabled, gMSA, overlapping groups, etc.). Also runs the **Domain Admins membership review (size-adjusted)** and **Built-in domain Administrator (RID-500) hygiene** checks. |
| `-InactiveComputers` | Identify computer activity review candidates using creation, replicated logon, and machine-password timestamps (>90 days); does not assert that a server is unused |
| `-passwordpolicy` | Review password policy and password quality (requires DSInternals) |
| `-oldboxes` | Review legacy operating-system names recorded in AD; verify actual OS version and support entitlement before remediation |
| `-gpo` | Export GPOs in XML and HTML format, check SYSVOL for passwords |
| `-ouperms` | Check for generic OU permission issues |
| `-laps` | Check if LAPS is deployed |
| `-authpolsilos` | Check authentication policies and silos |
| `-insecurednszone` | Detect DNS zones allowing insecure/unauthenticated updates |
| `-dnszone` | Generate DNS zone posture report |
| `-recentchanges` | Check for newly created users and groups (last 30 days) |
| `-adcs` | Review AD CS template publication, flags, enrollment ACLs, and web enrollment endpoints for potential exposures requiring verification |
| `-spn` | Find kerberoastable high-value accounts |
| `-asrep` | Find accounts vulnerable to AS-REP roasting |
| `-acl` | Review dangerous Allow permissions on computers, users, groups, and domain-root replication delegations; no replication is performed by this check |
| `-ldapsecurity` | Check LDAP security configuration |
| `-dataextract` | Export raw AD audit data |
| `-delegatedpermissions` | Generate AD delegated permissions report |
| `-highrisk` | Generate high-risk AD baseline report |
| `-overlappinggroups` | Check for overlapping group memberships |
| `-portconnectivity` | Test selected DC TCP endpoints from this host and, when WinRM permits, between DCs. GC applicability follows the DC role; DNS, LDAPS, and management endpoints are contextual inventory. TCP reachability does not verify UDP, dynamic RPC, LDAP signing, or encryption. Aliases: `-dcports`, `-dc-ports`, `-portcheck`. |
| `-adhealth` | AD platform health and explicit per-test coverage: replication, dcdiag, SYSVOL/DFSR availability, NTDS size/free space, time, services, events, site/GC placement, Recycle Bin, group hygiene. Writes `AD_Health.html`. Aliases: `-ad-health`, `-health`. |
| `-lateralmovement` | Lateral movement analysis of group nesting (runs `Checks\Invoke-LateralMovementCheck.ps1`): every nesting path into a Tier 0 / privileged built-in group, every account that is Tier 0 only through a chain, AGDLP violations (role in role, resource in resource, users directly in resource groups, role+resource hubs), broad "all employees" groups used for access, circular and deep nesting, dormant privileged paths, hidden membership via primaryGroupID, computers / gMSAs / foreign principals in privileged groups, Tier 0 account hygiene, tier boundary crossings (T0/T1/T2 tags) and optional baseline drift. Risk per finding, per user and per group (Critical / High / Medium / Low / Information). Writes `Lateral-Movement.html`. Aliases: `-lateral`, `-lateral-movement`, `-lm`. |

## Switches

### Run Modes

| Switch | Description |
|---|---|
| `-all` | Run all audit checks (recommended) |
| `-exclude <checks>` | Comma-separated list of checks to skip when using `-all` (e.g. `-exclude gpo,dnszone`) |
| `-select <checks>` | Comma-separated list of checks to run (alternative to individual switches) |
| `-installdeps` | Install optional dependencies (DSInternals, NuGet) |

### Advanced Options

| Switch | Description |
|---|---|
| `-KeepLegacyArtifacts` | Retain legacy evidence layout inside this run's folder; never reuse earlier-run evidence |
| `-IsolateHost` | Assess an isolated copy of a DC: local collection only, remote DC operational probes recorded as excluded, snapshot limitations identified in reports (alias: `-IsolatedClone`) |
| `-SnapshotDate yyyy-MM-dd` | Optional known copy date; requires `-IsolateHost`, must be a valid date and cannot be in the future |
| `-TargetTimeoutSec <5-3600>` | Deadline per remote target operation including transport fallback (default 60) |
| `-ConnectionCacheSec <0-86400>` | Lifetime of a cached target/protocol connection failure before another attempt (default 300) |
| `-MaxConcurrency <1-16>` | Parallel target workers inside a check; `1` = serial troubleshooting mode (default 2) |
| `-DnsZoneOutputRoot <path>` | Custom output directory for DNS zone reports |
| `-DnsIncludeRecordCounts` | Include record counts in DNS zone report |
| `-DnsIncludeSystemZones` | Include system DNS zones in the report |
| `-DelegatedOutputRoot <path>` | Custom output directory for delegated permissions report |
| `-DelegIncludeSystemTrustees` | Include system trustees in delegated permissions report |
| `-DelegIncludeDeny` | Include deny permissions in delegated permissions report |
| `-DelegIncludeInherited` | Include inherited permissions in delegated permissions report |
| `-DelegServer <server>` | Target a specific server for delegated permissions queries |
| `-LateralBaselinePath <csv>` | A `lateral_movement_edges.csv` from a previous run; new / removed group-to-group nestings are reported (LM19) |
| `-LateralTier0Groups <names>` | Extra groups to treat as Tier 0 in the lateral movement analysis (PAM groups, `AD-Admins`, backup infrastructure ...) |

## Examples

Run all checks:
```powershell
.\AdAudit-PS7.ps1 -all
```

Run all checks except GPO and DNS:
```powershell
.\AdAudit-PS7.ps1 -all -exclude gpo,dnszone
```

Run only account and password checks:
```powershell
.\AdAudit-PS7.ps1 -accounts -passwordpolicy
```

Install dependencies and run everything:
```powershell
.\AdAudit-PS7.ps1 -installdeps -all
```

## Lateral movement check (standalone)

`Checks\Invoke-LateralMovementCheck.ps1` is self-contained (its own parameters, no dependency on the runner). It runs inside `-all` / `-lateralmovement`, from the GUI, or on its own:

```powershell
# Analyse the current domain -> .\<COMPUTERNAME>\HTML Reports\Lateral-Movement.html + Raw Data\Source\LateralMovement\*.csv
.\Checks\Invoke-LateralMovementCheck.ps1

# Custom output folder, extra Tier 0 groups, documented exceptions, baseline diff against the previous run
.\Checks\Invoke-LateralMovementCheck.ps1 -OutputRoot D:\Audit\CORP -Tier0Groups 'PAM-T0-Admins','ADFS-Admins' -ApprovedNestings 'GRP-All-IT|GRP-Helpdesk' -BaselinePath .\baseline\lateral_movement_edges.csv
```

How it reasons: the analysis follows direct and nested group membership and classifies groups using known privileged SIDs, declared tiers, group scope, and naming hints. The 23 rules (LM01-LM23, documented in the report) identify privilege paths and review candidates with supporting evidence. Naming hints do not prove administrator rights on any host. Only AD group nesting is visible to this analysis; local Administrators membership, applied GPO rights, share/SQL permissions, and ACL attack paths need separate checks. Optional `-BaselinePath` compares group-to-group edges when a previous export is explicitly supplied; ordinary audits do not need a baseline.

## GUI

A graphical interface is also available for users who prefer a visual way to configure and launch the audit:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\ADAudit-GUI.ps1
```

The GUI provides:

- **Password Audit** section that launches `Invoke-PwnedPasswordCheck.ps1` / `Invoke-SamePasswordCheck.ps1` in their own window (results in `<COMPUTERNAME>\Password Audit\`), kept apart from the audit run
- **Run All Checks** toggle (enabled by default, recommended)
- **Exclude** specific checks when running all
- **Individual check selection** when Run All is unchecked
- **Advanced options** for isolated DC clones (optional snapshot date), DNS zone, delegated permissions and lateral movement (baseline CSV, extra Tier 0 groups) configuration
- **Command preview** showing the exact command that will be executed
- **Online/Offline dependency installation**

When you click "Run Audit", the script launches in a new elevated PowerShell window and the GUI closes automatically.

<br><br>
## Active Directory Assessment Overview
This script performs an assessment of Active Directory configuration, security posture, and operational health.  
The output is intended to provide visibility into potential risks, misconfigurations, and improvement areas.
<br><br>

## Risk Report

The management report separates finding priority, accumulated finding points, and assessment coverage. Methodology **v2.1** keeps the v2 severity weights (Critical 12, High 8, Medium 5, Low 2) and count/baseline adjustments, while correcting informational port scoring, duplicate membership rollups, and review-only classifications. Information and disabled-account password hygiene contribute zero. Membership counts, nesting, name patterns, and password age alone do not establish a Critical credential exposure.

The headline is the higher of the highest scored finding severity and the existing index threshold (50/100/150 points). It explicitly states which caused the priority. The score matrix keeps the colored Low/Medium/High/Critical levels for the 0-49/50-99/100-149/150+ point ranges; the Priority basis line states whether the points or a single higher-severity finding set the headline. These thresholds and weights are script-defined and have not been empirically calibrated; two audits cannot validate them. The index is not a percentage, probability of compromise, or compliance certification. Related controls can still overlap. The JSON retains legacy `ScoreBand` for compatibility and adds `IndexBand`, `HighestFindingSeverity`, `PriorityBasis`, and `IndexCalibration`.

Failed, partial, and omitted checks are visible separately. Missing evidence is not a pass and does not create a security finding by itself. Counts represent grouped conditions, not unique affected accounts or the number of controls passed.

Retain each delivered report for manual comparison. Compare scope, coverage, tool and methodology versions, severity counts, and the finding register together. Treat the first v2.1 report as a corrected baseline: lower points may reflect fixed detection/classification or missing coverage rather than customer remediation. An old isolated copy cannot establish current production risk. No previous report is needed or loaded.

### Account evidence

An account's **PasswordNotRequired** flag permits a password policy exception; it does not prove that its password is empty. A confirmed empty-password finding requires the empty NT hash. Unavailable hashes are reported as unverified evidence. Enabled accounts, disabled accounts, and unknown account status are shown separately so disabled-account cleanup does not inflate active exposure.

Computer activity is assessed using multiple AD timestamps. A recent machine-password change or replicated logon suppresses a stale candidate, and newly created accounts are not treated as long inactive. Remaining candidates require owner and workload verification: interactive logons by people do not directly establish computer-account authentication, and directory timestamps alone cannot prove that a server is unused.

## Offline validation

Regression fixtures exercise account classification, ACL and AD CS interpretation, coverage handling, and generated reports without contacting a domain or replicating credentials. From PowerShell 7 with Pester installed:

```powershell
$standalone = @('Report.Tests.ps1','ReportReview.Tests.ps1','DcSecurityReport.Tests.ps1','PasswordLookup.Tests.ps1','ProgressChecks.Tests.ps1','LateralSeverity.Tests.ps1','WorkerRuntime.Tests.ps1','TcpPreflight.Tests.ps1','CimTimeout.Tests.ps1','PilotScenarios.Tests.ps1')
$testFiles = Get-ChildItem .\Tests\*.Tests.ps1 | Where-Object Name -notin $standalone
$result = Invoke-Pester -Script $testFiles.FullName -PassThru
if ($result.FailedCount -gt 0) { throw 'Offline regression tests failed.' }
foreach ($suite in $standalone) {
    pwsh -NoProfile -File (Join-Path .\Tests $suite)
    if ($LASTEXITCODE -ne 0) { throw "Regression suite failed: $suite" }
}
```

The Pester suites use the in-process seam (`ADAuditWorkerMode = 'InProcess'`) so command mocks apply. `WorkerRuntime.Tests.ps1` exercises real runspaces, child processes, deadlines, cancellation cleanup and runner validation; its host-details run reads local machine information. `TcpPreflight.Tests.ps1` uses synthetic sockets and real loopback listeners, without DNS or remote network access. `CimTimeout.Tests.ps1` distinguishes connection failures from provider timeouts. `PilotScenarios.Tests.ps1` runs the service collector with real workers and synthetic directory/CIM boundaries to compare serial and parallel results, excluded peers, inaccessible targets and partial coverage. Validated with Pester 3.4.0 under PowerShell 7. These tests do not replace a pilot audit in a representative AD environment.

The `Tests\` folder is developer tooling and is excluded from the synced repository (`.gitignore`); it lives only in the development working copy. Run output folders (`<COMPUTERNAME>\<yyyy-MM-dd_HH-mm-ss>\`) are excluded as well.

### Single-server clone pilot

Extract the entire deployment package to a new folder on the clone. In the GUI, open **Advanced Options**, enable **Isolated host (-IsolateHost)** and optionally enter the known snapshot date. The command preview must contain `-IsolateHost`; **Run Audit** launches that same command. Set **Parallel target workers** to `1` or `2` for the comparison runs.

For the equivalent command-line pilot in PowerShell 7, first compare the affected checks with one and two workers:

```powershell
.\AdAudit-PS7.ps1 -select domainaudit,adhealth,portconnectivity -IsolateHost -MaxConcurrency 1
.\AdAudit-PS7.ps1 -select domainaudit,adhealth,portconnectivity -IsolateHost -MaxConcurrency 2
# Exercise the revised evidence and pilot corrections:
.\AdAudit-PS7.ps1 -select domainaudit,ldapsecurity,accounts,dnszone -IsolateHost
# Then review the complete audit and all reports:
.\AdAudit-PS7.ps1 -all -IsolateHost
```

If the actual clone date is known, add the same `-SnapshotDate yyyy-MM-dd` to each command using that date; otherwise omit it. Keep the identity, selected checks and data unchanged between the first two runs. On a one-server clone most remote work is intentionally excluded, so a speedup is not an acceptance requirement. Findings and coverage should agree apart from timestamps, elapsed times and genuinely changing local service/event data. Verify that remote DCs are excluded, local collection remains available, collection failures stay visible, the isolated-host banner appears, and `Collection.Workers.OrphansRemaining` is zero in `Raw Data\Source\audit_run.json`.

Review the HTML reports in light/dark mode, a narrow window and print preview; open evidence links and CSV downloads. Retain the complete run folders for review. A single isolated clone cannot establish successful collection across production DCs, real remote permission failures, or the speedup of parallel collection across multiple reachable DCs. Those live scenarios remain pending until a connected test environment is available; offline fixtures cover their control flow only.

## Releases

Releases are built by the GitHub Actions workflow in `.github/workflows/release.yml`. To cut one: set `$versionnum` in `AdAudit-PS7.ps1`, add the matching section to `RELEASE-NOTES.md`, commit, then tag and push:

```powershell
git tag v9.4.0
git push origin v9.4.0
```

The workflow checks that the tag matches the declared version, verifies every script parses, assembles the deployment folder (runner, GUI, `Library\`, `Checks\`, `Password Audit\`, README, release notes), writes a SHA-256 manifest and publishes a GitHub Release with `ADAudit-<version>.zip` attached. Deploy the whole zip; copying only the runner is insufficient.


### IMPORTANT
All findings must be evaluated in the context of:<br>
- Organizational and regulatory requirements<br>
- Internal security policies and approved exceptions<br>
- Established operational practices and business constraints<br>
- Business requirements<br>
<br>
The presence of a finding does not automatically indicate a security issue.  <br>
Results should be reviewed, validated, and prioritized according to the organization’s risk management process.<br>
<br>

### Purpose
This script is designed to support informed decision-making and continuous improvement of Active Directory security and operational hygiene.
<br><br>

# adaudit
This PowerShell script is designed to conduct a comprehensive audit of Microsoft Active Directory, focusing on identifying common security vulnerabilities and weaknesses. Its execution facilitates the pinpointing of critical areas that require reinforcement, thereby fortifying your infrastructure against prevalent tactics used in lateral movement or privilege escalation attacks targeting Active Directory.
```
### Original script created by:
_____ ____     _____       _ _ _
|  _  |    \   |  _  |_ _ _| |_| |_
|     |  |  |  |     | | | . | |  _|
|__|__|____/   |__|__|___|___|_|_|
                 by phillips321
```
<br>
https://github.com/phillips321/adaudit
<br><br>

## Adding a check

1. Create `Checks\Invoke-<Name>Check.ps1` with the check's functions and an `Invoke-<Name>Check` entry function (copy the standalone-launch tail from any existing file).
2. Add a row to `$script:ADAuditChecks` in `AdAudit-PS7.ps1` (switch, parameter variable, name, file, required modules, description, entry function) and the matching `[switch]` parameter.
3. Write evidence to `Get-EvidencePath`, record failures with `Register-ADAuditNotAssessed`, export with `Write-Nessus-Finding`; the management report in `Library\ADAudit.Report.ps1` turns the evidence into findings.
4. Add the switch to `$AuditChecks` in `ADAudit-GUI.ps1` and to the table above.

## Credits

- Original script by [phillips321](https://github.com/phillips321)
- PowerShell 7 conversion and updates by Keberneth
