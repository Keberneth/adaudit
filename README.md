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
Checks\Invoke-<Name>Check.ps1  One file per audit check (25 files, one per switch in the table below)
Checks\Invoke-LateralMovementCheck.ps1  Lateral movement analysis (self-contained, also runs on its own)
Password Audit\             Invoke-PwnedPasswordCheck.ps1, Invoke-SamePasswordCheck.ps1, PasswordAuditCommon.psm1 (separate from the audit run)
```

Always copy the whole folder. The runner and the GUI refuse to start when `Library\` or `Checks\` are missing. Results are written to `<COMPUTERNAME>\` next to the scripts.

## Password Audit
Two separate scripts in `Password Audit\` check accounts with the same NTLM hash (same passwords) and check Active Directory account NTLM hashes against the
https://api.pwnedpasswords.com service using a k-anonymity range query. They need replication rights (DSInternals `Get-ADReplAccount`) and are therefore **never part of `-all`**: start them from the GUI (section "Password Audit") or directly:

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
- Run as a user with sufficient AD read permissions (Domain Admin recommended for full results)
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

## Output

Results are written to a folder named after the host (e.g. `<COMPUTERNAME>\HTML Reports\` and `<COMPUTERNAME>\Raw Data\Source\`) in the script directory. The six primary HTML reports share a top navigation bar so you can move between them in the browser; everything else (companion wrappers, intermediate `.source.html` files, the GPO export HTML, the dangerous-ACL HTML, the high-risk baseline index, the DNS audit / recommendations HTML) is removed at the end of the run so the output folder stays focused.

Primary HTML reports (in `HTML Reports\`):

- **ADAudit-Results.html** - the main audit report. Severity-grouped findings (Critical / High / Medium / Low / Information), filterable, with per-finding "Why it matters" / "Recommended action" / source-link / result preview panels. Includes the new **Domain Admins membership review (size-adjusted)** and **Built-in domain Administrator (RID-500) hygiene** findings.
- **Risk-Report.html** - executive risk summary with overall score, score-band matrix, top findings, and links back into ADAudit-Results.html.
- **AD_Health.html** - AD platform health: replication, DC diagnostics (dcdiag), DC interconnect (network reachability between DCs with severity scaled by remaining redundancy), SYSVOL/DFSR backlog, NTDS database, time synchronization, core AD services (KPSSVC is informational, not High), event-log scrape (last 72h), sites and subnets, AD Recycle Bin, group hygiene. Hero gauge, "Tests Performed" status grid, and a "Test Details" section with one collapsible card per test (summary / why it matters / what to look for / how to fix / source link / copy-paste rerun command).
- **overlapping_group_memberships.html** - users who reach the same target group via multiple direct group memberships.
- **multiple_nested_paths.html** - users who reach the same target group via multiple nesting chains from a single direct group (group-nesting complexity, not necessarily duplicate effective permissions).
- **Lateral-Movement.html** - interactive, offline map of group nesting (member / memberOf). Privilege overview with Tier 0 groups on top and every group that reaches them below, hop-by-hop focus view for any user or group (who gets in / where it leads), filters for severity, scope, tier, OU and name, per-node details with every path to Tier 0, findings and fixes, plus sortable tables (findings, accounts, groups, Tier 0 paths) and a rules & guidance tab. Generated by `Invoke-LateralMovementCheck.ps1` (see below).

Other output:

- **Nessus-compatible** XML file (`adaudit.nessus`)
- **Raw Data\Source\\** - per-check evidence files (more detail than the HTML reports), including `health_*.txt` for AD Health, `domain_admins_scaled.txt` / `domain_admin_builtin_rid500.txt` for the Domain Admins review and `lateral_movement.txt` + `LateralMovement\*.csv` (findings, users, groups, edges = baseline for the next run, Tier 0 paths) for the lateral movement analysis
- **Raw Data\GPOReports\\** - GPO XML/HTML exports when the GroupPolicy module is available (the GPOReport HTML in HTML Reports is removed by the final cleanup; the XML export and the per-GPO HTML files in Raw Data are kept)

## Audit Checks

| Switch | Description |
|---|---|
| `-hostdetails` | Retrieve hostname and useful audit information |
| `-domainaudit` | Audit AD functional level, delegation, spooler, SMB signing, tombstone |
| `-trusts` | Check domain trust relationships |
| `-accounts` | Identify account issues (expired, disabled, gMSA, overlapping groups, etc.). Also runs the **Domain Admins membership review (size-adjusted)** and **Built-in domain Administrator (RID-500) hygiene** checks. |
| `-InactiveComputers` | Find inactive computer objects (>90 days) |
| `-passwordpolicy` | Review password policy and password quality (requires DSInternals) |
| `-oldboxes` | Find machines running unsupported OS (older than Server 2019) |
| `-gpo` | Export GPOs in XML and HTML format, check SYSVOL for passwords |
| `-ouperms` | Check for generic OU permission issues |
| `-laps` | Check if LAPS is deployed |
| `-authpolsilos` | Check authentication policies and silos |
| `-insecurednszone` | Detect DNS zones allowing insecure/unauthenticated updates |
| `-dnszone` | Generate DNS zone posture report |
| `-recentchanges` | Check for newly created users and groups (last 30 days) |
| `-adcs` | Check for ADCS vulnerabilities (ESC1-4, ESC8) |
| `-spn` | Find kerberoastable high-value accounts |
| `-asrep` | Find accounts vulnerable to AS-REP roasting |
| `-acl` | Check for dangerous ACL permissions on computers, users, and groups |
| `-ldapsecurity` | Check LDAP security configuration |
| `-dataextract` | Export raw AD audit data |
| `-delegatedpermissions` | Generate AD delegated permissions report |
| `-highrisk` | Generate high-risk AD baseline report |
| `-overlappinggroups` | Check for overlapping group memberships |
| `-portconnectivity` | Probe every DC on the canonical AD port set (DNS 53, Kerberos 88, RPC EPM 135, LDAP 389, SMB 445, kpasswd 464, LDAPS 636, GC 3268/3269, ADWS 9389, WinRM 5985/5986, NetBIOS 139, sample dynamic RPC). Also runs a cross-DC TCP probe via WinRM when reachable. Aliases: `-dcports`, `-dc-ports`, `-portcheck`. |
| `-adhealth` | AD platform health check: replication, DC diagnostics, DC interconnect (severity scales with remaining redundancy - 2 DCs / 1 isolated = Critical, 3 / 1 = High, 4+ / 1 = Medium), SYSVOL/DFSR, NTDS, time sync, services, event logs, sites/subnets, Recycle Bin, group hygiene. Writes `AD_Health.html`. Aliases: `-ad-health`, `-health`. |
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
| `-KeepLegacyArtifacts` | Preserve raw data and evidence files in legacy locations |
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

How it reasons: `memberOf` is followed transitively ("I am memberOf X" = "I inherit the rights of X"), every group is classified (well-known Tier 0 / privileged built-in, declared tier by `T0`/`T1`/`T2` name tags or parameters, Global = role, Domain Local = resource, admin-ish by name, broad, temporary) and 21 rules (LM01-LM21, documented in the report) produce findings with an explanation and a fix. Only AD group nesting is visible to the script - local Administrators groups, GPO Restricted Groups, share/SQL permissions and ACL attack paths are not; use the Dangerous ACL / Delegated-permissions reports and BloodHound for those. Keep `lateral_movement_edges.csv` of each approved state and pass it as `-BaselinePath` next time: new group-to-group edges are the one signal that catches every chain early.

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
- **Advanced options** for DNS zone, delegated permissions and lateral movement (baseline CSV, extra Tier 0 groups) configuration
- **Command preview** showing the exact command that will be executed
- **Online/Offline dependency installation**

When you click "Run Audit", the script launches in a new elevated PowerShell window and the GUI closes automatically.

<br><br>
## Active Directory Assessment Overview
This script performs an assessment of Active Directory configuration, security posture, and operational health.  
The output is intended to provide visibility into potential risks, misconfigurations, and improvement areas.
<br><br>

## Risk Report
The management report is an HTML file that provides a more presentable summary of the audit, including an overall security score.<br>
The further a finding deviates from the defined baseline, the higher the risk score becomes. For example, Critical risks start at 12 points, but both criticality and score increase the further the risk is from the baseline.<br>
If the KRBTGT password has not been changed in 180 days, it is considered a Critical risk (12 points). However, if it has not been changed in 2000 days, the score increases to 31 points.<br>
Similarly, if there are many accounts that have not been used for a long time, the risk score increases as the number of inactive accounts grows.<br>
This scoring model helps pinpoint and prioritize security issues and highlights how neglected certain areas are. A finding with low initial criticality can become high or Critical if it deviates far enough from the baseline value.
<br><br>


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
