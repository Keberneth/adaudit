# ADAudit-PS7 - Active Directory Security Audit Tool

A comprehensive PowerShell 7 script for auditing Active Directory security configurations, policies, and vulnerabilities. Originally created by phillips321, converted to PowerShell 7 and extended by Keberneth.

## Quick Start

**From the GUI version you can install dependencies and chose what audits to run**
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

To also install optional dependencies (DSInternals for password quality analysis):

```powershell
.\AdAudit-PS7.ps1 -installdeps -all
```

## Requirements

- **PowerShell 7.x** on Windows (`pwsh.exe`)
- **ActiveDirectory** PowerShell module (installed with RSAT tools)
- Run as a user with sufficient AD read permissions (Domain Admin recommended for full results)
- NuGet and DSInternals modules from PowerShell Gallery
<rb>
https://www.powershellgallery.com/packages/NuGet/
<br>
https://www.powershellgallery.com/packages/DSInternals/
<br>
Chose Manual Download. You will get two .nuplkg files. Plase them in the ADAudit folder for offline installation.
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

Results are written to a timestamped folder in the script directory, including:

- **Risk Report** (HTML) with findings, severity scores, and recommendations
- **Nessus-compatible** output file (`.nessus`)
- **Raw data** exports (text files with detailed findings)
- **GPO reports** (HTML/XML) when GroupPolicy module is available

## Audit Checks

| Switch | Description |
|---|---|
| `-hostdetails` | Retrieve hostname and useful audit information |
| `-domainaudit` | Audit AD functional level, delegation, spooler, SMB signing, tombstone |
| `-trusts` | Check domain trust relationships |
| `-accounts` | Identify account issues (expired, disabled, gMSA, overlapping groups, etc.) |
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

## GUI

A graphical interface is also available for users who prefer a visual way to configure and launch the audit:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\ADAudit-GUI.ps1
```

The GUI provides:

- **Run All Checks** toggle (enabled by default, recommended)
- **Exclude** specific checks when running all
- **Individual check selection** when Run All is unchecked
- **Advanced options** for DNS zone and delegated permissions configuration
- **Command preview** showing the exact command that will be executed
- **Online/Offline dependency installation**

When you click "Run Audit", the script launches in a new elevated PowerShell window and the GUI closes automatically.

## Credits

- Original script by [phillips321](https://github.com/phillips321)
- PowerShell 7 conversion and updates by Keberneth
