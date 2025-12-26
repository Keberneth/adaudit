# Fork Explination
Copy the ADAudit folder to the DC Server or a server with the RSAT tools installed and can manage active directory. The account running the script need to be Domain Admin to run the full audit. <br><br>

Download NuGet and DSInternals modules from PowerShell Gallery before using this script and place in the same folder as the script.<br>
https://www.powershellgallery.com/packages/NuGet/<br>
https://www.powershellgallery.com/packages/DSInternals/<br>
Chose Manual Download. You will get two .nuplkg files. Plase them in the ADAudit folder.<br><br>

To install the required modules, run the powershell script AdAudit-Run.ps1 and chose option 2 for offline installation.<br><br>

Changes to this fork:<br>
Offline installation for dependencies<br>
Added explainations to some of the report files<br>
Deligated AD permissions report<br>
Lookup DNS servers and then run the DNS report. (DNS report do not need to run on the DNS server)<br>
Full DNS-ZoneReport report<br>
Can run on an other server then AD DC as long as:<br>
-RSAT tools is installed<br>
-Server can manage AD<br>
-Powershell can run using domain admin account<br>
Added runtime arg<br>
-delegatedpermissions<br>
-dnszone
<br>
Overall report for management added as a separate script
<br><br>

**Run the script**
<br>
Create the folder C:\ADAudit\
<br>
Coppy all script files to the folder and if installing dependencies offline the .nuplkg files.<br>
**Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force & "C:\ADAudit\AdAudit-Run.ps1"**
<br>
Run the install dependencies
<br>
Run full check
<br><br>

## Active Directory Assessment Overview
This script performs an assessment of Active Directory configuration, security posture, and operational health.  
The output is intended to provide visibility into potential risks, misconfigurations, and improvement areas.
<br><br>

## Mangament Report
Management report script creates a html file that give a more reprisentible summary of the audit with a overall security score
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
This script is designed to support informed decision-making and continuous improvement of Active Directory security.
<br><br>

# adaudit
This PowerShell script is designed to conduct a comprehensive audit of Microsoft Active Directory, focusing on identifying common security vulnerabilities and weaknesses. Its execution facilitates the pinpointing of critical areas that require reinforcement, thereby fortifying your infrastructure against prevalent tactics used in lateral movement or privilege escalation attacks targeting Active Directory.
```
_____ ____     _____       _ _ _
|  _  |    \   |  _  |_ _ _| |_| |_
|     |  |  |  |     | | | . | |  _|
|__|__|____/   |__|__|___|___|_|_|
                 by phillips321
```

If you have any decent powershell one liners that could be used in the script please let me know. I'm trying to keep this script as a single file with no requirements on external tools (other than ntdsutil and cmd.exe)

Run directly on a DC using a DA. If you don't trust the code I suggest reading it first and you'll see it's all harmless! (But shouldn't you be doing that anyway with code you download off the net and then run as DA??)

## What this does
* Device Information
  * Get-HostDetails
* Domain Audit
  * Get-LastWUDate
  * Get-DCEval
  * Get-TimeSource
  * Get-PrivilegedGroupMembership
  * Get-MachineAccountQuota
  * Get-DefaultDomainControllersPolicy
  * Get-SMB1Support
  * Get-FunctionalLevel
  * Get-DCsNotOwnedByDA
  * Get-ReplicationType
  * Get-RecycleBinState
  * Get-CriticalServicesStatus
  * Get-RODC
* Domain Trust Audit
  * Get-DomainTrusts
* User Accounts Audit
  * Get-InactiveAccounts
  * Get-DisabledAccounts
  * Get-LockedAccounts
  * Get-AdminAccountChecks
  * Get-NULLSessions
  * Get-PrivilegedGroupAccounts
  * Get-ProtectedUsers
* Password Information Audit
  * Get-AccountPassDontExpire
  * Get-UserPasswordNotChangedRecently
  * Get-PasswordPolicy
  * Get-PasswordQuality
* Dumps NTDS.dit
  * Get-NTDSdit
* Computer Objects Audit
  * Get-OldBoxes
* GPO audit (and checking SYSVOL for passwords)
  * Get-GPOtoFile
  * Get-GPOsPerOU
  * Get-SYSVOLXMLS
  * Get-GPOEnum
* Check Generic Group AD Permissions
  * Get-OUPerms
* Check For Existence of LAPS in domain
  * Get-LAPSStatus
* Check For Existence of Authentication Polices and Silos
  * Get-AuthenticationPoliciesAndSilos
* Check for insecure DNS zones
  * Get-DNSZoneInsecure
* Check for newly created users and groups
  * Get-RecentChanges
* Check for ADCS vulnerabilties, ESC1,2,3,4 and 8. 
* Check for high value kerberoastable accounts 
* Check for ASREPRoastable accounts
* Check for dangerous ACL permissions on Users, Groups and Computers. 
* Check LDAP and LDAPs settings (Signing, null sessions etc )

## Runtime Args
The following switches can be used in combination
* `-installdeps` installs optional features (DSInternals)
* `-hostdetails` retrieves hostname and other useful audit info
* `-domainaudit` retrieves information about the AD such as functional level
* `-trusts` retrieves information about any domain trusts
* `-accounts` identifies account issues such as expired, disabled, etc...
* `-passwordpolicy` retrieves password policy information
* `-ntds` dumps the NTDS.dit file using `ntdsutil`
* `-oldboxes` identified outdated OSs like XP/2003 joined to the domain
* `-gpo` dumps the GPOs in XML and HTML for later analysis
* `-ouperms` checks generic OU permission issues
* `-laps` checks if LAPS is installed
* `-authpolsilos` checks for existence of authentication policies and silos
* `-insecurednszone` checks for insecure DNS zones
* `-recentchanges` checks for newly created users and groups (last 30 days)
* `-adcs` checks for ADCS vulnerabilties, ESC1,2,3,4 and 8.
* `-acl` checks for dangerous ACL permissions on Users, Groups and Computers. 
* `-spn` checks for high value kerberoastable accounts 
* `-asrep` checks for ASREPRoastable accounts
* `-ldapsecurity` checks for multiple LDAP issues
* `-exclude` allows you to exclude specific checks when using `adaudit.ps1 -all -exclude ouperms,ntds,adcs"`
* `-select` allows you to exclude specific checks when using `adaudit.ps1 -all "gpo,ntds,acl"`
* `-all` runs all checks, e.g. `AdAudit.ps1 -all`
