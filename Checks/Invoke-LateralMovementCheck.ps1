<#
    .SYNOPSIS
        Lateral movement analysis of Active Directory group nesting (member / memberOf).

    .DESCRIPTION
        Builds the complete membership graph of the domain (users, computers, service
        accounts, groups, foreign security principals) and evaluates it the way an
        attacker - and a careful AD administrator - reads it: along memberOf.

        "I am memberOf X" means "I inherit the rights of X". Every edge where a group is a
        member of another group is a privilege path that nobody reviews, because ADUC only
        shows one step at a time. The script follows those edges transitively, classifies
        every group and account, and reports:

          - every nesting path that ends in a Tier 0 / privileged built-in group
            (Domain Admins, Administrators, Backup/Account/Server Operators, DnsAdmins, ...)
          - every account that becomes Tier 0 through a chain without being a visible member
          - AGDLP violations: role group in role group, resource group in resource group,
            users directly in resource groups, groups that are both role and resource
          - broad groups ("all employees") used as building blocks for access
          - circular nesting, deep chains, dormant (empty) privileged paths
          - hidden membership through primaryGroupID
          - computers, gMSAs, foreign/cross-domain principals inside privileged groups
          - Tier 0 account hygiene (SPN, pre-auth, password age, Protected Users, stale,
            daily-use looking accounts, memberships outside Tier 0)
          - stale / temporary groups that still grant access
          - optional baseline diff: which group-to-group edges are new since the last run

        Every finding carries severity (Critical / High / Medium / Low / Information), an
        explanation of why it matters and what to do about it. Results are written as
        CSV/TXT evidence plus an interactive HTML map (Lateral-Movement.html) where groups
        and users can be filtered and followed hop by hop.

        Runs standalone, from AdAudit-PS7.ps1 (-lateralmovement, or -all) and from the GUI.
        When dot-sourced by AdAudit-PS7.ps1 it reuses the runner's logging, not-assessed
        tracking, Nessus export and report styling (Library\ADAudit.Common.ps1). Standalone
        it needs only the ActiveDirectory module (RSAT). Unlike the other Checks\ files it
        is self-contained with its own parameters, so the runner dot-sources it at run time
        with the arguments it needs instead of loading it at startup.

        What this check can NOT see (use BloodHound / Delegated-permissions report for that):
        local Administrators groups on member servers, GPO Restricted Groups / Group
        Policy Preferences, ACLs on servers, SQL logins, share permissions. The script
        therefore reasons about group NAMES (admin, rdp, localadmin, ...) and SCOPE
        (Global = role, Domain Local = resource) to estimate what a chain gives access to.
        Validate the estimate against the systems the groups are used on.

    .PARAMETER OutputRoot
        Base output folder. Evidence goes to <OutputRoot>\Raw Data\Source\LateralMovement
        and the HTML map to <OutputRoot>\HTML Reports\Lateral-Movement.html (same layout as
        AdAudit-PS7.ps1). Default: .\<COMPUTERNAME>

    .PARAMETER Server
        Domain controller / ADWS endpoint to query. Default: automatic.

    .PARAMETER SearchBase
        Restrict USER / COMPUTER enumeration to this OU subtree. Groups are always loaded
        domain-wide because a group inside the OU can be nested into a group outside it.

    .PARAMETER BaselinePath
        A lateral_movement_edges.csv from a previous run. Every group-to-group edge that is
        new or removed since that baseline is reported (LM19). Keep the newest
        lateral_movement_edges.csv as the next baseline.

    .PARAMETER Tier0Groups
        Additional groups (sAMAccountName, name, SID or DN) that must be treated as Tier 0
        in this environment, e.g. PAM groups, 'AD-Admins', backup-infrastructure groups.

    .PARAMETER Tier1Groups / Tier2Groups
        Groups that are explicitly Tier 1 (servers) / Tier 2 (clients). Also detected by
        name tags (T0/T1/T2, Tier0/Tier1/Tier2) - see -TierTagPattern.

    .PARAMETER ApprovedNestings
        Group pairs 'Parent|Child' (sAMAccountNames) that are documented exceptions. They are
        still drawn on the map but produce no AGDLP / nesting findings.

    .PARAMETER AdminGroupPattern
        Regex that marks a group name as "admin-ish" (grants administrative access by name).
        Used to raise severity when such a group is reached through a chain.

    .PARAMETER AdminAccountPattern
        Regex that identifies dedicated admin / tiered accounts by sAMAccountName. Accounts
        that reach Tier 0 without matching it are reported as daily-use looking accounts.

    .PARAMETER TierTagPattern
        Regex template with {0} replaced by the tier digit, used to detect T0/T1/T2 tags in
        group and account names.

    .PARAMETER TemporaryGroupPattern
        Regex that marks a group as temporary / project / legacy by name or description.

    .PARAMETER BroadGroupPercent
        A group whose transitive members cover at least this percentage of enabled users is
        "broad" (an "all employees" group). Default 50.

    .PARAMETER StaleDays
        An enabled account without logon for this many days is stale. Default 90.

    .PARAMETER PasswordAgeDays
        Tier 0 account password older than this is reported. Default 365.

    .PARAMETER DeepNestingLevels
        Longest member chain below a group that counts as deep nesting. Default 5.

    .PARAMETER MaxDepth
        Maximum nesting depth followed when expanding closures. Default 30.

    .PARAMETER HtmlUserLimit
        Maximum number of user/computer nodes embedded in the HTML map (highest risk
        first). Groups are always embedded. Default 20000.

    .PARAMETER NoHtml
        Skip the HTML map.

    .PARAMETER PassThru
        Return the analysis result object (graph, findings, summary).

    .EXAMPLE
        .\Checks\Invoke-LateralMovementCheck.ps1
        Analyses the current domain, writes .\<COMPUTERNAME>\Raw Data\Source\LateralMovement\*
        and .\<COMPUTERNAME>\HTML Reports\Lateral-Movement.html

    .EXAMPLE
        .\Checks\Invoke-LateralMovementCheck.ps1 -OutputRoot D:\Audit\CORP -Tier0Groups 'PAM-T0-Admins','ADFS-Admins'

    .EXAMPLE
        .\Checks\Invoke-LateralMovementCheck.ps1 -BaselinePath .\baseline\lateral_movement_edges.csv
        Reports group-to-group edges added/removed since the baseline.

    .EXAMPLE
        .\AdAudit-PS7.ps1 -lateralmovement
        .\AdAudit-PS7.ps1 -all
        Runs the same analysis from the main audit (results feed ADAudit-Results.html and
        Risk-Report.html).

    .NOTES
        Author : Keberneth (AdAudit-PS7 companion)
        Version: 1.0 - 08/10/2026
        Requires PowerShell 7 and the ActiveDirectory module. Read-only - never modifies AD.

        Rule ids (LM01-LM23) are documented in the 'Rules & guidance' tab of the HTML map and
        in lateral_movement.txt. The reasoning follows the AGDLP model (Accounts -> Global
        role groups -> Domain Local resource groups -> Permissions) and the Microsoft
        tiering / Enterprise Access model.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot,
    [string]$Server,
    [string]$SearchBase,
    [string]$BaselinePath,
    [string[]]$Tier0Groups = @(),
    [string[]]$Tier1Groups = @(),
    [string[]]$Tier2Groups = @(),
    [string[]]$ApprovedNestings = @(),
    [string]$AdminGroupPattern = '(?i)(admin|(^|[^a-z])adm([^a-z]|$)|sysadmin|(^|[^a-z])root([^a-z]|$)|sudo|(^|[^a-z])rdp([^a-z]|$)|remote ?desktop|operator|(^|[^a-z])dba([^a-z]|$)|privileg|elevat|backup|(^|[^a-z])dcs?([^a-z]|$)|domain ?controller|(^|[^a-z])srv ?adm|local ?adm|enterprise|schema|(^|[^a-z])gpo([^a-z]|$)|group ?policy|sccm|mecm|vcenter|vsphere|hyper-?v|exchange|tier ?0|(^|[^a-z0-9])t0([^a-z0-9]|$)|infrastructure|security|service ?account|(^|[^a-z])svc([^a-z]|$)|sysop|superuser|power ?user)',
    [string]$AdminAccountPattern = '(?i)(^adm[-_.]|[-_.]adm$|^admin|[-_.]admin$|[-_.]a$|^a[-_.]|[-_.]t[0-2]$|^t[0-2][-_.]|tier[-_ ]?[0-2]|[-_.]da$|^da[-_.]|[-_.]ea$|[-_.]pa$|[-_.]priv$|[-_.]sa$|^sa[-_.]|^svc[-_.]|[-_.]svc$|[-_.]srv$|^srv[-_.]|^sys[-_.]|[-_.]sys$|^brk|break ?glass|emergency|^pam[-_.]|[-_.]pam$|^msol_|^aad_|\$$)',
    [string]$TierTagPattern = '(?i)(^|[^a-z0-9])(t|tier)[-_ ]?{0}([^a-z0-9]|$)',
    [string]$TemporaryGroupPattern = '(?i)((^|[^a-z])temp([^a-z]|$)|(^|[^a-z])tmp([^a-z]|$)|tempor|tillf|(^|[^a-z])test([^a-z]|$)|(^|[^a-z])old([^a-z]|$)|migr|(^|[^a-z])proj|pilot|legacy|deprec|archiv|interim|(^|[^a-z])poc([^a-z]|$)|(^|[^0-9])(19|20)[0-9]{2}([^0-9]|$))',
    [ValidateRange(1,100)][int]$BroadGroupPercent = 50,
    [ValidateRange(1,3650)][int]$StaleDays = 90,
    [ValidateRange(1,3650)][int]$PasswordAgeDays = 365,
    [ValidateRange(2,50)][int]$DeepNestingLevels = 4,
    [ValidateRange(2,100)][int]$MaxDepth = 30,
    [ValidateRange(0,1000000)][int]$HtmlUserLimit = 20000,
    [switch]$NoHtml,
    [switch]$PassThru
)

Set-StrictMode -Off
$lmPrevEap = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

#region ===================================================== Integration shims
# When dot-sourced by AdAudit-PS7.ps1 these helpers already exist and carry the main
# script's state (output folders, not-assessed list, Nessus file, report CSS). Standalone
# they are replaced by minimal local equivalents, so the file never depends on the main
# script being present.
$script:LmIntegrated   = [bool](Get-Command -Name 'Register-ADAuditNotAssessed' -ErrorAction SilentlyContinue) -and
                         [bool](Get-Command -Name 'Write-Both' -ErrorAction SilentlyContinue)
$script:LmNotAssessed  = New-Object System.Collections.Generic.List[object]
$script:LmVersion      = '1.0'

function Write-LmLog {
    param([string]$Message)
    if (Get-Command -Name 'Write-Both' -ErrorAction SilentlyContinue) { Write-Both $Message } else { Write-Host $Message }
}

function Register-LmNotAssessed {
    # Never turn a failed query into a clean verdict: record reduced coverage instead.
    param([Parameter(Mandatory)][string]$Reason, [string]$Target)
    $script:LmNotAssessed.Add([pscustomobject]@{ Reason = $Reason; Target = $Target }) | Out-Null
    if (Get-Command -Name 'Register-ADAuditNotAssessed' -ErrorAction SilentlyContinue) {
        try { Register-ADAuditNotAssessed -Name 'LateralMovement' -Switch 'lateralmovement' -Reason $Reason -Target $Target } catch { }
    } else {
        $tgt = if ($Target) { " [$Target]" } else { '' }
        Write-LmLog "    [~] NOT ASSESSED (LateralMovement$tgt): $Reason"
    }
}

function Write-LmNessusFinding {
    param([string]$Name, [string]$Kb, [string]$Text, [string]$Severity)
    if (Get-Command -Name 'Write-Nessus-Finding' -ErrorAction SilentlyContinue) {
        try { Write-Nessus-Finding $Name $Kb $Text $Severity } catch { }
    }
}

function Get-LmHtmlEncoded {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Get-LmReportHeader {
    param([string]$Title)
    if (Get-Command -Name 'Get-ADAuditReportHeader' -ErrorAction SilentlyContinue) {
        try { return (Get-ADAuditReportHeader -Title $Title) } catch { }
    }
    return $null
}

function Get-LmPrimaryNav {
    if (Get-Command -Name 'Get-ADAuditPrimaryNav' -ErrorAction SilentlyContinue) {
        try { return (Get-ADAuditPrimaryNav -Active 'lateral') } catch { }
        try { return (Get-ADAuditPrimaryNav -Active 'none') } catch { }
    }
    return ''
}
#endregion

#region ===================================================== Catalogs
# Well-known groups. RID-based entries are resolved against the domain SID (or forest root
# SID for the forest-level groups), BUILTIN entries against S-1-5-32-<rid>. Name entries
# cover groups without a fixed RID (DnsAdmins, Exchange). Tier: 0 = classic Tier 0 (full
# control of AD / the forest: Domain/Enterprise/Schema Admins, Administrators, the three
# AdminSDHolder operator groups, Key Admins, DC accounts and the Exchange groups that hold
# rights on the domain), 'P' = privileged (rights on domain controllers or a Tier 0 service,
# but not AD control - reported on their own severity, never counted as "reaches Tier 0"),
# 'B' = broad (everyone), 'N' = neutral.
# Severity = severity of an unexpected principal reaching the group through nesting.
function Get-LmWellKnownCatalog {
    return @(
        @{ Key='DA';   Rid=512; Where='Domain';  Name='Domain Admins';            Tier=0;   Severity='Critical'; Tag='Full control of the domain and every domain-joined machine'; Why='Members are local administrators on every domain-joined computer and have full control of the directory. Anything nested here is Domain Admin, whether it looks like it or not.'; Fix='Keep only dedicated Tier 0 admin accounts as direct members. Remove every nested group; use PIM/PAM time-bound membership for the rest.' }
        @{ Key='EA';   Rid=519; Where='Root';    Name='Enterprise Admins';        Tier=0;   Severity='Critical'; Tag='Full control of the whole forest'; Why='Enterprise Admins control every domain in the forest, the configuration partition, sites, trusts and schema-adjacent settings.'; Fix='Should be empty except during forest-level changes. Add members just-in-time and remove them afterwards.' }
        @{ Key='SA';   Rid=518; Where='Root';    Name='Schema Admins';            Tier=0;   Severity='Critical'; Tag='Can modify the AD schema'; Why='Schema changes are forest-wide and irreversible; schema admin rights are also a known persistence technique.'; Fix='Keep empty; add a member only for the duration of a schema change.' }
        @{ Key='ADM';  Rid=544; Where='Builtin'; Name='Administrators';           Tier=0;   Severity='Critical'; Tag='Administrator on every domain controller'; Why='BUILTIN\Administrators in AD is the local Administrators group of every domain controller. It can take ownership of any object, reset any password and read NTDS.dit.'; Fix='Only Domain Admins, Enterprise Admins and the built-in Administrator belong here. Nested custom groups are a hidden Tier 0 path.' }
        @{ Key='AO';   Rid=548; Where='Builtin'; Name='Account Operators';        Tier=0;   Severity='Critical'; Tag='Can modify most users and groups - including adding itself to other groups'; Why='Account Operators can create and modify accounts and groups that are not protected by AdminSDHolder, and can log on to domain controllers. It is a privilege escalation path that needs no exploit, only Add-ADGroupMember.'; Fix='Keep empty. Delegate create-user / reset-password on specific OUs instead.' }
        @{ Key='SO';   Rid=549; Where='Builtin'; Name='Server Operators';         Tier=0;   Severity='Critical'; Tag='Can log on to DCs, control services, shut down and back up'; Why='Server Operators can log on locally to domain controllers, start/stop services and change service binaries - that is SYSTEM on a DC with one extra step.'; Fix='Keep empty. Use dedicated Tier 0 accounts for DC maintenance.' }
        @{ Key='BO';   Rid=551; Where='Builtin'; Name='Backup Operators';         Tier=0;   Severity='Critical'; Tag='Can read and write every file on DCs, including NTDS.dit, bypassing ACLs'; Why='SeBackupPrivilege/SeRestorePrivilege on domain controllers means every file is readable and writable regardless of its ACL. Dumping NTDS.dit and SYSTEM gives every password hash in the domain.'; Fix='Keep empty. Back up DCs with a dedicated Tier 0 service identity and treat the backup infrastructure as Tier 0.' }
        @{ Key='PO';   Rid=550; Where='Builtin'; Name='Print Operators';          Tier='P';   Severity='Medium';     Tag='Can load printer drivers (kernel code) on DCs and log on locally'; Why='Print Operators can log on to domain controllers and install printer drivers, which run as SYSTEM. Microsoft lists the group as Tier 0.'; Fix='Keep empty. DCs should not be print servers; manage printing from Tier 1 servers.' }
        @{ Key='REPL'; Rid=552; Where='Builtin'; Name='Replicator';               Tier='P';   Severity='Low';     Tag='Legacy file replication group'; Why='Legacy group for NT4 file replication. Nothing should be in it; membership indicates misuse or an attacker hiding privilege.'; Fix='Keep empty.' }
        @{ Key='GPCO'; Rid=520; Where='Domain';  Name='Group Policy Creator Owners'; Tier='P'; Severity='High';   Tag='Can create Group Policy Objects'; Why='Members can create GPOs. Combined with link rights (or a careless OU admin) a GPO runs code as SYSTEM on every targeted machine, including DCs.'; Fix='Keep empty; delegate GPO management to a dedicated Tier 0 group with change control.' }
        @{ Key='KA';   Rid=526; Where='Domain';  Name='Key Admins';               Tier=0;   Severity='Critical'; Tag='Can write msDS-KeyCredentialLink (shadow credentials) on any object'; Why='Key Admins can add key credentials to any user or computer, including domain controllers, and then authenticate as that object with a certificate - a direct takeover path.'; Fix='Keep empty unless Windows Hello for Business key trust is actively being administered; then use dedicated Tier 0 accounts.' }
        @{ Key='EKA';  Rid=527; Where='Root';    Name='Enterprise Key Admins';    Tier=0;   Severity='Critical'; Tag='Forest-wide shadow credential rights'; Why='Same as Key Admins but forest-wide.'; Fix='Keep empty.' }
        @{ Key='CP';   Rid=517; Where='Domain';  Name='Cert Publishers';          Tier='P';   Severity='Medium';     Tag='Can publish certificates to AD (userCertificate / NTAuth)'; Why='Cert Publishers can write certificates to user objects and the enterprise CA containers. With a rogue CA certificate an attacker can mint authentication certificates for any account.'; Fix='Only the certification authority computer accounts belong here.'; ExpectComputers=$true }
        @{ Key='DCS';  Rid=516; Where='Domain';  Name='Domain Controllers';       Tier=0;   Severity='Critical'; Tag='Domain controller computer accounts'; Why='Only DC computer accounts belong here. Any other principal gets DC-equivalent rights such as DCSync.'; Fix='Remove every non-DC member immediately and investigate.'; ExpectComputers=$true }
        @{ Key='RODC'; Rid=521; Where='Domain';  Name='Read-only Domain Controllers'; Tier=0; Severity='Critical'; Tag='RODC computer accounts'; Why='Only RODC computer accounts belong here.'; Fix='Remove every non-RODC member and investigate.'; ExpectComputers=$true }
        @{ Key='ERODC';Rid=498; Where='Root';    Name='Enterprise Read-only Domain Controllers'; Tier=0; Severity='Critical'; Tag='Forest RODC accounts'; Why='Only RODC computer accounts belong here.'; Fix='Remove every non-RODC member and investigate.'; ExpectComputers=$true }
        @{ Key='CDC';  Rid=522; Where='Domain';  Name='Cloneable Domain Controllers'; Tier='P'; Severity='Medium'; Tag='DCs allowed to be cloned'; Why='Members may be cloned as virtual DCs. Unexpected members indicate misuse of DC cloning.'; Fix='Only DC accounts that are intentionally cloneable.'; ExpectComputers=$true }
        @{ Key='IFTB'; Rid=557; Where='Builtin'; Name='Incoming Forest Trust Builders'; Tier='P'; Severity='High'; Tag='Can create incoming forest trusts'; Why='A trust is an authentication path. Members can create one-way incoming forest trusts and open the forest to a foreign forest.'; Fix='Keep empty; create trusts with Enterprise Admins under change control.' }
        @{ Key='DNSA'; Name='DnsAdmins';       Where='Name'; Tier='P'; Severity='High'; Tag='Historically code execution as SYSTEM on DCs through the DNS service'; Why='DnsAdmins could load an arbitrary DLL into the DNS service running on domain controllers (CVE-2021-40469). Microsoft hardened it, but the group still manages a Tier 0 service and should be treated as Tier 0.'; Fix='Use dedicated Tier 0 accounts for DNS administration or delegate rights on specific zones.' }
        @{ Key='DNSP'; Name='DnsUpdateProxy'; Where='Name'; Tier='P'; Severity='Low'; Tag='DHCP servers registering DNS records'; Why='Records created by members are unsecured and can be overwritten by anyone - a name-spoofing path when user accounts are members.'; Fix='Only DHCP server computer accounts belong here.'; ExpectComputers=$true }
        @{ Key='HVA';  Rid=578; Where='Builtin'; Name='Hyper-V Administrators';   Tier='P';   Severity='High';     Tag='Full control of Hyper-V on DCs / virtualization hosts'; Why='A Hyper-V administrator on a host that runs a domain controller can copy the DC virtual disk and read NTDS.dit offline. Virtualization hosts for DCs are Tier 0.'; Fix='Keep empty on DCs; manage virtualization with dedicated Tier 0 accounts.' }
        @{ Key='RDU';  Rid=555; Where='Builtin'; Name='Remote Desktop Users';     Tier='P';   Severity='Medium';     Tag='RDP logon right to domain controllers (only if the DC logon-rights policy allows it)'; Why='The BUILTIN group in AD applies to domain controllers only. By default it grants nothing on a DC (Allow log on through Remote Desktop Services is not assigned to it there); it matters when that right has been granted. It is not a Tier 0 group - RDP to member servers is governed by each server''s local group.'; Fix='Keep the AD BUILTIN group empty; RDP to member servers is granted through each server''s local group.' }
        @{ Key='RMU';  Rid=580; Where='Builtin'; Name='Remote Management Users';  Tier='P';   Severity='Medium';     Tag='WinRM / PowerShell remoting to domain controllers'; Why='Members may connect to the PowerShell remoting endpoint of domain controllers and run code there.'; Fix='Keep empty on DCs; use JEA endpoints with dedicated accounts instead.' }
        @{ Key='CO';   Rid=569; Where='Builtin'; Name='Cryptographic Operators';  Tier='P'; Severity='Medium';   Tag='Can perform cryptographic operations on DCs'; Why='Can manage IPsec / crypto configuration on domain controllers.'; Fix='Keep empty.' }
        @{ Key='DCOM'; Rid=562; Where='Builtin'; Name='Distributed COM Users';    Tier='P'; Severity='Medium';   Tag='Can launch / activate DCOM objects on DCs'; Why='DCOM activation rights on domain controllers are a lateral movement primitive (WMI/DCOM execution).'; Fix='Keep empty.' }
        @{ Key='NCO';  Rid=556; Where='Builtin'; Name='Network Configuration Operators'; Tier='P'; Severity='Medium'; Tag='Can change network settings on DCs'; Why='Changing DNS/IP settings of a domain controller enables traffic interception.'; Fix='Keep empty.' }
        @{ Key='PLU';  Rid=559; Where='Builtin'; Name='Performance Log Users';    Tier='P'; Severity='Medium';   Tag='Can schedule performance logging (code execution path) on DCs'; Why='Data collector sets run commands on completion; members have been used for privilege escalation on the host.'; Fix='Keep empty.' }
        @{ Key='PMU';  Rid=558; Where='Builtin'; Name='Performance Monitor Users'; Tier='P'; Severity='Low';     Tag='Can read performance counters on DCs'; Why='Read-only monitoring access to DCs; low risk but no business reason for standing membership.'; Fix='Use a monitoring service account with least privilege.' }
        @{ Key='ELR';  Rid=573; Where='Builtin'; Name='Event Log Readers';        Tier='P'; Severity='Low';      Tag='Can read all event logs on DCs'; Why='Security logs on DCs reveal every logon and can leak sensitive data; membership should be limited to the SIEM collector.'; Fix='Only the log collection service account.' }
        @{ Key='ACAO'; Rid=579; Where='Builtin'; Name='Access Control Assistance Operators'; Tier='P'; Severity='Low'; Tag='Can query effective access on DCs'; Why='Read-only ACL insight; reconnaissance value.'; Fix='Keep empty unless used by a help-desk tool.' }
        @{ Key='SRA';  Rid=582; Where='Builtin'; Name='Storage Replica Administrators'; Tier='P'; Severity='Medium'; Tag='Can manage storage replication on DCs'; Why='Replicating DC volumes elsewhere exposes NTDS.dit.'; Fix='Keep empty.' }
        @{ Key='PW2K'; Rid=554; Where='Builtin'; Name='Pre-Windows 2000 Compatible Access'; Tier='N'; Severity='High'; Tag='Grants read access to all user/group attributes'; Why='If Everyone or Anonymous Logon is a member, unauthenticated clients can enumerate the whole directory. Authenticated Users is the expected member.'; Fix='Remove Everyone / Anonymous Logon; keep Authenticated Users only if legacy systems still need it.' }
        @{ Key='WAAG'; Rid=560; Where='Builtin'; Name='Windows Authorization Access Group'; Tier='N'; Severity='Low'; Tag='Can read tokenGroupsGlobalAndUniversal'; Why='Lets applications read computed group membership; Enterprise Domain Controllers is the expected member.'; Fix='Only add application service accounts that are documented to need it.' }
        @{ Key='TSLS'; Rid=561; Where='Builtin'; Name='Terminal Server License Servers'; Tier='N'; Severity='Low'; Tag='RDS licensing servers'; Why='Members can update license-related user attributes.'; Fix='Only RDS license server computer accounts.'; ExpectComputers=$true }
        @{ Key='IIS';  Rid=568; Where='Builtin'; Name='IIS_IUSRS';                Tier='N'; Severity='Low';      Tag='IIS worker process identities'; Why='Only relevant if IIS runs on a DC, which it should not.'; Fix='No IIS on domain controllers.' }
        @{ Key='CSDA'; Rid=574; Where='Builtin'; Name='Certificate Service DCOM Access'; Tier='N'; Severity='Low'; Tag='Can connect to the CA over DCOM'; Why='Enrollment access to the CA; usually Authenticated Users / Domain Computers.'; Fix='Review when custom members appear.' }
        @{ Key='RDSRA';Rid=575; Where='Builtin'; Name='RDS Remote Access Servers'; Tier='N'; Severity='Low';     Tag='RDS gateway / web access servers'; Why='RDS role computer accounts.'; Fix='Computer accounts only.'; ExpectComputers=$true }
        @{ Key='RDSES';Rid=576; Where='Builtin'; Name='RDS Endpoint Servers';     Tier='N'; Severity='Low';      Tag='RDS session hosts'; Why='RDS role computer accounts.'; Fix='Computer accounts only.'; ExpectComputers=$true }
        @{ Key='RDSMS';Rid=577; Where='Builtin'; Name='RDS Management Servers';   Tier='N'; Severity='Low';      Tag='RDS brokers'; Why='RDS role computer accounts.'; Fix='Computer accounts only.'; ExpectComputers=$true }
        @{ Key='DO';   Rid=583; Where='Builtin'; Name='Device Owners';            Tier='N'; Severity='Low';      Tag='Reserved group'; Why='Reserved for future use; should be empty.'; Fix='Keep empty.' }
        @{ Key='SMAG'; Rid=581; Where='Builtin'; Name='System Managed Accounts Group'; Tier='N'; Severity='Information'; Tag='System managed accounts'; Why='Managed by the OS.'; Fix='-' }
        @{ Key='USERS';Rid=545; Where='Builtin'; Name='Users';                    Tier='B'; Severity='Information'; Tag='All users (contains Domain Users)'; Why='Broad group; nesting it into anything gives that access to everyone.'; Fix='-' }
        @{ Key='GUEST';Rid=546; Where='Builtin'; Name='Guests';                   Tier='N'; Severity='Low';      Tag='Guest accounts'; Why='Should only contain Domain Guests and the disabled Guest account.'; Fix='Remove other members.' }
        @{ Key='DU';   Rid=513; Where='Domain';  Name='Domain Users';             Tier='B'; Severity='Information'; Tag='Every user account (primary group)'; Why='Every user is a member through primaryGroupID, so it never appears in member lists. Nesting Domain Users into a group gives that group to everyone - including service and guest accounts.'; Fix='Never nest Domain Users into an access-granting group; use a maintained role group instead.' }
        @{ Key='DC';   Rid=515; Where='Domain';  Name='Domain Computers';         Tier='B'; Severity='Information'; Tag='Every workstation and member server'; Why='Broad group of all computer accounts.'; Fix='Do not nest into access-granting groups.' }
        @{ Key='DG';   Rid=514; Where='Domain';  Name='Domain Guests';            Tier='N'; Severity='Low';      Tag='Guest accounts'; Why='Should be empty apart from the disabled Guest account.'; Fix='Remove other members.' }
        @{ Key='PU';   Rid=525; Where='Domain';  Name='Protected Users';          Tier='N'; Severity='Information'; Tag='Protective group - hardens Kerberos for members (no NTLM, no delegation, no RC4, 4h TGT)'; Why='Membership is a control, not a privilege. Tier 0 human accounts should be in it.'; Fix='Add Tier 0 admin accounts (not service accounts, not the break-glass account).'; Protective=$true }
        @{ Key='RAS';  Rid=553; Where='Domain';  Name='RAS and IAS Servers';      Tier='N'; Severity='Low';      Tag='Can read dial-in properties of users'; Why='NPS/RAS server accounts; user members are unusual.'; Fix='Computer accounts of NPS/RAS servers only.'; ExpectComputers=$true }
        @{ Key='ARPG'; Rid=571; Where='Domain';  Name='Allowed RODC Password Replication Group'; Tier='N'; Severity='Medium'; Tag='Passwords of members are cached on RODCs'; Why='If a privileged account is allowed to replicate to an RODC, compromising the RODC compromises that account.'; Fix='Only accounts of the branch office that the RODC serves - never admin accounts.' }
        @{ Key='DRPG'; Rid=572; Where='Domain';  Name='Denied RODC Password Replication Group'; Tier='N'; Severity='Information'; Tag='Passwords of members are never cached on RODCs'; Why='Protective group; the privileged built-in groups are members by default.'; Fix='-'; Protective=$true }
        @{ Key='EXOM'; Name='Organization Management';     Where='Name'; Tier=0; Severity='High'; Tag='Exchange: full Exchange control, historically WriteDACL on the domain'; Why='Exchange Organization Management members control the Exchange Trusted Subsystem, which in older installations holds dangerous rights on the domain object (the PrivExchange / WriteDACL path).'; Fix='Treat as Tier 0; use dedicated admin accounts; apply the Exchange split-permissions / AD-permission hardening.' }
        @{ Key='EXTS'; Name='Exchange Trusted Subsystem';  Where='Name'; Tier=0; Severity='High'; Tag='Exchange server rights in AD'; Why='Exchange server computer accounts act through this group; it has extensive rights on users and historically on the domain.'; Fix='Only Exchange server computer accounts.'; ExpectComputers=$true }
        @{ Key='EXWP'; Name='Exchange Windows Permissions'; Where='Name'; Tier=0; Severity='High'; Tag='Exchange rights on Active Directory objects'; Why='Holds WriteDACL-class rights on the domain in shared-permissions deployments.'; Fix='Only the Exchange Trusted Subsystem group.' }
        @{ Key='EXSV'; Name='Exchange Servers';            Where='Name'; Tier='P'; Severity='Medium'; Tag='Exchange server computer accounts'; Why='Computer accounts of Exchange servers; a user member gets server-level Exchange rights.'; Fix='Computer accounts only.'; ExpectComputers=$true }
    )
}

# Rule catalog: what is checked, why it matters, how to fix. The HTML map renders this
# as the 'Rules & guidance' tab; the TXT evidence carries the same text.
function Get-LmRuleCatalog {
    return [ordered]@{
        'LM01' = @{ Title='Nesting path into a Tier 0 / privileged built-in group'; Default='Critical'
                    What='A group that is not itself a well-known or declared Tier 0 group is (directly or through other groups) a member of a Tier 0 / privileged built-in group. Everyone who is or will be put into that group inherits the privilege, and nobody who reviews the privileged group sees them.'
                    Why='This is the mechanism behind most "we did not know helpdesk was Domain Admin" incidents. Each edge looked reasonable when it was added; the chain is only visible when you follow memberOf transitively. The token of every user in the chain contains the Tier 0 SID exactly as if they were a direct member.'
                    Fix='Remove the edge that closes the chain (the group nested in the Tier 0 group). If a team really needs a Tier 0 right, give it through a dedicated, named Tier 0 group with direct members and time-bound membership (PAM/PIM), never through a role or resource group that exists for another purpose. Afterwards compare lateral_movement_edges.csv against a baseline on a schedule.' }
        'LM02' = @{ Title='Account reaches Tier 0 through group nesting'; Default='Critical'
                    What='A user, computer or service account is effectively Tier 0: its transitive group membership contains a Tier 0 group. Severity depends on how it gets there (visible direct membership vs. hidden chain), whether the account looks like a dedicated admin account, and its hygiene.'
                    Why='Attackers do not need to compromise a Domain Admin - they need any account whose token contains a Tier 0 SID. "whoami /groups" on a compromised client lists the whole transitive set directly; your access reviews usually show only the direct members.'
                    Fix='For every listed account decide: is this person supposed to be Tier 0? If yes, give them a dedicated Tier 0 account (-t0 / adm- naming), add it to Protected Users, mark it sensitive, and remove the hidden path. If no, remove the edge in the chain that grants it (see LM01).' }
        'LM03' = @{ Title='Non-user principal inside a Tier 0 / privileged group'; Default='Critical'
                    What='A computer account, gMSA/MSA, foreign security principal (Everyone, Authenticated Users, cross-domain SID), contact or unresolved object is a transitive member of a privileged group where it is not expected.'
                    Why='A computer account in Domain Admins means anyone who is SYSTEM on that machine is Domain Admin. A service account there is Kerberoastable Tier 0. Everyone / Authenticated Users makes the privilege public. Cross-domain principals move the trust boundary to a domain you cannot audit.'
                    Fix='Remove the principal. Grant the service the specific delegated right it needs (gMSA with least privilege), or move the workload to a Tier 0 host managed as such.' }
        'LM04' = @{ Title='Hidden membership through primaryGroupID'; Default='Critical'
                    What='The primary group of an account is not the default (Domain Users / Domain Computers). Primary group membership is NOT stored in the member attribute of the group, so Get-ADGroupMember, ADUC and most access reviews do not show it.'
                    Why='Setting primaryGroupID to 512 (Domain Admins) is a documented persistence technique: the account is Domain Admin and the group looks unchanged.'
                    Fix='Set-ADUser <account> -Replace @{primaryGroupID=513} after adding the account to Domain Users, then investigate who changed it (event 4738 / 5136).' }
        'LM05' = @{ Title='Circular group nesting'; Default='Medium'
                    What='Groups that are members of each other, directly or through a longer loop (A in B, B in C, C in A). AD blocks the simplest cases but a loop that crosses scopes or three or more hops is often accepted.'
                    Why='When two groups are in a loop they are functionally one group: every member of either has the union of all rights. The direction that made the model readable is gone. The same effect appears without a loop when chains are long enough - see LM12.'
                    Fix='Break the loop by removing the edge that was added last (compare with the baseline). Re-model as role group -> resource group with a single direction.' }
        'LM06' = @{ Title='Broad group used as a building block for access'; Default='Medium'
                    What='A group that contains (almost) everyone - by transitive member count, or because Domain Users, Domain Computers, Authenticated Users, Everyone or Users is a member - is itself nested into another group.'
                    Why='Someone needed "everyone" to reach one thing and used the all-employees group. The parent group now grants its access to every account in the domain, including consultants, service accounts and guests, and the broad group looks harmless because its member list is just "everyone". The error is in its memberOf.'
                    Fix='Remove the broad group from the parent. If everyone really needs the access, grant it in the application (read right), not through an administrative or resource group. Never nest Domain Users / Authenticated Users into access-granting groups.' }
        'LM07' = @{ Title='Role group nested in role group (Global in Global)'; Default='Low'
                    What='A Global (or Universal) group is a member of another Global/Universal group. In AGDLP a role group describes WHO someone is and should only contain users; role-in-role creates identity inheritance.'
                    Why='Every member of the inner group silently inherits every current and future membership of the outer group. Reviewing the outer group shows its direct members only - the real population is larger and nobody approved it.'
                    Fix='Remove the edge. If the inner role needs a specific access the outer role has, add the inner role group to that specific resource group instead. Document deliberate aggregation groups and exclude them with -ApprovedNestings.' }
        'LM08' = @{ Title='Resource group nested in resource group (Domain Local in Domain Local)'; Default='Medium'
                    What='A Domain Local group is a member of another Domain Local group. AD allows it without warning. A resource group stands in an ACL; nesting resource groups makes the effective population of the ACL deeper than the ACL shows.'
                    Why='"Everyone with RDP to the jump host is now local admin on APP-02" is the classic result. The ACL on APP-02 mentions one group; the real set is two groups deep, and the next nesting makes it three.'
                    Fix='Remove the edge and add the role group that really needs the access directly to the target resource group. Resource groups should contain role groups only.' }
        'LM09' = @{ Title='User account directly in a resource (Domain Local) group'; Default='Low'
                    What='A user is a direct member of a Domain Local group instead of getting the access through a role group.'
                    Why='Direct membership bypasses the role layer. When the person changes role or leaves, no role changes, so no process removes the access; the account keeps it until someone happens to open that specific group.'
                    Fix='Move the user into the appropriate role group (or create one) and remove the direct membership. Alert automatically on user objects added directly to resource groups.' }
        'LM10' = @{ Title='Collection-point group (many groups converge here)'; Default='Low'
                    What='A group that contains several other groups and is itself nested onward, or is admin-ish by name. It behaves as both role and resource at the same time: several independent chains meet in it and continue together.'
                    Why='One edge into a collection point gives the member every right the collection point has. "Server-Admin"-style groups that are both member and memberOf of many things are where tiering collapses: whoever is nested in - directly or four hops away - is administrator everywhere the group is used.'
                    Fix='Split the group: one role group with people, one resource group per system/tier that stands in the ACL, one edge between them. A group is either role or resource - never both.' }
        'LM11' = @{ Title='Temporary / legacy group still granting access'; Default='Low'
                    What='A group whose name or description indicates a temporary purpose (temp, test, migration, project, a year) that still has members, is still nested into other groups, and has not been modified for a long time.'
                    Why='Incident and migration groups get a permanent edge and are forgotten. Years later everyone who was in the project is still local administrator on the migrated server.'
                    Fix='Verify with the owner whether the access is still needed; remove the group or its nesting. Put expiry dates in the process (expiring group membership / review date), not only in the name. Require an owner (managedBy) for every access-granting group.' }
        'LM12' = @{ Title='Deep nesting chain'; Default='Medium'
                    What='The longest chain of groups below this group reaches the configured depth. Effective rights can no longer be read in two steps (role -> resource).'
                    Why='A chain that is long enough has the same effect as a circle: nobody can see the direction any more. Each hop was added by a different person, for a different reason, in a different year.'
                    Fix='Flatten: users -> one role group -> one resource group. Remove intermediate aggregation groups or convert them to explicit role groups with direct user members.' }
        'LM13' = @{ Title='Tier boundary crossed'; Default='High'
                    What='A group or account that is explicitly tagged as Tier 1 (servers) or Tier 2 (clients) by name or parameter transitively reaches a higher tier (Tier 0 or Tier 1).'
                    Why='The tier model exists so that a compromised client (Tier 2 token in memory) cannot give server or AD control. A T2 group nested into a T1/T0 group collapses the model with one edge.'
                    Fix='Remove the crossing edge. Give the higher-tier access only to the dedicated higher-tier account (-t1 / -t0) of the same person.' }
        'LM14' = @{ Title='Tier 0 account with memberships outside Tier 0'; Default='High'
                    What='An account that reaches Tier 0 is also a member of groups that are not Tier 0 (resource / role / application groups beyond the default baseline). The same credential is used for daily work and for domain administration.'
                    Why='Every server, share, application and client the account touches with its non-Tier-0 memberships is a place where its Tier 0 credential can be stolen from memory. Microsoft tiering requires separate accounts per tier for exactly this reason.'
                    Fix='Create a separate standard account for daily work and strip the Tier 0 account down to Tier 0 groups only. Deny the Tier 0 account logon to Tier 1/2 systems via GPO (deny log on locally / through RDS / as batch / as service).' }
        'LM15' = @{ Title='Tier 0 account hygiene'; Default='Medium'
                    What='Hygiene problems on accounts that reach Tier 0: service principal names (Kerberoastable), Kerberos pre-authentication disabled (AS-REP roastable), password never expires, old password, not in Protected Users / not marked sensitive, stale (no logon), disabled but still member, or a name that does not look like a dedicated admin account.'
                    Why='Tier 0 accounts are the target. A Kerberoastable Tier 0 account can be cracked offline from any domain account; a Tier 0 account without Protected Users leaves NTLM hashes and unconstrained delegation open; a daily-use looking account suggests the person browses the web with Domain Admin rights.'
                    Fix='Remove SPNs from user accounts (use gMSA), enable pre-auth, rotate passwords, add human Tier 0 accounts to Protected Users and set "Account is sensitive and cannot be delegated", disable/remove stale and disabled members, and use dedicated admin accounts with a recognizable naming standard.' }
        'LM16' = @{ Title='Privileged built-in group has members'; Default='High'
                    What='Well-known privileged / operator groups that should be empty (or contain only specific computer accounts) have members. Severity follows the group catalog.'
                    Why='The operator groups (Account / Server / Backup / Print Operators), DnsAdmins, Key Admins and similar are Tier 0 in effect but rarely reviewed, which makes them the preferred place to hide privilege.'
                    Fix='Empty the group; delegate the specific task instead (OU delegation, JEA, dedicated Tier 0 accounts). Monitor membership changes (event 4728/4732/4756).' }
        'LM17' = @{ Title='Distribution group in a nesting chain'; Default='Information'
                    What='A distribution (non-security) group is nested into a security group or contains security groups.'
                    Why='Distribution groups are not in access tokens, so the nesting grants nothing - it only makes the chain look like access exists (or like it does not). Converting the group to a security group later silently activates the whole chain.'
                    Fix='Remove distribution groups from security group nesting; keep mail lists and access groups separate.' }
        'LM18' = @{ Title='Orphaned AdminSDHolder protection (adminCount=1)'; Default='Low'
                    What='The object has adminCount=1 but is no longer a member of any protected group. The restrictive AdminSDHolder ACL stays and inheritance remains disabled.'
                    Why='Orphaned adminCount objects break delegation (help desk cannot reset the password) and show that the object once was privileged - review why.'
                    Fix='Clear adminCount, re-enable inheritance on the object and verify its current rights: Set-ADObject <dn> -Clear adminCount; then enable inheritance in the object''s security tab.' }
        'LM19' = @{ Title='Group nesting drift since baseline'; Default='Medium'
                    What='Group-to-group edges that are new or removed compared with the baseline file (-BaselinePath).'
                    Why='Detecting new nesting edges is the single control that would have caught every chain in this report before it was exploited. A new edge into a Tier 0 group is an incident until proven otherwise.'
                    Fix='Review each new edge with the person who created it (event 4728/4756 on the DC). Keep lateral_movement_edges.csv of every approved state as the next baseline and alert on differences.' }
        'LM20' = @{ Title='Dormant privileged path (empty group nested into Tier 0)'; Default='Medium'
                    What='A group with no transitive user members is nested into a Tier 0 / privileged group.'
                    Why='The group grants nothing today, but any account added to it tomorrow is Tier 0 instantly - a pre-built escalation path that no one monitors because the group is "empty".'
                    Fix='Remove the empty group from the privileged group, or delete the group.' }
        'LM21' = @{ Title='Token bloat (very many transitive groups)'; Default='Low'
                    What='An account is a transitive member of a very large number of groups.'
                    Why='Beyond roughly 1,000 SIDs Kerberos tickets exceed MaxTokenSize and logons / group policy fail; it is also a sign that nobody understands what the account can reach.'
                    Fix='Clean up nested memberships; use resource groups per system instead of per permission; set MaxTokenSize only as a stop-gap.' }
        'LM22' = @{ Title='Group grants administrative access on many systems through nesting'; Default='High'
                    What='Through its memberOf chain the group is a transitive member of several administrative groups (local Administrators / sysadmin / RDP style resource groups, matched by name). Everyone who is put into this group is an administrator on every one of those systems, whatever the group''s own name suggests. Severity follows the number of administrative groups reached: 10 or more = Critical, 5 or more = High, 2 or more = Medium.'
                    Why='This is Tier 1 lateral movement in one edge: an account in an innocent-looking role group (a SQL sysadmin group for one server, a support group) is local administrator on dozens of servers because that group sits inside an aggregation group that sits inside every SRV-*-Administrators group. A single compromised member credential gives an attacker the whole server estate.'
                    Fix='Cut the chain: remove the group from the aggregation group that carries the administrative memberships (the first hop of the path shown), and add only the people who really administer those servers to a dedicated server-admin role group. Keep per-system admin groups flat (role group -> SRV-x-Administrators) and never nest a resource-style group into another one.' }
        'LM23' = @{ Title='Account is administrator on many systems'; Default='Medium'
                    What='An account whose transitive group membership contains several administrative groups (see LM22). The account can log on with administrative rights to every one of those systems.'
                    Why='The more systems one credential administers, the more places it can be stolen from and the bigger the blast radius when it is. A daily-use account (not a dedicated admin account) with admin on many servers combines browsing/mail exposure with server-wide impact.'
                    Fix='Give the person a dedicated admin account (-adm / -t1 naming) for server administration and remove the administrative memberships from the daily-use account. Scope admin groups per system or per application tier instead of one group for everything.' }
    }
}

$script:LmSeverityRank  = @{ 'Critical' = 5; 'High' = 4; 'Medium' = 3; 'Low' = 2; 'Information' = 1 }
$script:LmSeverityScore = @{ 'Critical' = 40; 'High' = 20; 'Medium' = 8; 'Low' = 3; 'Information' = 0 }
#endregion

#region ===================================================== Helpers
function Get-LmJsonString {
    # JSON string literal that is also safe inside an inline <script> block.
    param([string]$Value)
    if ($null -eq $Value) { return 'null' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $Value.ToCharArray()) {
        switch ([int]$ch) {
            34 { [void]$sb.Append('\"') }
            92 { [void]$sb.Append('\\') }
            8  { [void]$sb.Append('\b') }
            12 { [void]$sb.Append('\f') }
            10 { [void]$sb.Append('\n') }
            13 { [void]$sb.Append('\r') }
            9  { [void]$sb.Append('\t') }
            60 { [void]$sb.Append('<') }
            62 { [void]$sb.Append('>') }
            38 { [void]$sb.Append('&') }
            default {
                if ([int]$ch -lt 32 -or [int]$ch -eq 0x2028 -or [int]$ch -eq 0x2029) { [void]$sb.Append(('\u{0:x4}' -f [int]$ch)) }
                else { [void]$sb.Append($ch) }
            }
        }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Get-LmJsonValue {
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [int16] -or $Value -is [byte]) { return ([string]$Value) }
    if ($Value -is [datetime]) { return (Get-LmJsonString $Value.ToString('yyyy-MM-dd HH:mm')) }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = foreach ($k in $Value.Keys) { (Get-LmJsonString ([string]$k)) + ':' + (Get-LmJsonValue $Value[$k]) }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $parts = foreach ($v in $Value) { Get-LmJsonValue $v }
        return '[' + ($parts -join ',') + ']'
    }
    return (Get-LmJsonString ([string]$Value))
}

function ConvertFrom-LmFileTime {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        $v = [int64]$Value
        if ($v -le 0 -or $v -eq [int64]::MaxValue) { return $null }
        return [DateTime]::FromFileTimeUtc($v)
    } catch { return $null }
}

function Get-LmParentDn {
    param([string]$Dn)
    if ([string]::IsNullOrWhiteSpace($Dn)) { return '' }
    $idx = -1
    for ($i = 0; $i -lt $Dn.Length; $i++) {
        if ($Dn[$i] -eq '\') { $i++; continue }
        if ($Dn[$i] -eq ',') { $idx = $i; break }
    }
    if ($idx -lt 0) { return '' }
    return $Dn.Substring($idx + 1)
}

function Get-LmRdnValue {
    param([string]$Dn)
    if ([string]::IsNullOrWhiteSpace($Dn)) { return '' }
    $first = $Dn
    for ($i = 0; $i -lt $Dn.Length; $i++) {
        if ($Dn[$i] -eq '\') { $i++; continue }
        if ($Dn[$i] -eq ',') { $first = $Dn.Substring(0, $i); break }
    }
    $eq = $first.IndexOf('=')
    if ($eq -ge 0) { $first = $first.Substring($eq + 1) }
    return ($first -replace '\\(.)', '$1')
}

function Get-LmDnDomainSuffix {
    param([string]$Dn)
    $parts = @()
    foreach ($m in [regex]::Matches($Dn, '(?i)(?<=^|,)DC=([^,]+)')) { $parts += $m.Groups[1].Value }
    return ($parts -join '.')
}

$script:LmWellKnownSids = @{
    'S-1-1-0'   = @{ Name='Everyone';                     Broad=$true;  Severity='Critical' }
    'S-1-5-11'  = @{ Name='Authenticated Users';          Broad=$true;  Severity='Critical' }
    'S-1-5-7'   = @{ Name='Anonymous Logon';              Broad=$true;  Severity='Critical' }
    'S-1-5-4'   = @{ Name='Interactive';                  Broad=$true;  Severity='High' }
    'S-1-5-2'   = @{ Name='Network';                      Broad=$true;  Severity='High' }
    'S-1-5-9'   = @{ Name='Enterprise Domain Controllers'; Broad=$false; Severity='Information' }
    'S-1-5-17'  = @{ Name='IUSR';                         Broad=$false; Severity='Medium' }
    'S-1-5-18'  = @{ Name='SYSTEM';                       Broad=$false; Severity='Information' }
    'S-1-5-19'  = @{ Name='Local Service';                Broad=$false; Severity='Information' }
    'S-1-5-20'  = @{ Name='Network Service';              Broad=$false; Severity='Information' }
    'S-1-5-15'  = @{ Name='This Organization';            Broad=$true;  Severity='High' }
    'S-1-5-1000'= @{ Name='Other Organization';           Broad=$true;  Severity='High' }
    'S-1-5-14'  = @{ Name='Remote Interactive Logon';     Broad=$true;  Severity='High' }
    'S-1-5-6'   = @{ Name='Service';                      Broad=$true;  Severity='High' }
    'S-1-5-3'   = @{ Name='Batch';                        Broad=$true;  Severity='High' }
    'S-1-5-1'   = @{ Name='Dialup';                       Broad=$true;  Severity='Medium' }
    'S-1-5-113' = @{ Name='Local account';                Broad=$true;  Severity='High' }
    'S-1-5-114' = @{ Name='Local account and member of Administrators group'; Broad=$true; Severity='High' }
    'S-1-5-64-10' = @{ Name='NTLM Authentication';        Broad=$true;  Severity='High' }
    'S-1-5-64-14' = @{ Name='SChannel Authentication';    Broad=$true;  Severity='Medium' }
    'S-1-5-64-21' = @{ Name='Digest Authentication';      Broad=$true;  Severity='Medium' }
}

function New-LmNode {
    param([int]$Id, [string]$Dn, [string]$Type)
    return [pscustomobject]@{
        Id = $Id; Dn = $Dn; Type = $Type; Name = (Get-LmRdnValue $Dn); Sam = ''; Sid = ''; Rid = -1
        Class = ''; Enabled = $true; Scope = ''; Security = $true; Builtin = $false
        WellKnown = $null; WkKey = ''; WkTier = $null; DeclTier = $null; DeclTierSource = ''
        EffTier = $null; TierVia = ''; TierViaPath = ''
        Description = ''; Info = ''; WhenCreated = $null; WhenChanged = $null; ManagedBy = ''
        AdminCount = 0; PrimaryGroupId = 0; Uac = 0; HasSpn = $false; Spns = 0
        PwdLastSet = $null; LastLogon = $null; OS = ''; OU = (Get-LmParentDn $Dn); Domain = (Get-LmDnDomainSuffix $Dn)
        External = $false; IsRid500 = $false; IsKrbtgt = $false; Protective = $false
        Temporary = $false; AdminIsh = $false; AdminNamed = $false; Broad = $false; BroadReason = ''
        ExpectComputers = $false
        DirectUsers = 0; DirectGroups = 0; DirectComputers = 0; DirectOther = 0; DirectTotal = 0
        TransUsers = 0; TransEnabledUsers = 0; TransComputers = 0; TransGroupsUp = 0; ParentsCount = 0
        DistT0 = -1; NextHopT0 = -1; T0Targets = @(); PrivTargets = @(); Height = 0
        InCycle = $false; CycleId = -1; ReachesT0 = $false; T0Path = ''; T0Hops = -1
        ResourceReach = 0; AdminReach = 0; T0DirectMember = $false; InProtectedUsers = $false
        Findings = (New-Object System.Collections.Generic.List[object]); Score = 0; Severity = 'Information'
        RuleIds = ''
    }
}

function Get-LmScopeName {
    param($GroupType)
    if ($null -eq $GroupType) { return '' }
    $gt = [int64]$GroupType
    if ($gt -lt 0) { $gt += 4294967296 }
    if (($gt -band 0x2) -ne 0) { return 'Global' }
    if (($gt -band 0x4) -ne 0) { return 'DomainLocal' }
    if (($gt -band 0x8) -ne 0) { return 'Universal' }
    return 'Unknown'
}

function Test-LmSecurityGroup {
    param($GroupType)
    if ($null -eq $GroupType) { return $true }
    $gt = [int64]$GroupType
    if ($gt -lt 0) { $gt += 4294967296 }
    return (($gt -band 0x80000000) -ne 0)
}

function Add-LmListItem {
    # Adds to Dictionary[int, List[int]] creating the list on demand.
    param($Dict, [int]$Key, [int]$Value)
    $list = $null
    if (-not $Dict.TryGetValue($Key, [ref]$list)) {
        $list = New-Object System.Collections.Generic.List[int]
        $Dict[$Key] = $list
    }
    $list.Add($Value)
}
#endregion

#region ===================================================== Collection
function Get-LmDirectoryData {
    [CmdletBinding()]
    param(
        [string]$Server,
        [string]$SearchBase,
        [array]$Catalog,
        [string[]]$Tier0Groups,
        [string[]]$Tier1Groups,
        [string[]]$Tier2Groups,
        [string]$AdminGroupPattern,
        [string]$AdminAccountPattern,
        [string]$TierTagPattern,
        [string]$TemporaryGroupPattern
    )

    $ad = @{}
    if ($Server) { $ad['Server'] = $Server }

    $domain = Get-ADDomain @ad
    $domainSid = [string]$domain.DomainSID.Value
    $domainDn  = [string]$domain.DistinguishedName
    $domainDns = [string]$domain.DNSRoot
    $netbios   = [string]$domain.NetBIOSName
    $rootSid   = $domainSid
    $rootDns   = $domainDns
    $gcServer  = $null
    try {
        $forest  = Get-ADForest @ad
        $rootDns = [string]$forest.RootDomain
        if ($rootDns -and ($rootDns -ne $domainDns)) {
            $rootSid = [string](Get-ADDomain -Identity $rootDns -ErrorAction Stop).DomainSID.Value
        }
        $gcServer = "$($rootDns):3268"
    } catch {
        Register-LmNotAssessed -Reason "Forest root domain could not be queried ($($_.Exception.Message)); forest-level groups (Enterprise Admins, Schema Admins, Enterprise Key Admins) are matched against the current domain SID only." -Target $domainDns
    }

    $data = @{
        DomainDn = $domainDn; DomainDns = $domainDns; DomainSid = $domainSid; NetBios = $netbios; RootDns = $rootDns; RootSid = $rootSid
        Nodes = New-Object System.Collections.Generic.List[object]
        ByDn  = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::OrdinalIgnoreCase)
        BySid = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::OrdinalIgnoreCase)
        BySam = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::OrdinalIgnoreCase)
        Children = New-Object 'System.Collections.Generic.Dictionary[int,System.Collections.Generic.List[int]]'
        Parents  = New-Object 'System.Collections.Generic.Dictionary[int,System.Collections.Generic.List[int]]'
        Edges = New-Object System.Collections.Generic.List[object]
        GroupIds = New-Object System.Collections.Generic.List[int]
        PrincipalIds = New-Object System.Collections.Generic.List[int]
        Stats = @{ Groups = 0; Users = 0; Computers = 0; ServiceAccounts = 0; Fsp = 0; External = 0; Unresolved = 0; Edges = 0; PrimaryEdges = 0; Lookups = 0; EnabledUsers = 0 }
        Coverage = New-Object System.Collections.Generic.List[string]
    }
    $nodes = $data.Nodes

    $t0re = $TierTagPattern.Replace('{0}', '0')
    $t1re = $TierTagPattern.Replace('{0}', '1')
    $t2re = $TierTagPattern.Replace('{0}', '2')
    $paramTier = @{}
    foreach ($g in $Tier0Groups) { if ($g) { $paramTier[$g.Trim().ToLowerInvariant()] = 0 } }
    foreach ($g in $Tier1Groups) { if ($g) { $paramTier[$g.Trim().ToLowerInvariant()] = 1 } }
    foreach ($g in $Tier2Groups) { if ($g) { $paramTier[$g.Trim().ToLowerInvariant()] = 2 } }

    $catBySid  = @{}
    $catByName = @{}
    foreach ($c in $Catalog) {
        switch ($c.Where) {
            'Domain'  { $catBySid["$domainSid-$($c.Rid)"] = $c }
            'Root'    { $catBySid["$rootSid-$($c.Rid)"] = $c; if ($rootSid -ne $domainSid) { $catBySid["$domainSid-$($c.Rid)"] = $c } }
            'Builtin' { $catBySid["S-1-5-32-$($c.Rid)"] = $c }
            'Name'    { $catByName[$c.Name.ToLowerInvariant()] = $c }
        }
    }

    function Add-LmNodeToData {
        param($Node)
        $Node.Id = $nodes.Count
        $nodes.Add($Node)
        if ($Node.Dn -and -not $data.ByDn.ContainsKey($Node.Dn)) { $data.ByDn[$Node.Dn] = $Node.Id }
        if ($Node.Sid -and -not $data.BySid.ContainsKey($Node.Sid)) { $data.BySid[$Node.Sid] = $Node.Id }
        if ($Node.Sam -and -not $data.BySam.ContainsKey($Node.Sam)) { $data.BySam[$Node.Sam] = $Node.Id }
        return $Node
    }

    function Set-LmGroupClassification {
        param($Node)
        $wk = $null
        if ($Node.Sid -and $catBySid.ContainsKey($Node.Sid)) { $wk = $catBySid[$Node.Sid] }
        elseif ($Node.Sam -and $catByName.ContainsKey($Node.Sam.ToLowerInvariant())) { $wk = $catByName[$Node.Sam.ToLowerInvariant()] }
        if ($wk) {
            $Node.WellKnown = $wk.Name; $Node.WkKey = $wk.Key; $Node.WkTier = $wk.Tier
            $Node.ExpectComputers = [bool]$wk.ExpectComputers
            $Node.Protective = [bool]$wk.Protective
            if ($wk.Tier -eq 0) { $Node.DeclTier = 0; $Node.DeclTierSource = 'well-known' }
            if ($wk.Tier -eq 'B') { $Node.Broad = $true; $Node.BroadReason = 'well-known broad group' }
        }
        $keys = @($Node.Sam, $Node.Name, $Node.Sid, $Node.Dn) | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() }
        foreach ($k in $keys) {
            if ($paramTier.ContainsKey($k)) {
                $t = $paramTier[$k]
                if ($null -eq $Node.DeclTier -or $t -lt $Node.DeclTier) { $Node.DeclTier = $t; $Node.DeclTierSource = 'parameter' }
            }
        }
        if ($null -eq $Node.DeclTier -or $Node.DeclTierSource -eq '') {
            $nm = "$($Node.Sam) $($Node.Name)"
            if ($nm -match $t0re)     { $Node.DeclTier = 0; $Node.DeclTierSource = 'name tag' }
            elseif ($nm -match $t1re) { $Node.DeclTier = 1; $Node.DeclTierSource = 'name tag' }
            elseif ($nm -match $t2re) { $Node.DeclTier = 2; $Node.DeclTierSource = 'name tag' }
        }
        $Node.AdminIsh  = [bool]("$($Node.Sam) $($Node.Name)" -match $AdminGroupPattern)
        $Node.Temporary = [bool]("$($Node.Sam) $($Node.Name) $($Node.Description)" -match $TemporaryGroupPattern)
    }

    # ---- Groups (always domain-wide)
    Write-LmLog "    [*] Loading groups from $domainDns ..."
    $groupProps = @('sAMAccountName','name','objectSid','groupType','member','description','info','whenCreated','whenChanged','managedBy','adminCount','isCriticalSystemObject','mail')
    $rawMembers = New-Object 'System.Collections.Generic.Dictionary[int,object]'
    try {
        Get-ADObject -LDAPFilter '(objectCategory=group)' -SearchBase $domainDn -SearchScope Subtree -Properties $groupProps -ResultPageSize 2000 @ad | ForEach-Object {
            $g = $_
            $n = New-LmNode -Id 0 -Dn ([string]$g.DistinguishedName) -Type 'group'
            $n.Class = 'group'
            $n.Name = [string]$g.name
            $n.Sam  = [string]$g.sAMAccountName
            try { $n.Sid = [string]$g.objectSid.Value } catch { $n.Sid = [string]$g.objectSid }
            if ($n.Sid -match '-(\d+)$') { $n.Rid = [int]$matches[1] }
            $n.Scope = Get-LmScopeName $g.groupType
            $n.Security = Test-LmSecurityGroup $g.groupType
            $n.Builtin = ([bool]$g.isCriticalSystemObject) -or ($n.Dn -like '*,CN=Builtin,*')
            $n.Description = [string]$g.description
            $n.Info = [string]$g.info
            $n.WhenCreated = $g.whenCreated
            $n.WhenChanged = $g.whenChanged
            $n.ManagedBy = [string]$g.managedBy
            $n.AdminCount = [int]($(if ($g.adminCount) { $g.adminCount } else { 0 }))
            Set-LmGroupClassification -Node $n
            Add-LmNodeToData -Node $n | Out-Null
            $data.GroupIds.Add($n.Id)
            $rawMembers[$n.Id] = @($g.member)
        }
    } catch {
        throw "Group enumeration failed: $($_.Exception.Message)"
    }
    $data.Stats.Groups = $data.GroupIds.Count
    Write-LmLog "    [*] Groups loaded: $($data.Stats.Groups)"

    # ---- Users, computers, managed service accounts
    $principalBase = if ($SearchBase) { $SearchBase } else { $domainDn }
    Write-LmLog "    [*] Loading users, computers and service accounts from $principalBase ..."
    $principalProps = @('sAMAccountName','name','displayName','objectSid','userAccountControl','primaryGroupID','adminCount','servicePrincipalName','pwdLastSet','lastLogonTimestamp','description','whenCreated','whenChanged','objectClass','objectCategory','operatingSystem','title','department')
    $principalFilter = '(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer)(objectCategory=msDS-GroupManagedServiceAccount)(objectCategory=msDS-ManagedServiceAccount))'
    $now = Get-Date
    try {
        Get-ADObject -LDAPFilter $principalFilter -SearchBase $principalBase -SearchScope Subtree -Properties $principalProps -ResultPageSize 2000 @ad | ForEach-Object {
            $u = $_
            $cat = [string]$u.objectCategory
            $cls = [string]$u.objectClass
            $type = 'user'
            if ($cat -match '(?i)^CN=Computer,' -or $cls -ieq 'computer') { $type = 'computer' }
            elseif ($cat -match '(?i)msDS-GroupManagedServiceAccount' -or $cls -ieq 'msDS-GroupManagedServiceAccount') { $type = 'gmsa' }
            elseif ($cat -match '(?i)msDS-ManagedServiceAccount' -or $cls -ieq 'msDS-ManagedServiceAccount') { $type = 'msa' }
            $n = New-LmNode -Id 0 -Dn ([string]$u.DistinguishedName) -Type $type
            $n.Class = $cls
            $n.Name = if ($u.displayName) { [string]$u.displayName } else { [string]$u.name }
            $n.Sam  = [string]$u.sAMAccountName
            try { $n.Sid = [string]$u.objectSid.Value } catch { $n.Sid = [string]$u.objectSid }
            if ($n.Sid -match '-(\d+)$') { $n.Rid = [int]$matches[1] }
            $n.Uac = [int]($(if ($u.userAccountControl) { $u.userAccountControl } else { 0 }))
            $n.Enabled = (($n.Uac -band 2) -eq 0)
            $n.PrimaryGroupId = [int]($(if ($u.primaryGroupID) { $u.primaryGroupID } else { 0 }))
            $n.AdminCount = [int]($(if ($u.adminCount) { $u.adminCount } else { 0 }))
            $spns = @($u.servicePrincipalName)
            $n.Spns = $spns.Count
            $n.HasSpn = ($spns.Count -gt 0)
            $n.PwdLastSet = ConvertFrom-LmFileTime $u.pwdLastSet
            $n.LastLogon = ConvertFrom-LmFileTime $u.lastLogonTimestamp
            $n.Description = [string]$u.description
            $n.WhenCreated = $u.whenCreated
            $n.WhenChanged = $u.whenChanged
            $n.OS = [string]$u.operatingSystem
            $n.Info = (@([string]$u.title, [string]$u.department) | Where-Object { $_ }) -join ' / '
            $n.IsRid500 = ($n.Sid -eq "$domainSid-500")
            $n.IsKrbtgt = ($n.Sam -ieq 'krbtgt')
            $n.AdminNamed = [bool]($n.Sam -match $AdminAccountPattern) -or $n.IsRid500 -or ($type -ne 'user')
            if ($n.Sam -match $t0re)     { $n.DeclTier = 0; $n.DeclTierSource = 'name tag' }
            elseif ($n.Sam -match $t1re) { $n.DeclTier = 1; $n.DeclTierSource = 'name tag' }
            elseif ($n.Sam -match $t2re) { $n.DeclTier = 2; $n.DeclTierSource = 'name tag' }
            Add-LmNodeToData -Node $n | Out-Null
            $data.PrincipalIds.Add($n.Id)
            switch ($type) {
                'user'     { $data.Stats.Users++; if ($n.Enabled) { $data.Stats.EnabledUsers++ } }
                'computer' { $data.Stats.Computers++ }
                default    { $data.Stats.ServiceAccounts++ }
            }
        }
    } catch {
        throw "User/computer enumeration failed: $($_.Exception.Message)"
    }
    Write-LmLog "    [*] Principals loaded: $($data.Stats.Users) users ($($data.Stats.EnabledUsers) enabled), $($data.Stats.Computers) computers, $($data.Stats.ServiceAccounts) managed service accounts"
    if ($SearchBase) { $data.Coverage.Add("Users/computers limited to SearchBase '$SearchBase'; members outside it are resolved individually (capped) or shown as unresolved.") }

    # ---- Member resolution: foreign security principals, cross-domain and unloaded objects
    $lookupCap = 20000
    $resolveCache = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::OrdinalIgnoreCase)

    function Resolve-LmUnknownMember {
        param([string]$MemberDn)
        $id = -1
        if ($resolveCache.TryGetValue($MemberDn, [ref]$id)) { return $id }
        $n = $null
        if ($MemberDn -match '(?i),CN=ForeignSecurityPrincipals,') {
            $sid = Get-LmRdnValue $MemberDn
            $n = New-LmNode -Id 0 -Dn $MemberDn -Type 'fsp'
            $n.Sid = $sid; $n.Class = 'foreignSecurityPrincipal'; $n.External = $true; $n.Enabled = $true
            if ($script:LmWellKnownSids.ContainsKey($sid)) {
                $wk = $script:LmWellKnownSids[$sid]
                $n.Name = $wk.Name; $n.Sam = $wk.Name; $n.Broad = [bool]$wk.Broad
                if ($n.Broad) { $n.BroadReason = 'well-known identity (everyone / all authenticated users)' }
                $n.WellKnown = $wk.Name; $n.WkKey = 'SID'; $n.AdminNamed = $true
            } elseif ($sid -match '^S-1-5-21-') {
                $n.Name = $sid
                try {
                    $nt = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
                    if ($nt) { $n.Name = $nt; $n.Sam = $nt }
                } catch { $n.Sam = $sid }
                $n.Domain = 'trusted domain'
                $n.AdminNamed = $true
            } else {
                $n.Name = $sid; $n.Sam = $sid; $n.AdminNamed = $true
            }
            $data.Stats.Fsp++
        }
        else {
            $suffix = Get-LmDnDomainSuffix $MemberDn
            $isLocal = ($suffix -ieq $domainDns) -or ($MemberDn.EndsWith($domainDn, [System.StringComparison]::OrdinalIgnoreCase))
            $obj = $null
            if ($data.Stats.Lookups -lt $lookupCap) {
                $data.Stats.Lookups++
                try {
                    if ($isLocal) {
                        $obj = Get-ADObject -Identity $MemberDn -Properties objectClass,objectCategory,sAMAccountName,objectSid,userAccountControl,primaryGroupID,groupType,servicePrincipalName,adminCount,description,displayName,name -ErrorAction Stop @ad
                    } elseif ($gcServer) {
                        $obj = Get-ADObject -Identity $MemberDn -Server $gcServer -Properties objectClass,objectCategory,sAMAccountName,objectSid,userAccountControl,primaryGroupID,groupType,name,displayName -ErrorAction Stop
                    }
                } catch { $obj = $null }
            }
            if ($obj) {
                $cls = [string]$obj.objectClass
                $type = switch -Regex ($cls) {
                    '^group$' { 'group' }
                    '^computer$' { 'computer' }
                    'msDS-GroupManagedServiceAccount' { 'gmsa' }
                    'msDS-ManagedServiceAccount' { 'msa' }
                    '^user$' { 'user' }
                    '^contact$' { 'contact' }
                    default { 'other' }
                }
                $n = New-LmNode -Id 0 -Dn $MemberDn -Type $type
                $n.Class = $cls
                $n.Name = if ($obj.displayName) { [string]$obj.displayName } else { [string]$obj.name }
                $n.Sam = [string]$obj.sAMAccountName
                try { $n.Sid = [string]$obj.objectSid.Value } catch { $n.Sid = [string]$obj.objectSid }
                if ($n.Sid -match '-(\d+)$') { $n.Rid = [int]$matches[1] }
                $n.External = -not $isLocal
                if ($type -eq 'group') {
                    $n.Scope = Get-LmScopeName $obj.groupType; $n.Security = Test-LmSecurityGroup $obj.groupType
                    Set-LmGroupClassification -Node $n
                } else {
                    $n.Uac = [int]($(if ($obj.userAccountControl) { $obj.userAccountControl } else { 0 }))
                    $n.Enabled = (($n.Uac -band 2) -eq 0)
                    $n.PrimaryGroupId = [int]($(if ($obj.primaryGroupID) { $obj.primaryGroupID } else { 0 }))
                    $n.HasSpn = (@($obj.servicePrincipalName).Count -gt 0)
                    $n.AdminNamed = [bool]($n.Sam -match $AdminAccountPattern) -or ($type -ne 'user')
                }
                if ($n.External) { $data.Stats.External++ }
            } else {
                $n = New-LmNode -Id 0 -Dn $MemberDn -Type $(if ($isLocal) { 'unknown' } else { 'external' })
                $n.Sam = $n.Name; $n.External = -not $isLocal; $n.AdminNamed = $true
                if ($isLocal) { $data.Stats.Unresolved++ } else { $data.Stats.External++ }
            }
        }
        Add-LmNodeToData -Node $n | Out-Null
        if ($n.Type -eq 'group') { $data.GroupIds.Add($n.Id) } else { $data.PrincipalIds.Add($n.Id) }
        $resolveCache[$MemberDn] = $n.Id
        return $n.Id
    }

    Write-LmLog "    [*] Building membership graph ..."
    foreach ($gid in @($data.GroupIds)) {
        $members = $null
        if (-not $rawMembers.TryGetValue($gid, [ref]$members)) { continue }
        $gnode = $nodes[$gid]
        foreach ($mdn in $members) {
            if ([string]::IsNullOrWhiteSpace($mdn)) { continue }
            $cid = -1
            if (-not $data.ByDn.TryGetValue($mdn, [ref]$cid)) { $cid = Resolve-LmUnknownMember -MemberDn $mdn }
            if ($cid -lt 0) { continue }
            Add-LmListItem -Dict $data.Children -Key $gid -Value $cid
            Add-LmListItem -Dict $data.Parents  -Key $cid -Value $gid
            $cnode = $nodes[$cid]
            switch ($cnode.Type) {
                'group'    { $gnode.DirectGroups++ }
                'user'     { $gnode.DirectUsers++ }
                'computer' { $gnode.DirectComputers++ }
                default    { $gnode.DirectOther++ }
            }
            $gnode.DirectTotal++
            $data.Edges.Add([pscustomobject]@{ P = $gid; C = $cid; Kind = 'member' })
        }
    }
    $rawMembers.Clear()
    $data.Stats.Edges = $data.Edges.Count

    # Primary group membership is not in 'member' - add it as its own edge kind.
    foreach ($prId in @($data.PrincipalIds)) {
        $p = $nodes[$prId]
        if ($p.PrimaryGroupId -le 0) { continue }
        $gid = -1
        if ($data.BySid.TryGetValue("$domainSid-$($p.PrimaryGroupId)", [ref]$gid)) {
            $existing = $null
            if ($data.Parents.TryGetValue($prId, [ref]$existing) -and $existing.Contains($gid)) { continue }
            Add-LmListItem -Dict $data.Children -Key $gid -Value $prId
            Add-LmListItem -Dict $data.Parents  -Key $prId -Value $gid
            $g = $nodes[$gid]
            if ($p.Type -eq 'user') { $g.DirectUsers++ } elseif ($p.Type -eq 'computer') { $g.DirectComputers++ } else { $g.DirectOther++ }
            $g.DirectTotal++
            $data.Edges.Add([pscustomobject]@{ P = $gid; C = $prId; Kind = 'primary' })
            $data.Stats.PrimaryEdges++
        }
    }
    foreach ($n in $nodes) {
        $pl = $null
        if ($data.Parents.TryGetValue($n.Id, [ref]$pl)) { $n.ParentsCount = $pl.Count }
    }
    if ($data.Stats.Lookups -ge $lookupCap) {
        Register-LmNotAssessed -Reason "More than $lookupCap member objects had to be resolved individually; the remaining ones are shown as 'unknown' nodes." -Target $domainDns
    }
    Write-LmLog "    [*] Graph: $($nodes.Count) nodes, $($data.Edges.Count) edges ($($data.Stats.PrimaryEdges) via primaryGroupID), $($data.Stats.Fsp) foreign security principals, $($data.Stats.External) cross-domain, $($data.Stats.Unresolved) unresolved"
    return $data
}
#endregion

#region ===================================================== Graph analysis
function Get-LmChainSinkRank {
    # Severity rank (5 = Critical) of the sink that the shortest-path chain from StartId ends in.
    param($Nodes, [int]$StartId, $SinkRank)
    $cur = $StartId; $guard = 0
    while ($cur -ge 0 -and $guard -lt 64) {
        if ($Nodes[$cur].DistT0 -eq 0) { if ($SinkRank.ContainsKey($cur)) { return $SinkRank[$cur] } else { return 0 } }
        $cur = $Nodes[$cur].NextHopT0; $guard++
    }
    return 0
}

function Invoke-LmGraphAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Data,
        [int]$MaxDepth = 30,
        [int]$BroadGroupPercent = 50
    )
    $nodes = $Data.Nodes
    $children = $Data.Children
    $parents = $Data.Parents
    $groupIds = $Data.GroupIds

    # ---- Up-closure per group: every (security) group the group is transitively a member of.
    Write-LmLog "    [*] Computing transitive membership (memberOf closure) for $($groupIds.Count) groups ..."
    $upClosure = New-Object 'System.Collections.Generic.Dictionary[int,System.Collections.Generic.HashSet[int]]'
    $queue = New-Object System.Collections.Generic.Queue[int]
    foreach ($gid in $groupIds) {
        $set = New-Object System.Collections.Generic.HashSet[int]
        $queue.Clear()
        $queue.Enqueue($gid)
        $depthOf = @{ $gid = 0 }
        while ($queue.Count -gt 0) {
            $cur = $queue.Dequeue()
            $d = $depthOf[$cur]
            if ($d -ge $MaxDepth) { continue }
            $pl = $null
            if (-not $parents.TryGetValue($cur, [ref]$pl)) { continue }
            foreach ($p in $pl) {
                $pn = $nodes[$p]
                if ($pn.Type -ne 'group') { continue }
                if (-not $pn.Security) { continue }      # distribution groups carry no token - stop here
                if ($set.Add($p)) {
                    $depthOf[$p] = $d + 1
                    $queue.Enqueue($p)
                }
            }
        }
        $upClosure[$gid] = $set
        $nodes[$gid].TransGroupsUp = $set.Count
        if ($set.Contains($gid)) { $nodes[$gid].InCycle = $true }
    }
    $Data.UpClosure = $upClosure

    # ---- Cycles: group cycle ids
    $cycleId = 0
    foreach ($gid in $groupIds) {
        $n = $nodes[$gid]
        if (-not $n.InCycle -or $n.CycleId -ge 0) { continue }
        $cycleId++
        $n.CycleId = $cycleId
        foreach ($h in $upClosure[$gid]) {
            if ($h -eq $gid) { continue }
            $hn = $nodes[$h]
            if ($hn.InCycle -and $hn.CycleId -lt 0 -and $upClosure[$h].Contains($gid)) { $hn.CycleId = $cycleId }
        }
    }
    $Data.CycleCount = $cycleId

    # ---- Tier 0 / privileged sinks and shortest downward distance (multi-source BFS over members)
    $t0Ids = New-Object System.Collections.Generic.List[int]
    $privIds = New-Object System.Collections.Generic.List[int]
    foreach ($gid in $groupIds) {
        $n = $nodes[$gid]
        if ($n.DeclTier -eq 0 -or $n.WkTier -eq 0) { $t0Ids.Add($gid) }
        elseif ($n.WkTier -eq 'P') { $privIds.Add($gid) }
    }
    $Data.T0Ids = $t0Ids
    $Data.PrivIds = $privIds
    # Sinks are processed in severity order (Critical first): a group below both Backup
    # Operators and Remote Desktop Users gets its distance / shortest path towards the
    # Critical sink, which is what the report should lead with.
    $catSev = @{}
    foreach ($c in (Get-LmWellKnownCatalog)) { $catSev[$c.Key] = $c.Severity }
    $sinkRank = @{}
    foreach ($t in $t0Ids) {
        $tn = $nodes[$t]
        $sev = if ($tn.WellKnown -and $catSev.ContainsKey($tn.WkKey)) { $catSev[$tn.WkKey] } else { 'High' }
        $sinkRank[$t] = $script:LmSeverityRank[$sev]
    }
    foreach ($rank in @(5, 4, 3, 2, 1)) {
        $queue.Clear()
        foreach ($t in $t0Ids) { if ($sinkRank[$t] -eq $rank -and $nodes[$t].DistT0 -lt 0) { $nodes[$t].DistT0 = 0; $queue.Enqueue($t) } }
        while ($queue.Count -gt 0) {
            $cur = $queue.Dequeue()
            $cn = $nodes[$cur]
            $cl = $null
            if (-not $children.TryGetValue($cur, [ref]$cl)) { continue }
            foreach ($c in $cl) {
                $child = $nodes[$c]
                if ($child.Type -ne 'group') { continue }
                if (-not $child.Security) { continue }
                if ($child.DistT0 -ge 0) { continue }
                $child.DistT0 = $cn.DistT0 + 1
                $child.NextHopT0 = $cur
                $queue.Enqueue($c)
            }
        }
    }

    # ---- Effective tier, targets reached, resource/admin reach per group
    foreach ($gid in $groupIds) {
        $n = $nodes[$gid]
        $set = $upClosure[$gid]
        $effTier = $n.DeclTier
        $via = ''
        $t0t = New-Object System.Collections.Generic.List[int]
        $pvt = New-Object System.Collections.Generic.List[int]
        $res = 0; $adm = 0
        foreach ($h in $set) {
            $hn = $nodes[$h]
            if ($hn.DeclTier -eq 0 -or $hn.WkTier -eq 0) { $t0t.Add($h) }
            elseif ($hn.WkTier -eq 'P') { $pvt.Add($h) }
            if ($hn.Scope -eq 'DomainLocal' -and -not $hn.WellKnown) { $res++ }
            if ($hn.AdminIsh -and -not $hn.WellKnown) { $adm++ }
            if ($null -ne $hn.DeclTier) {
                if ($null -eq $effTier -or $hn.DeclTier -lt $effTier) { $effTier = $hn.DeclTier; $via = $hn.Name }
                elseif ($hn.DeclTier -eq $effTier -and -not $via -and $hn.Id -ne $gid) { $via = $hn.Name }
            }
        }
        if ($n.WkTier -eq 0 -and $null -eq $effTier) { $effTier = 0 }
        $n.EffTier = $effTier
        if ($effTier -eq 0 -and $n.DeclTier -ne 0) { $n.TierVia = $via }
        if ($n.DistT0 -gt 0) {
            # report the sink at the end of the (severity-preferred) shortest path, not an arbitrary closure member
            $cur = $gid; $guard = 0
            while ($cur -ge 0 -and $guard -lt 64) { if ($nodes[$cur].DistT0 -eq 0) { $n.TierVia = $nodes[$cur].Name; break }; $cur = $nodes[$cur].NextHopT0; $guard++ }
        }
        $n.T0Targets = $t0t.ToArray()
        $n.PrivTargets = $pvt.ToArray()
        $n.ResourceReach = $res
        $n.AdminReach = $adm
        $n.ReachesT0 = ($t0t.Count -gt 0)
        if ($n.ReachesT0 -and $n.DistT0 -gt 0) {
            $path = New-Object System.Collections.Generic.List[string]
            $cur = $gid; $guard = 0
            while ($cur -ge 0 -and $guard -lt 64) {
                $path.Add($nodes[$cur].Name)
                if ($nodes[$cur].DistT0 -eq 0) { break }
                $cur = $nodes[$cur].NextHopT0; $guard++
            }
            $n.T0Path = ($path -join ' -> ')
            $n.T0Hops = $n.DistT0
        } elseif ($n.DistT0 -eq 0) {
            $n.T0Path = $n.Name; $n.T0Hops = 0
        }
    }

    # ---- Height: longest chain of nested groups below each group (bounded relaxation)
    $groupChildEdges = New-Object System.Collections.Generic.List[int[]]
    foreach ($gid in $groupIds) {
        $cl = $null
        if (-not $children.TryGetValue($gid, [ref]$cl)) { continue }
        foreach ($c in $cl) { if ($nodes[$c].Type -eq 'group') { $groupChildEdges.Add(@($gid, $c)) } }
    }
    for ($iter = 0; $iter -lt $MaxDepth; $iter++) {
        $changed = $false
        foreach ($e in $groupChildEdges) {
            $p = $nodes[$e[0]]; $c = $nodes[$e[1]]
            if ($p.InCycle -or $c.InCycle) { continue }   # loops are reported by LM05; never let them inflate depth
            if ($c.Height + 1 -gt $p.Height) { $p.Height = $c.Height + 1; $changed = $true }
        }
        if (-not $changed) { break }
    }

    # ---- Principals: closure, counts per group, Tier 0 reach, hops and path
    Write-LmLog "    [*] Evaluating $($Data.PrincipalIds.Count) principals against the group graph ..."
    $protectedUsersId = -1
    foreach ($gid in $groupIds) { if ($nodes[$gid].WkKey -eq 'PU') { $protectedUsersId = $gid; break } }
    $userSet = New-Object System.Collections.Generic.HashSet[int]
    foreach ($prId in $Data.PrincipalIds) {
        $p = $nodes[$prId]
        $pl = $null
        if (-not $parents.TryGetValue($prId, [ref]$pl)) { $p.TransGroupsUp = 0; continue }
        $userSet.Clear()
        $bestDist = -1; $bestGroup = -1; $bestRank = -1
        $effTier = $p.DeclTier; $via = ''
        $directT0 = $false
        foreach ($g in $pl) {
            $gn = $nodes[$g]
            if ($gn.Type -ne 'group') { continue }
            if ($gn.DeclTier -eq 0 -or $gn.WkTier -eq 0) { $directT0 = $true }
            if ($gn.Security) {
                [void]$userSet.Add($g)
                $cs = $null
                if ($upClosure.TryGetValue($g, [ref]$cs)) { $userSet.UnionWith($cs) }
                if ($gn.DistT0 -ge 0) {
                    $gRank = Get-LmChainSinkRank -Nodes $nodes -StartId $g -SinkRank $sinkRank
                    if ($bestGroup -lt 0 -or $gRank -gt $bestRank -or ($gRank -eq $bestRank -and $gn.DistT0 -lt $bestDist)) { $bestDist = $gn.DistT0; $bestGroup = $g; $bestRank = $gRank }
                }
            }
        }
        $t0t = New-Object System.Collections.Generic.List[int]
        $pvt = New-Object System.Collections.Generic.List[int]
        $res = 0; $adm = 0
        foreach ($h in $userSet) {
            $hn = $nodes[$h]
            if ($p.Type -eq 'user') { $hn.TransUsers++; if ($p.Enabled) { $hn.TransEnabledUsers++ } }
            elseif ($p.Type -eq 'computer') { $hn.TransComputers++ }
            else { $hn.TransUsers++; if ($p.Enabled) { $hn.TransEnabledUsers++ } }
            if ($hn.DeclTier -eq 0 -or $hn.WkTier -eq 0) { $t0t.Add($h) }
            elseif ($hn.WkTier -eq 'P') { $pvt.Add($h) }
            if ($hn.Scope -eq 'DomainLocal' -and -not $hn.WellKnown) { $res++ }
            if ($hn.AdminIsh -and -not $hn.WellKnown) { $adm++ }
            if ($null -ne $hn.DeclTier -and ($null -eq $effTier -or $hn.DeclTier -lt $effTier)) { $effTier = $hn.DeclTier; $via = $hn.Name }
        }
        $p.TransGroupsUp = $userSet.Count
        $p.T0Targets = $t0t.ToArray()
        $p.PrivTargets = $pvt.ToArray()
        $p.ResourceReach = $res
        $p.AdminReach = $adm
        $p.ReachesT0 = ($t0t.Count -gt 0)
        $p.T0DirectMember = $directT0
        $p.EffTier = $effTier
        if ($effTier -eq 0 -and $p.DeclTier -ne 0) { $p.TierVia = $via }
        if ($bestGroup -ge 0) {
            $cur = $bestGroup; $guard = 0
            while ($cur -ge 0 -and $guard -lt 64) { if ($nodes[$cur].DistT0 -eq 0) { $p.TierVia = $nodes[$cur].Name; break }; $cur = $nodes[$cur].NextHopT0; $guard++ }
        }
        $p.InProtectedUsers = ($protectedUsersId -ge 0 -and $userSet.Contains($protectedUsersId))
        if ($p.ReachesT0 -and $bestGroup -ge 0) {
            $path = New-Object System.Collections.Generic.List[string]
            $path.Add($p.Sam)
            $cur = $bestGroup; $guard = 0
            while ($cur -ge 0 -and $guard -lt 64) {
                $path.Add($nodes[$cur].Name)
                if ($nodes[$cur].DistT0 -eq 0) { break }
                $cur = $nodes[$cur].NextHopT0; $guard++
            }
            $p.T0Path = ($path -join ' -> ')
            $p.T0Hops = $bestDist + 1
            $p.DistT0 = $bestDist + 1
            $p.NextHopT0 = $bestGroup
        }
    }

    # ---- Broad groups (everyone-style)
    $enabledUsers = [int]$Data.Stats.EnabledUsers
    $threshold = [math]::Ceiling($enabledUsers * $BroadGroupPercent / 100.0)
    foreach ($gid in $groupIds) {
        $n = $nodes[$gid]
        if ($n.Broad) { continue }
        if ($enabledUsers -ge 20 -and $n.TransEnabledUsers -ge $threshold -and $threshold -gt 0) {
            $n.Broad = $true; $n.BroadReason = "$($n.TransEnabledUsers) of $enabledUsers enabled users ($([math]::Round(100.0 * $n.TransEnabledUsers / [math]::Max(1,$enabledUsers)))%) are transitive members"
            continue
        }
        $cl = $null
        if ($children.TryGetValue($gid, [ref]$cl)) {
            foreach ($c in $cl) {
                $cn = $nodes[$c]
                if ($cn.Broad -and ($cn.Type -eq 'fsp' -or $cn.WkTier -eq 'B')) { $n.Broad = $true; $n.BroadReason = "contains $($cn.Name)"; break }
            }
        }
    }
    # a second pass so that groups containing a derived-broad group are broad as well
    foreach ($gid in $groupIds) {
        $n = $nodes[$gid]
        if ($n.Broad) { continue }
        $cl = $null
        if ($children.TryGetValue($gid, [ref]$cl)) {
            foreach ($c in $cl) {
                $cn = $nodes[$c]
                if ($cn.Type -eq 'group' -and $cn.Broad -and $cn.Security) { $n.Broad = $true; $n.BroadReason = "contains broad group $($cn.Name)"; break }
            }
        }
    }
    Write-LmLog "    [*] Tier 0 sinks: $($t0Ids.Count), privileged built-in: $($privIds.Count), cycles: $cycleId"
}
#endregion

#region ===================================================== Findings
function Add-LmFinding {
    param(
        $Data, [string]$RuleId, [string]$Severity, $Subject, $Target = $null,
        [string]$Kind = 'node', [string]$Path = '', [string]$Detail = '', [string]$Fix = '',
        [int]$EdgeP = -1, [int]$EdgeC = -1
    )
    $rule = $script:LmRules[$RuleId]
    if (-not $script:LmSeverityRank.ContainsKey($Severity)) { $Severity = $rule.Default }
    $subjLabel = if ($Subject.Sam) { $Subject.Sam } else { $Subject.Name }
    $f = [pscustomobject]@{
        Id          = $Data.Findings.Count + 1
        RuleId      = $RuleId
        Rule        = $rule.Title
        Severity    = $Severity
        SubjectId   = $Subject.Id
        Subject     = $subjLabel
        SubjectName = $Subject.Name
        SubjectType = $Subject.Type
        TargetId    = $(if ($Target) { $Target.Id } else { -1 })
        Target      = $(if ($Target) { $(if ($Target.Sam) { $Target.Sam } else { $Target.Name }) } else { '' })
        Kind        = $Kind
        Path        = $Path
        Detail      = $Detail
        Fix         = $(if ($Fix) { $Fix } else { $rule.Fix })
        EdgeP       = $EdgeP
        EdgeC       = $EdgeC
    }
    $Data.Findings.Add($f)
    $Subject.Findings.Add($f)
    $Subject.Score += [int]$script:LmSeverityScore[$Severity]
    if ($script:LmSeverityRank[$Severity] -gt $script:LmSeverityRank[$Subject.Severity]) { $Subject.Severity = $Severity }
    return $f
}

function Get-LmMaxSeverity {
    param([string[]]$Severities)
    $best = 'Information'
    foreach ($s in $Severities) { if ($s -and $script:LmSeverityRank[$s] -gt $script:LmSeverityRank[$best]) { $best = $s } }
    return $best
}

function Get-LmGroupLabel {
    param($Node)
    $scope = switch ($Node.Scope) { 'DomainLocal' { 'Domain Local' } default { $Node.Scope } }
    $kind = if ($Node.Security) { 'security' } else { 'distribution' }
    $extra = if ($Node.WellKnown) { ", well-known: $($Node.WellKnown)" } else { '' }
    return "$($Node.Name) ($scope $kind group, $($Node.DirectUsers) direct users, $($Node.DirectGroups) nested groups, $($Node.TransUsers) transitive users$extra)"
}

function Invoke-LmFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Data,
        [string[]]$ApprovedNestings = @(),
        [int]$StaleDays = 90,
        [int]$PasswordAgeDays = 365,
        [int]$DeepNestingLevels = 4,
        [string]$BaselinePath
    )
    $nodes = $Data.Nodes
    $children = $Data.Children
    $parents = $Data.Parents
    $Data.Findings = New-Object System.Collections.Generic.List[object]
    $now = Get-Date
    $approved = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($a in $ApprovedNestings) { if ($a -and $a.Contains('|')) { [void]$approved.Add($a.Trim()) } }
    function Test-LmApproved { param($P, $C) return ($approved.Contains("$($P.Sam)|$($C.Sam)") -or $approved.Contains("$($P.Name)|$($C.Name)")) }
    $catalog = @{}
    foreach ($c in (Get-LmWellKnownCatalog)) { $catalog[$c.Key] = $c }
    $resourceNameRe = '(?i)(acl|perm|rights|admin|rdp|local)'

    Write-LmLog "    [*] Evaluating rules ..."

    # ---- LM01 / LM20: group nested (directly) into a Tier 0 / privileged / declared-Tier-0 group
    foreach ($e in $Data.Edges) {
        if ($e.Kind -ne 'member') { continue }
        $p = $nodes[$e.P]; $c = $nodes[$e.C]
        if ($c.Type -ne 'group' -or -not $c.Security) { continue }
        $parentPriv = ($p.WkTier -eq 0) -or ($p.WkTier -eq 'P') -or ($p.DeclTier -eq 0)
        if (-not $parentPriv) { continue }
        if ($c.WellKnown -or $c.DeclTier -eq 0) { continue }   # default / designed Tier 0 nesting
        if (Test-LmApproved -P $p -C $c) { continue }
        $sev = if ($p.WellKnown -and $catalog.ContainsKey($p.WkKey)) { $catalog[$p.WkKey].Severity } else { 'High' }
        $what = if ($p.WellKnown) { "well-known $(if ($p.WkTier -eq 0) { 'Tier 0' } else { 'privileged' }) group '$($p.Name)'" } else { "declared Tier 0 group '$($p.Name)' ($($p.DeclTierSource))" }
        if ($c.TransUsers -eq 0 -and $c.TransComputers -eq 0) {
            Add-LmFinding -Data $Data -RuleId 'LM20' -Severity 'Medium' -Subject $c -Target $p -Kind 'edge' -EdgeP $p.Id -EdgeC $c.Id `
                -Path "$($c.Name) -> $($p.Name)" `
                -Detail "Group $($c.Name) has no transitive user or computer members but is a member of $what. Any account added to it becomes a member of '$($p.Name)' immediately." | Out-Null
            continue
        }
        $detail = "$(Get-LmGroupLabel $c) is a direct member of $what. $($p.Tag)"
        if ($p.WellKnown -and $catalog.ContainsKey($p.WkKey)) { $detail = "$(Get-LmGroupLabel $c) is a direct member of $what - $($catalog[$p.WkKey].Tag). Every transitive member of '$($c.Name)' holds that privilege." }
        Add-LmFinding -Data $Data -RuleId 'LM01' -Severity $sev -Subject $c -Target $p -Kind 'edge' -EdgeP $p.Id -EdgeC $c.Id `
            -Path "$($c.Name) -> $($p.Name)" -Detail $detail `
            -Fix "Remove '$($c.Name)' from '$($p.Name)': Remove-ADGroupMember -Identity '$($p.Sam)' -Members '$($c.Sam)'. If the members really need the right, create a dedicated Tier 0 group with direct, reviewed membership instead of nesting a role/resource group." | Out-Null
    }
    # groups that inherit Tier 0 further down the chain
    foreach ($gid in $Data.GroupIds) {
        $g = $nodes[$gid]
        if (-not $g.ReachesT0 -or $g.DistT0 -lt 2) { continue }
        if ($g.WellKnown -or $g.DeclTier -eq 0) { continue }
        $closingChild = $null; $closingParent = $null
        $cur = $gid; $guard = 0
        while ($cur -ge 0 -and $guard -lt 64) {
            $nx = $nodes[$cur].NextHopT0
            if ($nx -lt 0) { break }
            if ($nodes[$nx].DistT0 -eq 0) { $closingChild = $nodes[$cur]; $closingParent = $nodes[$nx]; break }
            $cur = $nx; $guard++
        }
        if ($closingChild -and (Test-LmApproved -P $closingParent -C $closingChild)) { continue }
        $sev = 'Critical'
        if ($closingParent -and $closingParent.WellKnown -and $catalog.ContainsKey($closingParent.WkKey)) { $sev = $catalog[$closingParent.WkKey].Severity }
        elseif ($closingParent -and -not $closingParent.WellKnown) { $sev = 'High' }
        if ($g.TransUsers -eq 0 -and $g.TransComputers -eq 0) { $sev = 'Medium' }
        $edgeTxt = if ($closingChild) { " The edge that closes the chain is '$($closingChild.Name)' -> '$($closingParent.Name)'." } else { '' }
        Add-LmFinding -Data $Data -RuleId 'LM01' -Severity $sev -Subject $g -Target $closingParent -Kind 'inherited' `
            -Path $g.T0Path -Detail "$(Get-LmGroupLabel $g) inherits Tier 0 through $($g.DistT0) hops: $($g.T0Path).$edgeTxt" `
            -Fix "Fix the closing edge ($(if ($closingChild) { "remove '$($closingChild.Name)' from '$($closingParent.Name)'" } else { 'see path' })). Then verify whether '$($g.Name)' still reaches any Tier 0 group through another path." | Out-Null
    }

    # ---- LM02: user accounts that are effectively Tier 0
    foreach ($prId in $Data.PrincipalIds) {
        $u = $nodes[$prId]
        if ($u.Type -ne 'user' -or -not $u.ReachesT0 -or $u.IsKrbtgt) { continue }
        $targets = @($u.T0Targets | ForEach-Object { $nodes[$_].Name } | Sort-Object -Unique)
        $declaredChain = $true
        $pl = $null
        if ($parents.TryGetValue($prId, [ref]$pl)) {
            foreach ($g in $pl) {
                $gn = $nodes[$g]
                if ($gn.Type -ne 'group' -or -not $gn.Security) { continue }
                if ($gn.ReachesT0 -or $gn.DeclTier -eq 0 -or $gn.WkTier -eq 0) {
                    if ($gn.DeclTier -ne 0 -and $gn.WkTier -ne 0) { $declaredChain = $false }
                }
            }
        }
        $hidden = (-not $u.T0DirectMember) -or (-not $declaredChain)
        $sev = 'Low'
        $how = ''
        if ($u.IsRid500) { $sev = 'Information'; $how = 'built-in domain Administrator (RID-500); expected direct member of Domain Admins / Administrators' }
        elseif ($hidden) { $sev = 'Critical'; $how = "reaches Tier 0 through nesting ($($u.T0Hops) hops) - not visible as a direct member of the Tier 0 group" }
        elseif (-not $u.AdminNamed) { $sev = 'High'; $how = 'direct Tier 0 member, but the account name does not follow a dedicated-admin naming standard (daily-use account?)' }
        else { $sev = 'Low'; $how = 'direct member of a Tier 0 group through a dedicated admin account (expected - review hygiene in LM15)' }
        if (-not $u.Enabled -and $sev -ne 'Information') { $sev = 'Low'; $how = "DISABLED account that still reaches Tier 0 ($how); re-enabling restores the privilege" }
        $detail = "$($u.Sam) ($($u.Name)) $how. Tier 0 groups reached: $($targets -join ', '). Transitive groups in token: $($u.TransGroupsUp)."
        Add-LmFinding -Data $Data -RuleId 'LM02' -Severity $sev -Subject $u -Target $(if ($u.NextHopT0 -ge 0) { $nodes[$u.NextHopT0] } else { $null }) -Kind 'principal' `
            -Path $u.T0Path -Detail $detail | Out-Null
    }

    # ---- LM03: computers, service accounts, foreign / cross-domain / unresolved principals in privileged groups
    foreach ($prId in $Data.PrincipalIds) {
        $p = $nodes[$prId]
        if ($p.Type -eq 'user') { continue }
        $hits = @($p.T0Targets) + @($p.PrivTargets)
        if ($hits.Count -eq 0) { continue }
        $relevant = New-Object System.Collections.Generic.List[object]
        foreach ($t in $hits) {
            $tn = $nodes[$t]
            if ($p.Type -eq 'computer' -and $tn.ExpectComputers) { continue }
            $relevant.Add($tn)
        }
        if ($relevant.Count -eq 0) { continue }
        $sevs = foreach ($tn in $relevant) { if ($tn.WellKnown -and $catalog.ContainsKey($tn.WkKey)) { $catalog[$tn.WkKey].Severity } else { 'High' } }
        $sev = Get-LmMaxSeverity $sevs
        $kindTxt = switch ($p.Type) {
            'computer' { "Computer account $($p.Sam)$(if ($p.OS) { " ($($p.OS))" }) - anyone who is SYSTEM on this machine holds the privilege" }
            'gmsa'     { "Group managed service account $($p.Sam) - the service that runs under it holds the privilege" }
            'msa'      { "Managed service account $($p.Sam)" }
            'fsp'      { if ($p.Broad) { "Well-known identity '$($p.Name)' - the privilege is granted to EVERYONE who matches it"; $sev = 'Critical' } else { "Foreign security principal '$($p.Name)' from a trusted domain - cannot be audited here"; if ($script:LmSeverityRank[$sev] -lt 4) { $sev = 'High' } } }
            'external' { "Cross-domain principal '$($p.Name)' ($($p.Domain)) - cannot be audited in this domain"; if ($script:LmSeverityRank[$sev] -lt 4) { $sev = 'High' } }
            'contact'  { "Contact object '$($p.Name)' (no SID, grants nothing - but indicates a mistaken membership)"; $sev = 'Low' }
            default    { "Unresolved object '$($p.Name)' (could not be read)"; $sev = 'Low' }
        }
        $tnames = @($relevant | ForEach-Object { $_.Name } | Sort-Object -Unique)
        Add-LmFinding -Data $Data -RuleId 'LM03' -Severity $sev -Subject $p -Target $relevant[0] -Kind 'principal' -Path $p.T0Path `
            -Detail "$kindTxt. Privileged groups reached: $($tnames -join ', ')." | Out-Null
    }

    # ---- LM04: hidden membership through primaryGroupID
    foreach ($prId in $Data.PrincipalIds) {
        $p = $nodes[$prId]
        if ($p.PrimaryGroupId -le 0 -or $p.External) { continue }
        $default = switch ($p.Type) { 'computer' { @(515, 516, 521) } 'gmsa' { @(515) } 'msa' { @(515) } default { @(513) } }
        if ($default -contains $p.PrimaryGroupId) { continue }
        if ($p.Rid -eq 501 -and $p.PrimaryGroupId -eq 514) { continue }   # built-in Guest belongs to Domain Guests by default
        $gid = -1
        $gname = "RID $($p.PrimaryGroupId)"
        $gnode = $null
        if ($Data.BySid.TryGetValue("$($Data.DomainSid)-$($p.PrimaryGroupId)", [ref]$gid)) { $gnode = $nodes[$gid]; $gname = $gnode.Name }
        $priv = $gnode -and (($gnode.WkTier -eq 0) -or ($gnode.WkTier -eq 'P') -or ($gnode.EffTier -eq 0))
        $sev = if ($priv) { 'Critical' } else { 'Low' }
        Add-LmFinding -Data $Data -RuleId 'LM04' -Severity $sev -Subject $p -Target $gnode -Kind 'principal' -Path "$($p.Sam) -> $gname (primaryGroupID)" `
            -Detail "$($p.Sam) has primaryGroupID=$($p.PrimaryGroupId) ($gname). The membership is not stored in the group's member attribute and is invisible to Get-ADGroupMember / ADUC member lists.$(if ($priv) { ' The group is privileged - treat as a potential persistence technique.' })" `
            -Fix "Add-ADGroupMember -Identity 'Domain Users' -Members '$($p.Sam)'; Set-ADUser -Identity '$($p.Sam)' -Replace @{primaryGroupID=513}; then review the account's remaining memberships and who changed the attribute (event 5136 / 4738)." | Out-Null
    }

    # ---- LM05: circular nesting
    if ($Data.CycleCount -gt 0) {
        for ($cid = 1; $cid -le $Data.CycleCount; $cid++) {
            $members = @($Data.GroupIds | Where-Object { $nodes[$_].CycleId -eq $cid } | ForEach-Object { $nodes[$_] })
            if ($members.Count -eq 0) { continue }
            $sev = 'Medium'
            if ($members | Where-Object { $_.ReachesT0 -or $_.AdminIsh -or $_.WkTier -eq 0 -or $_.WkTier -eq 'P' }) { $sev = 'High' }
            # A loop that carries administrative memberships is one big admin group: every
            # member of the smallest group in it is administrator everywhere the loop reaches.
            $loopAdm = ($members | ForEach-Object { $_.AdminReach } | Measure-Object -Maximum).Maximum
            if ($loopAdm -ge 5 -or ($members | Where-Object { $_.ReachesT0 })) { $sev = 'Critical' }
            $names = @($members | ForEach-Object { $_.Name })
            Add-LmFinding -Data $Data -RuleId 'LM05' -Severity $sev -Subject $members[0] -Kind 'cycle' -Path (($names + $names[0]) -join ' -> ') `
                -Detail "Groups in a membership loop: $($names -join ', '). They are functionally one group; every member of any of them has the union of all their rights$(if ($loopAdm -ge 2) { " - including administrative access on $loopAdm system(s)" })." | Out-Null
        }
    }

    # ---- LM06: broad group nested into other groups
    foreach ($gid in $Data.GroupIds) {
        $b = $nodes[$gid]
        if (-not $b.Broad -or -not $b.Security) { continue }
        $pl = $null
        if (-not $parents.TryGetValue($gid, [ref]$pl)) { continue }
        foreach ($p in $pl) {
            $pn = $nodes[$p]
            if ($pn.Type -ne 'group' -or -not $pn.Security) { continue }
            if ($pn.WkTier -eq 'B' -or $pn.WkTier -eq 'N') { continue }   # Users, Pre-Windows 2000 ... are default containers for broad identities
            if (Test-LmApproved -P $pn -C $b) { continue }
            if (-not $b.WellKnown -and $b.DeclTier -ne 0 -and ($pn.WkTier -eq 0 -or $pn.WkTier -eq 'P' -or $pn.DeclTier -eq 0)) { continue }   # LM01 reports this edge; LM06 adds nothing
            $sev = 'Medium'; $why = 'the parent is a role / aggregation group - everyone now inherits whatever it is nested into'
            if ($pn.ReachesT0 -or $pn.WkTier -eq 0 -or $pn.WkTier -eq 'P' -or $pn.DeclTier -eq 0) { $sev = 'Critical'; $why = 'the parent reaches a Tier 0 / privileged group - everyone is effectively privileged' }
            elseif ($pn.AdminIsh) { $sev = 'Critical'; $why = 'the parent grants administrative access by name - everyone in the domain is an administrator there' }
            elseif ($pn.Scope -eq 'DomainLocal') { $sev = 'High'; $why = 'the parent is a resource group - every account in the domain gets that resource access' }
            Add-LmFinding -Data $Data -RuleId 'LM06' -Severity $sev -Subject $b -Target $pn -Kind 'edge' -EdgeP $pn.Id -EdgeC $b.Id -Path "$($b.Name) -> $($pn.Name)" `
                -Detail "Broad group $($b.Name) ($($b.BroadReason)) is a member of $(Get-LmGroupLabel $pn): $why." `
                -Fix "Remove-ADGroupMember -Identity '$($pn.Sam)' -Members '$($b.Sam)'. Replace with a maintained role group that lists the people who need '$($pn.Name)', or grant read access inside the application instead." | Out-Null
        }
    }

    # ---- LM07 / LM08 / LM17: AGDLP scope rules and distribution groups in chains
    $userInDl = New-Object 'System.Collections.Generic.Dictionary[int,System.Collections.Generic.List[int]]'
    foreach ($e in $Data.Edges) {
        if ($e.Kind -ne 'member') { continue }
        $p = $nodes[$e.P]; $c = $nodes[$e.C]
        if ($c.Type -eq 'user' -and $p.Type -eq 'group') {
            if ($p.Scope -eq 'DomainLocal' -and $p.Security -and -not $p.WellKnown) { Add-LmListItem -Dict $userInDl -Key $p.Id -Value $c.Id }
            continue
        }
        if ($c.Type -ne 'group' -or $p.Type -ne 'group') { continue }
        if (-not $p.Security -or -not $c.Security) {
            if ($p.Security -and -not $c.Security) {
                $sev = if ($p.WkTier -eq 0 -or $p.WkTier -eq 'P' -or $p.ReachesT0) { 'Low' } else { 'Information' }
                Add-LmFinding -Data $Data -RuleId 'LM17' -Severity $sev -Subject $c -Target $p -Kind 'edge' -EdgeP $p.Id -EdgeC $c.Id -Path "$($c.Name) -> $($p.Name)" `
                    -Detail "Distribution group $($c.Name) is a member of security group $($p.Name). Its members get nothing from this (distribution groups are not in access tokens) - the chain is misleading and would activate silently if the group were converted to a security group." | Out-Null
            }
            continue
        }
        if ($p.WellKnown -or $c.WellKnown -or $c.Broad) { continue }
        if (Test-LmApproved -P $p -C $c) { continue }
        $escalate = $p.ReachesT0 -or $p.AdminIsh -or ($null -ne $p.EffTier)
        if ($p.Scope -in @('Global','Universal') -and $c.Scope -in @('Global','Universal')) {
            $sev = if ($escalate) { 'Medium' } else { 'Low' }
            Add-LmFinding -Data $Data -RuleId 'LM07' -Severity $sev -Subject $c -Target $p -Kind 'edge' -EdgeP $p.Id -EdgeC $c.Id -Path "$($c.Name) -> $($p.Name)" `
                -Detail "Role group $($c.Name) ($($c.Scope), $($c.DirectUsers) direct users) is nested in role group $(Get-LmGroupLabel $p). Members of '$($c.Name)' inherit every current and future membership of '$($p.Name)'$(if ($p.ReachesT0) { " - including Tier 0 ($($p.T0Path))" } elseif ($p.AdminIsh) { ' - an administrative group by name' })." | Out-Null
        }
        elseif ($p.Scope -eq 'DomainLocal' -and $c.Scope -eq 'DomainLocal') {
            $sev = if ($escalate) { 'High' } else { 'Medium' }
            Add-LmFinding -Data $Data -RuleId 'LM08' -Severity $sev -Subject $c -Target $p -Kind 'edge' -EdgeP $p.Id -EdgeC $c.Id -Path "$($c.Name) -> $($p.Name)" `
                -Detail "Resource group $($c.Name) is nested in resource group $(Get-LmGroupLabel $p). Everyone who has the access of '$($c.Name)' also has the access of '$($p.Name)', two levels below what its ACL shows$(if ($p.ReachesT0) { " - and '$($p.Name)' reaches Tier 0 ($($p.T0Path))" })." | Out-Null
        }
    }

    # ---- LM09: users directly in resource groups (aggregated per group)
    foreach ($gid in $userInDl.Keys) {
        $g = $nodes[$gid]
        $users = $userInDl[$gid]
        $sev = if ($g.ReachesT0 -or $g.AdminIsh) { 'Medium' } else { 'Low' }
        $sample = @($users | Select-Object -First 10 | ForEach-Object { $nodes[$_].Sam })
        $more = if ($users.Count -gt 10) { " (+$($users.Count - 10) more)" } else { '' }
        Add-LmFinding -Data $Data -RuleId 'LM09' -Severity $sev -Subject $g -Kind 'group' -Path "$($users.Count) user(s) -> $($g.Name)" `
            -Detail "$($users.Count) user account(s) are direct members of resource group $(Get-LmGroupLabel $g) instead of coming through a role group: $($sample -join ', ')$more." | Out-Null
    }

    # ---- LM10: collection-point groups
    foreach ($gid in $Data.GroupIds) {
        $g = $nodes[$gid]
        if ($g.WellKnown -or -not $g.Security -or $g.DirectGroups -lt 2) { continue }
        $resourceish = ($g.Scope -in @('Global','Universal')) -and ("$($g.Sam) $($g.Name)" -match $resourceNameRe)
        if ($g.ParentsCount -lt 1 -and -not $resourceish -and -not $g.AdminIsh) { continue }
        $sev = 'Low'
        if ($g.DirectGroups -ge 3) { $sev = 'Medium' }
        if ($g.AdminIsh -or $g.ReachesT0 -or $g.PrivTargets.Count -gt 0) { $sev = 'High' }
        $cl = $null; $nested = @()
        if ($children.TryGetValue($gid, [ref]$cl)) { $nested = @($cl | ForEach-Object { $nodes[$_] } | Where-Object { $_.Type -eq 'group' } | ForEach-Object { $_.Name }) }
        $pl = $null; $onward = @()
        if ($parents.TryGetValue($gid, [ref]$pl)) { $onward = @($pl | ForEach-Object { $nodes[$_].Name }) }
        Add-LmFinding -Data $Data -RuleId 'LM10' -Severity $sev -Subject $g -Kind 'group' -Path "$($nested -join ', ') -> $($g.Name)$(if ($onward.Count) { " -> $($onward -join ', ')" })" `
            -Detail "$(Get-LmGroupLabel $g) aggregates $($g.DirectGroups) groups ($($nested -join ', '))$(if ($onward.Count) { " and is itself nested onward into $($onward -join ', ')" })$(if ($resourceish) { ' and its name suggests it stands in ACLs' }). It behaves as role and resource at the same time$(if ($g.ReachesT0) { " and reaches Tier 0 ($($g.T0Path))" })." | Out-Null
    }

    # ---- LM22: groups that are administrator on many systems through their memberOf chain
    $admGroupNames = { param($Node) @($Data.UpClosure[$Node.Id] | ForEach-Object { $nodes[$_] } | Where-Object { $_.AdminIsh -and -not $_.WellKnown } | ForEach-Object { $_.Name } | Sort-Object) }
    foreach ($gid in $Data.GroupIds) {
        $g = $nodes[$gid]
        if ($g.WellKnown -or -not $g.Security -or $g.ReachesT0 -or $g.DeclTier -eq 0) { continue }   # Tier 0 reach is LM01 - already Critical
        if ($g.AdminReach -lt 2) { continue }
        $reached = @(& $admGroupNames $g)
        if ($reached.Count -lt 2) { continue }
        $sev = if ($reached.Count -ge 10) { 'Critical' } elseif ($reached.Count -ge 5) { 'High' } else { 'Medium' }
        if ($g.TransUsers -eq 0 -and $g.TransComputers -eq 0) { $sev = 'Low' }   # dormant: nobody holds it yet
        $pl = $null; $firstHop = @()
        if ($parents.TryGetValue($gid, [ref]$pl)) { $firstHop = @($pl | ForEach-Object { $nodes[$_] } | Where-Object { $_.Type -eq 'group' -and $_.Security -and -not $_.WellKnown -and ($_.AdminIsh -or $_.AdminReach -gt 0) } | Sort-Object -Property @{ Expression = 'AdminReach'; Descending = $true } | Select-Object -First 3 | ForEach-Object { $_.Name }) }
        Add-LmFinding -Data $Data -RuleId 'LM22' -Severity $sev -Subject $g -Kind 'group' `
            -Path "$($g.Name) -> $(if ($firstHop.Count) { ($firstHop -join ' / ') + ' -> ' })$($reached.Count) administrative groups" `
            -Detail "$(Get-LmGroupLabel $g) is a transitive member of $($reached.Count) administrative group(s): $(($reached | Select-Object -First 15) -join ', ')$(if ($reached.Count -gt 15) { " ... (+$($reached.Count - 15) more)" }). Its $($g.TransUsers) transitive user(s)$(if ($g.TransComputers) { " and $($g.TransComputers) computer(s)" }) are administrators on every one of those systems$(if ($g.InCycle) { ' (the group is part of a membership loop - see LM05)' })." `
            -Fix "Remove '$($g.Name)' from $(if ($firstHop.Count) { "'$($firstHop[0])'" } else { 'the group that carries the administrative memberships' }) (Remove-ADGroupMember) and grant server administration through a dedicated server-admin role group with reviewed, direct members." | Out-Null
    }

    # ---- LM23: accounts that are administrator on many systems
    foreach ($prId in $Data.PrincipalIds) {
        $u = $nodes[$prId]
        if ($u.Type -ne 'user' -or $u.ReachesT0 -or $u.AdminReach -lt 5 -or -not $u.Enabled) { continue }   # Tier 0 accounts are LM02/LM14/LM15
        $pl = $null; $set = New-Object System.Collections.Generic.HashSet[int]
        if ($parents.TryGetValue($prId, [ref]$pl)) { foreach ($g in $pl) { if ($nodes[$g].Type -eq 'group' -and $nodes[$g].Security) { [void]$set.Add($g); $cs = $null; if ($Data.UpClosure.TryGetValue($g, [ref]$cs)) { $set.UnionWith($cs) } } } }
        $reached = @($set | ForEach-Object { $nodes[$_] } | Where-Object { $_.AdminIsh -and -not $_.WellKnown } | ForEach-Object { $_.Name } | Sort-Object)
        if ($reached.Count -lt 5) { continue }
        $sev = if ($reached.Count -ge 10) { if ($u.AdminNamed) { 'Medium' } else { 'High' } } else { if ($u.AdminNamed) { 'Low' } else { 'Medium' } }
        $direct = @($pl | ForEach-Object { $nodes[$_] } | Where-Object { $_.Type -eq 'group' -and $_.AdminIsh -and -not $_.WellKnown }).Count
        Add-LmFinding -Data $Data -RuleId 'LM23' -Severity $sev -Subject $u -Kind 'principal' -Path "$($u.Sam) -> $($reached.Count) administrative groups ($direct direct, $($reached.Count - $direct) through nesting)" `
            -Detail "$($u.Sam) ($($u.Name)) holds administrative membership on $($reached.Count) system(s)$(if (-not $u.AdminNamed) { ' with an account that does not look like a dedicated admin account' }): $(($reached | Select-Object -First 15) -join ', ')$(if ($reached.Count -gt 15) { " ... (+$($reached.Count - 15) more)" }). $($reached.Count - $direct) of them come through group nesting and are not visible on the account's member-of tab as administrative groups." | Out-Null
    }

    # ---- LM11: temporary / legacy groups still granting access
    foreach ($gid in $Data.GroupIds) {
        $g = $nodes[$gid]
        if (-not $g.Temporary -or $g.WellKnown -or -not $g.Security) { continue }
        if ($g.ParentsCount -lt 1 -or ($g.DirectTotal -eq 0 -and $g.TransUsers -eq 0)) { continue }
        $pl = $null; $onward = @()
        if ($parents.TryGetValue($gid, [ref]$pl)) { $onward = @($pl | ForEach-Object { $nodes[$_] }) }
        $sev = 'Low'
        if ($onward | Where-Object { $_.AdminIsh -or $_.ReachesT0 -or $_.WkTier -eq 0 -or $_.WkTier -eq 'P' -or $_.Scope -eq 'DomainLocal' }) { $sev = 'Medium' }
        $ageTxt = ''
        if ($g.WhenChanged -is [datetime]) { $ageTxt = " Last modified $($g.WhenChanged.ToString('yyyy-MM-dd')) ($([int]($now - $g.WhenChanged).TotalDays) days ago)." }
        $ownerTxt = if ($g.ManagedBy) { " Owner: $(Get-LmRdnValue $g.ManagedBy)." } else { ' No owner (managedBy) set.' }
        Add-LmFinding -Data $Data -RuleId 'LM11' -Severity $sev -Subject $g -Target $onward[0] -Kind 'group' -Path "$($g.Name) -> $(($onward | ForEach-Object { $_.Name }) -join ', ')" `
            -Detail "$(Get-LmGroupLabel $g) looks temporary/legacy by name or description ('$($g.Description)') but still grants access through $(($onward | ForEach-Object { $_.Name }) -join ', ').$ageTxt$ownerTxt" | Out-Null
    }

    # ---- LM12: deep nesting chains (report the top of each chain)
    foreach ($gid in $Data.GroupIds) {
        $g = $nodes[$gid]
        if ($g.Height -lt $DeepNestingLevels -or -not $g.Security -or $g.InCycle) { continue }
        if ($g.WkTier -eq 'N' -or $g.WkTier -eq 'B' -or $g.Protective) { continue }   # Denied RODC PRG / Users etc. contain the privileged groups by design
        $pl = $null; $isTop = $true
        if ($parents.TryGetValue($gid, [ref]$pl)) { foreach ($p in $pl) { if ($nodes[$p].Type -eq 'group' -and $nodes[$p].Height -gt $g.Height) { $isTop = $false; break } } }
        if (-not $isTop) { continue }
        # one example chain: follow the child with the greatest height
        $chain = New-Object System.Collections.Generic.List[string]
        $cur = $gid; $guard = 0
        while ($cur -ge 0 -and $guard -lt 64) {
            $chain.Add($nodes[$cur].Name)
            $cl = $null; $next = -1; $best = -1
            if ($children.TryGetValue($cur, [ref]$cl)) { foreach ($c in $cl) { if ($nodes[$c].Type -eq 'group' -and $nodes[$c].Height -gt $best -and -not $chain.Contains($nodes[$c].Name)) { $best = $nodes[$c].Height; $next = $c } } }
            if ($next -lt 0) { break }
            $cur = $next; $guard++
        }
        [array]::Reverse($chain)
        $sev = if ($g.WkTier -eq 0 -or $g.ReachesT0 -or $g.AdminIsh) { 'Medium' } else { 'Low' }
        Add-LmFinding -Data $Data -RuleId 'LM12' -Severity $sev -Subject $g -Kind 'group' -Path ($chain -join ' -> ') `
            -Detail "The longest nesting chain below $($g.Name) is $($g.Height) groups deep: $($chain -join ' -> '). Effective membership of '$($g.Name)' can no longer be read from its member list." | Out-Null
    }

    # ---- LM13: tier boundary crossed (declared Tier 1 / Tier 2 reaching a higher tier)
    foreach ($n in $nodes) {
        if ($null -eq $n.DeclTier -or $n.DeclTier -eq 0) { continue }
        if ($null -eq $n.EffTier -or $n.EffTier -ge $n.DeclTier) { continue }
        if ($n.Type -notin @('group','user','computer','gmsa','msa')) { continue }
        $sev = if ($n.EffTier -eq 0) { 'High' } else { 'Medium' }
        $label = if ($n.Type -eq 'group') { Get-LmGroupLabel $n } else { "$($n.Sam) ($($n.Type))" }
        Add-LmFinding -Data $Data -RuleId 'LM13' -Severity $sev -Subject $n -Kind $(if ($n.Type -eq 'group') { 'group' } else { 'principal' }) -Path $(if ($n.T0Path) { $n.T0Path } else { "$($n.Name) -> $($n.TierVia)" }) `
            -Detail "$label is declared Tier $($n.DeclTier) ($($n.DeclTierSource)) but effectively reaches Tier $($n.EffTier) through $($n.TierVia)$(if ($n.T0Path) { ": $($n.T0Path)" })." | Out-Null
    }

    # ---- LM14 / LM15 / LM21: Tier 0 account memberships and hygiene, token bloat
    $baselineKeys = @('DU','USERS','DRPG','PU','GPCO','DA','EA','SA','ADM','KA','EKA')
    foreach ($prId in $Data.PrincipalIds) {
        $u = $nodes[$prId]
        if ($u.Type -eq 'user' -and $u.TransGroupsUp -gt 1000) {
            Add-LmFinding -Data $Data -RuleId 'LM21' -Severity 'Low' -Subject $u -Kind 'principal' -Detail "$($u.Sam) is a transitive member of $($u.TransGroupsUp) groups." | Out-Null
        }
        if ($u.Type -ne 'user' -or -not $u.ReachesT0 -or $u.IsKrbtgt) { continue }
        # LM14
        if ($u.Enabled) {
            $pl = $null; $outside = @()
            if ($parents.TryGetValue($prId, [ref]$pl)) {
                foreach ($g in $pl) {
                    $gn = $nodes[$g]
                    if ($gn.Type -ne 'group' -or -not $gn.Security) { continue }
                    if ($gn.EffTier -eq 0 -or $gn.WkTier -eq 0 -or $gn.WkTier -eq 'P' -or $gn.Protective) { continue }
                    if ($gn.WkKey -and ($baselineKeys -contains $gn.WkKey)) { continue }
                    if ($gn.WkTier -eq 'B' -or $gn.WkTier -eq 'N') { continue }
                    $outside += $gn.Name
                }
            }
            if ($outside.Count -gt 0) {
                Add-LmFinding -Data $Data -RuleId 'LM14' -Severity 'High' -Subject $u -Kind 'principal' -Path $u.T0Path `
                    -Detail "$($u.Sam) reaches Tier 0 ($(($u.T0Targets | ForEach-Object { $nodes[$_].Name } | Sort-Object -Unique) -join ', ')) and is also a direct member of $($outside.Count) non-Tier-0 group(s): $(($outside | Sort-Object | Select-Object -First 15) -join ', ')$(if ($outside.Count -gt 15) { ' ...' }). The Tier 0 credential is exposed wherever those memberships are used." | Out-Null
            }
        }
        # LM15
        $issues = New-Object System.Collections.Generic.List[string]
        $sevs = New-Object System.Collections.Generic.List[string]
        if ($u.HasSpn -and -not $u.IsKrbtgt) { $issues.Add("has $($u.Spns) SPN(s) - Kerberoastable Tier 0 credential"); $sevs.Add('Critical') }
        if (($u.Uac -band 0x400000) -ne 0) { $issues.Add('Kerberos pre-authentication disabled - AS-REP roastable'); $sevs.Add('Critical') }
        if ($u.Enabled) {
            if (($u.Uac -band 0x10000) -ne 0) { $issues.Add('password never expires'); $sevs.Add('High') }
            if ($u.PwdLastSet -is [datetime] -and ($now - $u.PwdLastSet).TotalDays -gt $PasswordAgeDays) { $issues.Add("password last set $($u.PwdLastSet.ToString('yyyy-MM-dd')) ($([int]($now - $u.PwdLastSet).TotalDays) days)"); $sevs.Add('Medium') }
            if (-not $u.IsRid500 -and -not $u.InProtectedUsers -and (($u.Uac -band 0x100000) -eq 0)) { $issues.Add('not in Protected Users and not marked "sensitive, cannot be delegated"'); $sevs.Add('Medium') }
            $stale = $false
            if ($u.LastLogon -is [datetime]) { if (($now - $u.LastLogon).TotalDays -gt $StaleDays) { $stale = $true } }
            elseif ($u.WhenCreated -is [datetime] -and ($now - $u.WhenCreated).TotalDays -gt $StaleDays) { $stale = $true }
            if ($stale) { $issues.Add("stale - no logon for more than $StaleDays days$(if ($u.LastLogon) { " (last $($u.LastLogon.ToString('yyyy-MM-dd')))" } else { ' (never)' })"); $sevs.Add('Medium') }
            if (-not $u.AdminNamed -and -not $u.IsRid500) { $issues.Add('name does not look like a dedicated admin account (daily-use account with Tier 0 rights?)'); $sevs.Add('Medium') }
        } else {
            $issues.Add('disabled but still a member of Tier 0 groups'); $sevs.Add('Low')
        }
        if ($issues.Count -gt 0) {
            Add-LmFinding -Data $Data -RuleId 'LM15' -Severity (Get-LmMaxSeverity $sevs.ToArray()) -Subject $u -Kind 'principal' -Path $u.T0Path `
                -Detail "$($u.Sam) ($(if ($u.T0DirectMember) { 'direct' } else { 'nested' }) Tier 0): $($issues -join '; ')." | Out-Null
        }
    }

    # ---- LM16: well-known privileged groups that have members
    $shouldBeEmpty = @('AO','SO','BO','PO','REPL','GPCO','KA','EKA','IFTB','HVA','RDU','RMU','CO','DCOM','NCO','PLU','PMU','ELR','ACAO','SRA','DO','GUEST','DG','IIS','EXWP')
    $review = @('DNSA','CP','SA','EA','EXOM','ARPG','CDC','DNSP','EXSV','EXTS','RAS','TSLS','WAAG','CSDA','RDSRA','RDSES','RDSMS')
    foreach ($gid in $Data.GroupIds) {
        $g = $nodes[$gid]
        if (-not $g.WellKnown -or -not $catalog.ContainsKey($g.WkKey)) { continue }
        $cat = $catalog[$g.WkKey]
        $cl = $null
        if (-not $children.TryGetValue($gid, [ref]$cl)) { continue }
        $members = @($cl | ForEach-Object { $nodes[$_] })
        if ($g.WkKey -eq 'PW2K') {
            $bad = @($members | Where-Object { $_.Type -eq 'fsp' -and $_.Sid -in @('S-1-1-0','S-1-5-7') })
            if ($bad.Count -gt 0) {
                Add-LmFinding -Data $Data -RuleId 'LM16' -Severity 'High' -Subject $g -Kind 'group' -Detail "Pre-Windows 2000 Compatible Access contains $(($bad | ForEach-Object { $_.Name }) -join ', '): unauthenticated clients can read every user and group attribute in the domain." -Fix 'Remove Everyone / Anonymous Logon from Pre-Windows 2000 Compatible Access (keep Authenticated Users only while legacy systems need it).' | Out-Null
            }
            continue
        }
        if ($g.WkKey -eq 'ADM') {
            $unexpected = @($members | Where-Object { -not ($_.WkKey -in @('DA','EA')) -and -not $_.IsRid500 })
            if ($unexpected.Count -gt 0) {
                $names = @($unexpected | ForEach-Object { if ($_.Sam) { $_.Sam } else { $_.Name } })
                Add-LmFinding -Data $Data -RuleId 'LM16' -Severity 'High' -Subject $g -Kind 'group' -Detail "BUILTIN\Administrators has $($unexpected.Count) direct member(s) beyond Domain Admins / Enterprise Admins / the built-in Administrator: $(($names | Select-Object -First 15) -join ', ')$(if ($names.Count -gt 15) { ' ...' }). Each is an administrator on every domain controller." | Out-Null
            }
            continue
        }
        $unexpected = @($members | Where-Object { -not ($g.ExpectComputers -and $_.Type -eq 'computer') })
        # Default members that are not findings: the built-in Administrator (RID 500) in the
        # admin groups and GPCO, the built-in Guest (RID 501) in Domain Guests via its primary
        # group, Exchange Trusted Subsystem inside Exchange Windows Permissions.
        if ($g.WkKey -in @('DA','EA','SA','GPCO','ADM')) { $unexpected = @($unexpected | Where-Object { -not $_.IsRid500 }) }
        if ($g.WkKey -eq 'DG')   { $unexpected = @($unexpected | Where-Object { $_.Rid -ne 501 }) }
        if ($g.WkKey -eq 'EXWP') { $unexpected = @($unexpected | Where-Object { $_.WkKey -ne 'EXTS' }) }
        if ($g.WkKey -eq 'WAAG') { $unexpected = @($unexpected | Where-Object { $_.Sid -ne 'S-1-5-9' }) }
        if ($g.WkKey -eq 'CSDA') { $unexpected = @($unexpected | Where-Object { $_.WkKey -notin @('DU','DC') -and $_.Sid -ne 'S-1-5-11' }) }
        if ($unexpected.Count -eq 0) { continue }
        $names = @($unexpected | ForEach-Object { if ($_.Sam) { $_.Sam } else { $_.Name } })
        if ($shouldBeEmpty -contains $g.WkKey) {
            Add-LmFinding -Data $Data -RuleId 'LM16' -Severity $cat.Severity -Subject $g -Kind 'group' `
                -Detail "$($g.Name) should be empty but has $($unexpected.Count) direct member(s): $(($names | Select-Object -First 15) -join ', ')$(if ($names.Count -gt 15) { ' ...' }). $($cat.Tag). Transitive users: $($g.TransUsers)." -Fix $cat.Fix | Out-Null
        } elseif ($review -contains $g.WkKey) {
            $sev = $cat.Severity
            if ($script:LmSeverityRank[$sev] -gt 3) { $sev = 'Medium' }
            Add-LmFinding -Data $Data -RuleId 'LM16' -Severity $sev -Subject $g -Kind 'group' `
                -Detail "$($g.Name) has $($unexpected.Count) direct member(s) to review: $(($names | Select-Object -First 15) -join ', ')$(if ($names.Count -gt 15) { ' ...' }). $($cat.Tag). Transitive users: $($g.TransUsers)." -Fix $cat.Fix | Out-Null
        }
    }

    # ---- LM18: orphaned adminCount
    $protectedKeys = @('AO','ADM','BO','DA','DCS','EA','EKA','KA','PO','RODC','REPL','SA','SO')
    foreach ($n in $nodes) {
        if ($n.AdminCount -ne 1 -or $n.IsKrbtgt -or $n.IsRid500 -or $n.External) { continue }
        if ($n.Type -notin @('user','group')) { continue }
        if ($n.WkKey -and ($protectedKeys -contains $n.WkKey)) { continue }
        $protectedHit = $false
        foreach ($t in @($n.T0Targets)) { if ($nodes[$t].WkKey -and ($protectedKeys -contains $nodes[$t].WkKey)) { $protectedHit = $true; break } }
        if ($protectedHit) { continue }
        Add-LmFinding -Data $Data -RuleId 'LM18' -Severity 'Low' -Subject $n -Kind $(if ($n.Type -eq 'group') { 'group' } else { 'principal' }) `
            -Detail "$(if ($n.Sam) { $n.Sam } else { $n.Name }) ($($n.Type)) has adminCount=1 but is not a member of any AdminSDHolder-protected group any more. Inheritance is still disabled and the restrictive ACL remains." | Out-Null
    }

    # ---- LM19: baseline drift (group-to-group edges)
    $Data.BaselineDiff = $null
    if ($BaselinePath) {
        if (-not (Test-Path -LiteralPath $BaselinePath)) {
            Register-LmNotAssessed -Reason "Baseline file not found: $BaselinePath" -Target 'LM19'
        } else {
            try {
                $base = @(Import-Csv -LiteralPath $BaselinePath -ErrorAction Stop | Where-Object { $_.ChildType -eq 'group' })
                $baseKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($r in $base) { [void]$baseKeys.Add("$($r.ParentSam)|$($r.ChildSam)") }
                $curKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                $added = New-Object System.Collections.Generic.List[object]
                foreach ($e in $Data.Edges) {
                    if ($e.Kind -ne 'member') { continue }
                    $p = $nodes[$e.P]; $c = $nodes[$e.C]
                    if ($c.Type -ne 'group') { continue }
                    $key = "$($p.Sam)|$($c.Sam)"
                    [void]$curKeys.Add($key)
                    if ($baseKeys.Contains($key)) { continue }
                    $sev = 'Medium'
                    if ($p.WkTier -eq 0 -or $p.DeclTier -eq 0 -or $p.ReachesT0 -or $p.AdminIsh) { $sev = 'Critical' }
                    elseif ($p.WkTier -eq 'P' -or $p.Scope -eq 'DomainLocal') { $sev = 'High' }
                    $added.Add([pscustomobject]@{ Change='Added'; ParentSam=$p.Sam; ChildSam=$c.Sam; Severity=$sev })
                    Add-LmFinding -Data $Data -RuleId 'LM19' -Severity $sev -Subject $c -Target $p -Kind 'edge' -EdgeP $p.Id -EdgeC $c.Id -Path "$($c.Name) -> $($p.Name)" `
                        -Detail "NEW since baseline: group $($c.Name) is now a member of $(Get-LmGroupLabel $p)$(if ($p.ReachesT0) { " which reaches Tier 0 ($($p.T0Path))" })." | Out-Null
                }
                $removed = New-Object System.Collections.Generic.List[object]
                foreach ($k in $baseKeys) {
                    if ($curKeys.Contains($k)) { continue }
                    $parts = $k.Split('|', 2)
                    $removed.Add([pscustomobject]@{ Change='Removed'; ParentSam=$parts[0]; ChildSam=$parts[1]; Severity='Information' })
                    $subjId = -1
                    $subj = $null
                    if ($Data.BySam.TryGetValue($parts[1], [ref]$subjId)) { $subj = $nodes[$subjId] }
                    if (-not $subj) { $subj = New-LmNode -Id -1 -Dn "CN=$($parts[1])" -Type 'group'; $subj.Sam = $parts[1]; $subj.Name = $parts[1]; $subj.Id = -1 }
                    $f = [pscustomobject]@{ Id = $Data.Findings.Count + 1; RuleId='LM19'; Rule=$script:LmRules['LM19'].Title; Severity='Information'; SubjectId=$subj.Id; Subject=$parts[1]; SubjectName=$parts[1]; SubjectType='group'; TargetId=-1; Target=$parts[0]; Kind='edge'; Path="$($parts[1]) -> $($parts[0])"; Detail="REMOVED since baseline: group $($parts[1]) is no longer a member of $($parts[0])."; Fix='Confirm the removal was intended and update the baseline.'; EdgeP=-1; EdgeC=-1 }
                    $Data.Findings.Add($f)
                }
                $Data.BaselineDiff = @{ Path = $BaselinePath; BaselineEdges = $baseKeys.Count; CurrentEdges = $curKeys.Count; Added = $added; Removed = $removed }
                Write-LmLog "    [*] Baseline comparison: $($added.Count) new and $($removed.Count) removed group-to-group edges (baseline $($baseKeys.Count), current $($curKeys.Count))"
            } catch {
                Register-LmNotAssessed -Reason "Baseline file could not be read ($($_.Exception.Message)): $BaselinePath" -Target 'LM19'
            }
        }
    }

    foreach ($n in $nodes) {
        if ($n.Findings.Count -gt 0) { $n.RuleIds = (($n.Findings | ForEach-Object { $_.RuleId } | Sort-Object -Unique) -join ' ') }
    }
    Write-LmLog "    [*] Findings: $($Data.Findings.Count)"
}
#endregion

#region ===================================================== Outputs: TXT / CSV / JSON
function Get-LmOutputDirs {
    param([string]$OutputRoot)
    $root = $OutputRoot
    if ([string]::IsNullOrWhiteSpace($root)) { $root = Join-Path (Get-Location) $env:COMPUTERNAME }
    $html = $null; $source = $null
    if (Get-Command -Name 'Get-HtmlReportsDir' -ErrorAction SilentlyContinue) { try { $html = Get-HtmlReportsDir -BaseRoot $root } catch { } }
    if (Get-Command -Name 'Get-RawSourceDataDir' -ErrorAction SilentlyContinue) { try { $source = Get-RawSourceDataDir -BaseRoot $root } catch { } }
    if (-not $html)   { $html   = Join-Path $root 'HTML Reports' }
    if (-not $source) { $source = Join-Path (Join-Path $root 'Raw Data') 'Source' }
    $lm = Join-Path $source 'LateralMovement'
    foreach ($d in @($root, $html, $source, $lm)) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }
    return @{ Root = $root; Html = $html; Source = $source; Lm = $lm }
}

function Get-LmSummary {
    param($Data)
    $nodes = $Data.Nodes
    $bySev = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0; Information = 0 }
    $byRule = [ordered]@{}
    foreach ($rid in $script:LmRules.Keys) { $byRule[$rid] = @{ Count = 0; Critical = 0; High = 0; Medium = 0; Low = 0; Information = 0; Max = '' } }
    foreach ($f in $Data.Findings) {
        $bySev[$f.Severity]++
        $r = $byRule[$f.RuleId]
        $r.Count++; $r[$f.Severity]++
        if (-not $r.Max -or $script:LmSeverityRank[$f.Severity] -gt $script:LmSeverityRank[$r.Max]) { $r.Max = $f.Severity }
    }
    $t0Users = @($Data.PrincipalIds | ForEach-Object { $nodes[$_] } | Where-Object { $_.Type -eq 'user' -and $_.ReachesT0 -and -not $_.IsKrbtgt })
    $t0Hidden = @($t0Users | Where-Object { -not $_.T0DirectMember })
    $t0Enabled = @($t0Users | Where-Object { $_.Enabled })
    $t0Groups = @($Data.GroupIds | ForEach-Object { $nodes[$_] } | Where-Object { $_.ReachesT0 -and $_.DeclTier -ne 0 -and -not $_.WellKnown })
    $overall = 'Information'
    foreach ($s in @('Critical','High','Medium','Low')) { if ($bySev[$s] -gt 0) { $overall = $s; break } }
    return @{
        BySeverity = $bySev; ByRule = $byRule; Overall = $overall
        Tier0Users = $t0Users.Count; Tier0UsersEnabled = $t0Enabled.Count; Tier0UsersHidden = $t0Hidden.Count
        Tier0ReachingGroups = $t0Groups.Count; Tier0Sinks = $Data.T0Ids.Count
        GroupEdges = @($Data.Edges | Where-Object { $_.Kind -eq 'member' -and $nodes[$_.C].Type -eq 'group' }).Count
        Cycles = $Data.CycleCount
        Broad = @($Data.GroupIds | Where-Object { $nodes[$_].Broad -and -not $nodes[$_].WellKnown }).Count
    }
}

function Write-LmCsvOutputs {
    param($Data, $Dirs)
    $nodes = $Data.Nodes
    $lm = $Dirs.Lm
    $sevOrder = { $script:LmSeverityRank[$_.Severity] }

    $findingsCsv = Join-Path $lm 'lateral_movement_findings.csv'
    $Data.Findings | Sort-Object -Property @{ Expression = $sevOrder; Descending = $true }, RuleId, Subject |
        Select-Object Id, Severity, RuleId, Rule, Kind, SubjectType, Subject, SubjectName, Target, Path, Detail, Fix |
        Export-Csv -LiteralPath $findingsCsv -NoTypeInformation -Encoding UTF8

    $usersCsv = Join-Path $lm 'lateral_movement_users.csv'
    $Data.PrincipalIds | ForEach-Object { $nodes[$_] } | Where-Object { $_.Type -in @('user','computer','gmsa','msa') } |
        Sort-Object -Property @{ Expression = { $script:LmSeverityRank[$_.Severity] }; Descending = $true }, @{ Expression = 'Score'; Descending = $true }, Sam |
        ForEach-Object {
            [pscustomobject]@{
                SamAccountName   = $_.Sam
                Name             = $_.Name
                Type             = $_.Type
                Enabled          = $_.Enabled
                Severity         = $_.Severity
                Score            = $_.Score
                ReachesTier0     = $_.ReachesT0
                Tier0Direct      = $_.T0DirectMember
                Tier0Hops        = $_.T0Hops
                Tier0Groups      = (($_.T0Targets | ForEach-Object { $nodes[$_].Name } | Sort-Object -Unique) -join '; ')
                Tier0Path        = $_.T0Path
                PrivilegedGroups = (($_.PrivTargets | ForEach-Object { $nodes[$_].Name } | Sort-Object -Unique) -join '; ')
                DeclaredTier     = $_.DeclTier
                EffectiveTier    = $_.EffTier
                DirectGroups     = $_.ParentsCount
                TransitiveGroups = $_.TransGroupsUp
                ResourceGroupsReached = $_.ResourceReach
                AdminGroupsReached    = $_.AdminReach
                AdminNamed       = $_.AdminNamed
                ProtectedUsers   = $_.InProtectedUsers
                HasSPN           = $_.HasSpn
                PasswordLastSet  = $(if ($_.PwdLastSet) { $_.PwdLastSet.ToString('yyyy-MM-dd') } else { '' })
                LastLogon        = $(if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd') } else { '' })
                PrimaryGroupId   = $_.PrimaryGroupId
                AdminCount       = $_.AdminCount
                Rules            = $_.RuleIds
                DistinguishedName = $_.Dn
            }
        } | Export-Csv -LiteralPath $usersCsv -NoTypeInformation -Encoding UTF8

    $groupsCsv = Join-Path $lm 'lateral_movement_groups.csv'
    $Data.GroupIds | ForEach-Object { $nodes[$_] } |
        Sort-Object -Property @{ Expression = { $script:LmSeverityRank[$_.Severity] }; Descending = $true }, @{ Expression = 'Score'; Descending = $true }, Name |
        ForEach-Object {
            $pl = $null; $memberOf = ''
            if ($Data.Parents.TryGetValue($_.Id, [ref]$pl)) { $memberOf = (($pl | ForEach-Object { $nodes[$_].Name } | Sort-Object) -join '; ') }
            [pscustomobject]@{
                SamAccountName    = $_.Sam
                Name              = $_.Name
                Scope             = $_.Scope
                SecurityGroup     = $_.Security
                WellKnown         = $_.WellKnown
                DeclaredTier      = $_.DeclTier
                DeclaredTierSource = $_.DeclTierSource
                EffectiveTier     = $_.EffTier
                TierVia           = $_.TierVia
                Severity          = $_.Severity
                Score             = $_.Score
                ReachesTier0      = $_.ReachesT0
                DistanceToTier0   = $_.DistT0
                Tier0Path         = $_.T0Path
                Tier0Groups       = (($_.T0Targets | ForEach-Object { $nodes[$_].Name } | Sort-Object -Unique) -join '; ')
                DirectUsers       = $_.DirectUsers
                DirectGroups      = $_.DirectGroups
                DirectComputers   = $_.DirectComputers
                DirectOther       = $_.DirectOther
                TransitiveUsers   = $_.TransUsers
                TransitiveEnabledUsers = $_.TransEnabledUsers
                TransitiveComputers = $_.TransComputers
                MemberOfDirect    = $_.ParentsCount
                MemberOfTransitive = $_.TransGroupsUp
                MemberOf          = $memberOf
                NestingDepthBelow = $_.Height
                Broad             = $_.Broad
                BroadReason       = $_.BroadReason
                AdminIsh          = $_.AdminIsh
                Temporary         = $_.Temporary
                InCycle           = $_.InCycle
                AdminCount        = $_.AdminCount
                ManagedBy         = $_.ManagedBy
                Description       = $_.Description
                WhenCreated       = $(if ($_.WhenCreated -is [datetime]) { $_.WhenCreated.ToString('yyyy-MM-dd') } else { '' })
                WhenChanged       = $(if ($_.WhenChanged -is [datetime]) { $_.WhenChanged.ToString('yyyy-MM-dd') } else { '' })
                Rules             = $_.RuleIds
                DistinguishedName = $_.Dn
            }
        } | Export-Csv -LiteralPath $groupsCsv -NoTypeInformation -Encoding UTF8

    # Every edge where a group (or other principal) is a member of a group. The group-to-group
    # rows are the baseline for the next run (-BaselinePath).
    $edgesCsv = Join-Path $lm 'lateral_movement_edges.csv'
    $Data.Edges | Where-Object { $_.Kind -eq 'member' -and $nodes[$_.C].Type -eq 'group' } | ForEach-Object {
        $p = $nodes[$_.P]; $c = $nodes[$_.C]
        [pscustomobject]@{
            ParentSam = $p.Sam; ParentName = $p.Name; ParentScope = $p.Scope; ParentWellKnown = $p.WellKnown; ParentReachesTier0 = $p.ReachesT0
            ChildSam = $c.Sam; ChildName = $c.Name; ChildType = $c.Type; ChildScope = $c.Scope; ChildTransitiveUsers = $c.TransUsers
            EdgeKind = $_.Kind; ParentDn = $p.Dn; ChildDn = $c.Dn
        }
    } | Sort-Object ParentSam, ChildSam | Export-Csv -LiteralPath $edgesCsv -NoTypeInformation -Encoding UTF8

    $pathsCsv = Join-Path $lm 'lateral_movement_tier0_paths.csv'
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($id in $Data.PrincipalIds) { $n = $nodes[$id]; if ($n.ReachesT0 -and $n.T0Path) { $rows.Add([pscustomobject]@{ Principal = $n.Sam; Type = $n.Type; Enabled = $n.Enabled; Hops = $n.T0Hops; Direct = $n.T0DirectMember; Tier0Groups = (($n.T0Targets | ForEach-Object { $nodes[$_].Name } | Sort-Object -Unique) -join '; '); ShortestPath = $n.T0Path }) } }
    foreach ($id in $Data.GroupIds) { $n = $nodes[$id]; if ($n.ReachesT0 -and $n.DistT0 -gt 0 -and -not $n.WellKnown) { $rows.Add([pscustomobject]@{ Principal = $n.Sam; Type = 'group'; Enabled = $true; Hops = $n.DistT0; Direct = ($n.DistT0 -eq 1); Tier0Groups = (($n.T0Targets | ForEach-Object { $nodes[$_].Name } | Sort-Object -Unique) -join '; '); ShortestPath = $n.T0Path }) } }
    $rows | Sort-Object Type, Hops, Principal | Export-Csv -LiteralPath $pathsCsv -NoTypeInformation -Encoding UTF8

    if ($Data.BaselineDiff) {
        $diffCsv = Join-Path $lm 'lateral_movement_baseline_diff.csv'
        @($Data.BaselineDiff.Added) + @($Data.BaselineDiff.Removed) | Export-Csv -LiteralPath $diffCsv -NoTypeInformation -Encoding UTF8
    }
    return @{ Findings = $findingsCsv; Users = $usersCsv; Groups = $groupsCsv; Edges = $edgesCsv; Paths = $pathsCsv }
}

function Write-LmTextReport {
    param($Data, $Summary, $Dirs, [string]$HtmlPath, [string]$ScriptLine)
    $nodes = $Data.Nodes
    $txtPath = Join-Path $Dirs.Source 'lateral_movement.txt'
    $sb = New-Object System.Text.StringBuilder
    $line = '=' * 78
    [void]$sb.AppendLine($line)
    [void]$sb.AppendLine(' LATERAL MOVEMENT ANALYSIS - GROUP NESTING (member / memberOf)')
    [void]$sb.AppendLine($line)
    [void]$sb.AppendLine(" Domain      : $($Data.DomainDns) ($($Data.DomainDn))")
    [void]$sb.AppendLine(" Generated   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine(" Severity    : $($Summary.Overall)")
    [void]$sb.AppendLine(" HTML map    : $HtmlPath")
    [void]$sb.AppendLine(" Evidence    : $($Dirs.Lm)")
    [void]$sb.AppendLine(" Command     : $ScriptLine")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('What this is:')
    [void]$sb.AppendLine(' Every group membership edge in the domain was followed transitively along memberOf.')
    [void]$sb.AppendLine(' "I am memberOf X" means "I inherit the rights of X" - that is the direction an attacker')
    [void]$sb.AppendLine(' uses and the direction ADUC hides (it shows one hop). Findings are grouped by rule LM01-LM23;')
    [void]$sb.AppendLine(' each rule is explained at the end of this file and in the HTML map (Rules & guidance).')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('--- INVENTORY ---')
    [void]$sb.AppendLine(" Groups: $($Data.Stats.Groups)   Users: $($Data.Stats.Users) ($($Data.Stats.EnabledUsers) enabled)   Computers: $($Data.Stats.Computers)   Managed service accounts: $($Data.Stats.ServiceAccounts)")
    [void]$sb.AppendLine(" Membership edges: $($Data.Edges.Count) (group-in-group: $($Summary.GroupEdges), via primaryGroupID: $($Data.Stats.PrimaryEdges))")
    [void]$sb.AppendLine(" Foreign security principals: $($Data.Stats.Fsp)   Cross-domain members: $($Data.Stats.External)   Unresolved members: $($Data.Stats.Unresolved)")
    [void]$sb.AppendLine(" Tier 0 / privileged sink groups: $($Summary.Tier0Sinks)   Groups reaching Tier 0 through nesting: $($Summary.Tier0ReachingGroups)   Membership loops: $($Summary.Cycles)   Broad (everyone) groups: $($Summary.Broad)")
    [void]$sb.AppendLine(" Users effectively Tier 0: $($Summary.Tier0Users) ($($Summary.Tier0UsersEnabled) enabled, $($Summary.Tier0UsersHidden) only through nesting)")
    [void]$sb.AppendLine('')
    if ($script:LmNotAssessed.Count -gt 0) {
        [void]$sb.AppendLine('--- REDUCED COVERAGE (not findings) ---')
        foreach ($na in $script:LmNotAssessed) { [void]$sb.AppendLine(" - $($na.Reason)$(if ($na.Target) { " [$($na.Target)]" })") }
        [void]$sb.AppendLine('')
    }
    if ($Data.Coverage.Count -gt 0) {
        foreach ($c in $Data.Coverage) { [void]$sb.AppendLine(" Note: $c") }
        [void]$sb.AppendLine('')
    }
    [void]$sb.AppendLine('--- FINDINGS BY SEVERITY ---')
    foreach ($s in $Summary.BySeverity.Keys) { [void]$sb.AppendLine(("   {0,-12} {1,6}" -f $s, $Summary.BySeverity[$s])) }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('--- FINDINGS BY RULE ---')
    foreach ($rid in $Summary.ByRule.Keys) {
        $r = $Summary.ByRule[$rid]
        if ($r.Count -eq 0) { continue }
        [void]$sb.AppendLine(("   {0} {1,-70} {2,5}  (worst: {3})" -f $rid, $script:LmRules[$rid].Title, $r.Count, $r.Max))
    }
    [void]$sb.AppendLine('')

    $ordered = $Data.Findings | Sort-Object -Property @{ Expression = { $script:LmSeverityRank[$_.Severity] }; Descending = $true }, RuleId, Subject
    [void]$sb.AppendLine('--- FINDINGS (Critical and High in full, others capped at 40 per rule) ---')
    $perRule = @{}
    foreach ($f in $ordered) {
        if ($f.Severity -notin @('Critical','High')) {
            if (-not $perRule.ContainsKey($f.RuleId)) { $perRule[$f.RuleId] = 0 }
            $perRule[$f.RuleId]++
            if ($perRule[$f.RuleId] -gt 40) { continue }
        }
        [void]$sb.AppendLine(("[{0}] {1} {2} - {3}" -f $f.Severity.ToUpperInvariant(), $f.RuleId, $f.SubjectType, $f.Subject))
        if ($f.Path) { [void]$sb.AppendLine("    Path  : $($f.Path)") }
        [void]$sb.AppendLine("    Detail: $($f.Detail)")
        [void]$sb.AppendLine("    Fix   : $($f.Fix)")
        [void]$sb.AppendLine('')
    }
    foreach ($rid in $perRule.Keys) { if ($perRule[$rid] -gt 40) { [void]$sb.AppendLine(" ... $($perRule[$rid] - 40) more $rid findings in lateral_movement_findings.csv") } }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('--- EFFECTIVE TIER 0 PRINCIPALS (shortest path) ---')
    $t0 = @($Data.PrincipalIds | ForEach-Object { $nodes[$_] } | Where-Object { $_.ReachesT0 -and -not $_.IsKrbtgt } | Sort-Object -Property @{ Expression = { $_.T0DirectMember }; Descending = $false }, T0Hops, Sam)
    if ($t0.Count -eq 0) { [void]$sb.AppendLine(' (none found)') }
    foreach ($p in ($t0 | Select-Object -First 500)) {
        [void]$sb.AppendLine(("   {0,-8} {1,-28} {2,-8} {3,-7} hops={4,-2} {5}" -f $p.Type, $p.Sam, $(if ($p.Enabled) { 'enabled' } else { 'DISABLED' }), $(if ($p.T0DirectMember) { 'direct' } else { 'NESTED' }), $p.T0Hops, $p.T0Path))
    }
    if ($t0.Count -gt 500) { [void]$sb.AppendLine("   ... $($t0.Count - 500) more in lateral_movement_users.csv") }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('--- GROUPS THAT REACH TIER 0 THROUGH NESTING ---')
    $gg = @($Data.GroupIds | ForEach-Object { $nodes[$_] } | Where-Object { $_.ReachesT0 -and $_.DistT0 -gt 0 -and -not $_.WellKnown } | Sort-Object DistT0, Name)
    if ($gg.Count -eq 0) { [void]$sb.AppendLine(' (none found)') }
    foreach ($g in $gg) { [void]$sb.AppendLine(("   {0,-40} {1,-12} users={2,-6} hops={3,-2} {4}" -f $g.Name, $g.Scope, $g.TransUsers, $g.DistT0, $g.T0Path)) }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('--- RULES ---')
    foreach ($rid in $script:LmRules.Keys) {
        $r = $script:LmRules[$rid]
        [void]$sb.AppendLine("$rid $($r.Title) [default $($r.Default)]")
        [void]$sb.AppendLine("  What: $($r.What)")
        [void]$sb.AppendLine("  Why : $($r.Why)")
        [void]$sb.AppendLine("  Fix : $($r.Fix)")
        [void]$sb.AppendLine('')
    }
    [void]$sb.AppendLine('Limitations: AD group nesting only. Local Administrators groups on servers, GPO Restricted Groups,')
    [void]$sb.AppendLine('share/NTFS/SQL permissions and ACL-based paths are not visible here - run BloodHound and the')
    [void]$sb.AppendLine('Delegated-permissions / Dangerous-ACL checks for those. Group names and scopes are used to estimate')
    [void]$sb.AppendLine('what a chain grants; validate against the systems the groups are used on.')
    Set-Content -LiteralPath $txtPath -Value $sb.ToString() -Encoding UTF8
    return $txtPath
}

function Get-LmHtmlJson {
    # Builds the JSON model embedded in the HTML map with a StringBuilder (ConvertTo-Json is
    # too slow for 100k objects). Users are capped by HtmlUserLimit, highest risk first.
    param($Data, $Summary, [int]$HtmlUserLimit, $Dirs, [string]$HtmlPath)
    $nodes = $Data.Nodes
    $include = New-Object System.Collections.Generic.HashSet[int]
    foreach ($gid in $Data.GroupIds) { [void]$include.Add($gid) }
    $principals = @($Data.PrincipalIds | ForEach-Object { $nodes[$_] } | Sort-Object -Property @{ Expression = { $script:LmSeverityRank[$_.Severity] }; Descending = $true }, @{ Expression = 'Score'; Descending = $true }, @{ Expression = { $_.ReachesT0 }; Descending = $true }, @{ Expression = { $_.Type -ne 'user' }; Descending = $true }, Sam)
    $embeddedPrincipals = 0
    foreach ($p in $principals) {
        if ($p.Type -in @('fsp','external','unknown','contact','other')) { [void]$include.Add($p.Id); continue }
        if ($embeddedPrincipals -ge $HtmlUserLimit) { break }
        [void]$include.Add($p.Id); $embeddedPrincipals++
    }
    $truncated = [math]::Max(0, $Data.PrincipalIds.Count - $include.Count + $Data.GroupIds.Count)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{"meta":')
    $meta = [ordered]@{
        domain = $Data.DomainDns; domainDn = $Data.DomainDn; netbios = $Data.NetBios; generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        version = $script:LmVersion; overall = $Summary.Overall
        stats = [ordered]@{ groups = $Data.Stats.Groups; users = $Data.Stats.Users; enabledUsers = $Data.Stats.EnabledUsers; computers = $Data.Stats.Computers; serviceAccounts = $Data.Stats.ServiceAccounts; edges = $Data.Edges.Count; groupEdges = $Summary.GroupEdges; primaryEdges = $Data.Stats.PrimaryEdges; fsp = $Data.Stats.Fsp; external = $Data.Stats.External; unresolved = $Data.Stats.Unresolved; cycles = $Summary.Cycles; broad = $Summary.Broad; t0Sinks = $Summary.Tier0Sinks; t0Groups = $Summary.Tier0ReachingGroups; t0Users = $Summary.Tier0Users; t0UsersEnabled = $Summary.Tier0UsersEnabled; t0UsersHidden = $Summary.Tier0UsersHidden }
        bySeverity = $Summary.BySeverity
        embeddedPrincipals = $embeddedPrincipals; principalsTotal = $Data.PrincipalIds.Count; truncated = ($embeddedPrincipals -lt ($Data.PrincipalIds.Count - $Data.Stats.Fsp - $Data.Stats.External - $Data.Stats.Unresolved))
        notAssessed = @($script:LmNotAssessed | ForEach-Object { "$($_.Reason)$(if ($_.Target) { " [$($_.Target)]" })" })
        coverage = @($Data.Coverage)
        evidenceDir = $Dirs.Lm; htmlPath = $HtmlPath
        baseline = $(if ($Data.BaselineDiff) { [ordered]@{ path = $Data.BaselineDiff.Path; baselineEdges = $Data.BaselineDiff.BaselineEdges; currentEdges = $Data.BaselineDiff.CurrentEdges; added = $Data.BaselineDiff.Added.Count; removed = $Data.BaselineDiff.Removed.Count } } else { $null })
    }
    [void]$sb.Append((Get-LmJsonValue $meta))
    [void]$sb.Append(',"rules":')
    $rulesObj = [ordered]@{}
    foreach ($rid in $script:LmRules.Keys) { $r = $script:LmRules[$rid]; $rulesObj[$rid] = [ordered]@{ title = $r.Title; severity = $r.Default; what = $r.What; why = $r.Why; fix = $r.Fix; count = $Summary.ByRule[$rid].Count; max = $Summary.ByRule[$rid].Max } }
    [void]$sb.Append((Get-LmJsonValue $rulesObj))
    [void]$sb.Append(',"catalog":')
    $catObj = @()
    foreach ($c in (Get-LmWellKnownCatalog)) { $catObj += [ordered]@{ key = $c.Key; name = $c.Name; tier = [string]$c.Tier; severity = $c.Severity; tag = $c.Tag; why = $c.Why; fix = $c.Fix } }
    [void]$sb.Append((Get-LmJsonValue $catObj))

    # nodes: compact arrays keyed by field order (see JS: NF)
    [void]$sb.Append(',"nf":["id","t","n","s","dn","en","sc","sec","wk","wkt","dt","et","via","desc","ou","du","dg","dc","tu","te","tg","pc","dist","hops","t0","path","res","adm","broad","br","admish","temp","cyc","h","sev","score","rules","spn","pu","adminNamed","pwd","logon","pgid","ext","t0direct","prot","ac","os","changed","owner"]')
    [void]$sb.Append(',"nodes":[')
    $first = $true
    foreach ($n in $nodes) {
        if (-not $include.Contains($n.Id)) { continue }
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        $vals = @(
            $n.Id, $n.Type, $n.Name, $n.Sam, $n.Dn, $n.Enabled, $n.Scope, $n.Security, $n.WellKnown, $(if ($null -ne $n.WkTier) { [string]$n.WkTier } else { $null }),
            $n.DeclTier, $n.EffTier, $n.TierVia, $n.Description, $n.OU, $n.DirectUsers, $n.DirectGroups, $n.DirectComputers, $n.TransUsers, $n.TransEnabledUsers,
            $n.TransGroupsUp, $n.ParentsCount, $n.DistT0, $n.T0Hops, @($n.T0Targets), $n.T0Path, $n.ResourceReach, $n.AdminReach, $n.Broad, $n.BroadReason,
            $n.AdminIsh, $n.Temporary, $n.CycleId, $n.Height, $n.Severity, $n.Score, $n.RuleIds, $n.HasSpn, $n.InProtectedUsers, $n.AdminNamed,
            $n.PwdLastSet, $n.LastLogon, $n.PrimaryGroupId, $n.External, $n.T0DirectMember, $n.Protective, $n.AdminCount, $n.OS, $n.WhenChanged, $(if ($n.ManagedBy) { Get-LmRdnValue $n.ManagedBy } else { '' })
        )
        [void]$sb.Append('[')
        $fv = $true
        foreach ($v in $vals) {
            if (-not $fv) { [void]$sb.Append(',') }
            $fv = $false
            [void]$sb.Append((Get-LmJsonValue $v))
        }
        [void]$sb.Append(']')
    }
    [void]$sb.Append(']')
    # edges: [parent, child, kind] - only edges whose both ends are embedded
    [void]$sb.Append(',"edges":[')
    $first = $true
    foreach ($e in $Data.Edges) {
        if (-not ($include.Contains($e.P) -and $include.Contains($e.C))) { continue }
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        [void]$sb.Append("[$($e.P),$($e.C),$(if ($e.Kind -eq 'primary') { 1 } else { 0 })]")
    }
    [void]$sb.Append(']')
    # findings
    [void]$sb.Append(',"findings":[')
    $first = $true
    foreach ($f in $Data.Findings) {
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        $fo = [ordered]@{ id = $f.Id; r = $f.RuleId; sev = $f.Severity; k = $f.Kind; sid = $f.SubjectId; s = $f.Subject; st = $f.SubjectType; tid = $f.TargetId; t = $f.Target; p = $f.Path; d = $f.Detail; fix = $f.Fix; ep = $f.EdgeP; ec = $f.EdgeC }
        [void]$sb.Append((Get-LmJsonValue $fo))
    }
    [void]$sb.Append(']')
    if ($Data.BaselineDiff) {
        [void]$sb.Append(',"baselineDiff":')
        $rows = @()
        foreach ($r in @($Data.BaselineDiff.Added) + @($Data.BaselineDiff.Removed)) { $rows += [ordered]@{ change = $r.Change; parent = $r.ParentSam; child = $r.ChildSam; sev = $r.Severity } }
        [void]$sb.Append((Get-LmJsonValue $rows))
    }
    [void]$sb.Append('}')
    return $sb.ToString()
}
#endregion

#region ===================================================== HTML: styles and markup
$script:LmHtmlCss = @'
<style>
:root{--bg:#f5f7fb;--panel:#ffffff;--panel2:#f8fafc;--text:#1b2430;--muted:#5f6b7a;--line:#d9e0ea;--shadow:0 10px 24px rgba(15,23,42,.08);--radius:14px;
--accent:#3b82f6;--accent-soft:#dbeafe;--critical:#c62828;--critical-soft:#fdecec;--high:#ef6c00;--high-soft:#fff2e5;--medium:#0277bd;--medium-soft:#e8f4fd;
--low:#2e7d32;--low-soft:#edf8ee;--info:#6c757d;--info-soft:#f2f4f6;--t0:#7f1d1d;--t0-soft:#fee2e2;--edge:#94a3b8;--edge-bad:#dc2626;--edge-warn:#f59e0b;--edge-path:#2563eb;--node-user:#0ea5e9;--node-group:#64748b}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f172a;--panel:#1e293b;--panel2:#162032;--text:#e2e8f0;--muted:#94a3b8;--line:#334155;--shadow:0 10px 24px rgba(0,0,0,.4);
--accent:#60a5fa;--accent-soft:rgba(96,165,250,.15);--critical:#f87171;--critical-soft:rgba(248,113,113,.15);--high:#fb923c;--high-soft:rgba(251,146,60,.15);--medium:#60a5fa;--medium-soft:rgba(96,165,250,.15);
--low:#4ade80;--low-soft:rgba(74,222,128,.15);--info:#94a3b8;--info-soft:rgba(148,163,184,.15);--t0:#fca5a5;--t0-soft:rgba(248,113,113,.22);--edge:#475569;--edge-bad:#f87171;--edge-warn:#fbbf24;--edge-path:#93c5fd}}
:root[data-theme="dark"]{--bg:#0f172a;--panel:#1e293b;--panel2:#162032;--text:#e2e8f0;--muted:#94a3b8;--line:#334155;--shadow:0 10px 24px rgba(0,0,0,.4);
--accent:#60a5fa;--accent-soft:rgba(96,165,250,.15);--critical:#f87171;--critical-soft:rgba(248,113,113,.15);--high:#fb923c;--high-soft:rgba(251,146,60,.15);--medium:#60a5fa;--medium-soft:rgba(96,165,250,.15);
--low:#4ade80;--low-soft:rgba(74,222,128,.15);--info:#94a3b8;--info-soft:rgba(148,163,184,.15);--t0:#fca5a5;--t0-soft:rgba(248,113,113,.22);--edge:#475569;--edge-bad:#f87171;--edge-warn:#fbbf24;--edge-path:#93c5fd}
*,*::before,*::after{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,-apple-system,Arial,sans-serif;line-height:1.5;-webkit-font-smoothing:antialiased}
body{padding:20px 16px}
.container{max-width:1600px;margin:0 auto}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
code,.mono{font-family:Consolas,Menlo,Monaco,monospace;font-size:.9em}
.hero{background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);padding:22px 26px;margin-bottom:16px;display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start;justify-content:space-between}
.hero h1{margin:0 0 4px;font-size:1.5rem}.hero .meta{color:var(--muted);font-size:.86rem}
.hero .verdict{display:flex;flex-direction:column;align-items:flex-end;gap:6px}
.btn{display:inline-block;padding:6px 12px;border-radius:999px;border:1px solid var(--line);background:var(--panel2);color:var(--text);font-size:.82rem;font-weight:600;cursor:pointer;user-select:none}
.btn:hover{background:var(--accent-soft)}.btn.primary{background:var(--accent);color:#fff;border-color:var(--accent)}.btn.sm{padding:3px 9px;font-size:.76rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:0 0 16px}
.stat{background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);padding:12px 14px;text-align:center;cursor:default}
.stat .val{font-size:1.5rem;font-weight:700;line-height:1.1}.stat .lbl{font-size:.74rem;color:var(--muted);margin-top:3px;text-transform:uppercase;letter-spacing:.04em}
.stat.critical .val{color:var(--critical)}.stat.high .val{color:var(--high)}.stat.medium .val{color:var(--medium)}.stat.low .val{color:var(--low)}.stat.info .val{color:var(--info)}.stat.t0 .val{color:var(--t0)}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:.76rem;font-weight:600;letter-spacing:.02em;white-space:nowrap}
.badge-critical{background:var(--critical-soft);color:var(--critical)}.badge-high{background:var(--high-soft);color:var(--high)}.badge-medium{background:var(--medium-soft);color:var(--medium)}
.badge-low{background:var(--low-soft);color:var(--low)}.badge-information,.badge-info{background:var(--info-soft);color:var(--info)}.badge-t0{background:var(--t0-soft);color:var(--t0)}
.badge-tag{background:var(--accent-soft);color:var(--text)}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 12px}
.tab{padding:8px 14px;border-radius:999px;border:1px solid var(--line);background:var(--panel);cursor:pointer;font-weight:600;font-size:.86rem}
.tab.active{background:var(--accent);color:#fff;border-color:var(--accent)}.tab .cnt{opacity:.75;font-weight:500;margin-left:4px}
.view{display:none}.view.active{display:block}
.card{background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);padding:16px 18px;margin-bottom:14px}
.card h2{margin:0 0 10px;font-size:1.1rem}.card h3{margin:14px 0 6px;font-size:.95rem}
.note{background:var(--panel2);border-left:4px solid var(--accent);padding:10px 14px;border-radius:8px;font-size:.88rem;margin:8px 0}
.note.warn{border-left-color:var(--high)}
/* map layout */
.maplayout{display:grid;grid-template-columns:270px 1fr;gap:12px;min-height:640px}
.details{position:absolute;top:50px;right:10px;bottom:46px;width:min(460px,62%);z-index:6;display:none;border:1px solid var(--line)}
.details.open{display:block}
.details .closebtn{float:right;cursor:pointer;font-size:1.1rem;line-height:1;padding:0 6px;color:var(--muted)}.details .closebtn:hover{color:var(--text)}
@media(max-width:900px){.details{position:static;width:auto;max-height:none;margin-top:10px}.details.open{display:block}}
.sidebar,.details{background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);padding:12px 14px;font-size:.86rem;overflow:auto;max-height:860px}
.sidebar h4,.details h4{margin:10px 0 6px;font-size:.78rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.sidebar label{display:flex;align-items:center;gap:6px;margin:2px 0;cursor:pointer}
.sidebar input[type=text],.details input[type=text],.filterbar input[type=text],.filterbar select,.sidebar select{width:100%;padding:6px 8px;border:1px solid var(--line);border-radius:8px;background:var(--panel2);color:var(--text);font-size:.86rem}
.sidebar input[type=range]{width:100%}
.suggest{position:relative}.suggest .list{position:absolute;left:0;right:0;top:100%;z-index:20;background:var(--panel);border:1px solid var(--line);border-radius:8px;box-shadow:var(--shadow);max-height:260px;overflow:auto;display:none}
.suggest .list div{padding:6px 8px;cursor:pointer;border-bottom:1px solid var(--line)}.suggest .list div:hover{background:var(--accent-soft)}.suggest .list small{color:var(--muted);margin-left:6px}
.mapwrap{position:relative;background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;min-height:640px}
.mapwrap svg{width:100%;height:100%;min-height:640px;display:block;cursor:grab}.mapwrap svg.dragging{cursor:grabbing}
.maptools{position:absolute;top:10px;left:10px;display:flex;gap:6px;flex-wrap:wrap;z-index:5}
.mapinfo{position:absolute;bottom:10px;left:10px;right:10px;font-size:.78rem;color:var(--muted);background:var(--panel);opacity:.95;padding:6px 10px;border-radius:8px;border:1px solid var(--line);z-index:5;pointer-events:none}
.legend{position:absolute;bottom:50px;right:10px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:8px 10px;font-size:.74rem;z-index:5;max-width:260px}
.legend.hidden{display:none}.legend div{display:flex;align-items:center;gap:6px;margin:2px 0}.legend .sw{width:14px;height:14px;border-radius:4px;border:2px solid #000;flex:none}
.legend .ln{width:22px;height:0;border-top:3px solid #000;flex:none}
.node{cursor:grab}.node.dragging{cursor:grabbing}.node rect,.node circle,.node polygon{stroke-width:2}.node text{font-size:11px;pointer-events:none;fill:var(--text)}.node .icon{font-size:9px;font-weight:700;fill:#fff}
.node.selected rect,.node.selected circle,.node.selected polygon{stroke:var(--accent)!important;stroke-width:4}
.node.dim{opacity:.18}.edge.dim{opacity:.08}
.edge{fill:none;stroke:var(--edge);stroke-width:1.4}.edge.bad{stroke:var(--edge-bad);stroke-width:2.4}.edge.warn{stroke:var(--edge-warn);stroke-width:2}.edge.path{stroke:var(--edge-path);stroke-width:3}.edge.primary{stroke-dasharray:5 4}
.edge.hl{stroke:var(--accent);stroke-width:3.5}
.layerlabel{font-size:11px;fill:var(--muted);font-weight:600;letter-spacing:.05em}
.tip{position:absolute;pointer-events:none;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:.8rem;box-shadow:var(--shadow);max-width:360px;z-index:10;display:none}
/* details */
.details .title{font-size:1.05rem;font-weight:700;margin:0 0 4px;word-break:break-word}
.details .kv{display:grid;grid-template-columns:120px 1fr;gap:3px 8px;font-size:.82rem;margin:6px 0}.details .kv div:nth-child(odd){color:var(--muted)}
.details ul{margin:4px 0;padding-left:18px}.details li{margin:2px 0}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;background:var(--accent-soft);font-size:.76rem;margin:1px 2px;cursor:pointer;border:1px solid transparent}
.chip:hover{border-color:var(--accent)}.chip.t0{background:var(--t0-soft);color:var(--t0)}.chip.priv{background:var(--high-soft);color:var(--high)}.chip.res{background:var(--medium-soft)}.chip.adm{background:var(--high-soft)}
.finding{border-left:4px solid var(--info);background:var(--panel2);border-radius:8px;padding:8px 10px;margin:6px 0;font-size:.82rem}
.finding.critical{border-left-color:var(--critical)}.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--medium)}.finding.low{border-left-color:var(--low)}
.finding .fhead{display:flex;gap:8px;align-items:center;flex-wrap:wrap;font-weight:600;margin-bottom:4px}.finding .fix{color:var(--muted);margin-top:4px}
.pathline{font-family:Consolas,Menlo,monospace;font-size:.78rem;background:var(--panel2);padding:4px 8px;border-radius:6px;margin:3px 0;cursor:pointer;word-break:break-all}.pathline:hover{background:var(--accent-soft)}
.pathline .hop{color:var(--muted)}.pathline .bad{color:var(--critical);font-weight:700}
/* tables */
.filterbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}.filterbar > *{flex:0 1 auto}.filterbar input[type=text]{min-width:260px}.filterbar label{font-size:.82rem;display:flex;gap:4px;align-items:center}
table.grid{width:100%;border-collapse:separate;border-spacing:0;background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;font-size:.84rem}
table.grid thead th{background:var(--accent-soft);text-align:left;padding:9px 10px;font-size:.76rem;text-transform:uppercase;letter-spacing:.04em;cursor:pointer;position:sticky;top:0;z-index:1;border-bottom:2px solid var(--line);white-space:nowrap}
table.grid tbody td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}table.grid tbody tr:hover{background:var(--accent-soft);cursor:pointer}table.grid tbody tr:last-child td{border-bottom:none}
.tablewrap{max-height:70vh;overflow:auto;border-radius:var(--radius)}
.more{margin:8px 0;color:var(--muted);font-size:.82rem}
.rule{border-left:5px solid var(--info);background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);padding:12px 16px;margin:10px 0}
.rule.critical{border-left-color:var(--critical)}.rule.high{border-left-color:var(--high)}.rule.medium{border-left-color:var(--medium)}.rule.low{border-left-color:var(--low)}
.rule h3{margin:0 0 6px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}.rule p{margin:4px 0;font-size:.88rem}.rule p b{color:var(--muted)}
.footer{margin-top:28px;padding-top:12px;border-top:1px solid var(--line);color:var(--muted);font-size:.8rem;text-align:center}
.primary-nav{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 16px;padding:10px 14px;background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}
.primary-nav-link{padding:6px 12px;border-radius:999px;font-size:.85rem;font-weight:600;text-decoration:none;color:var(--text);border:1px solid transparent}
.primary-nav-link:hover{background:var(--accent-soft);text-decoration:none}.primary-nav-link.active{background:var(--accent);color:#fff;border-color:var(--accent)}
@media(max-width:768px){body{padding:12px 10px}.maplayout{grid-template-columns:1fr}.hero{padding:16px}}
</style>
'@

$script:LmHtmlBody = @'
<div class="hero">
  <div>
    <h1>Lateral Movement Map - group nesting analysis</h1>
    <div class="meta" id="heroMeta"></div>
    <div class="meta" style="margin-top:6px">Direction of every arrow: <b>member &rarr; group</b> = "inherits the rights of". Follow arrows upward to see where an account can move; follow them backwards to see who gets in.</div>
  </div>
  <div class="verdict">
    <span id="overallBadge" class="badge"></span>
    <div><span class="btn sm" id="themeBtn">Theme</span> <a class="btn sm" id="evidenceLink" href="#">Evidence folder</a></div>
  </div>
</div>
<div class="stats" id="stats"></div>
<div id="coverageNotes"></div>
<div class="tabs" id="tabs">
  <div class="tab active" data-view="map">Map</div>
  <div class="tab" data-view="findings">Findings<span class="cnt" id="cntFindings"></span></div>
  <div class="tab" data-view="users">Accounts<span class="cnt" id="cntUsers"></span></div>
  <div class="tab" data-view="groups">Groups<span class="cnt" id="cntGroups"></span></div>
  <div class="tab" data-view="paths">Tier 0 paths<span class="cnt" id="cntPaths"></span></div>
  <div class="tab" data-view="rules">Rules &amp; guidance</div>
  <div class="tab" data-view="baseline" id="tabBaseline" style="display:none">Baseline drift<span class="cnt" id="cntBaseline"></span></div>
</div>

<div class="view active" id="view-map">
<div class="maplayout">
  <div class="sidebar">
    <h4>Find</h4>
    <div class="suggest"><input type="text" id="search" placeholder="user, group, computer ... (Enter = focus)" autocomplete="off"><div class="list" id="searchList"></div></div>
    <h4>View</h4>
    <label><input type="radio" name="mode" value="overview" checked> Privilege overview (groups that reach Tier 0 / have findings)</label>
    <label><input type="radio" name="mode" value="focus"> Focus on selected node (hop by hop)</label>
    <label><input type="radio" name="mode" value="all"> All groups (large)</label>
    <div id="focusOpts" style="display:none;margin:4px 0 0 18px">
      <label>Hops: <span id="hopsVal">3</span></label><input type="range" id="hops" min="1" max="8" value="3">
      <label><input type="checkbox" id="dirOut" checked> Outward (member of &rarr; what it can reach)</label>
      <label><input type="checkbox" id="dirIn" checked> Inward (members &rarr; who gets in)</label>
      <label><input type="checkbox" id="showUsers" checked> Show user / computer nodes (max <span id="userCapVal">80</span> per group)</label>
    </div>
    <h4>Severity</h4>
    <label><input type="checkbox" class="sevf" value="Critical" checked> <span class="badge badge-critical">Critical</span></label>
    <label><input type="checkbox" class="sevf" value="High" checked> <span class="badge badge-high">High</span></label>
    <label><input type="checkbox" class="sevf" value="Medium" checked> <span class="badge badge-medium">Medium</span></label>
    <label><input type="checkbox" class="sevf" value="Low" checked> <span class="badge badge-low">Low</span></label>
    <label><input type="checkbox" class="sevf" value="Information" checked> <span class="badge badge-info">Information / none</span></label>
    <h4>Groups</h4>
    <label><input type="checkbox" class="scopef" value="Global" checked> Global (role)</label>
    <label><input type="checkbox" class="scopef" value="DomainLocal" checked> Domain Local (resource)</label>
    <label><input type="checkbox" class="scopef" value="Universal" checked> Universal</label>
    <label><input type="checkbox" id="hideDist" checked> Hide distribution groups</label>
    <label><input type="checkbox" id="hideEmpty" checked> Hide groups with no users / computers in them</label>
    <label><input type="checkbox" id="onlyT0"> Only groups that reach Tier 0</label>
    <label><input type="checkbox" id="onlyFind"> Only groups with findings</label>
    <h4>Tier</h4>
    <label><input type="checkbox" class="tierf" value="0" checked> Tier 0 (well-known / declared / inherited)</label>
    <label><input type="checkbox" class="tierf" value="1" checked> Tier 1</label>
    <label><input type="checkbox" class="tierf" value="2" checked> Tier 2</label>
    <label><input type="checkbox" class="tierf" value="none" checked> Untagged</label>
    <h4>OU</h4>
    <select id="ouFilter"><option value="">(all)</option></select>
    <h4>Name filter</h4>
    <input type="text" id="nameFilter" placeholder="contains / regex, e.g. ^RES-">
    <div style="margin-top:10px;display:flex;gap:6px;flex-wrap:wrap"><span class="btn sm" id="btnApply">Apply</span><span class="btn sm" id="btnReset">Reset</span></div>
  </div>
  <div class="mapwrap">
    <div class="maptools"><span class="btn sm" id="btnFit">Fit</span><span class="btn sm" id="btnZoomIn">+</span><span class="btn sm" id="btnZoomOut">&minus;</span><span class="btn sm" id="btnClear">Clear selection</span><span class="btn sm" id="btnExportSvg">Download SVG</span><span class="btn sm" id="btnLegend">Legend</span><span class="btn sm" id="btnRelayout" title="Undo manual moves">Re-layout</span></div>
    <div class="legend" id="legend"></div>
    <svg id="svg" xmlns="http://www.w3.org/2000/svg"><defs>
      <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#94a3b8"/></marker>
      <marker id="arrowBad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#dc2626"/></marker>
      <marker id="arrowWarn" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#f59e0b"/></marker>
      <marker id="arrowPath" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#2563eb"/></marker>
    </defs><g id="viewport"></g></svg>
    <div class="tip" id="tip"></div>
    <div class="mapinfo" id="mapInfo"></div>
    <div class="details" id="details"></div>
  </div>
</div>
<div class="note" style="margin-top:10px">Click a node to see what it is, what it reaches, who gets in through it, every finding attached to it and how to fix it. Double-click (or choose "Focus") to redraw the map around it. Drag any box to move it (Re-layout undoes that). Arrows point from member to group: follow them to see where an account can move.</div>
</div>

<div class="view" id="view-findings"><div class="card">
  <div class="filterbar"><input type="text" id="fSearch" placeholder="search subject, target, path, detail ..."><select id="fRule"><option value="">(all rules)</option></select><select id="fSev"><option value="">(all severities)</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Information</option></select><label><input type="checkbox" id="fEdges"> only actionable edges</label><span class="btn sm" id="fCsv">Export CSV</span></div>
  <div class="tablewrap"><table class="grid" id="fTable"><thead><tr><th data-k="sev">Severity</th><th data-k="r">Rule</th><th data-k="st">Type</th><th data-k="s">Subject</th><th data-k="t">Target</th><th data-k="p">Path</th><th data-k="d">Detail</th></tr></thead><tbody></tbody></table></div><div class="more" id="fMore"></div>
</div></div>

<div class="view" id="view-users"><div class="card">
  <div class="filterbar"><input type="text" id="uSearch" placeholder="search account ..."><select id="uType"><option value="">(all types)</option><option value="user">user</option><option value="computer">computer</option><option value="gmsa">gMSA</option><option value="msa">MSA</option><option value="fsp">foreign security principal</option><option value="external">cross-domain</option></select><label><input type="checkbox" id="uT0"> only Tier 0</label><label><input type="checkbox" id="uEnabled"> only enabled</label><span class="btn sm" id="uCsv">Export CSV</span></div>
  <div class="tablewrap"><table class="grid" id="uTable"><thead><tr><th data-k="sev">Severity</th><th data-k="score">Score</th><th data-k="s">Account</th><th data-k="n">Name</th><th data-k="t">Type</th><th data-k="en">Enabled</th><th data-k="t0">Tier 0</th><th data-k="hops">Hops</th><th data-k="tg">Groups (transitive)</th><th data-k="res">Resource groups</th><th data-k="adm">Admin groups</th><th data-k="rules">Rules</th><th data-k="path">Shortest path to Tier 0</th></tr></thead><tbody></tbody></table></div><div class="more" id="uMore"></div>
</div></div>

<div class="view" id="view-groups"><div class="card">
  <div class="filterbar"><input type="text" id="gSearch" placeholder="search group ..."><select id="gScope"><option value="">(all scopes)</option><option>Global</option><option>DomainLocal</option><option>Universal</option></select><label><input type="checkbox" id="gT0"> only reaching Tier 0</label><label><input type="checkbox" id="gWk"> only well-known</label><label><input type="checkbox" id="gFind"> only with findings</label><span class="btn sm" id="gCsv">Export CSV</span></div>
  <div class="tablewrap"><table class="grid" id="gTable"><thead><tr><th data-k="sev">Severity</th><th data-k="score">Score</th><th data-k="n">Group</th><th data-k="sc">Scope</th><th data-k="tier">Tier</th><th data-k="wk">Well-known</th><th data-k="du">Direct users</th><th data-k="dg">Nested groups</th><th data-k="tu">Transitive users</th><th data-k="pc">Member of</th><th data-k="dist">Hops to Tier 0</th><th data-k="h">Depth below</th><th data-k="rules">Rules</th><th data-k="path">Path to Tier 0</th></tr></thead><tbody></tbody></table></div><div class="more" id="gMore"></div>
</div></div>

<div class="view" id="view-paths"><div class="card">
  <h2>Shortest path to Tier 0 for every effectively privileged principal</h2>
  <div class="note">One row per account or group whose transitive membership contains a Tier 0 group. "Nested" means the principal is not a direct member of the Tier 0 group - the privilege is inherited through the chain shown. Click a row to draw the chain on the map.</div>
  <div class="filterbar"><input type="text" id="pSearch" placeholder="search ..."><label><input type="checkbox" id="pNested" checked> nested only</label><label><input type="checkbox" id="pUsersOnly"> accounts only</label></div>
  <div class="tablewrap"><table class="grid" id="pTable"><thead><tr><th data-k="t">Type</th><th data-k="s">Principal</th><th data-k="en">Enabled</th><th data-k="direct">Direct?</th><th data-k="hops">Hops</th><th data-k="t0">Tier 0 groups</th><th data-k="path">Shortest path</th></tr></thead><tbody></tbody></table></div><div class="more" id="pMore"></div>
</div></div>

<div class="view" id="view-rules">
  <div class="card"><h2>How to read this report</h2>
  <p>Active Directory has exactly one membership relation: the <code>member</code> attribute of a group. <code>memberOf</code> is the same edge seen from the other side. The direction that matters for security is memberOf: <b>"I am memberOf X" means "I inherit the rights of X"</b>. Rights sit in ACLs (local Administrators, SQL logins, shares) that name a group; everyone inside that group - directly or through any number of nested groups - gets the right when LSASS builds their token at logon.</p>
  <p>The AGDLP model keeps that readable: <b>A</b>ccounts go into <b>G</b>lobal role groups (who someone is), role groups go into <b>D</b>omain <b>L</b>ocal resource groups (what one may do on a named system), and the resource group stands in the ACL (<b>P</b>ermissions). One direction, two levels, every effective right readable in two steps. The rules below catch the ways that model breaks: role in role, resource in resource, users straight into resources, broad groups as building blocks, groups that are both role and resource, and - the expensive one - any chain that ends in a Tier 0 group.</p>
  <p><b>Tier 0</b> = the classic set that controls Active Directory itself: Domain Admins, Enterprise Admins, Schema Admins, BUILTIN\Administrators, the AdminSDHolder operator groups (Account / Server / Backup Operators), Key Admins, the domain-controller accounts and the Exchange groups that hold rights on the domain (Organization Management, Exchange Trusted Subsystem, Exchange Windows Permissions). A group that is nested into a Tier 0 group <i>is</i> Tier 0, whatever its name says. Groups with rights on domain controllers or on a Tier 0 service but without AD control - DnsAdmins, Group Policy Creator Owners, Cert Publishers, Print Operators, Remote Desktop Users, Remote Management Users, Hyper-V Administrators and the like - are shown as <b>privileged</b> [priv] with their own severity; they are never counted as "reaches Tier 0". Groups and accounts tagged T0/T1/T2 in their name (or via -Tier0Groups/-Tier1Groups/-Tier2Groups) are checked against the tier they actually reach.</p>
  <p><b>Limitations.</b> This is the AD group graph only. Local Administrators groups on servers, GPO Restricted Groups, NTFS/share/SQL permissions and ACL-based attack paths (WriteDACL, GenericAll, ...) are outside it - the Dangerous ACL and Delegated-permissions reports and BloodHound cover those. "Admin-ish" and "resource" are estimated from group names and scopes; confirm against the systems where the groups are used.</p>
  </div>
  <div id="rulesList"></div>
  <div class="card"><h2>Well-known group catalog</h2><div class="tablewrap"><table class="grid" id="catTable"><thead><tr><th>Group</th><th>Tier</th><th>Severity if reached</th><th>What it gives</th><th>Why it matters</th><th>Expected state</th></tr></thead><tbody></tbody></table></div></div>
</div>

<div class="view" id="view-baseline"><div class="card"><h2>Group nesting drift since baseline</h2><div id="baselineInfo" class="note"></div><div class="tablewrap"><table class="grid" id="bTable"><thead><tr><th>Change</th><th>Severity</th><th>Child (member)</th><th>Parent (group)</th></tr></thead><tbody></tbody></table></div></div></div>
'@
#endregion

#region ===================================================== HTML: script (part 1 - model, layout, rendering)
$script:LmHtmlJs1 = @'
(function(){
'use strict';
var LM = JSON.parse(document.getElementById('lm-data').textContent);
var NF = LM.nf, N = new Map(), ALL = [];
LM.nodes.forEach(function(a){ var o = {}; for (var i = 0; i < NF.length; i++) o[NF[i]] = a[i]; N.set(o.id, o); ALL.push(o); });
var SEV = { Critical: 5, High: 4, Medium: 3, Low: 2, Information: 1 };
var SEVCLS = { Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low', Information: 'info' };
var parentsOf = new Map(), childrenOf = new Map(), edgeFind = new Map(), nodeFind = new Map();
function push(m, k, v){ var a = m.get(k); if (!a) { a = []; m.set(k, a); } a.push(v); }
LM.edges.forEach(function(e){ push(parentsOf, e[1], { id: e[0], primary: e[2] === 1 }); push(childrenOf, e[0], { id: e[1], primary: e[2] === 1 }); });
LM.findings.forEach(function(f){ if (f.ep >= 0 && f.ec >= 0) push(edgeFind, f.ep + '|' + f.ec, f); if (f.sid >= 0) push(nodeFind, f.sid, f); });
var GROUPS = ALL.filter(function(o){ return o.t === 'group'; });
var PRINCIPALS = ALL.filter(function(o){ return o.t !== 'group'; });
function isGroup(o){ return o && o.t === 'group'; }
function isSink(o){ return isGroup(o) && (o.dt === 0 || o.wkt === '0'); }
function isPriv(o){ return isGroup(o) && o.wkt === 'P'; }
function isUserish(o){ return o && (o.t === 'user' || o.t === 'computer' || o.t === 'gmsa' || o.t === 'msa'); }
function esc(s){ if (s === null || s === undefined) return ''; return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
function q(sel){ return document.querySelector(sel); }
function qa(sel){ return Array.prototype.slice.call(document.querySelectorAll(sel)); }
function badge(sev){ return '<span class="badge badge-' + (SEVCLS[sev] || 'info') + '">' + esc(sev) + '</span>'; }
function label(o){ return o.s && o.t !== 'group' ? o.s : (o.n || o.s || ('#' + o.id)); }
function typeLetter(o){ return { group: 'G', user: 'U', computer: 'C', gmsa: 'S', msa: 'S', fsp: 'F', external: 'X', contact: '?', unknown: '?', other: '?' }[o.t] || '?'; }
function tierLabel(o){ if (o.et === 0) return 'Tier 0'; if (o.et === 1) return 'Tier 1'; if (o.et === 2) return 'Tier 2'; return '-'; }
function effTierKey(o){ return o.et === 0 ? '0' : o.et === 1 ? '1' : o.et === 2 ? '2' : 'none'; }
function nodeSevRank(o){ return SEV[o.sev] || 1; }
function fmtInt(n){ return (n === null || n === undefined) ? '-' : String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ' '); }

// ---------- state
var state = { mode: 'overview', selected: -1, focus: -1, hops: 3, dirOut: true, dirIn: true, showUsers: true, userCap: 80,
  sev: new Set(['Critical','High','Medium','Low','Information']), scopes: new Set(['Global','DomainLocal','Universal']), tiers: new Set(['0','1','2','none']),
  hideDist: true, hideEmpty: true, onlyT0: false, onlyFind: false, ou: '', nameRe: null, highlightEdges: new Set(), highlightPath: [], manual: new Map(), manualKey: '' };

function readFilters(){
  state.sev = new Set(qa('.sevf').filter(function(c){ return c.checked; }).map(function(c){ return c.value; }));
  state.scopes = new Set(qa('.scopef').filter(function(c){ return c.checked; }).map(function(c){ return c.value; }));
  state.tiers = new Set(qa('.tierf').filter(function(c){ return c.checked; }).map(function(c){ return c.value; }));
  state.hideDist = q('#hideDist').checked; state.hideEmpty = q('#hideEmpty').checked; state.onlyT0 = q('#onlyT0').checked; state.onlyFind = q('#onlyFind').checked;
  state.ou = q('#ouFilter').value; state.hops = parseInt(q('#hops').value, 10); state.dirOut = q('#dirOut').checked; state.dirIn = q('#dirIn').checked; state.showUsers = q('#showUsers').checked;
  var nf = q('#nameFilter').value.trim(); state.nameRe = null;
  if (nf) { try { state.nameRe = new RegExp(nf, 'i'); } catch (e) { var lit = nf.toLowerCase(); state.nameRe = { test: function(s){ return String(s).toLowerCase().indexOf(lit) >= 0; } }; } }
  state.mode = (qa('input[name=mode]').filter(function(r){ return r.checked; })[0] || {}).value || 'overview';
  q('#focusOpts').style.display = state.mode === 'focus' ? 'block' : 'none';
}
function groupPasses(o, exemptSinks){
  if (!isGroup(o)) return true;
  var sink = isSink(o) || isPriv(o);
  if (state.hideDist && !o.sec) return false;
  if (!state.scopes.has(o.sc) && o.sc) return false;
  if (!state.tiers.has(effTierKey(o))) return false;
  if (state.ou && o.ou !== state.ou) return false;
  if (state.nameRe && !state.nameRe.test(o.n) && !state.nameRe.test(o.s)) return false;
  var empty = (o.tu === 0 && o.dc === 0);
  // Tier 0 sinks are always drawn (an empty Schema Admins is the expected state); an
  // empty privileged or ordinary group grants nothing to anyone and only clutters the map.
  if (sink && exemptSinks) return isSink(o) || !state.hideEmpty || !empty;
  if (!state.sev.has(o.sev || 'Information')) return false;
  if (state.hideEmpty && empty) return false;
  if (state.onlyT0 && o.dist < 0) return false;
  if (state.onlyFind && !o.rules) return false;
  return true;
}
function principalPasses(o){
  if (!state.sev.has(o.sev || 'Information')) return false;
  if (state.nameRe && !state.nameRe.test(o.n) && !state.nameRe.test(o.s)) return false;
  return true;
}

// ---------- visible subgraph
function visibleSet(){
  var vis = new Map(); // id -> layer hint (null = compute)
  var pseudo = [];     // {id, label, parent}
  var fallback = '';
  if (state.mode === 'focus' && state.focus >= 0 && N.has(state.focus)) {
    var f = N.get(state.focus); vis.set(f.id, 0);
    var frontier = [f.id];
    if (state.dirOut) { for (var d = 1; d <= state.hops && frontier.length; d++) { var next = []; frontier.forEach(function(id){ (parentsOf.get(id) || []).forEach(function(p){ var o = N.get(p.id); if (!o || vis.has(p.id)) return; if (!groupPasses(o, true)) return; vis.set(p.id, d); next.push(p.id); }); }); frontier = next; } }
    frontier = [f.id];
    if (state.dirIn) { for (var d2 = 1; d2 <= state.hops && frontier.length; d2++) { var next2 = []; frontier.forEach(function(id){ var kids = childrenOf.get(id) || []; var ucount = 0, uhidden = 0; kids.forEach(function(c){ var o = N.get(c.id); if (!o || vis.has(c.id)) return; if (isGroup(o)) { if (!groupPasses(o, true)) return; vis.set(c.id, -d2); next2.push(c.id); } else { if (!state.showUsers || !principalPasses(o)) { uhidden++; return; } if (ucount >= state.userCap) { uhidden++; return; } ucount++; vis.set(c.id, -d2); } }); if (uhidden > 0) pseudo.push({ id: 'pseudo' + id, label: '+' + fmtInt(uhidden) + ' more members', parent: id, layer: -d2 }); }); frontier = next2; } }
  } else if (state.mode === 'all') {
    GROUPS.forEach(function(o){ if (groupPasses(o, true)) vis.set(o.id, null); });
  } else {
    GROUPS.forEach(function(o){ if ((o.dist >= 0 || nodeSevRank(o) >= 3 || isSink(o) || isPriv(o)) && groupPasses(o, true)) vis.set(o.id, null); });
    var nonSink = 0; vis.forEach(function(v, id){ var o = N.get(id); if (!isSink(o) && !isPriv(o)) nonSink++; });
    if (nonSink === 0) {
      GROUPS.forEach(function(o){ if (o.rules && groupPasses(o, true)) vis.set(o.id, null); });
      nonSink = 0; vis.forEach(function(v, id){ var o = N.get(id); if (!isSink(o) && !isPriv(o)) nonSink++; });
      if (nonSink === 0) { GROUPS.filter(function(o){ return groupPasses(o, true); }).sort(function(a, b){ return b.tu - a.tu; }).slice(0, 150).forEach(function(o){ vis.set(o.id, null); }); fallback = 'No group reaches Tier 0 and no finding is attached to a group - showing the 150 largest groups instead.'; }
      else fallback = 'No group reaches a Tier 0 / privileged group through nesting - showing groups with findings.';
    }
  }
  return { vis: vis, pseudo: pseudo, fallback: fallback };
}

// ---------- layered layout
function layout(vs){
  var vis = vs.vis, ids = Array.from(vis.keys()), horizontal = state.mode === 'focus';
  var layer = new Map();
  if (horizontal) { ids.forEach(function(id){ layer.set(id, vis.get(id)); }); }
  else {
    var maxDist = 0; ids.forEach(function(id){ var o = N.get(id); if (o.dist > maxDist) maxDist = o.dist; });
    ids.forEach(function(id){ var o = N.get(id); layer.set(id, o.dist >= 0 ? o.dist : -1); });
    var base = maxDist + 1;
    ids.forEach(function(id){ if (layer.get(id) >= 0) return; var hasVisParent = (parentsOf.get(id) || []).some(function(p){ return vis.has(p.id) && isGroup(N.get(p.id)); }); if (!hasVisParent) layer.set(id, base); });
    for (var it = 0; it < 40; it++) { var changed = false; ids.forEach(function(id){ if (N.get(id).dist >= 0) return; var best = layer.get(id); (parentsOf.get(id) || []).forEach(function(p){ if (!vis.has(p.id)) return; var pl = layer.get(p.id); if (pl === undefined || pl < 0) return; if (pl + 1 > best) best = pl + 1; }); if (best !== layer.get(id)) { layer.set(id, best); changed = true; } }); if (!changed) break; }
    ids.forEach(function(id){ if (layer.get(id) < 0) layer.set(id, base); });
  }
  vs.pseudo.forEach(function(p){ layer.set(p.id, p.layer); });
  var layers = new Map();
  layer.forEach(function(l, id){ push(layers, l, id); });
  var keys = Array.from(layers.keys()).sort(function(a, b){ return a - b; });
  // barycenter ordering
  var pos = new Map();
  keys.forEach(function(k){ layers.get(k).forEach(function(id, i){ pos.set(id, i); }); });
  function neigh(id){ var r = []; (parentsOf.get(id) || []).forEach(function(p){ if (layer.has(p.id)) r.push(p.id); }); (childrenOf.get(id) || []).forEach(function(c){ if (layer.has(c.id)) r.push(c.id); }); var ps = vs.pseudo; for (var i = 0; i < ps.length; i++) { if (ps[i].parent === id) r.push(ps[i].id); if (ps[i].id === id) r.push(ps[i].parent); } return r; }
  for (var sweep = 0; sweep < 6; sweep++) {
    var order = sweep % 2 === 0 ? keys : keys.slice().reverse();
    order.forEach(function(k){ var arr = layers.get(k); var bc = new Map(); arr.forEach(function(id){ var ns = neigh(id).filter(function(n){ return layer.get(n) !== k; }); if (!ns.length) { bc.set(id, pos.get(id)); return; } var s = 0; ns.forEach(function(n){ s += pos.get(n); }); bc.set(id, s / ns.length); }); arr.sort(function(a, b){ return bc.get(a) - bc.get(b) || String(a).localeCompare(String(b)); }); arr.forEach(function(id, i){ pos.set(id, i); }); });
  }
  // sizes and coordinates
  var geo = new Map();
  function width(id){ var p = pseudoById(vs, id); var txt = p ? p.label : label(N.get(id)); return Math.max(90, Math.min(250, txt.length * 6.6 + 40)); }
  var maxW = 0;
  keys.forEach(function(k){ layers.get(k).forEach(function(id){ maxW = Math.max(maxW, width(id)); }); });
  var colX = new Map(); var x0 = 0;
  keys.forEach(function(k, ki){ if (horizontal) { var mw = 0; layers.get(k).forEach(function(id){ mw = Math.max(mw, width(id)); }); colX.set(k, x0 + mw / 2); x0 += mw + 90; } });
  var layerY = new Map(), yCursor = 0;
  keys.forEach(function(k, ki){
    var arr = layers.get(k);
    if (horizontal) { var h = 34, total = arr.length * (h + 10); arr.forEach(function(id, i){ geo.set(id, { x: colX.get(k), y: -total / 2 + i * (h + 10) + h / 2, w: width(id), h: 30 }); }); }
    else {
      // wide layers wrap into sub-rows so the drawing stays roughly square instead of one long line
      var perRow = Math.max(6, Math.ceil(Math.sqrt(arr.length * 3)));
      var rows = []; for (var r = 0; r < arr.length; r += perRow) rows.push(arr.slice(r, r + perRow));
      rows.forEach(function(row, ri){ var widths = row.map(width), total2 = widths.reduce(function(a, b){ return a + b + 22; }, 0), cx = -total2 / 2; row.forEach(function(id, i){ cx += widths[i] / 2; geo.set(id, { x: cx, y: yCursor + ri * 44, w: widths[i], h: 30 }); cx += widths[i] / 2 + 22; }); });
      layerY.set(k, yCursor); yCursor += rows.length * 44 + 76;
    }
  });
  var viewKey = state.mode + ':' + (state.mode === 'focus' ? state.focus : '');
  if (state.manualKey !== viewKey) { state.manual.clear(); state.manualKey = viewKey; }
  state.manual.forEach(function(pos, id){ var g = geo.get(id); if (g) { g.x = pos.x; g.y = pos.y; } });
  return { geo: geo, layer: layer, keys: keys, horizontal: horizontal, layers: layers, layerY: layerY };
}
function pseudoById(vs, id){ for (var i = 0; i < vs.pseudo.length; i++) if (vs.pseudo[i].id === id) return vs.pseudo[i]; return null; }

// ---------- rendering
var svg = q('#svg'), vp = q('#viewport'), tip = q('#tip');
var view = { x: 0, y: 0, k: 1 }, drag = null;
function applyView(){ vp.setAttribute('transform', 'translate(' + view.x + ',' + view.y + ') scale(' + view.k + ')'); }
var current = null;
function t0PathIds(o){ var ids = []; if (!o || o.dist < 0) return ids; var cur = o; ids.push(cur.id); var guard = 0; while (cur && cur.dist > 0 && guard++ < 64) { var nxt = null; (parentsOf.get(cur.id) || []).forEach(function(p){ var pn = N.get(p.id); if (!nxt && pn && isGroup(pn) && pn.sec && pn.dist === cur.dist - 1) nxt = pn; }); if (!nxt) break; ids.push(nxt.id); cur = nxt; } return ids; }
function edgeClass(p, c){ var fs = edgeFind.get(p + '|' + c); if (!fs) return ''; var worst = 0; fs.forEach(function(f){ worst = Math.max(worst, SEV[f.sev] || 1); }); return worst >= 4 ? 'bad' : worst >= 2 ? 'warn' : ''; }
function render(){
  readFilters();
  var vs = visibleSet(); var L = layout(vs); current = { vs: vs, L: L };
  var html = [];
  var sel = state.selected, pathIds = (sel >= 0 && N.has(sel)) ? t0PathIds(N.get(sel)) : [];
  var pathEdges = new Set(); for (var i = 0; i + 1 < pathIds.length; i++) pathEdges.add(pathIds[i + 1] + '|' + pathIds[i]);
  state.highlightEdges.forEach(function(k){ pathEdges.add(k); });
  if (!L.horizontal) {
    var noPathLabelled = false;
    L.keys.forEach(function(k, ki){ var o0 = N.get(L.layers.get(k)[0]); var reach = (o0 && o0.dist === k); var txt = reach ? (k === 0 ? 'TIER 0 / PRIVILEGED' : k + ' HOP' + (k > 1 ? 'S' : '') + ' FROM TIER 0') : (noPathLabelled ? '' : 'NO PATH TO TIER 0'); if (!reach) noPathLabelled = true; var minx = Infinity; L.layers.get(k).forEach(function(id){ var g = L.geo.get(id); minx = Math.min(minx, g.x - g.w / 2); }); html.push('<text class="layerlabel" x="' + (minx - 30) + '" y="' + (L.layerY.get(k) - 24) + '">' + txt + '</text>'); });
  } else {
    L.keys.forEach(function(k){ var g0 = L.geo.get(L.layers.get(k)[0]); var txt = k === 0 ? 'SELECTED' : k > 0 ? 'MEMBER OF (' + k + ' hop' + (k > 1 ? 's' : '') + ')' : 'MEMBERS (' + (-k) + ' hop' + (k < -1 ? 's' : '') + ')'; var miny = Infinity; L.layers.get(k).forEach(function(id){ miny = Math.min(miny, L.geo.get(id).y); }); html.push('<text class="layerlabel" x="' + (g0.x - 40) + '" y="' + (miny - 34) + '">' + txt + '</text>'); });
  }
  // edges
  L.geo.forEach(function(g, id){
    if (typeof id === 'string') { var p = pseudoById(vs, id); var pg = L.geo.get(p.parent); if (pg) html.push(edgePath(g, pg, 'edge', L.horizontal, false, null, p.parent, id)); return; }
    (parentsOf.get(id) || []).forEach(function(pe){ var pg = L.geo.get(pe.id); if (!pg) return; var cls = 'edge ' + edgeClass(pe.id, id) + (pe.primary ? ' primary' : ''); var key = pe.id + '|' + id; if (pathEdges.has(key)) cls += ' path'; if (sel >= 0 && !(pe.id === sel || id === sel) && !pathEdges.has(key)) cls += ' dim'; html.push(edgePath(g, pg, cls, L.horizontal, true, key, pe.id, id)); });
  });
  // nodes
  L.geo.forEach(function(g, id){
    if (typeof id === 'string') { var p = pseudoById(vs, id); html.push('<g class="node pseudo" data-pid="' + id + '" transform="translate(' + (g.x - g.w / 2) + ',' + (g.y - g.h / 2) + ')"><rect rx="8" ry="8" width="' + g.w + '" height="' + g.h + '" fill="var(--panel2)" stroke="var(--line)" stroke-dasharray="4 3"/><text x="' + (g.w / 2) + '" y="19" text-anchor="middle" fill="var(--muted)">' + esc(p.label) + '</text></g>'); return; }
    var o = N.get(id), sink = isSink(o), priv = isPriv(o), sevc = SEVCLS[o.sev] || 'info';
    var fill = sink ? 'var(--t0-soft)' : 'var(--' + sevc + '-soft)', stroke = sink ? 'var(--t0)' : priv ? 'var(--high)' : 'var(--' + sevc + ')';
    var cls = 'node' + (id === sel ? ' selected' : '') + ((sel >= 0 && id !== sel && !isNeighbor(sel, id) && pathIds.indexOf(id) < 0) ? ' dim' : '');
    var dash = (isUserish(o) && !o.en) ? ' stroke-dasharray="5 3"' : '';
    var shape = isGroup(o) ? '<rect rx="8" ry="8" width="' + g.w + '" height="' + g.h + '" fill="' + fill + '" stroke="' + stroke + '"' + dash + '/>' : '<rect rx="15" ry="15" width="' + g.w + '" height="' + g.h + '" fill="' + fill + '" stroke="' + stroke + '"' + dash + '/>';
    var iconFill = isGroup(o) ? (sink ? 'var(--t0)' : 'var(--node-group)') : 'var(--node-user)';
    var mark = sink ? ' T0' : priv ? ' P' : (o.et === 0 ? ' t0' : o.et === 1 ? ' t1' : o.et === 2 ? ' t2' : '');
    var txt = label(o); if (txt.length > 32) txt = txt.slice(0, 30) + '..';
    html.push('<g class="' + cls + '" data-id="' + id + '" transform="translate(' + (g.x - g.w / 2) + ',' + (g.y - g.h / 2) + ')">' + shape + '<rect x="6" y="7" width="16" height="16" rx="4" fill="' + iconFill + '"/><text class="icon" x="14" y="19" text-anchor="middle">' + typeLetter(o) + '</text><text x="28" y="19"' + (sink ? ' font-weight="700"' : '') + '>' + esc(txt) + (mark ? '<tspan fill="var(--muted)" font-size="9px">' + mark + '</tspan>' : '') + '</text></g>');
  });
  vp.innerHTML = html.join('');
  var cnt = 0, ucnt = 0; vs.vis.forEach(function(v, id){ if (isGroup(N.get(id))) cnt++; else ucnt++; });
  q('#mapInfo').textContent = (state.mode === 'focus' ? 'Focus: ' + (N.has(state.focus) ? label(N.get(state.focus)) : '-') + ' | ' : state.mode === 'all' ? 'All groups | ' : 'Privilege overview | ') + cnt + ' groups' + (ucnt ? ', ' + ucnt + ' accounts' : '') + ' shown of ' + GROUPS.length + ' groups' + (vs.fallback ? ' | ' + vs.fallback : '') + ' | drag a box to move it, drag the background to pan, wheel to zoom, click = details, double-click = focus';
  if (!render.keepView) fit(); render.keepView = false;
}
function isNeighbor(a, b){ return (parentsOf.get(a) || []).some(function(p){ return p.id === b; }) || (childrenOf.get(a) || []).some(function(c){ return c.id === b; }); }
function edgeD(cg, pg, horizontal){
  var x1, y1, x2, y2;
  if (horizontal) { x1 = cg.x + cg.w / 2; y1 = cg.y; x2 = pg.x - pg.w / 2; y2 = pg.y; }
  else { x1 = cg.x; y1 = cg.y - cg.h / 2; x2 = pg.x; y2 = pg.y + pg.h / 2; }
  return horizontal ? ('M' + x1 + ',' + y1 + ' C' + (x1 + 40) + ',' + y1 + ' ' + (x2 - 40) + ',' + y2 + ' ' + x2 + ',' + y2) : ('M' + x1 + ',' + y1 + ' C' + x1 + ',' + (y1 - 50) + ' ' + x2 + ',' + (y2 + 50) + ' ' + x2 + ',' + y2);
}
function edgePath(cg, pg, cls, horizontal, arrow, key, pId, cId){
  var d = edgeD(cg, pg, horizontal);
  var m = cls.indexOf('path') >= 0 ? 'arrowPath' : cls.indexOf('bad') >= 0 ? 'arrowBad' : cls.indexOf('warn') >= 0 ? 'arrowWarn' : 'arrow';
  return '<path class="' + cls + '" d="' + d + '"' + (arrow ? ' marker-end="url(#' + m + ')"' : '') + (key ? ' data-key="' + key + '"' : '') + ' data-p="' + pId + '" data-c="' + cId + '"/>';
}
function geoKey(v){ return /^-?\d+$/.test(v) ? parseInt(v, 10) : v; }
function rerouteEdges(id){
  // re-draw every edge touching the moved node from the current geometry
  if (!current) return;
  var geo = current.L.geo, horizontal = current.L.horizontal, sid = String(id);
  qa('#viewport .edge').forEach(function(e){ if (e.dataset.p !== sid && e.dataset.c !== sid) return; var pg = geo.get(geoKey(e.dataset.p)), cg = geo.get(geoKey(e.dataset.c)); if (pg && cg) e.setAttribute('d', edgeD(cg, pg, horizontal)); });
}
function fit(){
  var bb; try { bb = vp.getBBox(); } catch (e) { return; }
  if (!bb || !bb.width) return;
  var W = svg.clientWidth || 900, H = svg.clientHeight || 640;
  var k = Math.min((W - 60) / bb.width, (H - 80) / bb.height, 1.6); if (!isFinite(k) || k <= 0) k = 1;
  view.k = k; view.x = (W - bb.width * k) / 2 - bb.x * k; view.y = (H - bb.height * k) / 2 - bb.y * k + 10; applyView();
}
var nodeDrag = null, suppressClick = false;
svg.addEventListener('mousedown', function(e){
  if (e.button !== 0) return;
  var g = e.target.closest('.node');
  if (g && g.dataset.id && current) {
    // drag a box: the user can pull groups and accounts apart to read the map
    var id = parseInt(g.dataset.id, 10), geo = current.L.geo.get(id);
    if (!geo) return;
    nodeDrag = { id: id, el: g, geo: geo, x: e.clientX, y: e.clientY, ox: geo.x, oy: geo.y, moved: false };
    g.classList.add('dragging'); tip.style.display = 'none'; e.preventDefault(); return;
  }
  if (g) return;
  drag = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y }; svg.classList.add('dragging');
});
window.addEventListener('mousemove', function(e){
  if (nodeDrag) {
    var dx = (e.clientX - nodeDrag.x) / view.k, dy = (e.clientY - nodeDrag.y) / view.k;
    if (!nodeDrag.moved && Math.abs(dx) < 2 && Math.abs(dy) < 2) return;
    nodeDrag.moved = true;
    nodeDrag.geo.x = nodeDrag.ox + dx; nodeDrag.geo.y = nodeDrag.oy + dy;
    nodeDrag.el.setAttribute('transform', 'translate(' + (nodeDrag.geo.x - nodeDrag.geo.w / 2) + ',' + (nodeDrag.geo.y - nodeDrag.geo.h / 2) + ')');
    rerouteEdges(nodeDrag.id);
    return;
  }
  if (!drag) return; view.x = drag.vx + (e.clientX - drag.x); view.y = drag.vy + (e.clientY - drag.y); applyView();
});
window.addEventListener('mouseup', function(){
  if (nodeDrag) { nodeDrag.el.classList.remove('dragging'); if (nodeDrag.moved) { state.manual.set(nodeDrag.id, { x: nodeDrag.geo.x, y: nodeDrag.geo.y }); suppressClick = true; setTimeout(function(){ suppressClick = false; }, 0); } nodeDrag = null; }
  drag = null; svg.classList.remove('dragging');
});
svg.addEventListener('wheel', function(e){ e.preventDefault(); var r = svg.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top, f = e.deltaY < 0 ? 1.15 : 1 / 1.15, nk = Math.max(0.05, Math.min(5, view.k * f)); view.x = mx - (mx - view.x) * (nk / view.k); view.y = my - (my - view.y) * (nk / view.k); view.k = nk; applyView(); }, { passive: false });
q('#btnFit').addEventListener('click', fit);
q('#btnZoomIn').addEventListener('click', function(){ view.k = Math.min(5, view.k * 1.25); applyView(); });
q('#btnZoomOut').addEventListener('click', function(){ view.k = Math.max(0.05, view.k / 1.25); applyView(); });
q('#btnClear').addEventListener('click', function(){ state.selected = -1; state.highlightEdges.clear(); render.keepView = true; render(); renderDetails(null); });
svg.addEventListener('click', function(e){ if (suppressClick) return; var g = e.target.closest('.node'); if (!g || !g.dataset.id) return; if (e.detail && e.detail > 1) return; selectNode(parseInt(g.dataset.id, 10), false); });
svg.addEventListener('dblclick', function(e){ var g = e.target.closest('.node'); if (!g || !g.dataset.id) return; focusNode(parseInt(g.dataset.id, 10)); });
svg.addEventListener('mousemove', function(e){ var g = e.target.closest('.node'); if (!g || !g.dataset.id) { tip.style.display = 'none'; return; } var o = N.get(parseInt(g.dataset.id, 10)); if (!o) return; var r = svg.getBoundingClientRect(); tip.style.display = 'block'; tip.style.left = (e.clientX - r.left + 14) + 'px'; tip.style.top = (e.clientY - r.top + 14) + 'px'; tip.innerHTML = '<b>' + esc(label(o)) + '</b> ' + badge(o.sev || 'Information') + '<br>' + esc(o.t) + (o.sc ? ' / ' + esc(o.sc) + (o.sec ? '' : ' (distribution)') : '') + (o.wk ? ' / ' + esc(o.wk) : '') + '<br>' + (isGroup(o) ? ('direct: ' + o.du + ' users, ' + o.dg + ' groups | transitive users: ' + fmtInt(o.tu) + ' | member of: ' + o.pc) : ('enabled: ' + o.en + ' | transitive groups: ' + o.tg)) + (o.dist >= 0 ? '<br>Tier 0 in ' + o.dist + ' hop(s)' : '') + (o.rules ? '<br>rules: ' + esc(o.rules) : ''); });
svg.addEventListener('mouseleave', function(){ tip.style.display = 'none'; });
q('#btnExportSvg').addEventListener('click', function(){ var s = new XMLSerializer().serializeToString(svg); var css = '<style>text{font-family:Segoe UI,Arial,sans-serif;font-size:11px}.edge{fill:none;stroke:#94a3b8;stroke-width:1.4}.edge.bad{stroke:#dc2626;stroke-width:2.4}.edge.warn{stroke:#f59e0b;stroke-width:2}.edge.path{stroke:#2563eb;stroke-width:3}.edge.primary{stroke-dasharray:5 4}.node .icon{fill:#fff;font-size:9px;font-weight:700}.layerlabel{fill:#5f6b7a;font-weight:600}.node.dim,.edge.dim{opacity:.2}</style>'; s = s.replace(/var\(--t0-soft\)/g, '#fee2e2').replace(/var\(--t0\)/g, '#7f1d1d').replace(/var\(--critical-soft\)/g, '#fdecec').replace(/var\(--critical\)/g, '#c62828').replace(/var\(--high-soft\)/g, '#fff2e5').replace(/var\(--high\)/g, '#ef6c00').replace(/var\(--medium-soft\)/g, '#e8f4fd').replace(/var\(--medium\)/g, '#0277bd').replace(/var\(--low-soft\)/g, '#edf8ee').replace(/var\(--low\)/g, '#2e7d32').replace(/var\(--info-soft\)/g, '#f2f4f6').replace(/var\(--info\)/g, '#6c757d').replace(/var\(--node-group\)/g, '#64748b').replace(/var\(--node-user\)/g, '#0ea5e9').replace(/var\(--panel2\)/g, '#f8fafc').replace(/var\(--line\)/g, '#d9e0ea').replace(/var\(--muted\)/g, '#5f6b7a').replace(/var\(--text\)/g, '#1b2430'); s = s.replace('<defs>', css + '<defs>'); download('lateral-movement-map.svg', s, 'image/svg+xml'); });
function download(name, content, mime){ var b = new Blob([content], { type: mime || 'text/plain' }); var a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = name; document.body.appendChild(a); a.click(); setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); }, 500); }
function decorate(){
  var sel = state.selected, pathIds = (sel >= 0 && N.has(sel)) ? t0PathIds(N.get(sel)) : [];
  var pathEdges = new Set(); for (var i = 0; i + 1 < pathIds.length; i++) pathEdges.add(pathIds[i + 1] + '|' + pathIds[i]);
  state.highlightEdges.forEach(function(k){ pathEdges.add(k); });
  qa('#viewport .node').forEach(function(g){ if (!g.dataset.id) return; var id = parseInt(g.dataset.id, 10); g.classList.toggle('selected', id === sel); g.classList.toggle('dim', sel >= 0 && id !== sel && !isNeighbor(sel, id) && pathIds.indexOf(id) < 0); });
  qa('#viewport .edge').forEach(function(e){ var key = e.dataset.key; if (!key) return; var parts = key.split('|'), p = parseInt(parts[0], 10), c = parseInt(parts[1], 10); var onPath = pathEdges.has(key); e.classList.toggle('path', onPath); e.classList.toggle('dim', sel >= 0 && !(p === sel || c === sel) && !onPath); var cls = e.getAttribute('class'); var m = onPath ? 'arrowPath' : cls.indexOf('bad') >= 0 ? 'arrowBad' : cls.indexOf('warn') >= 0 ? 'arrowWarn' : 'arrow'; e.setAttribute('marker-end', 'url(#' + m + ')'); });
}
function selectNode(id, switchTab){ if (!N.has(id)) return; state.selected = id; state.highlightEdges.clear(); tip.style.display = 'none'; if (switchTab) showView('map'); if (!current || !current.vs.vis.has(id)) { if (switchTab) { focusNode(id); return; } render.keepView = true; render(); } decorate(); renderDetails(N.get(id)); }
function focusNode(id){ if (!N.has(id)) return; state.focus = id; state.selected = id; state.highlightEdges.clear(); qa('input[name=mode]').forEach(function(r){ r.checked = r.value === 'focus'; }); showView('map'); render(); renderDetails(N.get(id)); }
window.lmSelect = function(id){ selectNode(id, true); }; window.lmFocus = focusNode;
'@
#endregion

#region ===================================================== HTML: script (part 2 - details, tables, init)
$script:LmHtmlJs2 = @'
// ---------- transitive helpers (client side)
function closureUp(id, maxDepth){ var seen = new Set(), frontier = [id], d = 0; while (frontier.length && d < (maxDepth || 40)) { var next = []; frontier.forEach(function(x){ (parentsOf.get(x) || []).forEach(function(p){ var o = N.get(p.id); if (!o || !isGroup(o) || !o.sec || seen.has(p.id)) return; seen.add(p.id); next.push(p.id); }); }); frontier = next; d++; } return seen; }
function pathsToTier0(id, maxPaths, maxDepth){
  var out = [], stack = [[id]];
  while (stack.length && out.length < maxPaths) {
    var path = stack.pop(), last = path[path.length - 1];
    (parentsOf.get(last) || []).forEach(function(p){ var o = N.get(p.id); if (!o || !isGroup(o) || !o.sec || path.indexOf(p.id) >= 0) return; var np = path.concat([p.id]); if (isSink(o) || isPriv(o)) { if (out.length < maxPaths) out.push(np); } else if (np.length <= maxDepth) stack.push(np); });
  }
  out.sort(function(a, b){ return a.length - b.length; });
  return out;
}
function chipFor(o, extraCls){ var c = isSink(o) ? 't0' : isPriv(o) ? 'priv' : (o.admish ? 'adm' : (o.sc === 'DomainLocal' ? 'res' : '')); return '<span class="chip ' + c + ' ' + (extraCls || '') + '" onclick="lmSelect(' + o.id + ')" title="' + esc(o.t + (o.sc ? ' ' + o.sc : '') + (o.wk ? ' - ' + o.wk : '')) + '">' + esc(label(o)) + (isSink(o) ? ' [T0]' : isPriv(o) ? ' [priv]' : '') + '</span>'; }
function pathHtml(ids){ var parts = []; for (var i = 0; i < ids.length; i++) { var o = N.get(ids[i]); var bad = i > 0 && edgeClass(ids[i], ids[i - 1]) === 'bad'; parts.push((i > 0 ? '<span class="hop"> &rarr; </span>' : '') + '<span class="' + (bad ? 'bad' : '') + '">' + esc(label(o)) + (isSink(o) ? ' [T0]' : isPriv(o) ? ' [priv]' : '') + '</span>'); } return '<div class="pathline" onclick="lmHighlightPath([' + ids.join(',') + '])">' + parts.join('') + '</div>'; }
window.lmHighlightPath = function(ids){ state.highlightEdges.clear(); for (var i = 0; i + 1 < ids.length; i++) state.highlightEdges.add(ids[i + 1] + '|' + ids[i]); var missing = ids.some(function(id){ return !current || !current.vs.vis.has(id); }); if (missing) { state.focus = ids[0]; state.selected = ids[0]; qa('input[name=mode]').forEach(function(r){ r.checked = r.value === 'focus'; }); q('#hops').value = Math.max(parseInt(q('#hops').value, 10), ids.length); q('#hopsVal').textContent = q('#hops').value; } render.keepView = !missing; render(); };
function findingHtml(f){ var rule = LM.rules[f.r] || {}; return '<div class="finding ' + (SEVCLS[f.sev] || 'info') + '"><div class="fhead">' + badge(f.sev) + '<span>' + esc(f.r) + ' ' + esc(rule.title || '') + '</span></div>' + (f.p ? '<div class="mono" style="color:var(--muted)">' + esc(f.p) + '</div>' : '') + '<div>' + esc(f.d) + '</div><div class="fix"><b>Fix:</b> ' + esc(f.fix) + '</div>' + (f.tid >= 0 && N.has(f.tid) ? '<div style="margin-top:4px">Target: ' + chipFor(N.get(f.tid)) + '</div>' : '') + '</div>'; }
function catalogFor(o){ if (!o.wk) return null; for (var i = 0; i < LM.catalog.length; i++) if (LM.catalog[i].name === o.wk) return LM.catalog[i]; return null; }

function renderDetails(o){
  var el = q('#details');
  el.classList.toggle('open', !!o);
  if (!o) { el.innerHTML = ''; return; }
  var h = [];
  h.push('<div class="title">' + esc(label(o)) + ' ' + badge(o.sev || 'Information') + (isSink(o) ? ' <span class="badge badge-t0">Tier 0 sink</span>' : '') + (isPriv(o) ? ' <span class="badge badge-high">privileged built-in</span>' : '') + '</div>');
  h.push('<div style="margin:4px 0 8px"><span class="btn sm" onclick="lmFocus(' + o.id + ')">Focus map here</span> <span class="btn sm" onclick="lmCopy(' + o.id + ')">Copy DN</span></div>');
  var tags = [];
  if (o.et === 0) tags.push('<span class="badge badge-t0">effective Tier 0' + (o.via ? ' via ' + esc(o.via) : '') + '</span>'); else if (o.et === 1) tags.push('<span class="badge badge-tag">Tier 1</span>'); else if (o.et === 2) tags.push('<span class="badge badge-tag">Tier 2</span>');
  if (o.dt !== null && o.dt !== undefined) tags.push('<span class="badge badge-tag">declared Tier ' + o.dt + '</span>');
  if (o.broad) tags.push('<span class="badge badge-high" title="' + esc(o.br) + '">broad group</span>');
  if (o.admish) tags.push('<span class="badge badge-tag">admin-ish name</span>');
  if (o.temp) tags.push('<span class="badge badge-tag">temporary / legacy name</span>');
  if (o.cyc > 0) tags.push('<span class="badge badge-medium">in membership loop #' + o.cyc + '</span>');
  if (isGroup(o) && !o.sec) tags.push('<span class="badge badge-info">distribution group</span>');
  if (isUserish(o) && !o.en) tags.push('<span class="badge badge-info">disabled</span>');
  if (o.spn) tags.push('<span class="badge badge-critical">has SPN</span>');
  if (o.pu) tags.push('<span class="badge badge-low">Protected Users</span>');
  if (isUserish(o) && o.t === 'user' && !o.adminNamed) tags.push('<span class="badge badge-tag">standard-looking name</span>');
  if (o.ext) tags.push('<span class="badge badge-high">cross-domain / foreign</span>');
  if (tags.length) h.push('<div style="margin-bottom:6px">' + tags.join(' ') + '</div>');
  h.push('<div class="kv">');
  h.push('<div>Type</div><div>' + esc(o.t) + (o.sc ? ' / ' + esc(o.sc) + (o.sec ? ' security' : ' distribution') : '') + (o.os ? ' / ' + esc(o.os) : '') + '</div>');
  if (o.s && o.s !== o.n) h.push('<div>sAMAccountName</div><div class="mono">' + esc(o.s) + '</div>');
  h.push('<div>DN</div><div class="mono" style="word-break:break-all">' + esc(o.dn) + '</div>');
  if (o.wk) h.push('<div>Well-known</div><div>' + esc(o.wk) + '</div>');
  if (o.desc) h.push('<div>Description</div><div>' + esc(o.desc) + '</div>');
  if (o.owner) h.push('<div>Owner</div><div>' + esc(o.owner) + '</div>');
  if (isGroup(o)) {
    h.push('<div>Direct members</div><div>' + o.du + ' users, ' + o.dg + ' groups, ' + o.dc + ' computers</div>');
    h.push('<div>Transitive</div><div>' + fmtInt(o.tu) + ' users (' + fmtInt(o.te) + ' enabled), member of ' + o.pc + ' groups directly / ' + o.tg + ' transitively</div>');
    h.push('<div>Nesting below</div><div>' + o.h + ' levels</div>');
    if (o.changed) h.push('<div>Changed</div><div>' + esc(o.changed) + '</div>');
  } else {
    h.push('<div>Enabled</div><div>' + (o.en ? 'yes' : 'no') + '</div>');
    h.push('<div>Groups</div><div>' + o.pc + ' direct, ' + o.tg + ' transitive</div>');
    if (o.pwd) h.push('<div>Password set</div><div>' + esc(o.pwd) + '</div>');
    if (o.logon) h.push('<div>Last logon</div><div>' + esc(o.logon) + '</div>');
    if (o.pgid) h.push('<div>Primary group</div><div>RID ' + o.pgid + (o.pgid !== 513 && o.pgid !== 515 && o.pgid !== 516 && o.pgid !== 521 ? ' (non-default!)' : '') + '</div>');
  }
  if (o.ac === 1) h.push('<div>adminCount</div><div>1 (AdminSDHolder)</div>');
  h.push('</div>');
  var cat = catalogFor(o);
  if (cat) h.push('<div class="note"><b>' + esc(cat.name) + '</b> - ' + esc(cat.tag) + '<br>' + esc(cat.why) + '<br><b>Expected:</b> ' + esc(cat.fix) + '</div>');
  // reach
  if (o.dist >= 0 || o.t0 && o.t0.length) {
    h.push('<h4>Tier 0 reach</h4>');
    if (isSink(o)) h.push('<div>This group <b>is</b> a Tier 0 / privileged sink.</div>');
    else {
      h.push('<div>Reaches: ' + (o.t0 || []).map(function(id){ return N.has(id) ? chipFor(N.get(id)) : ''; }).join(' ') + '</div>');
      var ps = pathsToTier0(o.id, 40, 10);
      if (ps.length) { h.push('<div style="margin-top:4px;color:var(--muted)">' + ps.length + (ps.length >= 40 ? '+' : '') + ' path(s), shortest first - click to draw:</div>'); ps.slice(0, 25).forEach(function(p){ h.push(pathHtml(p)); }); if (ps.length > 25) h.push('<div class="more">... ' + (ps.length - 25) + ' more</div>'); }
      else if (o.path) h.push('<div class="pathline">' + esc(o.path) + '</div>');
    }
  }
  // what it allows
  var cl = closureUp(o.id);
  var t0s = [], privs = [], adms = [], ress = [], others = [];
  cl.forEach(function(id){ var g = N.get(id); if (isSink(g)) t0s.push(g); else if (isPriv(g)) privs.push(g); else if (g.wk) others.push(g); else if (g.admish) adms.push(g); else if (g.sc === 'DomainLocal') ress.push(g); else others.push(g); });
  var byName = function(a, b){ return label(a).localeCompare(label(b)); };
  h.push('<h4>What this ' + (isGroup(o) ? 'group' : 'account') + ' can reach (transitive memberOf)</h4>');
  if (!cl.size) h.push('<div style="color:var(--muted)">No group membership beyond itself.</div>');
  if (t0s.length) h.push('<div><b>Tier 0:</b> ' + t0s.sort(byName).map(chipFor).join(' ') + '</div>');
  if (privs.length) h.push('<div><b>Privileged built-in:</b> ' + privs.sort(byName).map(chipFor).join(' ') + '</div>');
  if (adms.length) h.push('<div><b>Admin-ish groups:</b> ' + adms.sort(byName).slice(0, 60).map(chipFor).join(' ') + (adms.length > 60 ? ' +' + (adms.length - 60) : '') + '</div>');
  if (ress.length) h.push('<div><b>Resource groups (Domain Local):</b> ' + ress.sort(byName).slice(0, 60).map(chipFor).join(' ') + (ress.length > 60 ? ' +' + (ress.length - 60) : '') + '</div>');
  if (others.length) h.push('<details><summary style="cursor:pointer;color:var(--muted)">' + others.length + ' other group(s)</summary><div>' + others.sort(byName).slice(0, 300).map(chipFor).join(' ') + (others.length > 300 ? ' ...' : '') + '</div></details>');
  // member of (direct)
  var par = (parentsOf.get(o.id) || []).map(function(p){ return N.get(p.id); }).filter(Boolean).sort(byName);
  h.push('<h4>Member of (direct)</h4><div>' + (par.length ? par.map(chipFor).join(' ') : '<span style="color:var(--muted)">none</span>') + '</div>');
  if (isGroup(o)) {
    var kids = (childrenOf.get(o.id) || []).map(function(c){ return N.get(c.id); }).filter(Boolean);
    var kg = kids.filter(isGroup).sort(byName), ku = kids.filter(function(k){ return !isGroup(k); }).sort(byName);
    h.push('<h4>Who gets in (direct members)</h4>');
    h.push('<div><b>Groups (' + kg.length + '):</b> ' + (kg.length ? kg.map(chipFor).join(' ') : '-') + '</div>');
    var hiddenUsers = (o.du + o.dc) - ku.length;
    h.push('<details' + (ku.length && ku.length <= 25 ? ' open' : '') + '><summary style="cursor:pointer"><b>Accounts (' + (o.du + o.dc) + ')</b>' + (hiddenUsers > 0 ? ' <span style="color:var(--muted)">- ' + hiddenUsers + ' not embedded in this report (see lateral_movement_users.csv)</span>' : '') + '</summary><div>' + ku.slice(0, 300).map(function(u){ return chipFor(u, u.en ? '' : 'dis'); }).join(' ') + (ku.length > 300 ? ' ...' : '') + '</div></details>');
  }
  // findings
  var fs = (nodeFind.get(o.id) || []).slice().sort(function(a, b){ return (SEV[b.sev] || 0) - (SEV[a.sev] || 0); });
  h.push('<h4>Findings (' + fs.length + ')</h4>');
  if (!fs.length) h.push('<div style="color:var(--muted)">No finding attached to this node.</div>');
  fs.forEach(function(f){ h.push(findingHtml(f)); });
  // edge findings where this node is the target
  var tf = LM.findings.filter(function(f){ return f.tid === o.id && f.sid !== o.id; }).sort(function(a, b){ return (SEV[b.sev] || 0) - (SEV[a.sev] || 0); });
  if (tf.length) { h.push('<h4>Findings where this is the target (' + tf.length + ')</h4>'); tf.slice(0, 50).forEach(function(f){ h.push(findingHtml(f)); }); if (tf.length > 50) h.push('<div class="more">... ' + (tf.length - 50) + ' more in the Findings tab</div>'); }
  el.innerHTML = '<h4><span class="closebtn" id="detailsClose" title="Close">&times;</span>Details</h4>' + h.join('');
  el.scrollTop = 0;
}
q('#details').addEventListener('click', function(e){ if (e.target && e.target.id === 'detailsClose') { state.selected = -1; state.highlightEdges.clear(); render.keepView = true; render(); renderDetails(null); } });
q('#btnLegend').addEventListener('click', function(){ q('#legend').classList.toggle('hidden'); });
q('#btnRelayout').addEventListener('click', function(){ state.manual.clear(); render.keepView = true; render(); decorate(); });
window.lmCopy = function(id){ var o = N.get(id); if (!o) return; try { navigator.clipboard.writeText(o.dn); } catch (e) { window.prompt('Distinguished name', o.dn); } };

// ---------- generic sortable table
function makeTable(opts){
  var tbody = q('#' + opts.table + ' tbody'), more = q('#' + opts.more), sortKey = opts.defaultSort, sortDesc = true, cap = opts.cap || 1500, lastRows = [];
  qa('#' + opts.table + ' thead th').forEach(function(th){ th.addEventListener('click', function(){ var k = th.dataset.k; if (!k) return; if (sortKey === k) sortDesc = !sortDesc; else { sortKey = k; sortDesc = true; } draw(); }); });
  function draw(){
    var rows = opts.rows().filter(opts.filter);
    rows.sort(function(a, b){ var va = a[sortKey], vb = b[sortKey]; if (typeof va === 'string' || typeof vb === 'string') { va = (va === null || va === undefined) ? '' : String(va).toLowerCase(); vb = (vb === null || vb === undefined) ? '' : String(vb).toLowerCase(); return sortDesc ? vb.localeCompare(va) : va.localeCompare(vb); } va = va || 0; vb = vb || 0; return sortDesc ? vb - va : va - vb; });
    lastRows = rows;
    tbody.innerHTML = rows.slice(0, cap).map(opts.row).join('');
    more.textContent = rows.length > cap ? 'Showing ' + cap + ' of ' + rows.length + ' rows - refine the filter or export CSV.' : rows.length + ' row(s)';
    if (opts.count) q('#' + opts.count).textContent = ' ' + rows.length;
  }
  if (opts.csv) q('#' + opts.csv).addEventListener('click', function(){ var cols = opts.csvCols; var lines = [cols.map(function(c){ return '"' + c + '"'; }).join(',')]; lastRows.forEach(function(r){ lines.push(cols.map(function(c){ var v = r[c]; if (v === null || v === undefined) v = ''; return '"' + String(v).replace(/"/g, '""') + '"'; }).join(',')); }); download(opts.csvName, '﻿' + lines.join('\r\n'), 'text/csv'); });
  return { draw: draw };
}
var fRows = LM.findings.map(function(f){ return { id: f.id, sev: f.sev, sevr: SEV[f.sev] || 0, r: f.r, st: f.st, s: f.s, t: f.t, p: f.p, d: f.d, fix: f.fix, k: f.k, sid: f.sid, ep: f.ep, ec: f.ec }; });
var fTable = makeTable({ table: 'fTable', more: 'fMore', defaultSort: 'sevr', count: 'cntFindings', csv: 'fCsv', csvName: 'lateral_movement_findings_filtered.csv', csvCols: ['sev','r','st','s','t','p','d','fix'],
  rows: function(){ return fRows; },
  filter: function(r){ var s = q('#fSearch').value.toLowerCase(), rule = q('#fRule').value, sev = q('#fSev').value, edges = q('#fEdges').checked; if (rule && r.r !== rule) return false; if (sev && r.sev !== sev) return false; if (edges && r.k !== 'edge') return false; if (s && (r.s + ' ' + r.t + ' ' + r.p + ' ' + r.d).toLowerCase().indexOf(s) < 0) return false; return true; },
  row: function(r){ return '<tr onclick="lmFindingClick(' + r.id + ')"><td>' + badge(r.sev) + '</td><td title="' + esc((LM.rules[r.r] || {}).title) + '">' + esc(r.r) + '</td><td>' + esc(r.st) + '</td><td>' + esc(r.s) + '</td><td>' + esc(r.t) + '</td><td class="mono">' + esc(r.p) + '</td><td>' + esc(r.d) + '</td></tr>'; } });
window.lmFindingClick = function(id){ var f = null; for (var i = 0; i < LM.findings.length; i++) if (LM.findings[i].id === id) { f = LM.findings[i]; break; } if (!f) return; if (f.sid >= 0 && N.has(f.sid)) { state.focus = f.sid; state.selected = f.sid; qa('input[name=mode]').forEach(function(r){ r.checked = r.value === 'focus'; }); state.highlightEdges.clear(); if (f.ep >= 0 && f.ec >= 0) state.highlightEdges.add(f.ep + '|' + f.ec); showView('map'); render(); renderDetails(N.get(f.sid)); } };
var uRows = PRINCIPALS.map(function(o){ return { id: o.id, sev: o.sev || 'Information', sevr: SEV[o.sev] || 1, score: o.score, s: o.s, n: o.n, t: o.t, en: o.en ? 'yes' : 'no', t0: o.dist >= 0 ? (o.t0direct ? 'direct' : 'NESTED') : '', hops: o.hops >= 0 ? o.hops : '', tg: o.tg, res: o.res, adm: o.adm, rules: o.rules, path: o.path, dist: o.dist }; });
var uTable = makeTable({ table: 'uTable', more: 'uMore', defaultSort: 'sevr', count: 'cntUsers', csv: 'uCsv', csvName: 'lateral_movement_accounts_filtered.csv', csvCols: ['sev','score','s','n','t','en','t0','hops','tg','res','adm','rules','path'],
  rows: function(){ return uRows; },
  filter: function(r){ var s = q('#uSearch').value.toLowerCase(), t = q('#uType').value; if (t && r.t !== t) return false; if (q('#uT0').checked && r.dist < 0) return false; if (q('#uEnabled').checked && r.en !== 'yes') return false; if (s && (r.s + ' ' + r.n + ' ' + r.path).toLowerCase().indexOf(s) < 0) return false; return true; },
  row: function(r){ return '<tr onclick="lmSelect(' + r.id + ')"><td>' + badge(r.sev) + '</td><td>' + r.score + '</td><td class="mono">' + esc(r.s) + '</td><td>' + esc(r.n) + '</td><td>' + esc(r.t) + '</td><td>' + r.en + '</td><td>' + (r.t0 === 'NESTED' ? '<b style="color:var(--critical)">NESTED</b>' : esc(r.t0)) + '</td><td>' + r.hops + '</td><td>' + r.tg + '</td><td>' + r.res + '</td><td>' + r.adm + '</td><td class="mono">' + esc(r.rules) + '</td><td class="mono">' + esc(r.path) + '</td></tr>'; } });
var gRows = GROUPS.map(function(o){ return { id: o.id, sev: o.sev || 'Information', sevr: SEV[o.sev] || 1, score: o.score, n: o.n, sc: o.sc + (o.sec ? '' : ' (dist)'), tier: tierLabel(o), tierk: o.et === null || o.et === undefined ? 9 : o.et, wk: o.wk || '', du: o.du, dg: o.dg, tu: o.tu, pc: o.pc, dist: o.dist, h: o.h, rules: o.rules, path: o.path, sink: isSink(o) || isPriv(o) }; });
var gTable = makeTable({ table: 'gTable', more: 'gMore', defaultSort: 'sevr', count: 'cntGroups', csv: 'gCsv', csvName: 'lateral_movement_groups_filtered.csv', csvCols: ['sev','score','n','sc','tier','wk','du','dg','tu','pc','dist','h','rules','path'],
  rows: function(){ return gRows; },
  filter: function(r){ var s = q('#gSearch').value.toLowerCase(), sc = q('#gScope').value; if (sc && r.sc.indexOf(sc) !== 0) return false; if (q('#gT0').checked && r.dist < 0) return false; if (q('#gWk').checked && !r.wk) return false; if (q('#gFind').checked && !r.rules) return false; if (s && (r.n + ' ' + r.wk + ' ' + r.path).toLowerCase().indexOf(s) < 0) return false; return true; },
  row: function(r){ return '<tr onclick="lmSelect(' + r.id + ')"><td>' + badge(r.sev) + '</td><td>' + r.score + '</td><td>' + esc(r.n) + (r.sink ? ' <span class="badge badge-t0">sink</span>' : '') + '</td><td>' + esc(r.sc) + '</td><td>' + esc(r.tier) + '</td><td>' + esc(r.wk) + '</td><td>' + r.du + '</td><td>' + r.dg + '</td><td>' + fmtInt(r.tu) + '</td><td>' + r.pc + '</td><td>' + (r.dist >= 0 ? r.dist : '') + '</td><td>' + r.h + '</td><td class="mono">' + esc(r.rules) + '</td><td class="mono">' + esc(r.path) + '</td></tr>'; } });
var pRows = ALL.filter(function(o){ return o.dist > 0 && !isSink(o); }).map(function(o){ return { id: o.id, t: o.t, s: label(o), en: isGroup(o) ? '' : (o.en ? 'yes' : 'no'), direct: isGroup(o) ? (o.dist === 1 ? 'yes' : 'no') : (o.t0direct ? 'yes' : 'no'), hops: o.hops >= 0 ? o.hops : o.dist, t0: (o.t0 || []).map(function(id){ return N.has(id) ? label(N.get(id)) : ''; }).join('; '), path: o.path, nested: isGroup(o) ? o.dist > 1 : !o.t0direct }; });
var pTable = makeTable({ table: 'pTable', more: 'pMore', defaultSort: 'hops', count: 'cntPaths', cap: 3000,
  rows: function(){ return pRows; },
  filter: function(r){ var s = q('#pSearch').value.toLowerCase(); if (q('#pNested').checked && !r.nested) return false; if (q('#pUsersOnly').checked && r.t === 'group') return false; if (s && (r.s + ' ' + r.path).toLowerCase().indexOf(s) < 0) return false; return true; },
  row: function(r){ return '<tr onclick="lmSelect(' + r.id + ')"><td>' + esc(r.t) + '</td><td class="mono">' + esc(r.s) + '</td><td>' + r.en + '</td><td>' + (r.direct === 'no' ? '<b style="color:var(--critical)">nested</b>' : 'direct') + '</td><td>' + r.hops + '</td><td>' + esc(r.t0) + '</td><td class="mono">' + esc(r.path) + '</td></tr>'; } });

// ---------- views, stats, rules, search, init
function showView(v){ qa('.tab').forEach(function(t){ t.classList.toggle('active', t.dataset.view === v); }); qa('.view').forEach(function(x){ x.classList.toggle('active', x.id === 'view-' + v); }); if (v === 'map') setTimeout(fit, 0); }
qa('.tab').forEach(function(t){ t.addEventListener('click', function(){ showView(t.dataset.view); }); });
(function init(){
  var m = LM.meta, bs = m.bySeverity;
  q('#heroMeta').textContent = 'Domain ' + m.domain + ' | generated ' + m.generated + ' | ' + fmtInt(m.stats.groups) + ' groups, ' + fmtInt(m.stats.users) + ' users (' + fmtInt(m.stats.enabledUsers) + ' enabled), ' + fmtInt(m.stats.computers) + ' computers | ' + fmtInt(m.stats.edges) + ' membership edges, ' + fmtInt(m.stats.groupEdges) + ' group-in-group';
  q('#overallBadge').className = 'badge badge-' + (SEVCLS[m.overall] || 'info'); q('#overallBadge').textContent = 'Overall: ' + m.overall;
  q('#evidenceLink').href = 'file:///' + String(m.evidenceDir || '').replace(/\\/g, '/'); q('#evidenceLink').title = m.evidenceDir || '';
  var st = [['critical', bs.Critical, 'Critical', 'Critical'], ['high', bs.High, 'High', 'High'], ['medium', bs.Medium, 'Medium', 'Medium'], ['low', bs.Low, 'Low', 'Low'], ['info', bs.Information, 'Information', 'Information'], ['t0', m.stats.t0Users, 'Tier 0 accounts', null], ['t0', m.stats.t0UsersHidden, 'Tier 0 only via nesting', null], ['t0', m.stats.t0Groups, 'Groups reaching Tier 0', null], ['', m.stats.cycles, 'Membership loops', null], ['', m.stats.broad, 'Broad groups', null]];
  q('#stats').innerHTML = st.map(function(s){ return '<div class="stat ' + s[0] + '"' + (s[3] ? ' style="cursor:pointer" onclick="lmSevTab(\'' + s[3] + '\')"' : '') + '><div class="val">' + fmtInt(s[1]) + '</div><div class="lbl">' + s[2] + '</div></div>'; }).join('');
  var notes = [];
  (m.notAssessed || []).forEach(function(n){ notes.push('<div class="note warn"><b>Reduced coverage:</b> ' + esc(n) + '</div>'); });
  (m.coverage || []).forEach(function(n){ notes.push('<div class="note">' + esc(n) + '</div>'); });
  if (m.truncated) notes.push('<div class="note warn">Only the ' + fmtInt(m.embeddedPrincipals) + ' highest-risk accounts of ' + fmtInt(m.principalsTotal) + ' are embedded in this map (-HtmlUserLimit). All accounts are in lateral_movement_users.csv.</div>');
  q('#coverageNotes').innerHTML = notes.join('');
  // rules
  var rl = [];
  Object.keys(LM.rules).forEach(function(k){ var r = LM.rules[k]; rl.push('<div class="rule ' + (SEVCLS[r.max || r.severity] || 'info') + '"><h3>' + esc(k) + ' ' + esc(r.title) + ' ' + (r.count ? badge(r.max) + '<span class="badge badge-tag">' + r.count + ' finding(s)</span>' : '<span class="badge badge-low">no findings</span>') + '<span class="badge badge-tag">default ' + esc(r.severity) + '</span></h3><p><b>What:</b> ' + esc(r.what) + '</p><p><b>Why it matters:</b> ' + esc(r.why) + '</p><p><b>How to fix:</b> ' + esc(r.fix) + '</p></div>'); q('#fRule').insertAdjacentHTML('beforeend', '<option value="' + esc(k) + '">' + esc(k) + ' ' + esc(r.title) + (r.count ? ' (' + r.count + ')' : '') + '</option>'); });
  q('#rulesList').innerHTML = rl.join('');
  q('#catTable tbody').innerHTML = LM.catalog.map(function(c){ return '<tr><td>' + esc(c.name) + '</td><td>' + (c.tier === '0' ? 'Tier 0' : c.tier === 'P' ? 'privileged (DC-level, not Tier 0)' : c.tier === 'B' ? 'broad' : 'neutral') + '</td><td>' + badge(c.severity) + '</td><td>' + esc(c.tag) + '</td><td>' + esc(c.why) + '</td><td>' + esc(c.fix) + '</td></tr>'; }).join('');
  // ou filter
  var ous = {}; GROUPS.forEach(function(g){ if (g.ou) ous[g.ou] = (ous[g.ou] || 0) + 1; });
  Object.keys(ous).sort().forEach(function(ou){ q('#ouFilter').insertAdjacentHTML('beforeend', '<option value="' + esc(ou) + '">' + esc(ou) + ' (' + ous[ou] + ')</option>'); });
  // legend
  q('#legend').innerHTML = '<div><span class="sw" style="background:var(--t0-soft);border-color:var(--t0)"></span>Tier 0 / privileged sink</div><div><span class="sw" style="background:var(--critical-soft);border-color:var(--critical)"></span>Critical</div><div><span class="sw" style="background:var(--high-soft);border-color:var(--high)"></span>High</div><div><span class="sw" style="background:var(--medium-soft);border-color:var(--medium)"></span>Medium</div><div><span class="sw" style="background:var(--low-soft);border-color:var(--low)"></span>Low</div><div><span class="sw" style="background:var(--info-soft);border-color:var(--info)"></span>Information / none</div><div><span class="ln" style="border-color:var(--edge-bad)"></span>edge with Critical/High finding</div><div><span class="ln" style="border-color:var(--edge-warn)"></span>edge with Medium/Low finding</div><div><span class="ln" style="border-color:var(--edge-path)"></span>path to Tier 0 / highlighted</div><div><span class="ln" style="border-color:var(--edge);border-top-style:dashed"></span>primaryGroupID membership</div><div>G group &middot; U user &middot; C computer &middot; S service account &middot; F foreign &middot; X cross-domain</div>';
  // baseline
  if (LM.baselineDiff) { q('#tabBaseline').style.display = ''; var b = m.baseline; q('#cntBaseline').textContent = ' ' + LM.baselineDiff.length; q('#baselineInfo').innerHTML = 'Baseline: <span class="mono">' + esc(b.path) + '</span> (' + b.baselineEdges + ' group-in-group edges) vs now (' + b.currentEdges + '): <b>' + b.added + ' added</b>, ' + b.removed + ' removed.'; q('#bTable tbody').innerHTML = LM.baselineDiff.map(function(r){ return '<tr><td>' + esc(r.change) + '</td><td>' + badge(r.sev) + '</td><td class="mono">' + esc(r.child) + '</td><td class="mono">' + esc(r.parent) + '</td></tr>'; }).join(''); }
  // search suggestions
  var idx = ALL.map(function(o){ return { id: o.id, key: (label(o) + ' ' + (o.s || '') + ' ' + (o.n || '')).toLowerCase(), o: o }; });
  var sl = q('#searchList'), sinput = q('#search');
  sinput.addEventListener('input', function(){ var v = sinput.value.trim().toLowerCase(); if (v.length < 2) { sl.style.display = 'none'; return; } var hits = []; for (var i = 0; i < idx.length && hits.length < 25; i++) if (idx[i].key.indexOf(v) >= 0) hits.push(idx[i]); sl.innerHTML = hits.map(function(h){ return '<div data-id="' + h.id + '">' + esc(label(h.o)) + '<small>' + esc(h.o.t + (h.o.sc ? ' ' + h.o.sc : '')) + '</small> ' + badge(h.o.sev || 'Information') + '</div>'; }).join('') || '<div><small>no match</small></div>'; sl.style.display = 'block'; });
  sl.addEventListener('click', function(e){ var d = e.target.closest('div[data-id]'); if (!d) return; sl.style.display = 'none'; sinput.value = ''; focusNode(parseInt(d.dataset.id, 10)); });
  sinput.addEventListener('keydown', function(e){ if (e.key === 'Enter') { var v = sinput.value.trim().toLowerCase(); var hit = null; for (var i = 0; i < idx.length; i++) { if (idx[i].key.indexOf(v) >= 0) { if (!hit || (idx[i].o.s || '').toLowerCase() === v || (idx[i].o.n || '').toLowerCase() === v) hit = idx[i]; } } if (hit) { sl.style.display = 'none'; focusNode(hit.id); } } if (e.key === 'Escape') sl.style.display = 'none'; });
  document.addEventListener('click', function(e){ if (!e.target.closest('.suggest')) sl.style.display = 'none'; });
  // controls
  qa('input[name=mode]').forEach(function(r){ r.addEventListener('change', function(){ if (r.value === 'focus' && state.focus < 0 && state.selected >= 0) state.focus = state.selected; render(); }); });
  q('#hops').addEventListener('input', function(){ q('#hopsVal').textContent = q('#hops').value; });
  q('#hops').addEventListener('change', render);
  ['#dirOut', '#dirIn', '#showUsers', '#hideDist', '#hideEmpty', '#onlyT0', '#onlyFind', '#ouFilter'].forEach(function(s){ q(s).addEventListener('change', render); });
  qa('.sevf,.scopef,.tierf').forEach(function(c){ c.addEventListener('change', render); });
  q('#btnApply').addEventListener('click', render);
  q('#nameFilter').addEventListener('keydown', function(e){ if (e.key === 'Enter') render(); });
  q('#btnReset').addEventListener('click', function(){ qa('.sevf,.scopef,.tierf').forEach(function(c){ c.checked = true; }); q('#hideDist').checked = true; ['#hideEmpty', '#onlyT0', '#onlyFind', '#dirOut', '#dirIn', '#showUsers'].forEach(function(s){ q(s).checked = s === '#dirOut' || s === '#dirIn' || s === '#showUsers'; }); q('#ouFilter').value = ''; q('#nameFilter').value = ''; q('#hops').value = 3; q('#hopsVal').textContent = '3'; qa('input[name=mode]').forEach(function(r){ r.checked = r.value === 'overview'; }); state.selected = -1; state.focus = -1; state.highlightEdges.clear(); render(); renderDetails(null); });
  ['#fSearch', '#fRule', '#fSev', '#fEdges'].forEach(function(s){ q(s).addEventListener('input', fTable.draw); q(s).addEventListener('change', fTable.draw); });
  ['#uSearch', '#uType', '#uT0', '#uEnabled'].forEach(function(s){ q(s).addEventListener('input', uTable.draw); q(s).addEventListener('change', uTable.draw); });
  ['#gSearch', '#gScope', '#gT0', '#gWk', '#gFind'].forEach(function(s){ q(s).addEventListener('input', gTable.draw); q(s).addEventListener('change', gTable.draw); });
  ['#pSearch', '#pNested', '#pUsersOnly'].forEach(function(s){ q(s).addEventListener('input', pTable.draw); q(s).addEventListener('change', pTable.draw); });
  window.lmSevTab = function(sev){ q('#fSev').value = sev; showView('findings'); fTable.draw(); };
  // theme
  var themeBtn = q('#themeBtn'); var saved = null; try { saved = localStorage.getItem('adaudit-lm-theme'); } catch (e) {}
  if (saved === 'dark' || saved === 'light') document.documentElement.setAttribute('data-theme', saved);
  themeBtn.addEventListener('click', function(){ var cur = document.documentElement.getAttribute('data-theme'); var dark = cur ? cur === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches; var next = dark ? 'light' : 'dark'; document.documentElement.setAttribute('data-theme', next); try { localStorage.setItem('adaudit-lm-theme', next); } catch (e) {} });
  fTable.draw(); uTable.draw(); gTable.draw(); pTable.draw();
  render();
  window.addEventListener('resize', function(){ if (q('#view-map').classList.contains('active')) fit(); });
})();
})();
'@
#endregion

#region ===================================================== HTML: assembly
function Write-LmHtmlReport {
    param($Data, $Summary, $Dirs, [int]$HtmlUserLimit)
    $htmlPath = Join-Path $Dirs.Html 'Lateral-Movement.html'
    $json = Get-LmHtmlJson -Data $Data -Summary $Summary -HtmlUserLimit $HtmlUserLimit -Dirs $Dirs -HtmlPath $htmlPath
    $nav = Get-LmPrimaryNav
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!doctype html>')
    [void]$sb.AppendLine('<html lang="en">')
    [void]$sb.AppendLine('<head>')
    [void]$sb.AppendLine('<meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine("<title>ADAudit - Lateral Movement Map ($(Get-LmHtmlEncoded $Data.DomainDns))</title>")
    [void]$sb.AppendLine($script:LmHtmlCss)
    [void]$sb.AppendLine('</head>')
    [void]$sb.AppendLine('<body>')
    [void]$sb.AppendLine('<div class="container">')
    if ($nav) { [void]$sb.AppendLine($nav) }
    [void]$sb.AppendLine($script:LmHtmlBody)
    [void]$sb.AppendLine("<div class=""footer"">Generated by AD Audit - Invoke-LateralMovementCheck.ps1 v$($script:LmVersion) &mdash; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'). Read-only analysis of group nesting; see lateral_movement.txt and the CSV files next to it for the full evidence.</div>")
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('<script id="lm-data" type="application/json">')
    [void]$sb.AppendLine($json)
    [void]$sb.AppendLine('</script>')
    [void]$sb.AppendLine('<script>')
    [void]$sb.AppendLine($script:LmHtmlJs1)
    [void]$sb.AppendLine($script:LmHtmlJs2)
    [void]$sb.AppendLine('</script>')
    [void]$sb.AppendLine('</body>')
    [void]$sb.AppendLine('</html>')
    [System.IO.File]::WriteAllText($htmlPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    return $htmlPath
}
#endregion

#region ===================================================== Main
function Invoke-LmMain {
    [CmdletBinding()]
    param(
        [string]$OutputRoot, [string]$Server, [string]$SearchBase, [string]$BaselinePath,
        [string[]]$Tier0Groups, [string[]]$Tier1Groups, [string[]]$Tier2Groups, [string[]]$ApprovedNestings,
        [string]$AdminGroupPattern, [string]$AdminAccountPattern, [string]$TierTagPattern, [string]$TemporaryGroupPattern,
        [int]$BroadGroupPercent, [int]$StaleDays, [int]$PasswordAgeDays, [int]$DeepNestingLevels, [int]$MaxDepth,
        [int]$HtmlUserLimit, [bool]$NoHtml, [string]$ScriptLine
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $script:LmRules = Get-LmRuleCatalog
    $script:LmNotAssessed.Clear()
    Write-LmLog "    [*] Lateral movement analysis (group nesting) v$($script:LmVersion)$(if ($script:LmIntegrated) { ' - integrated with AdAudit-PS7' } else { ' - standalone' })"

    if (-not (Get-Command -Name 'Get-ADObject' -ErrorAction SilentlyContinue)) {
        try {
            if (Get-Command -Name 'Import-ADAuditModule' -ErrorAction SilentlyContinue) { Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null }
            else { Import-Module ActiveDirectory -ErrorAction Stop }
        } catch {
            Register-LmNotAssessed -Reason "ActiveDirectory PowerShell module is not available ($($_.Exception.Message)). Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
            Write-LmLog '    [!] Lateral movement check skipped - ActiveDirectory module missing.'
            return $null
        }
    }

    $dirs = Get-LmOutputDirs -OutputRoot $OutputRoot
    $data = $null
    try {
        $data = Get-LmDirectoryData -Server $Server -SearchBase $SearchBase -Catalog (Get-LmWellKnownCatalog) `
            -Tier0Groups $Tier0Groups -Tier1Groups $Tier1Groups -Tier2Groups $Tier2Groups `
            -AdminGroupPattern $AdminGroupPattern -AdminAccountPattern $AdminAccountPattern -TierTagPattern $TierTagPattern -TemporaryGroupPattern $TemporaryGroupPattern
    } catch {
        Register-LmNotAssessed -Reason "Directory enumeration failed: $($_.Exception.Message)" -Target $(if ($Server) { $Server } else { 'default DC' })
        Write-LmLog "    [!] Lateral movement check could not enumerate the directory: $($_.Exception.Message)"
        return $null
    }
    if ($data.GroupIds.Count -eq 0) {
        Register-LmNotAssessed -Reason 'No groups were returned by the directory query - nothing to analyse.' -Target $data.DomainDns
        return $null
    }

    Invoke-LmGraphAnalysis -Data $data -MaxDepth $MaxDepth -BroadGroupPercent $BroadGroupPercent
    Invoke-LmFindings -Data $data -ApprovedNestings $ApprovedNestings -StaleDays $StaleDays -PasswordAgeDays $PasswordAgeDays -DeepNestingLevels $DeepNestingLevels -BaselinePath $BaselinePath
    $summary = Get-LmSummary -Data $data

    Write-LmLog "    [*] Writing evidence to $($dirs.Lm) ..."
    $csv = Write-LmCsvOutputs -Data $data -Dirs $dirs
    $htmlPath = ''
    if (-not $NoHtml) {
        try { $htmlPath = Write-LmHtmlReport -Data $data -Summary $summary -Dirs $dirs -HtmlUserLimit $HtmlUserLimit }
        catch { Write-LmLog "    [!] HTML map could not be written: $($_.Exception.Message)"; Register-LmNotAssessed -Reason "HTML map not written: $($_.Exception.Message)" }
    }
    $txtPath = Write-LmTextReport -Data $data -Summary $summary -Dirs $dirs -HtmlPath $htmlPath -ScriptLine $ScriptLine

    # Nessus export (only when integrated): one item per rule with findings, severity = worst finding
    $kbByRule = @{}
    $i = 1
    foreach ($rid in $script:LmRules.Keys) { $kbByRule[$rid] = 'KB14{0:D2}' -f $i; $i++ }
    foreach ($rid in $script:LmRules.Keys) {
        $r = $summary.ByRule[$rid]
        if ($r.Count -eq 0) { continue }
        $items = @($data.Findings | Where-Object { $_.RuleId -eq $rid } | Sort-Object -Property @{ Expression = { $script:LmSeverityRank[$_.Severity] }; Descending = $true } | Select-Object -First 60)
        $text = New-Object System.Text.StringBuilder
        [void]$text.AppendLine("$rid $($script:LmRules[$rid].Title) - $($r.Count) finding(s), worst severity $($r.Max)")
        [void]$text.AppendLine($script:LmRules[$rid].Why)
        [void]$text.AppendLine('')
        foreach ($f in $items) { [void]$text.AppendLine("[$($f.Severity)] $($f.Subject): $($f.Detail)") }
        if ($r.Count -gt 60) { [void]$text.AppendLine("... $($r.Count - 60) more in lateral_movement_findings.csv") }
        Write-LmNessusFinding -Name "LateralMovement_$rid" -Kb $kbByRule[$rid] -Text $text.ToString() -Severity $r.Max
    }
    if ($data.Findings.Count -gt 0) {
        $head = @(Get-Content -LiteralPath $txtPath -TotalCount 120) -join [Environment]::NewLine
        Write-LmNessusFinding -Name 'LateralMovementSummary' -Kb 'KB1400' -Text ($head + [Environment]::NewLine + '... full report in lateral_movement.txt') -Severity $summary.Overall
    }

    $sw.Stop()
    $bs = $summary.BySeverity
    if ($data.Findings.Count -eq 0) {
        Write-LmLog "    [+] No lateral movement findings: no group nesting reaches a Tier 0 group and no AGDLP violations were detected ($($data.Stats.Groups) groups, $($data.Stats.Users) users)."
    } else {
        Write-LmLog "    [!] Lateral movement findings: $($data.Findings.Count) (Critical $($bs.Critical), High $($bs.High), Medium $($bs.Medium), Low $($bs.Low), Info $($bs.Information)) - overall $($summary.Overall)"
        Write-LmLog "    [!] Effectively Tier 0: $($summary.Tier0Users) user account(s), $($summary.Tier0UsersHidden) of them only through nesting; $($summary.Tier0ReachingGroups) group(s) reach Tier 0 through nesting"
        foreach ($f in ($data.Findings | Where-Object { $_.Severity -eq 'Critical' } | Sort-Object RuleId, Subject | Select-Object -First 12)) {
            Write-LmLog "        - [$($f.RuleId)] $($f.Subject)$(if ($f.Target) { " -> $($f.Target)" })"
        }
        if ($bs.Critical -gt 12) { Write-LmLog "        ... $($bs.Critical - 12) more Critical findings in lateral_movement.txt" }
    }
    Write-LmLog "        - TXT : $(Split-Path -Leaf $txtPath)"
    Write-LmLog "        - CSV : LateralMovement\lateral_movement_findings.csv, _users.csv, _groups.csv, _edges.csv (baseline), _tier0_paths.csv"
    if ($htmlPath) { Write-LmLog "        - HTML: $(Split-Path -Leaf $htmlPath)" }
    Write-LmLog "    [*] Lateral movement analysis finished in $([int]$sw.Elapsed.TotalSeconds) s"

    return [pscustomobject]@{
        Domain = $data.DomainDns; Overall = $summary.Overall; Findings = $data.Findings; Summary = $summary; Stats = $data.Stats
        Nodes = $data.Nodes; Edges = $data.Edges; TextReport = $txtPath; HtmlReport = $htmlPath; Csv = $csv; EvidenceDir = $dirs.Lm
        NotAssessed = $script:LmNotAssessed.ToArray()
    }
}

$lmScriptLine = try { [string]$MyInvocation.Line } catch { '' }
if ([string]::IsNullOrWhiteSpace($lmScriptLine) -or $lmScriptLine.Length -gt 300) { $lmScriptLine = 'Invoke-LateralMovementCheck.ps1' }
$lmResult = Invoke-LmMain -OutputRoot $OutputRoot -Server $Server -SearchBase $SearchBase -BaselinePath $BaselinePath `
    -Tier0Groups $Tier0Groups -Tier1Groups $Tier1Groups -Tier2Groups $Tier2Groups -ApprovedNestings $ApprovedNestings `
    -AdminGroupPattern $AdminGroupPattern -AdminAccountPattern $AdminAccountPattern -TierTagPattern $TierTagPattern -TemporaryGroupPattern $TemporaryGroupPattern `
    -BroadGroupPercent $BroadGroupPercent -StaleDays $StaleDays -PasswordAgeDays $PasswordAgeDays -DeepNestingLevels $DeepNestingLevels -MaxDepth $MaxDepth `
    -HtmlUserLimit $HtmlUserLimit -NoHtml ([bool]$NoHtml) -ScriptLine $lmScriptLine
$ErrorActionPreference = $lmPrevEap
if ($PassThru) { $lmResult }
#endregion
