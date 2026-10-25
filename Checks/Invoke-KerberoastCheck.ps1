<#
    .SYNOPSIS
        ADAudit check: Check high value kerberoastable user accounts

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -spn). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-KerberoastCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select spn [options]

    .NOTES
        Entry point: Invoke-KerberoastCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
Function Get-SPNs {
    [CmdletBinding()]
    param([string]$Server)
    Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null
    if (-not $Server) {
        $Server = if ($script:ADAuditIsolatedClone) { $env:COMPUTERNAME } else { [string](Get-ADDomainController -Discover -ErrorAction Stop).HostName }
    }
    $domain = Get-ADDomain -Server $Server -ErrorAction Stop
    $forest = Get-ADForest -Server $Server -ErrorAction Stop
    $rootDomain = Get-ADDomain -Identity $forest.RootDomain -Server $forest.RootDomain -ErrorAction Stop
    $domainSid = [string]$domain.DomainSID
    $rootSid = [string]$rootDomain.DomainSID
    # Well-known SIDs work with renamed/localized built-in groups. Forest groups
    # are queried in the forest root, not manufactured from a child domain SID.
    $groups = @(
        @{ Identity="$domainSid-512"; Server=$Server },
        @{ Identity="$domainSid-516"; Server=$Server },
        @{ Identity="$domainSid-521"; Server=$Server },
        @{ Identity="$domainSid-520"; Server=$Server },
        @{ Identity="$rootSid-519"; Server=$forest.RootDomain },
        @{ Identity="$rootSid-518"; Server=$forest.RootDomain }
    )
    foreach ($sid in @('S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551','S-1-5-32-569')) {
        $groups += @{ Identity=$sid; Server=$Server }
    }
    # Product-created groups have no well-known RID. Missing optional groups are
    # expected, but access/network errors are reduced coverage, never a clean pass.
    foreach ($name in @('DnsAdmins','Exchange Servers','Exchange Trusted Subsystem','Organization Management')) {
        try {
            $optional = Get-ADGroup -Filter { SamAccountName -eq $name } -Server $Server -ErrorAction Stop
            if ($optional) { $groups += @{ Identity=[string]$optional.SID; Server=$Server } }
        } catch {
            Register-ADAuditNotAssessed -Name 'Kerberoast optional group discovery' -Switch 'spn' -Target $name -Reason $_.Exception.Message
        }
    }
    $memberGroups = @{}
    $assessedGroups = 0
    $failedGroups = 0
    foreach ($definition in $groups) {
        try {
            $group = Get-ADGroup -Identity $definition.Identity -Server $definition.Server -ErrorAction Stop
            # AD performs the complete nested membership expansion. The previous
            # manual traversal pre-marked first-level groups visited and stopped.
            $members = @(Get-ADGroupMember -Identity $group -Recursive -Server $definition.Server -ErrorAction Stop)
            $assessedGroups++
            foreach ($member in $members) {
                $sid = [string]$member.SID
                if (-not $sid) { continue }
                if (-not $memberGroups.ContainsKey($sid)) { $memberGroups[$sid] = [System.Collections.Generic.List[string]]::new() }
                $memberGroups[$sid].Add([string]$group.Name)
            }
        } catch {
            $failedGroups++
            Register-ADAuditNotAssessed -Name 'Kerberoast privileged membership' -Switch 'spn' -Target $definition.Identity -Reason $_.Exception.Message
        }
    }
    $spnFile = Get-EvidencePath 'SPNs.txt'
    Remove-Item -LiteralPath $spnFile -Force -ErrorAction SilentlyContinue
    $users = @(Get-ADUser -Server $Server -LDAPFilter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Properties servicePrincipalName -ErrorAction Stop)
    $findings = @($users | Where-Object { $memberGroups.ContainsKey([string]$_.SID) } | ForEach-Object {
        "$($_.SamAccountName) ($($_.DistinguishedName)) in groups: $($memberGroups[[string]$_.SID] -join ', '); SPNs: $($_.servicePrincipalName -join '; ')"
    })
    if ($findings.Count) {
        $content = @('Enabled privileged user accounts with service principal names. This establishes Kerberoasting exposure, not a proven weak/cracked password.', '') + $findings
        $content | Set-Content -LiteralPath $spnFile -Encoding UTF8
        Write-Nessus-Finding 'Privileged SPN accounts exposed to Kerberoasting' 'KB611' ($content -join "`n")
        Write-Both "    [!] $($findings.Count) enabled privileged SPN account(s); review service design, password strength and gMSA eligibility."
    } else {
        Write-Both "    [+] No privileged SPN accounts found among $assessedGroups assessed groups; $failedGroups groups could not be assessed."
    }
}
function Invoke-KerberoastCheck {
    Get-SPNs
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select spn @args
}
