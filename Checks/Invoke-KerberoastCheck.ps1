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
                    Expression = { ,@($groups | ForEach-Object { $_.Name }) }
                }
            }

    $high_value_users = @()

    foreach ($spn in $SPNs) {
        if (-not $spn.Groups) {
            continue
        }

        $spn_groups = @($spn.Groups) | Where-Object { $_ -and $_.Trim() -ne "" }
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
        # Nothing to report: no evidence file is left behind (a file whose only content is
        # "nothing found" is noise in the output folder).
        Write-Both "    [+] No high value kerberoastable user accounts identified."
        Remove-Item -Path $spnFile -Force -ErrorAction SilentlyContinue
        return
    }

    foreach ($user in $high_value_users) {
        $kerbuser = '    [!]' + $user.Name + ' in groups: ' + $user.Group
        Write-Both $kerbuser
        Add-Content -Path $spnFile -Value ($user.Name + ' in groups: ' + $user.Group)
    }

    # Safe ReadAllText regardless of DC vs jump server
    $spnContent = [System.IO.File]::ReadAllText($spnFile)
    Write-Nessus-Finding "Kerberoast Attack - Services Configured With a Weak Password" "KB611" $spnContent
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