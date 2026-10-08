<#
    .SYNOPSIS
        ADAudit check: Check Generic Group AD Permissions

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -ouperms). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-OUPermissionsCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select ouperms [options]

    .NOTES
        Entry point: Invoke-OUPermissionsCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
Function Get-OUPerms {
    #Check for non-standard perms for authenticated users, domain users, users and everyone groups
    $count = 0
    $progresscount = 0
    # Scope to organizationalUnit objects only. The previous version enumerated EVERY object
    # in the domain and ran one Get-Acl per object (very slow on large estates), then labelled
    # every result 'OU:' even when it was a user/computer/container. Dangerous ACLs on non-OU
    # objects are covered by the -acl and -delegatedpermissions checks.
    $objects = @(Get-ADObject -LDAPFilter '(objectClass=organizationalUnit)')
    $totalcount = $objects.Count
    foreach ($object in $objects) {
        if ($totalcount -eq 0) { break }
        $progresscount++
        Write-Progress -Activity "Searching for non-standard OU permissions..." -Status "Currently identified $count" -PercentComplete ($progresscount / $totalcount * 100)
        try {
            $output = (Get-Acl -LiteralPath "AD:$($object.DistinguishedName)" -ErrorAction Stop).Access | Where-Object { ($_.IdentityReference -eq "$AuthenticatedUsers") -or ($_.IdentityReference -eq "$EveryOne") -or ($_.IdentityReference -like "*\$DomainUsers") -or ($_.IdentityReference -eq "BUILTIN\$Users") } | Where-Object { ($_.ActiveDirectoryRights -ne 'GenericRead') -and ($_.ActiveDirectoryRights -ne 'GenericExecute') -and ($_.ActiveDirectoryRights -ne 'ExtendedRight') -and ($_.ActiveDirectoryRights -ne 'ReadControl') -and ($_.ActiveDirectoryRights -ne 'ReadProperty') -and ($_.ActiveDirectoryRights -ne 'ListObject') -and ($_.ActiveDirectoryRights -ne 'ListChildren') -and ($_.ActiveDirectoryRights -ne 'ListChildren, ReadProperty, ListObject') -and ($_.ActiveDirectoryRights -ne 'ReadProperty, GenericExecute') -and ($_.AccessControlType -ne 'Deny') }
        } catch {
            $output = $null
            Add-Content -Path (Get-EvidencePath 'ou_permissions.txt') -Value "[?] Could not read ACL on $($object.DistinguishedName): $($_.Exception.Message)"
        }
        if ($output -ne $null) {
            $count++
            Add-Content -Path (Get-EvidencePath 'ou_permissions.txt') -Value "OU: $object"
            foreach ($ace in @($output)) {
                Add-Content -Path (Get-EvidencePath 'ou_permissions.txt') -Value "    [!] $($ace.IdentityReference) | $($ace.ActiveDirectoryRights) | $($ace.AccessControlType)"
            }
        }
    }
    Write-Progress -Activity "Searching for non-standard OU permissions..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] Non-standard OU permissions identified, see ou_permissions.txt"
        Write-Nessus-Finding "OUPermissions" "KB551" ([System.IO.File]::ReadAllText((Get-EvidencePath 'ou_permissions.txt')))
    }
}

function Invoke-OUPermissionsCheck {
    Get-OUPerms
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select ouperms @args
}