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
    $coverage = [System.Collections.Generic.List[object]]::new()
    $domainSid = (Get-ADDomain -ErrorAction Stop).DomainSID.Value
    $broadSids = @('S-1-1-0','S-1-5-11','S-1-5-32-545',"$domainSid-513","$domainSid-515")
    Remove-Item -LiteralPath (Get-EvidencePath 'ou_permissions.txt') -ErrorAction SilentlyContinue
    # Scope to organizationalUnit objects only. The previous version enumerated EVERY object
    # in the domain and ran one Get-Acl per object (very slow on large estates), then labelled
    # every result 'OU:' even when it was a user/computer/container. Dangerous ACLs on non-OU
    # objects are covered by the -acl and -delegatedpermissions checks.
    Write-ADAuditProgress -Activity 'OU permissions: enumeration' -Status 'Reading organizational units' -PercentComplete -1
    $objects = @(Get-ADObject -LDAPFilter '(objectClass=organizationalUnit)' -ErrorAction Stop)
    $totalcount = $objects.Count
    foreach ($object in $objects) {
        if ($totalcount -eq 0) { break }
        $progresscount++
        Write-ADAuditProgress -Activity "Searching for non-standard OU permissions..." -Status "Reading OU $progresscount/$totalcount; $count OUs with matching permissions" -PercentComplete (($progresscount - 1) / $totalcount * 100)
        try {
            $output = @((Get-ADObjectAclSafe -DistinguishedName $object.DistinguishedName).Access | Where-Object {
                (Get-ADAuditAceSid $_) -in $broadSids -and [string]$_.AccessControlType -eq 'Allow' -and
                (@(Get-ADAuditDangerousAceCapability $_ -IncludeDescendants).Count -gt 0 -or (([int]$_.ActiveDirectoryRights -band 67) -ne 0))
            })
            $coverage.Add([pscustomobject]@{DistinguishedName=$object.DistinguishedName; Status='Assessed'; MatchingAllowAces=$output.Count})
        } catch {
            $output = $null
            Register-ADAuditNotAssessed -Name 'OU permissions' -Switch 'ouperms' -Target $object.DistinguishedName -Reason $_.Exception.Message
            $coverage.Add([pscustomobject]@{DistinguishedName=$object.DistinguishedName; Status='NotAssessed'; MatchingAllowAces=$null})
        }
        if (@($output).Count -gt 0 -and $null -ne $output) {
            $count++
            Add-Content -Path (Get-EvidencePath 'ou_permissions.txt') -Value "OU: $object"
            foreach ($ace in @($output)) {
                Add-Content -Path (Get-EvidencePath 'ou_permissions.txt') -Value "    [!] Potential exposure: $($ace.IdentityReference) | $($ace.ActiveDirectoryRights) | $($ace.AccessControlType) | ObjectType=$($ace.ObjectType) | InheritedObjectType=$($ace.InheritedObjectType) | Inheritance=$($ace.InheritanceType). Validate target class/property scope and effective deny/group access."
            }
        }
    }
    Write-ADAuditProgress -Activity "Searching for non-standard OU permissions..." -Status "Ready" -Completed
    $coverage | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Get-EvidencePath 'ou_permission_coverage.csv')
    Write-Both "    [*] OU permission scope: broad-group allow ACEs; $(@($coverage | Where-Object Status -eq 'Assessed').Count)/$($objects.Count) OUs assessed. Custom groups and effective-access evaluation require review."
    if ($count -gt 0) {
        Write-Both "    [!] Non-standard OU permissions identified, see ou_permissions.txt"
        Write-Nessus-Finding "OUPermissions" "KB551" ([System.IO.File]::ReadAllText((Get-EvidencePath 'ou_permissions.txt')))
    }
}

function Invoke-OUPermissionsCheck {
    Write-ADAuditProgress -Activity 'OU permission checks' -Status 'Starting collection' -PercentComplete -1
    try {
        Get-OUPerms
    } finally {
        Write-ADAuditProgress -Activity 'OU permission checks' -Completed
    }
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select ouperms @args
}
