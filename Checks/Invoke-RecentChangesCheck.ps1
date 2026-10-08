<#
    .SYNOPSIS
        ADAudit check: Check For newly created users and groups

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -recentchanges). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-RecentChangesCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select recentchanges [options]

    .NOTES
        Entry point: Invoke-RecentChangesCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
Function Get-RecentChanges() {
    #Retrieve users and groups that have been created during last 30 days
    $DateCutOff = ((Get-Date).AddDays(-30)).Date
    $newUsers = Get-ADUser  -Filter { whenCreated -ge $DateCutOff } -Properties whenCreated | select whenCreated, SamAccountName
    $newGroups = Get-ADGroup -Filter { whenCreated -ge $DateCutOff } -Properties whenCreated | select whenCreated, SamAccountName
    $totalcountUsers = ($newUsers  | Measure-Object | Select-Object Count).count
    $totalcountGroups = ($newGroups | Measure-Object | Select-Object Count).count
    if ($totalcountUsers -gt 0) {
        # Add header line (overwrite any existing file)
"# Users created within the last 30 days" | Set-Content -Path (Get-EvidencePath 'new_users.txt')
        foreach ($newUser in $newUsers ) { Add-Content -Path (Get-EvidencePath 'new_users.txt') -Value "Account $($newUser.SamAccountName) was created $($newUser.whenCreated)" }
        Write-Both "    [!] $totalcountUsers new users were created last 30 days, see $outputdir\new_users.txt"
    }
    if ($totalcountGroups -gt 0) {
        "# Groups created within the last 30 days" | Set-Content -Path (Get-EvidencePath 'new_groups.txt')
        foreach ($newGroup in $newGroups ) { Add-Content -Path (Get-EvidencePath 'new_groups.txt') -Value "Group $($newGroup.SamAccountName) was created $($newGroup.whenCreated)" }
        Write-Both "    [!] $totalcountGroups new groups were created last 30 days, see $outputdir\new_groups.txt"
    }
}

function Invoke-RecentChangesCheck {
    Get-RecentChanges
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select recentchanges @args
}