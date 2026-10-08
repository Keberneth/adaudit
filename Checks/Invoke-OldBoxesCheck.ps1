<#
    .SYNOPSIS
        ADAudit check: Computer Objects Audit (legacy OS)

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -oldboxes). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-OldBoxesCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select oldboxes [options]

    .NOTES
        Entry point: Invoke-OldBoxesCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
Function Get-OldBoxes {
    #Lists machines running OS older than Windows Server 2019
    $count = 0
    $oldboxes = Get-ADComputer -Filter { Enabled -eq "true" -and (OperatingSystem -Like "*2016*" -or OperatingSystem -Like "*2012*" -or OperatingSystem -Like "*2008*" -or OperatingSystem -Like "*2003*" -or OperatingSystem -Like "*2000*" -or OperatingSystem -Like "*XP*" -or OperatingSystem -like '*Windows 7*' -or OperatingSystem -like '*Windows 8*' -or OperatingSystem -like '*Windows 10*' -or OperatingSystem -like '*vista*') } -Property OperatingSystem, OperatingSystemVersion, OperatingSystemServicePack, IPv4Address
    $totalcount = ($oldboxes | Measure-Object | Select-Object Count).count
    foreach ($machine in $oldboxes) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for unsupported OS devices joined to the domain..." -Status "Currently identified $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path (Get-EvidencePath 'machines_old.txt') -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersion), $($machine.IPv4Address)"
        $count++
    }
    Write-Progress -Activity "Searching for unsupported OS devices joined to the domain..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count machines are running an OS older than Windows Server 2019 (some, such as Server 2016 or Windows 10, may still be in extended support - verify each against the Microsoft product lifecycle). See machines_old.txt (KB259)"
        Write-Nessus-Finding "OldBoxes" "KB259" ([System.IO.File]::ReadAllText((Get-EvidencePath 'machines_old.txt')))
    }
}

function Invoke-OldBoxesCheck {
    Get-OldBoxes
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select oldboxes @args
}