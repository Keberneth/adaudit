<#
    .SYNOPSIS
        ADAudit check: Inactive Computer Objects Audit

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -inactivecomputers). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-InactiveComputersCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select inactivecomputers [options]

    .NOTES
        Entry point: Invoke-InactiveComputersCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
Function Get-InactiveComputerObjects {
    $count = 0
    $DaysAgo = (Get-Date).AddDays(-90)

    $ReportPath = Get-EvidencePath 'computers_inactive_90days.txt'
    Remove-Item -Path $ReportPath -ErrorAction SilentlyContinue

    # LDAP filter so computers that have NEVER logged on are included too; the
    # AD-cmdlet filter 'LastLogonTimeStamp -lt X' requires the attribute to be
    # present and silently excluded them (same approach as Get-InactiveAccounts).
    $cutoffFt = $DaysAgo.ToFileTimeUtc()
    $ldapFilter =
        "(&(objectCategory=computer)" +
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
        "(|(lastLogonTimestamp<=$cutoffFt)(!(lastLogonTimestamp=*))))"
    $inactiveComputers = Get-ADComputer -LDAPFilter $ldapFilter -Properties LastLogonTimeStamp, DNSHostName, OperatingSystem
    $totalcount = ($inactiveComputers | Measure-Object | Select-Object Count).count

    foreach ($computer in $inactiveComputers) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for inactive computer objects (>90 days)..." -Status "Currently identified $count" -PercentComplete ($count / $totalcount * 100)

        $datelastlogon = if ($computer.LastLogonTimeStamp) { [DateTime]::FromFileTime($computer.LastLogonTimeStamp) } else { "Never" }

        Add-Content -Path $ReportPath -Value "Computer $($computer.Name) ($($computer.DNSHostName)) OS: $($computer.OperatingSystem) last logon: $datelastlogon"
        $count++
    }

    Write-Progress -Activity "Searching for inactive computer objects (>90 days)..." -Status "Ready" -Completed

    if ($count -gt 0) {
        Write-Both "    [!] $count enabled computer objects inactive for >90 days, see computers_inactive_90days.txt (KB552)"
        Write-Nessus-Finding "InactiveComputers90Days" "KB552" ([System.IO.File]::ReadAllText($ReportPath))
    }
}

function Invoke-InactiveComputersCheck {
    Get-InactiveComputerObjects
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select inactivecomputers @args
}