<#
    .SYNOPSIS
        ADAudit check: Device Information

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -hostdetails). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-HostDetailsCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select hostdetails [options]

    .NOTES
        Entry point: Invoke-HostDetailsCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: none.
#>
Function Get-WinVersion {
    $WinVersion = [single]([string][environment]::OSVersion.Version.Major + "." + [string][environment]::OSVersion.Version.Minor)
    return [single]$WinVersion
}

Function Get-HostDetails {
    #Gets basic information about the host
    Write-Both "    [+] Device Name:  $env:ComputerName"
    Write-Both "    [+] Domain Name:  $env:UserDomain"
    Write-Both "    [+] User Name  :  $env:UserName"
    Write-Both "    [+] NT Version :  $(Get-WinVersion)"
    Write-Both "    [+] PowerShell :  $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
    $IPAddresses = [net.dns]::GetHostAddresses("") | Select-Object -ExpandProperty IPAddressToString
    foreach ($ip in $IPAddresses) {
        if ($ip -ne "::1") {
            Write-Both "    [+] IP Address :  $ip"
        }
    }
}

function Invoke-HostDetailsCheck {
    Get-HostDetails
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select hostdetails @args
}