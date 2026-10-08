<#
    .SYNOPSIS
        ADAudit check: Check for accounts with kerberos pre-auth

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -asrep). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-AsRepRoastCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select asrep [options]

    .NOTES
        Entry point: Invoke-AsRepRoastCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
function Get-ADUsersWithoutPreAuth {
    try {
        $asrepUsers = Get-ADUser -Filter 'DoesNotRequirePreAuth -eq True -and Enabled -eq True' `
                                 -Properties SamAccountName, Name, userAccountControl
    }
    catch {
        $asrepUsers = @()
    }

    if (-not $asrepUsers -or $asrepUsers.Count -eq 0) {
        $asrepUsers = Get-ADUser -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
                                 -Properties SamAccountName, Name, userAccountControl
    }

    $asrepUsers = $asrepUsers | Select-Object SamAccountName, Name, userAccountControl

    if (-not $asrepUsers -or $asrepUsers.Count -eq 0) {
        Write-Both "    [+] No ASREP Accounts"
        return
    }

    $asrepPath = Get-EvidencePath 'ASREP.txt'
    $header = @(
        'AS-REP Roastable accounts detected (DONT_REQ_PREAUTH set).',
        '',
        'To list all vulnerable accounts:',
        "  Get-ADUser -Filter 'DoesNotRequirePreAuth -eq True -and Enabled -eq True' | Select SamAccountName, Enabled",
        '  # Or LDAP bitwise (server-side):',
        "  Get-ADUser -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' | Select SamAccountName, Enabled",
        '',
        'Mitigate (clear DONT_REQ_PREAUTH bit 0x00400000):',
        '  $u = Get-ADUser <username> -Properties userAccountControl',
        '  Set-ADUser <username> -Replace @{userAccountControl = ($u.userAccountControl -band (-bnot 0x00400000))}',
        '',
        'Force password reset (must meet domain policy):',
        '  Set-ADAccountPassword -Identity <username> -Reset -NewPassword (Read-Host -AsSecureString)',
        '',
        '------------------------------------------------------------',
        '',
        'Accounts (Display Name (sAMAccountName)) with per-account commands:'
    )
    $header | Set-Content -LiteralPath $asrepPath -Encoding UTF8

    foreach ($user in $asrepUsers) {
        $display = ("{0} ({1})" -f $user.Name, $user.SamAccountName)
        Write-Both ("    [!] AS-REP Roastable user: {0}" -f $display)

        @(
            $display,
            '      # Verify vulnerable bit (non-zero means vulnerable):',
            "      (Get-ADUser '$($user.SamAccountName)' -Properties userAccountControl).userAccountControl -band 0x00400000",
            '      # Mitigate (clear bit 0x00400000):',
            "      `$u = Get-ADUser '$($user.SamAccountName)' -Properties userAccountControl",
            "      Set-ADUser '$($user.SamAccountName)' -Replace @{userAccountControl = (`$u.userAccountControl -band (-bnot 0x00400000))}",
            '      # Optional: force password reset (use compliant password):',
            "      Set-ADAccountPassword -Identity '$($user.SamAccountName)' -Reset -NewPassword (Read-Host -AsSecureString)",
            ''
        ) | Add-Content -LiteralPath $asrepPath -Encoding UTF8
    }

    Write-Nessus-Finding "AS-REP Roasting Attack" "KB720" ([System.IO.File]::ReadAllText($asrepPath))
}

function Invoke-AsRepRoastCheck {
    Get-ADUsersWithoutPreAuth
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select asrep @args
}