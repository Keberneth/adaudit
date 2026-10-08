<#
    .SYNOPSIS
        ADAudit check: Check for LDAP Security Issues

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -ldapsecurity). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-LdapSecurityCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select ldapsecurity [options]

    .NOTES
        Entry point: Invoke-LdapSecurityCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
function Get-LDAPSecurity {
    # LDAP signing, channel binding and the LDAPS certificate are PER-DC settings
    # that live in the DC's NTDS\Parameters registry / LocalMachine cert store.
    # Reading the LOCAL host is only valid on a DC; on a jump server the NTDS key
    # does not exist and the old code emitted a GUARANTEED-false "LDAP signing not
    # enabled" finding. We now target each DC and record NotAssessed (not a finding)
    # when the DC's registry/cert store cannot be read remotely.
    $serverAuthOid = '1.3.6.1.5.5.7.3.1'   # Server Authentication EKU
    $ntdsKey = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'

    $dcList = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
    if (-not $dcList -or $dcList.Count -eq 0) {
        Register-ADAuditNotAssessed -Name 'Get-LDAPSecurity' -Switch 'ldapsecurity' -Reason "No domain controllers enumerated; cannot assess LDAP signing / channel binding / LDAPS."
        return
    }

    foreach ($dc in $dcList) {
        # --- LDAP signing (LDAPServerIntegrity; 2 = required) ---
        $sig = Get-ADAuditRemoteRegistryDword -ComputerName $dc -SubKey $ntdsKey -ValueName 'LDAPServerIntegrity'
        if (-not $sig.Success) {
            Register-ADAuditNotAssessed -Name 'Get-LDAPSecurity' -Switch 'ldapsecurity' -Target $dc -RequiresRemotePS -Reason "Could not read NTDS\Parameters\LDAPServerIntegrity on $dc (needs the DC's registry over CIM/DCOM/WinRM, or this host is not a DC): $($sig.Error)"
        }
        elseif ($sig.Value -eq 2) {
            Write-Both "    [+] LDAP signing is required on $dc"
        }
        else {
            $lvl = if ($null -eq $sig.Value) { 'not set (default 1 = negotiate, not enforced)' } else { $sig.Value }
            Write-Both "    [!] LDAP signing is not enforced on $dc (LDAPServerIntegrity = $lvl)"
            Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "LDAP signing is not enforced on $dc (LDAPServerIntegrity = $lvl)"
            Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP signing is not enforced on $dc (LDAPServerIntegrity = $lvl)"
        }

        # --- LDAP channel binding (LdapEnforceChannelBinding; 2 = always) ---
        $cb = Get-ADAuditRemoteRegistryDword -ComputerName $dc -SubKey $ntdsKey -ValueName 'LdapEnforceChannelBinding'
        if (-not $cb.Success) {
            Register-ADAuditNotAssessed -Name 'Get-LDAPSecurity' -Switch 'ldapsecurity' -Target $dc -RequiresRemotePS -Reason "Could not read NTDS\Parameters\LdapEnforceChannelBinding on $dc (needs the DC's registry over CIM/DCOM/WinRM): $($cb.Error)"
        }
        elseif ($cb.Value -eq 2) {
            Write-Both "    [+] LDAP channel binding is enforced (always) on $dc"
        }
        else {
            $lvl = if ($null -eq $cb.Value) { 'not set' } else { $cb.Value }
            Write-Both "    [!] LDAP channel binding is not enforced on $dc (LdapEnforceChannelBinding = $lvl)"
            Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "LDAP channel binding is not enforced on $dc (LdapEnforceChannelBinding = $lvl)"
            Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP channel binding is not enforced on $dc (LdapEnforceChannelBinding = $lvl)"
        }

        # --- LDAPS certificate present (Server Authentication EKU in the DC's LocalMachine\My) ---
        try {
            $hasLdapsCert = Invoke-Command -ComputerName $dc -ArgumentList $serverAuthOid -ScriptBlock {
                param($oid)
                [bool](Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop | Where-Object {
                    ($_.EnhancedKeyUsageList.ObjectId -contains $oid) -or
                    ($_.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } | ForEach-Object { $_.EnhancedKeyUsages.Value }) -contains $oid
                })
            } -ErrorAction Stop

            if ($hasLdapsCert) {
                Write-Both "    [+] LDAPS (Server Authentication) certificate present on $dc"
            }
            else {
                Write-Both "    [!] No LDAPS (Server Authentication) certificate found on $dc"
                Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "No LDAPS (Server Authentication) certificate found on $dc"
                Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "No LDAPS (Server Authentication) certificate found on $dc"
            }
        }
        catch {
            Register-ADAuditNotAssessed -Name 'Get-LDAPSecurity' -Switch 'ldapsecurity' -Target $dc -RequiresRemotePS -Reason "Could not enumerate the DC's certificate store for an LDAPS certificate (needs WinRM to $dc): $($_.Exception.Message)"
        }
    }

    # --- LDAP anonymous (null) bind: a network test, valid from any host ---
    $Server = (Get-ADDomainController -Discover).HostName
    $Port = 389
    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols
        $ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection("$Server`:$Port")
        $ldapConnection.Timeout = [System.TimeSpan]::FromSeconds(5)
        $anonymousCredential = New-Object System.Net.NetworkCredential("", "")
        $ldapConnection.Bind($anonymousCredential)

        Write-Both "    [!] Issue identified LDAP null session allowed on server $Server`:$Port"
        Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "null session allowed on server $Server`:$Port"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP null session allowed on server $Server`:$Port"
    }
    catch [System.DirectoryServices.Protocols.LdapException] {
        Write-Both "    [+] LDAP null session not allowed on server $Server`:$Port"
    }
    catch {
        Register-ADAuditNotAssessed -Name 'Get-LDAPSecurity' -Switch 'ldapsecurity' -Target "$Server`:$Port" -Reason "LDAP null-bind test could not run: $($_.Exception.Message)"
    }
}

function Invoke-LdapSecurityCheck {
    Get-LDAPSecurity
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select ldapsecurity @args
}