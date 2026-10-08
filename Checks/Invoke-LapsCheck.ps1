<#
    .SYNOPSIS
        ADAudit check: Check For Existence of LAPS in domain

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -laps). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-LapsCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select laps [options]

    .NOTES
        Entry point: Invoke-LapsCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
Function Get-LAPSStatus {
    #Check for presence of Windows LAPS and/or legacy Microsoft LAPS in the forest
    $schemaNC = (Get-ADRootDSE).SchemaNamingContext
    $legacySchema = $null
    $windowsSchema = $null
    $schemaQueryError = $null

    try {
        $legacySchema = Get-ADObject -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwd)' -SearchBase $schemaNC -ErrorAction Stop
    }
    catch { $schemaQueryError = $_.Exception.Message }

    try {
        $windowsSchema = Get-ADObject -LDAPFilter '(lDAPDisplayName=msLAPS-PasswordExpirationTime)' -SearchBase $schemaNC -ErrorAction Stop
    }
    catch { $schemaQueryError = $_.Exception.Message }

    $legacyDetected = ($null -ne $legacySchema)
    $windowsDetected = ($null -ne $windowsSchema)

    if (-not $legacyDetected -and -not $windowsDetected) {
        if ($schemaQueryError) {
            # A failed schema query must not be reported as 'LAPS not installed'
            Register-ADAuditNotAssessed -Name 'Get-LAPSStatus' -Switch 'laps' -Reason "LAPS schema could not be queried: $schemaQueryError"
            return
        }
        Write-Both "    [!] LAPS Not Installed in domain (KB258)"
        Write-Nessus-Finding "LAPSMissing" "KB258" "LAPS Not Installed in domain"
        return
    }

    if ($windowsDetected) {
        Write-Both "    [+] Windows LAPS schema detected in the forest"
    }
    if ($legacyDetected) {
        Write-Both "    [+] Legacy Microsoft LAPS schema detected in the forest"
    }

    $missingPath = Get-EvidencePath 'laps_missing-computers.txt'
    $expiredPath = Get-EvidencePath 'laps_expired-passwords.txt'
    $rightsPath  = Get-EvidencePath 'laps_read-extendedrights.txt'

    Remove-Item -LiteralPath $missingPath,$expiredPath,$rightsPath -Force -ErrorAction SilentlyContinue

    if ($windowsDetected) {
        $lapsModule = Import-ADAuditModule -Name LAPS
        if ($lapsModule) {
            $missingComputers = @(Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(!(msLAPS-PasswordExpirationTime=*)))' -Properties msLAPS-PasswordExpirationTime | Select-Object -ExpandProperty Name)
            if ($missingComputers.Count -gt 0) {
                foreach ($name in $missingComputers) {
                    Add-Content -Path $missingPath -Value "[Windows LAPS] $name"
                }
                Write-Both "    [!] Some computers/servers don't have Windows LAPS password expiration data set, see $missingPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($missingPath))
            }

            $windowsComputers = @(Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(msLAPS-PasswordExpirationTime=*))' -Properties msLAPS-PasswordExpirationTime)
            foreach ($computer in $windowsComputers) {
                $expiration = Convert-ADAuditFileTime $computer.'msLAPS-PasswordExpirationTime'
                if ($expiration -and $expiration -lt (Get-Date)) {
                    Add-Content -Path $expiredPath -Value "[Windows LAPS] $($computer.Name) password is expired since $expiration"
                }
            }
            if (Test-Path -LiteralPath $expiredPath) {
                Write-Both "    [!] Some computers/servers have Windows LAPS password expired, see $expiredPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($expiredPath))
            }

            Get-ADOrganizationalUnit -Filter * | Find-LapsADExtendedRights -PipelineVariable OU | ForEach-Object {
                foreach ($holder in $_.ExtendedRightHolders) {
                    if ($holder -and $holder -ne $System) {
                        Add-Content -Path $rightsPath -Value "[Windows LAPS] $holder can read password attribute of $($_.ObjectDN)"
                    }
                }
            }
            if (Test-Path -LiteralPath $rightsPath) {
                Write-Both "    [!] Windows LAPS extended rights exported, see $rightsPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($rightsPath))
            }

            $DomainLevel = (Get-ADDomain).DomainMode
            if (-not (Test-ADAuditFunctionalLevelAtLeast -Mode $DomainLevel -MinimumMode 'Windows2016Domain')) {
                Write-Both "    [*] Windows LAPS is present, but domain functional level is below Windows Server 2016; encryption and DSRM management features may be limited."
            }
        }
        else {
            Write-Both "    [!] Windows LAPS schema detected, but the LAPS PowerShell module is not available on this host."
        }
    }

    if ($legacyDetected) {
        $legacyModule = Import-ADAuditModule -Name 'AdmPwd.PS' -PreferWindowsPowerShell
        if ($legacyModule) {
            $missingComputers = @(Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(!(ms-Mcs-AdmPwd=*)))' -Properties ms-Mcs-AdmPwd | Select-Object -ExpandProperty Name)
            if ($missingComputers.Count -gt 0) {
                foreach ($name in $missingComputers) {
                    Add-Content -Path $missingPath -Value "[Legacy LAPS] $name"
                }
                Write-Both "    [!] Some computers/servers don't have legacy LAPS password set, see $missingPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($missingPath))
            }

            $legacyComputers = @(Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))' -Properties ms-Mcs-AdmPwdExpirationTime)
            foreach ($computer in $legacyComputers) {
                $expiration = Convert-ADAuditFileTime $computer.'ms-Mcs-AdmPwdExpirationTime'
                if ($expiration -and $expiration -lt (Get-Date)) {
                    Add-Content -Path $expiredPath -Value "[Legacy LAPS] $($computer.Name) password is expired since $expiration"
                }
            }
            if (Test-Path -LiteralPath $expiredPath) {
                Write-Both "    [!] Some computers/servers have legacy LAPS password expired, see $expiredPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($expiredPath))
            }

            Get-ADOrganizationalUnit -Filter * | Find-AdmPwdExtendedRights -PipelineVariable OU | ForEach-Object {
                foreach ($holder in $_.ExtendedRightHolders) {
                    if ($holder -and $holder -ne $System) {
                        Add-Content -Path $rightsPath -Value "[Legacy LAPS] $holder can read password attribute of $($OU.ObjectDN)"
                    }
                }
            }
            if (Test-Path -LiteralPath $rightsPath) {
                Write-Both "    [!] Legacy LAPS extended rights exported, see $rightsPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($rightsPath))
            }
        }
        else {
            Write-Both "    [!] Legacy Microsoft LAPS schema detected, but the AdmPwd.PS module is not available on this host."
        }
    }
}

function Invoke-LapsCheck {
    Get-LAPSStatus
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select laps @args
}