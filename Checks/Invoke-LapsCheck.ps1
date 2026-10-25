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
function Get-ADAuditLapsBackupState {
    param([Parameter(Mandatory)][object]$Computer, [datetime]$NowUtc = [datetime]::UtcNow)
    $windowsExpiry = $null
    $legacyExpiry = $null
    if ($Computer.PSObject.Properties['msLAPS-PasswordExpirationTime']) { $windowsExpiry = Convert-ADAuditFileTime $Computer.'msLAPS-PasswordExpirationTime' }
    if ($Computer.PSObject.Properties['ms-Mcs-AdmPwdExpirationTime']) { $legacyExpiry = Convert-ADAuditFileTime $Computer.'ms-Mcs-AdmPwdExpirationTime' }
    # Schema presence is forest-wide. A device needs evidence for its active
    # deployment, not simultaneous native and legacy LAPS backups.
    $generations = @()
    if ($windowsExpiry) { $generations += [pscustomobject]@{ Generation='Windows LAPS'; Expiry=$windowsExpiry } }
    if ($legacyExpiry) { $generations += [pscustomobject]@{ Generation='Legacy LAPS'; Expiry=$legacyExpiry } }
    $latest = $generations | Sort-Object Expiry -Descending | Select-Object -First 1
    $status = if (-not $latest) { 'Backup destination unverified' } elseif ($latest.Expiry.ToUniversalTime() -lt $NowUtc) { 'Rotation overdue candidate' } else { 'AD expiration evidence present' }
    [pscustomobject][ordered]@{
        Name=$Computer.Name; DistinguishedName=$Computer.DistinguishedName; OperatingSystem=$Computer.OperatingSystem
        Generation=$(if ($latest) { $latest.Generation } else { 'Unknown' })
        ExpirationUTC=$(if ($latest) { $latest.Expiry.ToUniversalTime().ToString('o') } else { '' })
        Assessment=$status
        Detail=$(if (-not $latest) { 'No AD expiration metadata. Verify intended policy, supported OS, hybrid/Entra backup destination and deployment exceptions; AD absence alone does not prove missing LAPS.' } elseif ($status -eq 'Rotation overdue candidate') { 'Check device activity and LAPS operational logs; an offline device may not yet have rotated.' } else { 'Expiration metadata is present; effective policy, encryption and successful password retrieval are not established by this check.' })
    }
}

Function Get-LAPSStatus {
    $schemaNC = (Get-ADRootDSE -ErrorAction Stop).SchemaNamingContext
    $legacySchema = Get-ADObject -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)' -SearchBase $schemaNC -ErrorAction Stop
    $windowsSchema = Get-ADObject -LDAPFilter '(lDAPDisplayName=msLAPS-PasswordExpirationTime)' -SearchBase $schemaNC -ErrorAction Stop
    $missingPath = Get-EvidencePath 'laps_missing-computers.txt'
    $expiredPath = Get-EvidencePath 'laps_expired-passwords.txt'
    $rightsPath = Get-EvidencePath 'laps_read-extendedrights.txt'
    $csvPath = Get-EvidencePath 'laps_status.csv'
    Remove-Item -LiteralPath $missingPath,$expiredPath,$rightsPath,$csvPath -Force -ErrorAction SilentlyContinue
    if (-not $legacySchema -and -not $windowsSchema) {
        Register-ADAuditNotAssessed -Name 'LAPS coverage' -Switch 'laps' -Reason 'Neither AD LAPS schema generation is present. Verify whether eligible devices use Entra-backed Windows LAPS or another approved management solution.'
        return
    }
    $properties = @('OperatingSystem')
    if ($windowsSchema) { $properties += 'msLAPS-PasswordExpirationTime' }
    if ($legacySchema) { $properties += 'ms-Mcs-AdmPwdExpirationTime' }
    # No confidential password attributes are needed to audit expiration metadata.
    $computers = @(Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(operatingSystem=Windows*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Properties $properties -ErrorAction Stop)
    $rows = @($computers | ForEach-Object { Get-ADAuditLapsBackupState -Computer $_ })
    '"Name","DistinguishedName","OperatingSystem","Generation","ExpirationUTC","Assessment","Detail"' | Set-Content -LiteralPath $csvPath -Encoding UTF8
    if ($rows.Count) { $rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 }
    $missing = @($rows | Where-Object Assessment -eq 'Backup destination unverified')
    $expired = @($rows | Where-Object Assessment -eq 'Rotation overdue candidate')
    if ($missing.Count) {
        $missing | ForEach-Object { "$($_.Name): $($_.Detail)" } | Set-Content -LiteralPath $missingPath -Encoding UTF8
        Register-ADAuditNotAssessed -Name 'LAPS backup destination' -Switch 'laps' -Reason "$($missing.Count) enabled Windows computers have no AD expiration metadata; policy and backup destination require confirmation. See laps_status.csv."
    }
    if ($expired.Count) {
        $expired | ForEach-Object { "$($_.Name) [$($_.Generation)] expirationUTC=$($_.ExpirationUTC): $($_.Detail)" } | Set-Content -LiteralPath $expiredPath -Encoding UTF8
        Write-Nessus-Finding 'LAPS rotation overdue candidates' 'KB258' ([IO.File]::ReadAllText($expiredPath)) 'Low'
    }
    foreach ($generation in @(@{Present=$windowsSchema; Module='LAPS'; Command='Find-LapsADExtendedRights'; Name='Windows LAPS'}, @{Present=$legacySchema; Module='AdmPwd.PS'; Command='Find-AdmPwdExtendedRights'; Name='Legacy LAPS'})) {
        if (-not $generation.Present) { continue }
        if (-not (Import-ADAuditModule -Name $generation.Module)) {
            Register-ADAuditNotAssessed -Name 'LAPS extended rights' -Switch 'laps' -Reason "$($generation.Name) rights inventory requires module $($generation.Module); expiration checks completed independently."
            continue
        }
        try {
            $rights = Get-ADOrganizationalUnit -Filter * -ErrorAction Stop | & $generation.Command -ErrorAction Stop
            foreach ($right in $rights) {
                foreach ($holder in $right.ExtendedRightHolders) {
                    "[$($generation.Name)] $holder has extended rights on $($right.ObjectDN). Review intended delegation and, for encrypted passwords, decryptor authorization separately." | Add-Content -LiteralPath $rightsPath -Encoding UTF8
                }
            }
        } catch { Register-ADAuditNotAssessed -Name 'LAPS extended rights' -Switch 'laps' -Reason $_.Exception.Message }
    }
    Write-Both "    [+] LAPS AD metadata assessed on $($rows.Count) enabled Windows computers; $($missing.Count) backup destinations unverified; $($expired.Count) overdue rotation candidates. See laps_status.csv."
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
