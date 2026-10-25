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
function ConvertTo-ADAuditStaleComputerCandidate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Computer, [int]$InactiveDays = 90, [datetime]$NowUtc = [datetime]::UtcNow)
    $cutoff = $NowUtc.ToUniversalTime().AddDays(-[math]::Abs($InactiveDays))
    if ($Computer.PSObject.Properties['Enabled'] -and $Computer.Enabled -eq $false) { return }
    $created = $null
    try { if ($Computer.whenCreated) { $created = ([datetime]$Computer.whenCreated).ToUniversalTime() } } catch { }
    # Missing creation data cannot establish that an unused object is old enough.
    if (-not $created -or $created -gt $cutoff) { return }
    $lastLogon = $null
    $pwdLastSet = $null
    try { if ([int64]$Computer.lastLogonTimestamp -gt 0) { $lastLogon = [datetime]::FromFileTimeUtc([int64]$Computer.lastLogonTimestamp) } } catch { return }
    try { if ([int64]$Computer.pwdLastSet -gt 0) { $pwdLastSet = [datetime]::FromFileTimeUtc([int64]$Computer.pwdLastSet) } } catch { return }
    # Machine password rotation is positive activity evidence even when the
    # replicated logon timestamp is absent/stale. Never call such servers unused.
    if (($lastLogon -and $lastLogon -gt $cutoff) -or ($pwdLastSet -and $pwdLastSet -gt $cutoff)) { return }
    [pscustomobject][ordered]@{
        Name = $Computer.Name
        DNSHostName = $Computer.DNSHostName
        DistinguishedName = $Computer.DistinguishedName
        OperatingSystem = $Computer.OperatingSystem
        LastLogonTimestampUTC = $(if ($lastLogon) { $lastLogon.ToString('o') } else { '' })
        PasswordLastSetUTC = $(if ($pwdLastSet) { $pwdLastSet.ToString('o') } else { '' })
        WhenCreatedUTC = $created.ToString('o')
        InactiveDays = $InactiveDays
        Assessment = 'Stale activity candidate'
        Reason = 'Old object with no recent replicated logon or machine-password change. Validate owner, workload and per-DC lastLogon before disabling; these signals do not prove inactivity.'
    }
}

Function Get-InactiveComputerObjects {
    [CmdletBinding()]
    param([int]$InactiveDays = 90)
    $reportPath = Get-EvidencePath 'computers_inactive_90days.txt'
    $csvPath = Get-EvidencePath 'computers_inactive_90days.csv'
    Remove-Item -LiteralPath $reportPath,$csvPath -Force -ErrorAction SilentlyContinue
    $cutoffFt = [datetime]::UtcNow.AddDays(-[math]::Abs($InactiveDays)).ToFileTimeUtc()
    $filter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(lastLogonTimestamp<=$cutoffFt)(!(lastLogonTimestamp=*))))"
    $computers = @(Get-ADComputer -LDAPFilter $filter -Properties Enabled,lastLogonTimestamp,pwdLastSet,whenCreated,DNSHostName,OperatingSystem -ErrorAction Stop)
    $rows = @($computers | ForEach-Object { ConvertTo-ADAuditStaleComputerCandidate -Computer $_ -InactiveDays $InactiveDays })
    '"Name","DNSHostName","DistinguishedName","OperatingSystem","LastLogonTimestampUTC","PasswordLastSetUTC","WhenCreatedUTC","InactiveDays","Assessment","Reason"' | Set-Content -LiteralPath $csvPath -Encoding UTF8
    if ($rows.Count) {
        $rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
        $content = @("Computer accounts with stale activity signals (> $InactiveDays days): $($rows.Count)",
            'Review candidates only. Missing/stale lastLogonTimestamp does not prove a server is unused.',
            'Recent creation and recent machine-password rotation exclude a computer from this list.',
            'Confirm owner, workload and lastLogon on every relevant DC before disabling or deleting.', '')
        $content += @($rows | ForEach-Object { "$($_.Name) ($($_.DNSHostName)) | OS=$($_.OperatingSystem) | lastLogonTimestampUTC=$($_.LastLogonTimestampUTC) | pwdLastSetUTC=$($_.PasswordLastSetUTC) | createdUTC=$($_.WhenCreatedUTC)" })
        $content | Set-Content -LiteralPath $reportPath -Encoding UTF8
        Write-Both "    [!] $($rows.Count) computer accounts have stale activity signals; owner/workload review required. See computers_inactive_90days.txt (KB552)"
        Write-Nessus-Finding 'StaleComputerActivityCandidates' 'KB552' ($content -join "`n") 'Low'
    }
    $unknownCreation = @($computers | Where-Object { -not $_.whenCreated }).Count
    if ($unknownCreation) { Register-ADAuditNotAssessed -Name 'Computer activity age' -Switch 'inactivecomputers' -Reason "$unknownCreation candidate objects had no creation timestamp; they were not labelled inactive." }
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
