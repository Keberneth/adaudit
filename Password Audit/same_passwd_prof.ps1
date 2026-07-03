<#
.SYNOPSIS
Exports accounts that share duplicate NTLM passwords from AD replication data.

.DESCRIPTION
Reads replicated AD account data with DSInternals, groups accounts by NTLM hash,
and exports only accounts that share the same password.

Optionally checks each unique duplicate NTLM hash against the Have I Been Pwned
Pwned Passwords range API when -Pwned is used.

.NOTES
Requirements:
- ActiveDirectory PowerShell module
- DSInternals PowerShell module
- Account with rights required for Get-ADReplAccount

Examples:
.\same_passwd_prof.ps1
.\same_passwd_prof.ps1 -UsersOnly
.\same_passwd_prof.ps1 -Pwned
.\same_passwd_prof.ps1 -Server dc01.contoso.local -OutCsv C:\Temp\DUPLICATE_PASSWORDS.csv -Pwned
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [string]$OutCsv,

    [Parameter(Mandatory = $false)]
    [switch]$UsersOnly,

    [Parameter(Mandatory = $false)]
    [switch]$Pwned
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Shared helpers (Resolve-DefaultServer, Ensure-DirectoryPath, Resolve-ParentDirectory,
# Convert-BytesToHex, Get-AccountTypeLabel, Get-AccountStatusFromReplObject, Test-NtlmHashPwned,
# Get-PwnedResultsForHashes, Get-ReplicatedAccountHashes) live in the shared module so they are
# not duplicated across the two Password Audit scripts. Imported via $PSScriptRoot so it resolves
# regardless of the current working directory.
Import-Module (Join-Path $PSScriptRoot 'PasswordAuditCommon.psm1') -Force

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = (Get-Location).Path
}

if ([string]::IsNullOrWhiteSpace($OutCsv)) {
    $OutCsv = Join-Path $scriptDir 'DUPLICATE_PASSWORDS.csv'
}

Ensure-DirectoryPath -Path (Resolve-ParentDirectory -Path $OutCsv)

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module DSInternals -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($Server)) {
    $Server = Resolve-DefaultServer
}

$domain = Get-ADDomain -Server $Server -ErrorAction Stop
$domainDN = $domain.DistinguishedName

Write-Host ("Running duplicate password check against: {0}" -f $Server)
Write-Host ("Pwned password lookup: {0}" -f $(if ($Pwned) { 'ENABLED' } else { 'DISABLED' }))

$replAccounts = @(Get-ReplicatedAccountHashes -Server $Server -NamingContext $domainDN)

$hashRows = New-Object System.Collections.Generic.List[object]

foreach ($ra in $replAccounts) {
    $sam = $ra.SamAccountName

    if ([string]::IsNullOrWhiteSpace($sam)) {
        continue
    }

    if ($UsersOnly -and $sam -match '\$$') {
        continue
    }

    $ntlmHash = Convert-BytesToHex -Bytes $ra.NTHash
    if ([string]::IsNullOrWhiteSpace($ntlmHash)) {
        continue
    }

    $hashRows.Add([pscustomobject]@{
        SamAccountName = [string]$sam
        NTHash         = [string]$ntlmHash
        AccountType    = Get-AccountTypeLabel -AccountName $sam
        SourceServer   = [string]$Server
    })
}

$duplicateGroups = @(
    $hashRows |
        Group-Object -Property NTHash |
        Where-Object { $_.Count -gt 1 } |
        Sort-Object -Property Count, Name -Descending
)

$pwnedCache = @{}

if ($Pwned -and $duplicateGroups.Count -gt 0) {
    $uniqueDuplicateHashes = @($duplicateGroups | ForEach-Object { [string]$_.Name })
    Write-Host ("Checking {0} unique duplicate NTLM hash(es) against HIBP..." -f $uniqueDuplicateHashes.Count)

    # Prefix-batched lookup: one range fetch per 5-char prefix, matched locally (k-anonymity
    # preserved). Returns full-hash -> { Pwned; PwnedCount } including explicit 'LookupFailed'
    # (a failed lookup is NEVER collapsed to 'No').
    $pwnedCache = Get-PwnedResultsForHashes -Hashes $uniqueDuplicateHashes -UserAgent 'same_passwd_prof.ps1'
}

$results = New-Object System.Collections.Generic.List[object]
$groupNumber = 0
$pwnedLookupFailures = 0

foreach ($group in $duplicateGroups) {
    $members = @(
        $group.Group |
            Sort-Object -Property SamAccountName -Unique
    )

    if ($members.Count -lt 2) {
        continue
    }

    $groupNumber++

    # Pwned status is per duplicate group (all members share the same NTLM hash). The raw hash
    # is deliberately NOT written to the CSV (pass-the-hash risk); the DuplicatePasswordGroup id
    # keeps shared-password accounts correlatable without exposing the credential-equivalent hash.
    $pwnedValue = 'NotChecked'
    if ($Pwned) {
        $lookup = $pwnedCache[[string]$group.Name]
        if ($null -eq $lookup) {
            $pwnedValue = 'LookupFailed'
        }
        else {
            $pwnedValue = [string]$lookup.Pwned
        }
        if ($pwnedValue -eq 'LookupFailed') {
            $pwnedLookupFailures++
        }
    }

    foreach ($member in $members) {
        $results.Add([pscustomobject]([ordered]@{
            DuplicatePasswordGroup     = $groupNumber
            DuplicatePasswordGroupSize = $members.Count
            SamAccountName             = $member.SamAccountName
            AccountType                = $member.AccountType
            SourceServer               = $member.SourceServer
            Pwned                      = $pwnedValue
        }))
    }
}

if ($results.Count -eq 0) {
    # Mirror pwned_password_prof.ps1: emit a self-describing informational row instead of a
    # headerless empty CSV when there are no duplicate-password groups.
    $emptyResult = @(
        [pscustomobject]([ordered]@{
            DuplicatePasswordGroup     = ''
            DuplicatePasswordGroupSize = ''
            SamAccountName             = ''
            AccountType                = if ($UsersOnly) { 'UserScope' } else { 'UserAndComputerScope' }
            SourceServer               = [string]$Server
            Pwned                      = if ($Pwned) { 'NotApplicable' } else { 'NotChecked' }
            Comment                    = 'No duplicate-password groups were found.'
        })
    )

    $emptyResult | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
}
else {
    $sortedResults = @(
        $results |
            Sort-Object -Property DuplicatePasswordGroup, SamAccountName
    )

    $sortedResults | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
}

Write-Host ("Duplicate password groups found: {0}" -f $groupNumber)
Write-Host ("Affected accounts exported: {0}" -f $results.Count)
if ($Pwned -and $pwnedLookupFailures -gt 0) {
    Write-Warning ("{0} duplicate-password group(s) could NOT be checked against HIBP (lookup failed - possible rate limiting or network error). Those rows show Pwned=LookupFailed, NOT 'No'." -f $pwnedLookupFailures)
}
Write-Host ("CSV written to: {0}" -f $OutCsv)