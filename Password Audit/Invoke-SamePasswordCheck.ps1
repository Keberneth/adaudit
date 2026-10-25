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
.\Invoke-SamePasswordCheck.ps1
.\Invoke-SamePasswordCheck.ps1 -UsersOnly
.\Invoke-SamePasswordCheck.ps1 -Pwned
.\Invoke-SamePasswordCheck.ps1 -Server dc01.contoso.local -OutCsv C:\Temp\DUPLICATE_PASSWORDS.csv -Pwned
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
$runTimer = [diagnostics.stopwatch]::StartNew()
Write-PasswordAuditStage 'Shared password audit started. Loading Active Directory and DSInternals modules.'

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
    Write-PasswordAuditStage 'Discovering a domain controller.'
    $Server = Resolve-DefaultServer
}

Write-PasswordAuditStage 'Reading the domain naming context.'
$domain = Get-ADDomain -Server $Server -ErrorAction Stop
$domainDN = $domain.DistinguishedName

Write-Host ("Running duplicate password check against: {0}" -f $Server)
Write-Host ("Pwned password lookup: {0}" -f $(if ($Pwned) { 'ENABLED' } else { 'DISABLED' }))

$replAccounts = @(Get-ReplicatedAccountHashes -Server $Server -NamingContext $domainDN)

$hashRows = New-Object System.Collections.Generic.List[object]
$missingHashRows = New-Object System.Collections.Generic.List[object]
$excludedCount = 0
$missingNameCount = 0
$preparedCount = 0
Write-PasswordAuditStage 'Preparing account scope and password-material availability from replicated records.'

foreach ($ra in $replAccounts) {
    $preparedCount++
    if ($preparedCount % 250 -eq 0) { Write-Progress -Id 43 -Activity 'Password audit: preparing accounts' -Status "$preparedCount/$($replAccounts.Count) records" -PercentComplete ([int](100*$preparedCount/$replAccounts.Count)) }
    $sam = $ra.SamAccountName

    if ([string]::IsNullOrWhiteSpace($sam)) {
        $missingNameCount++
        continue
    }

    if ($UsersOnly -and $sam -match '\$$') {
        $excludedCount++
        continue
    }

    $ntlmHash = Convert-BytesToHex -Bytes $ra.NTHash
    if ([string]::IsNullOrWhiteSpace($ntlmHash)) {
        $missingHashRows.Add([pscustomobject][ordered]@{
            DuplicatePasswordGroup=''; DuplicatePasswordGroupSize=''; SamAccountName=$sam
            AccountType=Get-AccountTypeLabel -AccountName $sam; SourceServer=[string]$Server
            AccountStatus=Get-AccountStatusFromReplObject -ReplAccount $ra; Pwned='NotAssessed'
            Comment='No NT password material available; duplicate-password comparison was not possible. This does not establish an empty password.'
        })
        continue
    }

    $hashRows.Add([pscustomobject]@{
        SamAccountName = [string]$sam
        NTHash         = [string]$ntlmHash
        AccountType    = Get-AccountTypeLabel -AccountName $sam
        SourceServer   = [string]$Server
        AccountStatus  = Get-AccountStatusFromReplObject -ReplAccount $ra
    })
}
Write-Progress -Id 43 -Activity 'Password audit: preparing accounts' -Completed
Write-PasswordAuditStage ("Account preparation completed: {0} eligible; {1} without NT material; {2} excluded by scope. Comparing available password material locally." -f $hashRows.Count,$missingHashRows.Count,$excludedCount)

$duplicateGroups = @(
    $hashRows |
        Group-Object -Property NTHash |
        Where-Object { $_.Count -gt 1 } |
        Sort-Object -Property Count, Name -Descending
)
Write-PasswordAuditStage ("Local comparison completed: {0} shared password groups." -f $duplicateGroups.Count)

$pwnedCache = @{}

if ($Pwned -and $duplicateGroups.Count -gt 0) {
    $uniqueDuplicateHashes = @($duplicateGroups | ForEach-Object { [string]$_.Name })
    Write-Host ("Checking {0} unique duplicate NTLM hash(es) against HIBP..." -f $uniqueDuplicateHashes.Count)

    # Prefix-batched lookup: one range fetch per 5-char prefix, matched locally (k-anonymity
    # preserved). Returns full-hash -> { Pwned; PwnedCount } including explicit 'LookupFailed'
    # (a failed lookup is NEVER collapsed to 'No').
    $pwnedCache = Get-PwnedResultsForHashes -Hashes $uniqueDuplicateHashes -UserAgent 'Invoke-SamePasswordCheck.ps1'
}
elseif (-not $Pwned) { Write-PasswordAuditStage 'HIBP lookup was not requested. NotChecked is expected; use -Pwned to check the shared password groups online.' }
else { Write-PasswordAuditStage 'No shared password groups were found; there are no groups to check against HIBP.' }

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
            AccountStatus              = $member.AccountStatus
            Pwned                      = $pwnedValue
            Comment                    = 'Identical NT password material in this group. Prioritize enabled accounts; review disabled identities before reactivation.'
        }))
    }
}

foreach ($row in $missingHashRows) { $results.Add($row) }
Write-PasswordAuditStage 'Writing account evidence, coverage summary and offline HTML report.'
if ($results.Count -eq 0) {
    # Mirror Invoke-PwnedPasswordCheck.ps1: emit a self-describing informational row instead of a
    # headerless empty CSV when there are no duplicate-password groups.
    $emptyResult = @(
        [pscustomobject]([ordered]@{
            DuplicatePasswordGroup     = ''
            DuplicatePasswordGroupSize = ''
            SamAccountName             = ''
            AccountType                = if ($UsersOnly) { 'UserScope' } else { 'UserAndComputerScope' }
            SourceServer               = [string]$Server
            AccountStatus              = ''
            Pwned                      = if ($Pwned) { 'NotApplicable' } else { 'NotChecked' }
            Comment                    = $(if ($hashRows.Count -eq 0) { 'No accounts could be compared; this is not a clean duplicate-password result.' } else { 'No duplicate-password groups among compared accounts. See summary for exclusions and unavailable accounts.' })
        })
    )

    $emptyResult | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
    $exportRows = $emptyResult
}
else {
    $sortedResults = @(
        $results |
            Sort-Object -Property DuplicatePasswordGroup, SamAccountName
    )

    $sortedResults | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
    $exportRows = $sortedResults
}

$failedAccounts = @($results | Where-Object Pwned -eq 'LookupFailed').Count
$checkedAccounts = @($results | Where-Object Pwned -in @('Yes','No')).Count
$stateCounts = @{
    EnabledProcessedCount = @($hashRows | Where-Object AccountStatus -eq 'Active').Count
    DisabledProcessedCount = @($hashRows | Where-Object AccountStatus -eq 'Disabled').Count
    UnknownProcessedCount = @($hashRows | Where-Object AccountStatus -eq 'Unknown').Count
}
Export-PasswordAuditSummary -OutCsv $OutCsv -Mode Duplicate -Server $Server -ReturnedCount $replAccounts.Count -ProcessedCount $hashRows.Count -ExcludedCount $excludedCount -MissingNameCount $missingNameCount -MissingHashCount $missingHashRows.Count -LookupFailedCount $failedAccounts -DuplicateGroupCount $groupNumber -HibpCheckedCount $checkedAccounts -HibpRequested:$Pwned -Results $exportRows @stateCounts

Write-Host ("Duplicate password groups found: {0}" -f $groupNumber)
Write-Host ("Shared-password accounts exported: {0}; accounts without NT material: {1}" -f @($results | Where-Object DuplicatePasswordGroup -ne '').Count,$missingHashRows.Count)
if ($Pwned -and $pwnedLookupFailures -gt 0) {
    Write-Warning ("{0} duplicate-password group(s) could NOT be checked against HIBP (lookup failed - possible rate limiting or network error). Those rows show Pwned=LookupFailed, NOT 'No'." -f $pwnedLookupFailures)
}
Write-Host ("CSV written to: {0}" -f $OutCsv)
Write-PasswordAuditStage ("Shared password audit finished in {0:n1}s." -f $runTimer.Elapsed.TotalSeconds)
