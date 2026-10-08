<#
.SYNOPSIS
Checks AD account NTLM hashes against Have I Been Pwned and exports pwned accounts.

.DESCRIPTION
Reads replicated AD account data with DSInternals, extracts NTLM hashes, checks each
unique hash against the Have I Been Pwned Pwned Passwords range API in NTLM mode,
and exports only accounts whose NTLM hash is found in the breach corpus.

By default, only user accounts are checked.
Use -IncludeComputers to include computer accounts as well.

Adds AccountStatus to the CSV output:
- Active
- Disabled
- Unknown

If no matching accounts are found, the script still creates the CSV and writes
a single informational row.

.REQUIREMENTS
- ActiveDirectory PowerShell module
- DSInternals PowerShell module
- Account with rights required for Get-ADReplAccount

.EXAMPLES
.\pwned_password_prof.ps1
.\pwned_password_prof.ps1 -Server dc01.contoso.local
.\pwned_password_prof.ps1 -OutCsv C:\Temp\PWNED_PASSWORD_HASH.csv
.\pwned_password_prof.ps1 -IncludeComputers
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [string]$OutCsv,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeComputers
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
    $OutCsv = Join-Path $scriptDir 'PWNED_PASSWORD_HASH.csv'
}

Ensure-DirectoryPath -Path (Resolve-ParentDirectory -Path $OutCsv)

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module DSInternals -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($Server)) {
    $Server = Resolve-DefaultServer
}

$domain = Get-ADDomain -Server $Server -ErrorAction Stop
$domainDN = $domain.DistinguishedName

Write-Host ("Running pwned password check against: {0}" -f $Server)
Write-Host ("Include computer accounts: {0}" -f $(if ($IncludeComputers) { 'YES' } else { 'NO' }))

$replAccounts = @(Get-ReplicatedAccountHashes -Server $Server -NamingContext $domainDN)

$accountRows = New-Object System.Collections.Generic.List[object]

foreach ($ra in $replAccounts) {
    $sam = [string]$ra.SamAccountName

    if ([string]::IsNullOrWhiteSpace($sam)) {
        continue
    }

    if (-not $IncludeComputers -and $sam -match '\$$') {
        continue
    }

    $ntlmHash = Convert-BytesToHex -Bytes $ra.NTHash
    if ([string]::IsNullOrWhiteSpace($ntlmHash)) {
        continue
    }

    # AccountStatus is derived from the replication object already in hand (no per-account
    # Get-ADUser / Get-ADComputer round-trip). NTHash is kept ONLY in memory here for the
    # HIBP lookup / grouping; it is deliberately never written to the CSV (pass-the-hash risk).
    $accountRows.Add([pscustomobject]@{
        SamAccountName = $sam
        NTHash         = $ntlmHash
        AccountType    = Get-AccountTypeLabel -AccountName $sam
        SourceServer   = [string]$Server
        AccountStatus  = Get-AccountStatusFromReplObject -ReplAccount $ra
    })
}

if ($accountRows.Count -eq 0) {
    $emptyResult = @(
        [pscustomobject]([ordered]@{
            SamAccountName = ''
            AccountType    = ''
            SourceServer   = [string]$Server
            AccountStatus  = ''
            Pwned          = 'NoAccountsProcessed'
            PwnedCount     = ''
            Comment        = 'No matching accounts were available for processing.'
        })
    )

    $emptyResult | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
    Write-Host ("CSV written to: {0}" -f $OutCsv)
    return
}

$uniqueHashes = @(
    $accountRows |
        Select-Object -ExpandProperty NTHash -Unique |
        Sort-Object
)

Write-Host ("Checking {0} unique NTLM hash(es) against HIBP..." -f $uniqueHashes.Count)

# Prefix-batched lookup: one range fetch per 5-char prefix, matched locally (k-anonymity
# preserved). Returns a map of full-hash -> { Pwned; PwnedCount } including 'LookupFailed'.
$pwnedCache = Get-PwnedResultsForHashes -Hashes $uniqueHashes -UserAgent 'pwned_password_prof.ps1'

$results = New-Object System.Collections.Generic.List[object]
$failedResults = New-Object System.Collections.Generic.List[object]

foreach ($row in $accountRows) {
    $lookup = $pwnedCache[$row.NTHash]

    if ($null -eq $lookup) {
        # Defensive: hash was not in the cache (should not happen). Treat as a failed lookup
        # rather than silently dropping the account.
        $lookup = [pscustomobject]@{ Pwned = 'LookupFailed'; PwnedCount = $null }
    }

    if ($lookup.Pwned -eq 'Yes') {
        $results.Add([pscustomobject]([ordered]@{
            SamAccountName = $row.SamAccountName
            AccountType    = $row.AccountType
            SourceServer   = $row.SourceServer
            AccountStatus  = $row.AccountStatus
            Pwned          = $lookup.Pwned
            PwnedCount     = $lookup.PwnedCount
            Comment        = 'NTLM hash found in Have I Been Pwned Pwned Passwords corpus.'
        }))
    }
    elseif ($lookup.Pwned -eq 'LookupFailed') {
        # FIX: failed lookups are no longer silently dropped. They are reported as their own
        # rows so a rate-limited / errored run is not mistaken for a clean one.
        $failedResults.Add([pscustomobject]([ordered]@{
            SamAccountName = $row.SamAccountName
            AccountType    = $row.AccountType
            SourceServer   = $row.SourceServer
            AccountStatus  = $row.AccountStatus
            Pwned          = 'LookupFailed'
            PwnedCount     = ''
            Comment        = 'HIBP lookup failed for this account (possible rate limiting / network error) - status UNKNOWN.'
        }))
    }
}

# Distinct account count behind the failed lookups (for the summary warning).
$failedAccountCount = $failedResults.Count

if ($results.Count -eq 0 -and $failedResults.Count -eq 0) {
    $noPwnedResult = @(
        [pscustomobject]([ordered]@{
            SamAccountName = ''
            AccountType    = if ($IncludeComputers) { 'UserAndComputerScope' } else { 'UserScope' }
            SourceServer   = [string]$Server
            AccountStatus  = ''
            Pwned          = 'No'
            PwnedCount     = 0
            Comment        = 'No processed accounts were found in the Have I Been Pwned password corpus.'
        })
    )

    $noPwnedResult | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
}
else {
    $allRows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $results)       { $allRows.Add($r) }
    foreach ($r in $failedResults) { $allRows.Add($r) }

    $sortedResults = @(
        $allRows |
            Sort-Object -Property Pwned, AccountType, SamAccountName
    )

    $sortedResults | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
}

Write-Host ("Processed accounts: {0}" -f $accountRows.Count)
if ($results.Count -eq 0 -and $failedAccountCount -eq 0) {
    Write-Host "Pwned accounts exported: 0 (all lookups succeeded - none found in HIBP)."
}
else {
    Write-Host ("Pwned accounts exported: {0}" -f $results.Count)
}
if ($failedAccountCount -gt 0) {
    Write-Warning ("{0} account(s) could NOT be checked (lookup failed - possible rate limiting or network error). Their pwned status is UNKNOWN; re-run to complete the check." -f $failedAccountCount)
}
Write-Host ("CSV written to: {0}" -f $OutCsv)
