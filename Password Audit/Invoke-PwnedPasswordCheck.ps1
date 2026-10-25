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
.\Invoke-PwnedPasswordCheck.ps1
.\Invoke-PwnedPasswordCheck.ps1 -Server dc01.contoso.local
.\Invoke-PwnedPasswordCheck.ps1 -OutCsv C:\Temp\PWNED_PASSWORD_HASH.csv
.\Invoke-PwnedPasswordCheck.ps1 -IncludeComputers
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
$runTimer = [diagnostics.stopwatch]::StartNew()
Write-PasswordAuditStage 'Pwned password audit started. Loading Active Directory and DSInternals modules.'

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
    Write-PasswordAuditStage 'Discovering a domain controller.'
    $Server = Resolve-DefaultServer
}

Write-PasswordAuditStage 'Reading the domain naming context.'
$domain = Get-ADDomain -Server $Server -ErrorAction Stop
$domainDN = $domain.DistinguishedName

Write-Host ("Running pwned password check against: {0}" -f $Server)
Write-Host ("Include computer accounts: {0}" -f $(if ($IncludeComputers) { 'YES' } else { 'NO' }))

$replAccounts = @(Get-ReplicatedAccountHashes -Server $Server -NamingContext $domainDN)

$accountRows = New-Object System.Collections.Generic.List[object]
$missingHashRows = New-Object System.Collections.Generic.List[object]
$excludedCount = 0
$missingNameCount = 0
$preparedCount = 0
Write-PasswordAuditStage 'Preparing account scope and password-material availability from replicated records.'

foreach ($ra in $replAccounts) {
    $preparedCount++
    if ($preparedCount % 250 -eq 0) { Write-Progress -Id 43 -Activity 'Password audit: preparing accounts' -Status "$preparedCount/$($replAccounts.Count) records" -PercentComplete ([int](100*$preparedCount/$replAccounts.Count)) }
    $sam = [string]$ra.SamAccountName

    if ([string]::IsNullOrWhiteSpace($sam)) {
        $missingNameCount++
        continue
    }

    if (-not $IncludeComputers -and $sam -match '\$$') {
        $excludedCount++
        continue
    }

    $ntlmHash = Convert-BytesToHex -Bytes $ra.NTHash
    if ([string]::IsNullOrWhiteSpace($ntlmHash)) {
        $missingHashRows.Add([pscustomobject][ordered]@{
            SamAccountName=$sam; AccountType=Get-AccountTypeLabel -AccountName $sam; SourceServer=[string]$Server
            AccountStatus=Get-AccountStatusFromReplObject -ReplAccount $ra; Pwned='NotAssessed'; PwnedCount=''
            Comment='No NT password material available; not checked against HIBP. This does not establish an empty password or a safe account.'
        })
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
Write-Progress -Id 43 -Activity 'Password audit: preparing accounts' -Completed
Write-PasswordAuditStage ("Account preparation completed: {0} eligible; {1} without NT material; {2} excluded by scope." -f $accountRows.Count,$missingHashRows.Count,$excludedCount)

$stateCounts = @{
    EnabledProcessedCount = @($accountRows | Where-Object AccountStatus -eq 'Active').Count
    DisabledProcessedCount = @($accountRows | Where-Object AccountStatus -eq 'Disabled').Count
    UnknownProcessedCount = @($accountRows | Where-Object AccountStatus -eq 'Unknown').Count
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

    if ($missingHashRows.Count) { $emptyResult = @($missingHashRows.ToArray()) }
    Write-PasswordAuditStage 'Writing account evidence, coverage summary and offline HTML report.'
    $emptyResult | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
    Export-PasswordAuditSummary -OutCsv $OutCsv -Mode Pwned -Server $Server -ReturnedCount $replAccounts.Count -ProcessedCount 0 -ExcludedCount $excludedCount -MissingNameCount $missingNameCount -MissingHashCount $missingHashRows.Count -HibpRequested -Results $emptyResult @stateCounts
    Write-Host ("CSV written to: {0}" -f $OutCsv)
    Write-PasswordAuditStage ("Pwned password audit finished in {0:n1}s. No accounts could be checked; see coverage explanation." -f $runTimer.Elapsed.TotalSeconds)
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
$pwnedCache = Get-PwnedResultsForHashes -Hashes $uniqueHashes -UserAgent 'Invoke-PwnedPasswordCheck.ps1'

$results = New-Object System.Collections.Generic.List[object]
$failedAccountCount = 0
$pwnedAccountCount = 0
foreach ($row in $accountRows) {
    $lookup = $pwnedCache[$row.NTHash]
    if ($null -eq $lookup) { $lookup = [pscustomobject]@{ Pwned='LookupFailed'; PwnedCount=$null } }
    if ($lookup.Pwned -eq 'No') { continue }
    if ($lookup.Pwned -eq 'LookupFailed') { $failedAccountCount++ }
    if ($lookup.Pwned -eq 'Yes') { $pwnedAccountCount++ }
    $results.Add([pscustomobject][ordered]@{
        SamAccountName=$row.SamAccountName; AccountType=$row.AccountType; SourceServer=$row.SourceServer
        AccountStatus=$row.AccountStatus; Pwned=$lookup.Pwned; PwnedCount=$lookup.PwnedCount
        Comment=$(if ($lookup.Pwned -eq 'Yes') { 'Password found in the HIBP corpus; not proof this customer account was breached.' } else { 'HIBP lookup failed; password exposure remains unknown. Re-run to complete coverage.' })
    })
}
foreach ($row in $missingHashRows) { $results.Add($row) }
if ($results.Count -eq 0) {
    $results.Add([pscustomobject][ordered]@{
        SamAccountName=''; AccountType=$(if ($IncludeComputers) { 'UserAndComputerScope' } else { 'UserScope' })
        SourceServer=[string]$Server; AccountStatus=''; Pwned='No'; PwnedCount=0
        Comment='No matches among successfully checked accounts. A negative corpus lookup does not prove password strength; see coverage summary.'
    })
}
$exportRows = @($results | Sort-Object Pwned,AccountStatus,AccountType,SamAccountName)
Write-PasswordAuditStage 'Writing account evidence, coverage summary and offline HTML report.'
$exportRows | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $OutCsv
Export-PasswordAuditSummary -OutCsv $OutCsv -Mode Pwned -Server $Server -ReturnedCount $replAccounts.Count -ProcessedCount $accountRows.Count -ExcludedCount $excludedCount -MissingNameCount $missingNameCount -MissingHashCount $missingHashRows.Count -LookupFailedCount $failedAccountCount -HibpCheckedCount ($accountRows.Count - $failedAccountCount) -HibpRequested -Results $exportRows @stateCounts
Write-Host ("Processed accounts: {0}; pwned matches: {1}; failed lookups: {2}; missing NT material: {3}" -f $accountRows.Count,$pwnedAccountCount,$failedAccountCount,$missingHashRows.Count)
Write-Host ("CSV written to: {0}" -f $OutCsv)
Write-PasswordAuditStage ("Pwned password audit finished in {0:n1}s." -f $runTimer.Elapsed.TotalSeconds)
