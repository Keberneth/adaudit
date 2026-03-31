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
.\pwned_users_prof.ps1
.\pwned_users_prof.ps1 -Server dc01.contoso.local
.\pwned_users_prof.ps1 -OutCsv C:\Temp\PWNED_USERS.csv
.\pwned_users_prof.ps1 -IncludeComputers
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

function Resolve-DefaultServer {
    [CmdletBinding()]
    param()

    $dcObj = Get-ADDomainController -Discover -ErrorAction Stop

    foreach ($propertyName in @('DNSHostName', 'HostName', 'Name')) {
        $candidate = $dcObj.$propertyName
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            return [string]$candidate
        }
    }

    throw 'Could not determine a domain controller hostname.'
}

function Ensure-DirectoryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Resolve-ParentDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $parent = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($parent)) {
        return (Get-Location).Path
    }

    return $parent
}

function Convert-BytesToHex {
    [CmdletBinding()]
    param(
        [byte[]]$Bytes
    )

    if ($null -eq $Bytes -or $Bytes.Count -eq 0) {
        return $null
    }

    return (-join ($Bytes | ForEach-Object { $_.ToString('x2') })).ToUpperInvariant()
}

function Get-AccountTypeLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName
    )

    if ($AccountName -match '\$$') {
        return 'Computer'
    }

    return 'User'
}

function Get-AccountStatusLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,

        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    try {
        if ($SamAccountName -match '\$$') {
            $adObject = Get-ADComputer -Identity $SamAccountName -Properties Enabled -Server $Server -ErrorAction Stop
        }
        else {
            $adObject = Get-ADUser -Identity $SamAccountName -Properties Enabled -Server $Server -ErrorAction Stop
        }

        switch ($adObject.Enabled) {
            $true  { return 'Active' }
            $false { return 'Disabled' }
            default { return 'Unknown' }
        }
    }
    catch {
        Write-Warning ("Could not resolve account status for {0}: {1}" -f $SamAccountName, $_.Exception.Message)
        return 'Unknown'
    }
}

function Test-NtlmHashPwned {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$NtlmHash
    )

    $NtlmHash = $NtlmHash.ToUpperInvariant()

    if ($NtlmHash -notmatch '^[A-F0-9]{32}$') {
        throw "Invalid NTLM hash format: $NtlmHash"
    }

    $prefix = $NtlmHash.Substring(0, 5)
    $suffix = $NtlmHash.Substring(5)
    $uri = 'https://api.pwnedpasswords.com/range/{0}?mode=ntlm' -f $prefix

    try {
        $response = Invoke-WebRequest -Uri $uri -Method Get -Headers @{
            'User-Agent'  = 'pwned_users_prof.ps1'
            'Add-Padding' = 'true'
        } -TimeoutSec 30 -ErrorAction Stop
    }
    catch {
        Write-Warning ("Failed pwned lookup for hash prefix {0}: {1}" -f $prefix, $_.Exception.Message)
        return [pscustomobject]@{
            Pwned      = 'LookupFailed'
            PwnedCount = $null
        }
    }

    if ([string]::IsNullOrWhiteSpace($response.Content)) {
        return [pscustomobject]@{
            Pwned      = 'No'
            PwnedCount = 0
        }
    }

    foreach ($line in ($response.Content -split "(`r`n|`n|`r)")) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $parts = $line.Split(':', 2)
        if ($parts.Count -ne 2) {
            continue
        }

        $returnedSuffix = $parts[0].Trim().ToUpperInvariant()
        $countText = $parts[1].Trim()

        # Ignore padded fake rows when Add-Padding=true
        if ($countText -eq '0') {
            continue
        }

        if ($returnedSuffix -eq $suffix) {
            $countValue = 0
            [void][int64]::TryParse($countText, [ref]$countValue)

            return [pscustomobject]@{
                Pwned      = 'Yes'
                PwnedCount = $countValue
            }
        }
    }

    return [pscustomobject]@{
        Pwned      = 'No'
        PwnedCount = 0
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = (Get-Location).Path
}

if ([string]::IsNullOrWhiteSpace($OutCsv)) {
    $OutCsv = Join-Path $scriptDir 'PWNED_USERS.csv'
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

$replAccounts = @(Get-ADReplAccount -All -Server $Server -NamingContext $domainDN -ErrorAction Stop)

if ($replAccounts.Count -eq 0) {
    throw "No replication accounts were returned from $Server."
}

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

    $accountRows.Add([pscustomobject]@{
        SamAccountName = $sam
        NTHash         = $ntlmHash
        AccountType    = Get-AccountTypeLabel -AccountName $sam
        SourceServer   = [string]$Server
        AccountStatus  = Get-AccountStatusLabel -SamAccountName $sam -Server $Server
    })
}

if ($accountRows.Count -eq 0) {
    $emptyResult = @(
        [pscustomobject]([ordered]@{
            SamAccountName = ''
            NTHash         = ''
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

$pwnedCache = @{}

foreach ($hash in $uniqueHashes) {
    if (-not $pwnedCache.ContainsKey($hash)) {
        $pwnedCache[$hash] = Test-NtlmHashPwned -NtlmHash $hash
    }
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($row in $accountRows) {
    $lookup = $pwnedCache[$row.NTHash]

    if ($lookup.Pwned -eq 'Yes') {
        $results.Add([pscustomobject]([ordered]@{
            SamAccountName = $row.SamAccountName
            NTHash         = $row.NTHash
            AccountType    = $row.AccountType
            SourceServer   = $row.SourceServer
            AccountStatus  = $row.AccountStatus
            Pwned          = $lookup.Pwned
            PwnedCount     = $lookup.PwnedCount
            Comment        = 'NTLM hash found in Have I Been Pwned Pwned Passwords corpus.'
        }))
    }
}

if ($results.Count -eq 0) {
    $noPwnedResult = @(
        [pscustomobject]([ordered]@{
            SamAccountName = ''
            NTHash         = ''
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
    $sortedResults = @(
        $results |
            Sort-Object -Property AccountType, SamAccountName
    )

    $sortedResults | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
}

Write-Host ("Processed accounts: {0}" -f $accountRows.Count)
Write-Host ("Pwned accounts exported: {0}" -f $results.Count)
Write-Host ("CSV written to: {0}" -f $OutCsv)
