<#
.SYNOPSIS
Runs only the duplicate-password check and exports DUPLICATE_PASSWORDS.csv.

.DESCRIPTION
Standalone script that reads replicated AD account data directly with DSInternals,
groups accounts by NTLM hash, and exports only accounts that share the same password.

Requirements:
- ActiveDirectory PowerShell module
- DSInternals PowerShell module
- Account with rights required for Get-ADReplAccount
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [string]$OutCsv,

    [Parameter(Mandatory = $false)]
    [switch]$UsersOnly
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
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Resolve-ParentDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $parent = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($parent)) {
        return (Get-Location).Path
    }

    return $parent
}

function Convert-BytesToHex {
    [CmdletBinding()]
    param([byte[]]$Bytes)

    if ($null -eq $Bytes -or $Bytes.Count -eq 0) {
        return $null
    }

    return (-join ($Bytes | ForEach-Object { $_.ToString('x2') })).ToUpperInvariant()
}

function Get-AccountTypeLabel {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$AccountName)

    if ($AccountName -match '\$$') {
        return 'Computer'
    }

    return 'User'
}

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

$replAccounts = @(Get-ADReplAccount -All -Server $Server -NamingContext $domainDN -ErrorAction Stop)

if ($replAccounts.Count -eq 0) {
    throw "No replication accounts were returned from $Server."
}

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

$results = New-Object System.Collections.Generic.List[object]
$groupNumber = 0

foreach ($group in $duplicateGroups) {
    $members = @(
        $group.Group |
            Sort-Object -Property SamAccountName -Unique
    )

    if ($members.Count -lt 2) {
        continue
    }

    $groupNumber++

    foreach ($member in $members) {
        $results.Add([pscustomobject]@{
            DuplicatePasswordGroup     = $groupNumber
            DuplicatePasswordGroupSize = $members.Count
            SamAccountName             = $member.SamAccountName
            NTHash                     = $member.NTHash
            AccountType                = $member.AccountType
            SourceServer               = $member.SourceServer
        })
    }
}

$sortedResults = @(
    $results |
        Sort-Object -Property DuplicatePasswordGroup, SamAccountName
)

$sortedResults | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv

Write-Host ("Duplicate password groups found: {0}" -f $groupNumber)
Write-Host ("Affected accounts exported: {0}" -f $sortedResults.Count)
Write-Host ("CSV written to: {0}" -f $OutCsv)
