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
            'User-Agent'  = 'same_passwd_prof.ps1'
            'Add-Padding' = 'true'
        } -TimeoutSec 30 -ErrorAction Stop
    }
    catch {
        Write-Warning ("Failed pwned lookup for hash prefix {0}: {1}" -f $prefix, $_.Exception.Message)
        return 'LookupFailed'
    }

    if ([string]::IsNullOrWhiteSpace($response.Content)) {
        return 'No'
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
        $count = $parts[1].Trim()

        # Ignore padded fake rows when Add-Padding=true
        if ($count -eq '0') {
            continue
        }

        if ($returnedSuffix -eq $suffix) {
            return 'Yes'
        }
    }

    return 'No'
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
Write-Host ("Pwned password lookup: {0}" -f $(if ($Pwned) { 'ENABLED' } else { 'DISABLED' }))

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

$pwnedCache = @{}

if ($Pwned -and $duplicateGroups.Count -gt 0) {
    Write-Host ("Checking {0} unique duplicate NTLM hash(es) against HIBP..." -f $duplicateGroups.Count)

    foreach ($group in $duplicateGroups) {
        $hash = [string]$group.Name

        if (-not $pwnedCache.ContainsKey($hash)) {
            $pwnedCache[$hash] = Test-NtlmHashPwned -NtlmHash $hash
        }
    }
}

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

    $pwnedValue = 'NotChecked'
    if ($Pwned) {
        $pwnedValue = [string]$pwnedCache[[string]$group.Name]
    }

    foreach ($member in $members) {
        $results.Add([pscustomobject]([ordered]@{
            DuplicatePasswordGroup     = $groupNumber
            DuplicatePasswordGroupSize = $members.Count
            SamAccountName             = $member.SamAccountName
            NTHash                     = $member.NTHash
            AccountType                = $member.AccountType
            SourceServer               = $member.SourceServer
            Pwned                      = $pwnedValue
        }))
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