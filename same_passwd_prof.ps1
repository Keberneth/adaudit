<#
.SYNOPSIS
Parses password_quality.txt and compares accounts with same passwords across DCs.
"These groups of accounts have the same passwords:"
Create a .csv proof file for accounts with the same password.
Will include NTHashHex and pwdLastSetUTC per DC.

Need to have run ADaudit.ps1 -all or ADaudit.ps1 -accounts before to generate password_quality.txt.

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & "C:\ADAudit\same_passwd_prof.ps1"

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$PasswordQualityTxt,

    [Parameter(Mandatory=$false)]
    [string]$OutCsv,

    [Parameter(Mandatory=$false)]
    [ValidateSet('FirstVsRest','AllPairs')]
    [string]$PairMode = 'FirstVsRest',

    [Parameter(Mandatory=$false)]
    [ValidateRange(1,200)]
    [int]$MaxGroups = 200
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-BytesToHex {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Count -eq 0) { return $null }
    ($Bytes | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Normalize-Identity {
    param([string]$Identity)
    if (-not $Identity) { return $Identity }
    $id = $Identity.Trim()
    # Accept DOMAIN\sAM format => keep as-is for display, but for Get-ADUser we prefer the sAM portion
    return $id
}

function Identity-ToAdIdentity {
    param([string]$Identity)
    $id = Normalize-Identity $Identity
    if ($id -match '^[^\\]+\\(.+)$') { return $Matches[1] } # DOMAIN\sam -> sam
    return $id
}

function Resolve-AdUser {
    param([string]$Identity, [string]$Server)

    $id = Identity-ToAdIdentity $Identity

    try {
        return Get-ADUser -Server $Server -Identity $id -Properties pwdLastSet, DistinguishedName, SamAccountName, UserPrincipalName -ErrorAction Stop
    } catch {
        return Get-ADUser -Server $Server -Filter "SamAccountName -eq '$id' -or UserPrincipalName -eq '$id'" -Properties pwdLastSet, DistinguishedName, SamAccountName, UserPrincipalName -ErrorAction Stop
    }
}

function Get-ReplAccountByDn {
    param(
        [string]$Server,
        [string]$UserDn,
        [string]$NamingContext
    )
    Get-ADReplAccount -Server $Server -All -NamingContext $NamingContext |
        Where-Object { $_.DistinguishedName -eq $UserDn } |
        Select-Object -First 1
}

function Compare-UsersAcrossDCs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IdentityA,
        [Parameter(Mandatory)][string]$IdentityB,
        [Parameter(Mandatory)][string[]]$DcList,
        [Parameter(Mandatory)][string]$DefaultNC,
        [Parameter(Mandatory)][string]$ResolveServer
    )

    $uA = Resolve-AdUser -Identity $IdentityA -Server $ResolveServer
    $uB = Resolve-AdUser -Identity $IdentityB -Server $ResolveServer

    foreach ($dc in $DcList) {
        $row = [ordered]@{
            DC              = $dc
            A_User          = $uA.SamAccountName
            B_User          = $uB.SamAccountName
            A_Identity      = (Normalize-Identity $IdentityA)
            B_Identity      = (Normalize-Identity $IdentityB)
            A_pwdLastSetUTC = $null
            B_pwdLastSetUTC = $null
            A_NTHashHex     = $null
            B_NTHashHex     = $null
            HashEqual       = $null
            Note            = $null
        }

        try {
            $aAd = Get-ADUser -Server $dc -Identity $uA.DistinguishedName -Properties pwdLastSet -ErrorAction Stop
            $bAd = Get-ADUser -Server $dc -Identity $uB.DistinguishedName -Properties pwdLastSet -ErrorAction Stop

            if ($aAd.pwdLastSet -and [int64]$aAd.pwdLastSet -gt 0) {
                $row.A_pwdLastSetUTC = [DateTime]::FromFileTimeUtc([int64]$aAd.pwdLastSet).ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
            } else { $row.A_pwdLastSetUTC = "<not set>" }

            if ($bAd.pwdLastSet -and [int64]$bAd.pwdLastSet -gt 0) {
                $row.B_pwdLastSetUTC = [DateTime]::FromFileTimeUtc([int64]$bAd.pwdLastSet).ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
            } else { $row.B_pwdLastSetUTC = "<not set>" }

            $aRepl = Get-ReplAccountByDn -Server $dc -UserDn $uA.DistinguishedName -NamingContext $DefaultNC
            $bRepl = Get-ReplAccountByDn -Server $dc -UserDn $uB.DistinguishedName -NamingContext $DefaultNC

            if ($aRepl -and $bRepl) {
                $aHex = Convert-BytesToHex $aRepl.NTHash
                $bHex = Convert-BytesToHex $bRepl.NTHash

                $row.A_NTHashHex = if ($aHex) { $aHex } else { "<null/hidden>" }
                $row.B_NTHashHex = if ($bHex) { $bHex } else { "<null/hidden>" }

                if ($aHex -and $bHex) {
                    $row.HashEqual = ($aHex -eq $bHex)
                } else {
                    $row.Note = "NTHash not available (insufficient rights, protected user, or policy)."
                }
            } else {
                $row.Note = "Replication data missing"
            }
        } catch {
            $row.Note = $_.Exception.Message
        }

        [pscustomobject]$row
    }
}

function Parse-GroupsFromPasswordQualityTxt {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $lines = Get-Content -LiteralPath $Path -ErrorAction Stop

    $headerIdx = $null
    for ($i=0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*These groups of accounts have the same passwords\s*:\s*$') {
            $headerIdx = $i
            break
        }
    }
    if ($null -eq $headerIdx) { return @() }

    $groups = @{}
    $current = $null

    for ($i=$headerIdx+1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        # stop when a new section begins (non-group header ending with ':')
        if ($line -match '^[^:]+:\s*$' -and $line -notmatch '^Group\s+\d+\s*:\s*$') { break }

        if ($line -match '^Group\s+(\d+)\s*:\s*$') {
            $current = [int]$Matches[1]
            if (-not $groups.ContainsKey($current)) { $groups[$current] = New-Object System.Collections.Generic.List[string] }
            continue
        }

        if ($null -ne $current) {
            $groups[$current].Add($line)
        }
    }

    # return ordered objects
    $groups.Keys | Sort-Object | ForEach-Object {
        [pscustomobject]@{
            GroupId  = $_
            Accounts = @($groups[$_])
        }
    }
}

# --- Defaults for paths ---
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }

if (-not $PasswordQualityTxt -or [string]::IsNullOrWhiteSpace($PasswordQualityTxt)) {
    $hostFolder = Join-Path $scriptDir $env:COMPUTERNAME
    $PasswordQualityTxt = Join-Path $hostFolder 'password_quality.txt'
}

if (-not (Test-Path -LiteralPath $PasswordQualityTxt -PathType Leaf)) {
    throw "Could not find password_quality.txt at: $PasswordQualityTxt (expected .\$($env:COMPUTERNAME)\password_quality.txt next to the script). Use -PasswordQualityTxt to override."
}

if (-not $OutCsv -or [string]::IsNullOrWhiteSpace($OutCsv)) {
    $rootFolder = Split-Path -Parent $PasswordQualityTxt  # <HOSTNAME>
    $outDir = Join-Path $rootFolder 'HighRisk'
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    $OutCsv = Join-Path $outDir 'SamePasswordProof_CompareResults.csv'
} else {
    New-Item -ItemType Directory -Path (Split-Path -Parent $OutCsv) -Force | Out-Null
}

# --- Imports required for the compare logic ---
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module DSInternals   -ErrorAction Stop

$defaultNC = (Get-ADRootDSE).defaultNamingContext

$dcList = Get-ADDomainController -Filter * |
    Select-Object -ExpandProperty HostName |
    Sort-Object -Unique
if (-not $dcList -or $dcList.Count -eq 0) { throw "No Domain Controllers found." }

$pdc = (Get-ADDomain).PDCEmulator
$resolveServer = if ($pdc) { $pdc } else { $dcList[0] }

# --- Parse groups from password_quality.txt ---
$groups = Parse-GroupsFromPasswordQualityTxt -Path $PasswordQualityTxt
if (-not $groups -or $groups.Count -eq 0) {
    # still write an empty CSV with headers compatible with compare output
    @() | Select-Object GroupId,PairId,DC,A_User,B_User,A_Identity,B_Identity,A_pwdLastSetUTC,B_pwdLastSetUTC,A_NTHashHex,B_NTHashHex,HashEqual,Note |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
    Write-Host ("No 'These groups of accounts have the same passwords:' section found. Wrote empty CSV: {0}" -f (Resolve-Path $OutCsv).Path)
    return
}

$allResults = New-Object System.Collections.Generic.List[object]

$processed = 0
foreach ($g in $groups) {
    $processed++
    if ($processed -gt $MaxGroups) { break }

    $acct = @($g.Accounts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($acct.Count -lt 2) { continue }

    $pairs = New-Object System.Collections.Generic.List[object]
    if ($PairMode -eq 'FirstVsRest') {
        $a0 = $acct[0]
        for ($i=1; $i -lt $acct.Count; $i++) {
            $pairs.Add([pscustomobject]@{ A=$a0; B=$acct[$i] })
        }
    } else {
        for ($i=0; $i -lt $acct.Count; $i++) {
            for ($j=$i+1; $j -lt $acct.Count; $j++) {
                $pairs.Add([pscustomobject]@{ A=$acct[$i]; B=$acct[$j] })
            }
        }
    }

    $pairId = 0
    foreach ($p in $pairs) {
        $pairId++

        $cmpRows = Compare-UsersAcrossDCs `
            -IdentityA $p.A `
            -IdentityB $p.B `
            -DcList $dcList `
            -DefaultNC $defaultNC `
            -ResolveServer $resolveServer

        foreach ($r in $cmpRows) {
            $allResults.Add([pscustomobject]@{
                GroupId        = $g.GroupId
                PairId         = $pairId
                DC             = $r.DC
                A_User         = $r.A_User
                B_User         = $r.B_User
                A_Identity     = $r.A_Identity
                B_Identity     = $r.B_Identity
                A_pwdLastSetUTC= $r.A_pwdLastSetUTC
                B_pwdLastSetUTC= $r.B_pwdLastSetUTC
                A_NTHashHex    = $r.A_NTHashHex
                B_NTHashHex    = $r.B_NTHashHex
                HashEqual      = $r.HashEqual
                Note           = $r.Note
            })
        }
    }
}

# --- Console output (similar feel to comparepassword.ps1) ---
$allResults |
    Sort-Object GroupId,PairId,DC |
    Format-Table -AutoSize GroupId,PairId,DC,A_Identity,B_Identity,HashEqual,Note

# --- CSV output (compare-like columns + GroupId/PairId) ---
$allResults |
    Sort-Object GroupId,PairId,DC |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv

Write-Host ("`nCSV written to: {0}" -f (Resolve-Path $OutCsv).Path)
