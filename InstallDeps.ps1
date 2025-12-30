<#
Offline install/repair of DSInternals and NuGet PowerShell modules from local .nupkg files.

- Picks the highest version found by reading .nuspec inside each .nupkg in $PSScriptRoot
- Installs/repairs into: C:\Program Files\WindowsPowerShell\Modules\<Module>\<Version>\
- Validates by: manifest exists + Import-Module succeeds
- Local-machine changes only (no AD writes)
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Assert-IsAdmin {
    $id  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pri = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pri.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script elevated (Run as Administrator)."
    }
}

function Expand-NupkgToTemp {
    param([Parameter(Mandatory)][string]$NupkgPath)

    if (-not (Test-Path $NupkgPath)) { throw "Nupkg not found: $NupkgPath" }

    $tmp = Join-Path $env:TEMP ("nupkg_" + [guid]::NewGuid().ToString("n"))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null

    $tmpZip = Join-Path $env:TEMP ("nupkg_" + [IO.Path]::GetFileNameWithoutExtension($NupkgPath) + "_" + [guid]::NewGuid().ToString("n") + ".zip")
    Copy-Item $NupkgPath $tmpZip -Force

    try {
        try { Unblock-File -Path $NupkgPath -ErrorAction Stop } catch {}
        Expand-Archive -Path $tmpZip -DestinationPath $tmp -Force
        return $tmp
    }
    finally {
        if (Test-Path $tmpZip) { Remove-Item $tmpZip -Force -ErrorAction SilentlyContinue }
    }
}

function Get-NupkgVersionFromExtracted {
    param([Parameter(Mandatory)][string]$ExtractedPath)

    $nuspec = Get-ChildItem -Path $ExtractedPath -Recurse -Filter "*.nuspec" -File | Select-Object -First 1
    if (-not $nuspec) { throw "No .nuspec found in '$ExtractedPath'." }

    [xml]$x = Get-Content $nuspec.FullName
    $ver = $x.package.metadata.version
    if (-not $ver) { throw "Unable to read version from '$($nuspec.FullName)'." }

    [version]$ver
}

function Get-BestNupkg {
    param(
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$SearchRoot
    )

    $candidates = Get-ChildItem -Path $SearchRoot -Filter $Pattern -File -ErrorAction SilentlyContinue
    if (-not $candidates) { return $null }

    $best = $null
    $bestVer = $null

    foreach ($f in $candidates) {
        $tmp = $null
        try {
            $tmp = Expand-NupkgToTemp -NupkgPath $f.FullName
            $v = Get-NupkgVersionFromExtracted -ExtractedPath $tmp
            if (-not $bestVer -or $v -gt $bestVer) {
                $bestVer = $v
                $best = [pscustomobject]@{ File = $f; Version = $v }
            }
        } catch {
            # ignore and continue
        } finally {
            if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    $best
}

function Remove-DirHard {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) { return }

    try {
        & takeown.exe /f $Path /r /d y | Out-Null
        & icacls.exe  $Path /grant "Administrators:(OI)(CI)F" /t | Out-Null
        & attrib.exe -r -s -h (Join-Path $Path '*') /s /d | Out-Null
    } catch {}

    Remove-Item $Path -Recurse -Force -ErrorAction Stop
}

function Test-ModuleUsable {
    param([Parameter(Mandatory)][string]$ModuleName)

    $m = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $m) { return $false }

    $manifest = Join-Path $m.ModuleBase ($ModuleName + ".psd1")
    if (-not (Test-Path $manifest)) { return $false }

    try {
        Remove-Module -Name $ModuleName -ErrorAction SilentlyContinue
        Import-Module -Name $manifest -Force -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Install-ModuleFromNupkg {
    param(
        [Parameter(Mandatory)][string]$ModuleName,
        [Parameter(Mandatory)][string]$NupkgPath,
        [Parameter(Mandatory)][version]$Version
    )

    Write-Host "[*] Installing/repairing $ModuleName from '$NupkgPath' (v$Version)..."

    $modulesRoot = Join-Path $env:ProgramFiles "WindowsPowerShell\Modules"
    $destRoot    = Join-Path $modulesRoot $ModuleName
    $destVerDir  = Join-Path $destRoot  $Version.ToString()

    New-Item -ItemType Directory -Path $destRoot -Force | Out-Null

    $tmp = $null
    try {
        $tmp = Expand-NupkgToTemp -NupkgPath $NupkgPath

        $manifest = Get-ChildItem -Path $tmp -Recurse -Filter ($ModuleName + ".psd1") -File | Select-Object -First 1
        if (-not $manifest) { throw "Manifest '$ModuleName.psd1' not found inside extracted nupkg." }

        $moduleRoot = $manifest.Directory.FullName

        if (Test-Path $destVerDir) {
            Write-Host "[!] Removing existing $ModuleName $Version at '$destVerDir'..."
            Remove-DirHard -Path $destVerDir
        }

        New-Item -ItemType Directory -Path $destVerDir -Force | Out-Null
        Copy-Item -Path (Join-Path $moduleRoot '*') -Destination $destVerDir -Recurse -Force

        Get-ChildItem -Path $destVerDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            try { Unblock-File -Path $_.FullName -ErrorAction Stop } catch {}
        }

        Remove-Module -Name $ModuleName -ErrorAction SilentlyContinue
        Import-Module -Name (Join-Path $destVerDir ($ModuleName + ".psd1")) -Force -ErrorAction Stop

        $m = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $m) { throw "$ModuleName install failed: not discoverable after install." }

        Write-Host "[+] $ModuleName installed: v$($m.Version)"
        Write-Host "[+] $ModuleName path: $($m.ModuleBase)"
    }
    finally {
        if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

try {
    Assert-IsAdmin
    Write-Host "===== Offline DSInternals + NuGet module installation starting ====="

    $dsPkg = Get-BestNupkg -Pattern 'dsinternals*.nupkg' -SearchRoot $PSScriptRoot
    $ngPkg = Get-BestNupkg -Pattern 'nuget*.nupkg'       -SearchRoot $PSScriptRoot

    if (-not $dsPkg) { throw "No dsinternals*.nupkg found in '$PSScriptRoot'." }
    if (-not $ngPkg) { throw "No nuget*.nupkg found in '$PSScriptRoot'." }

    if (Test-ModuleUsable -ModuleName 'DSInternals') {
        $m = Get-Module -ListAvailable DSInternals | Sort-Object Version -Descending | Select-Object -First 1
        Write-Host "[=] DSInternals already usable: v$($m.Version) at $($m.ModuleBase)"
    } else {
        Install-ModuleFromNupkg -ModuleName 'DSInternals' -NupkgPath $dsPkg.File.FullName -Version $dsPkg.Version
    }

    if (Test-ModuleUsable -ModuleName 'NuGet') {
        $m = Get-Module -ListAvailable NuGet | Sort-Object Version -Descending | Select-Object -First 1
        Write-Host "[=] NuGet already usable: v$($m.Version) at $($m.ModuleBase)"
    } else {
        Install-ModuleFromNupkg -ModuleName 'NuGet' -NupkgPath $ngPkg.File.FullName -Version $ngPkg.Version
    }

    Write-Host "===== Done. Modules are installed and importable. ====="
}
catch {
    Write-Error "FAILED: $($_.Exception.Message)"
    exit 1
}
