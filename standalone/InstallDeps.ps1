<#
.SYNOPSIS
    Offline install of DSInternals and NuGet PowerShell modules from local .nupkg files.

.DESCRIPTION
    - Checks if DSInternals and NuGet modules are already installed.
    - If a module is installed, its install step is skipped completely
      (no .nupkg extraction, no file operations).
    - If both are installed, exits with "nothing to do".
    - If missing, installs from:
        dsinternals*.nupkg  (DSInternals)
        nuget*.nupkg        (NuGet module)
      located in the same folder as this script ($PSScriptRoot).

.NOTES
    Run in an elevated (Run as Administrator) Windows PowerShell 5.1 session.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Assert-IsAdmin {
    $id  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pri = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pri.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run in an elevated PowerShell session (Run as Administrator)."
    }
}

function Test-ModuleInstalled {
    param(
        [Parameter(Mandatory)][string]$Name
    )

    # 1) Prefer an actual discoverable module
    $mod = Get-Module -ListAvailable -Name $Name | Select-Object -First 1
    if ($mod) { return $true }

    # 2) Fallback: search for a real module manifest or module file in ProgramFiles modules path
    $modulesRoot = Join-Path $env:ProgramFiles "WindowsPowerShell\Modules"
    if (-not (Test-Path -LiteralPath $modulesRoot)) {
        return $false
    }

    $manifest = Get-ChildItem -Path $modulesRoot -Recurse -Filter "$Name.psd1" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($manifest) { return $true }

    $moduleFile = Get-ChildItem -Path $modulesRoot -Recurse -Filter "$Name.psm1" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($moduleFile) { return $true }

    return $false
}

function Expand-NupkgAsZip {
    param(
        [Parameter(Mandatory)][string]$NupkgPath,
        [Parameter(Mandatory)][string]$DestinationPath
    )

    if (-not (Test-Path -LiteralPath $NupkgPath)) {
        throw "File not found: $NupkgPath"
    }

    if (-not (Test-Path -LiteralPath $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }

    # Expand-Archive only supports .zip, so copy .nupkg to a temp .zip
    $tempZip = Join-Path $env:TEMP ("Pkg_" + [IO.Path]::GetFileNameWithoutExtension($NupkgPath) + "_" + [Guid]::NewGuid().ToString() + ".zip")
    Copy-Item -Path $NupkgPath -Destination $tempZip -Force

    try {
        Expand-Archive -Path $tempZip -DestinationPath $DestinationPath -Force
    }
    finally {
        if (Test-Path -LiteralPath $tempZip) {
            Remove-Item -LiteralPath $tempZip -Force -ErrorAction SilentlyContinue
        }
    }
}

function Install-DSInternalsFromNupkg {
    param(
        [Parameter(Mandatory)][string]$NupkgPath
    )

    Write-Host "[*] Installing DSInternals from '$NupkgPath'..."

    $modulesRoot = Join-Path $env:ProgramFiles "WindowsPowerShell\Modules"
    if (-not (Test-Path -LiteralPath $modulesRoot)) {
        New-Item -ItemType Directory -Path $modulesRoot -Force | Out-Null
    }

    $tempDir = Join-Path $env:TEMP ("DSInternals_Extract_" + [Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        # 1) Extract the nupkg
        Expand-NupkgAsZip -NupkgPath $NupkgPath -DestinationPath $tempDir

        # 2) Get version from DSInternals.nuspec
        $nuspec = Get-ChildItem -Path $tempDir -Filter 'DSInternals.nuspec' -File | Select-Object -First 1
        if (-not $nuspec) {
            throw "DSInternals.nuspec not found in extracted package."
        }

        [xml]$nuspecXml = Get-Content -LiteralPath $nuspec.FullName
        $version = $nuspecXml.package.metadata.version
        if (-not $version) {
            throw "Unable to read version from DSInternals.nuspec."
        }

        # 3) Destination: Modules\DSInternals\<version>\
        $destModuleRoot = Join-Path $modulesRoot "DSInternals"
        $destVersionDir = Join-Path $destModuleRoot $version

        if (-not (Test-Path -LiteralPath $destModuleRoot)) {
            New-Item -ItemType Directory -Path $destModuleRoot -Force | Out-Null
        }
        if (-not (Test-Path -LiteralPath $destVersionDir)) {
            New-Item -ItemType Directory -Path $destVersionDir -Force | Out-Null
        }

        # 4) Find the actual module root (where DSInternals.psd1 lives)
        $moduleManifest = Get-ChildItem -Path $tempDir -Filter 'DSInternals.psd1' -Recurse -File | Select-Object -First 1
        if (-not $moduleManifest) {
            throw "DSInternals.psd1 not found in extracted package."
        }
        $moduleRoot = $moduleManifest.Directory.FullName

        # 5) Check if dest already has a manifest; if not, fix layout IN PLACE
        $existingManifest = Get-ChildItem -Path $destVersionDir -Filter 'DSInternals.psd1' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($existingManifest) {
            Write-Host "[=] DSInternals version directory already exists at '$destVersionDir' and contains DSInternals.psd1. Using existing files."
        }
        else {
            Write-Host "[!] DSInternals version directory '$destVersionDir' exists but has no DSInternals.psd1. Fixing layout in-place."

            # Copy only module-definition bits; avoid touching existing bin DLLs (can be locked)
            Copy-Item -LiteralPath (Join-Path $moduleRoot 'DSInternals.psd1')           -Destination $destVersionDir -Force
            if (Test-Path -LiteralPath (Join-Path $moduleRoot 'DSInternals.Bootstrap.psm1')) {
                Copy-Item -LiteralPath (Join-Path $moduleRoot 'DSInternals.Bootstrap.psm1') -Destination $destVersionDir -Force
            }
            if (Test-Path -LiteralPath (Join-Path $moduleRoot 'DSInternals.types.ps1xml')) {
                Copy-Item -LiteralPath (Join-Path $moduleRoot 'DSInternals.types.ps1xml')   -Destination $destVersionDir -Force
            }

            if (Test-Path -LiteralPath (Join-Path $moduleRoot 'Views')) {
                $destViews = Join-Path $destVersionDir 'Views'
                if (-not (Test-Path -LiteralPath $destViews)) {
                    Copy-Item -LiteralPath (Join-Path $moduleRoot 'Views') -Destination $destVersionDir -Recurse -Force
                }
            }

            if (Test-Path -LiteralPath (Join-Path $moduleRoot 'en-US')) {
                $destEnUs = Join-Path $destVersionDir 'en-US'
                if (-not (Test-Path -LiteralPath $destEnUs)) {
                    Copy-Item -LiteralPath (Join-Path $moduleRoot 'en-US') -Destination $destVersionDir -Recurse -Force
                }
            }

            # Unblock all DSInternals-related files in dest
            Get-ChildItem -Path $destVersionDir -Recurse -File | ForEach-Object {
                try { Unblock-File -Path $_.FullName -ErrorAction Stop } catch {}
            }
        }

        # 6) Import and verify
        Remove-Module -Name DSInternals -ErrorAction SilentlyContinue
        Import-Module -Name DSInternals -Force -ErrorAction Stop

        $mod = Get-Module -ListAvailable DSInternals | Select-Object -First 1
        if (-not $mod) {
            throw "DSInternals installation appears to have failed; module not listed."
        }

        Write-Host "[+] DSInternals installed: $($mod.Name) v$($mod.Version)"
        Write-Host "[+] DSInternals path: $($mod.ModuleBase)"
    }
    finally {
        if (Test-Path -LiteralPath $tempDir) {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Install-NuGetModuleFromNupkg {
    param(
        [Parameter(Mandatory)][string]$NupkgPath
    )

    Write-Host "[*] Installing NuGet PowerShell module from '$NupkgPath'..."

    $modulesRoot = Join-Path $env:ProgramFiles "WindowsPowerShell\Modules"
    if (-not (Test-Path -LiteralPath $modulesRoot)) {
        New-Item -ItemType Directory -Path $modulesRoot -Force | Out-Null
    }

    $tempDir = Join-Path $env:TEMP ("NuGetModule_Extract_" + [Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        Expand-NupkgAsZip -NupkgPath $NupkgPath -DestinationPath $tempDir

        # Find the nuspec (name may be NuGet.nuspec or similar)
        $nuspec = Get-ChildItem -Path $tempDir -Filter '*uGet*.nuspec' -File | Select-Object -First 1
        if (-not $nuspec) {
            throw "NuGet .nuspec not found in extracted package."
        }

        [xml]$nuspecXml = Get-Content -LiteralPath $nuspec.FullName
        $version = $nuspecXml.package.metadata.version
        if (-not $version) {
            throw "Unable to read version from NuGet .nuspec."
        }

        # Destination: Modules\NuGet\<version>\
        $destModuleRoot = Join-Path $modulesRoot "NuGet"
        $destVersionDir = Join-Path $destModuleRoot $version

        if (-not (Test-Path -LiteralPath $destModuleRoot)) {
            New-Item -ItemType Directory -Path $destModuleRoot -Force | Out-Null
        }
        if (-not (Test-Path -LiteralPath $destVersionDir)) {
            New-Item -ItemType Directory -Path $destVersionDir -Force | Out-Null
        }

        # Find the actual module root (where NuGet.psd1 lives)
        $moduleManifest = Get-ChildItem -Path $tempDir -Filter 'NuGet.psd1' -Recurse -File | Select-Object -First 1
        if (-not $moduleManifest) {
            throw "NuGet.psd1 not found in extracted package."
        }
        $moduleRoot = $moduleManifest.Directory.FullName

        $existingManifest = Get-ChildItem -Path $destVersionDir -Filter 'NuGet.psd1' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($existingManifest) {
            Write-Host "[=] NuGet version directory already exists at '$destVersionDir' and contains NuGet.psd1. Using existing files."
        }
        else {
            Write-Host "[!] NuGet version directory '$destVersionDir' exists but has no NuGet.psd1. Installing layout."

            Copy-Item -Path (Join-Path $moduleRoot '*') -Destination $destVersionDir -Recurse -Force

            Get-ChildItem -Path $destVersionDir -Recurse -File | ForEach-Object {
                try { Unblock-File -Path $_.FullName -ErrorAction Stop } catch {}
            }
        }

        Remove-Module -Name NuGet -ErrorAction SilentlyContinue
        Import-Module -Name NuGet -Force -ErrorAction Stop

        $mod = Get-Module -ListAvailable NuGet | Select-Object -First 1
        if (-not $mod) {
            throw "NuGet module installation appears to have failed; module not listed."
        }

        Write-Host "[+] NuGet module installed: $($mod.Name) v$($mod.Version)"
        Write-Host "[+] NuGet module path: $($mod.ModuleBase)"
    }
    finally {
        if (Test-Path -LiteralPath $tempDir) {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

try {
    Write-Host "===== Offline DSInternals + NuGet module installation starting ====="
    Assert-IsAdmin

    # Initial checks
    $dsInstalled    = Test-ModuleInstalled -Name 'DSInternals'
    $nugetInstalled = Test-ModuleInstalled -Name 'NuGet'

    # Cross-check with Get-Module to avoid "installed:  at" situations
    $dsInfo    = Get-Module -ListAvailable DSInternals | Select-Object -First 1
    $nugetInfo = Get-Module -ListAvailable NuGet       | Select-Object -First 1

    if ($dsInstalled -and -not $dsInfo) {
        $dsInstalled = $false
    }
    if ($nugetInstalled -and -not $nugetInfo) {
        $nugetInstalled = $false
    }

    if ($dsInstalled -and $nugetInstalled) {
        Write-Host "[=] DSInternals already installed: $($dsInfo.Version) at $($dsInfo.ModuleBase)"
        Write-Host "[=] NuGet module already installed: $($nugetInfo.Version) at $($nugetInfo.ModuleBase)"
        Write-Host "===== Both modules are already installed. Nothing to do. ====="
        return
    }

    if (-not $dsInstalled) {
        $dsinternalsNupkg = Get-ChildItem -LiteralPath $PSScriptRoot -Filter 'dsinternals*.nupkg' -File | Select-Object -First 1
        if (-not $dsinternalsNupkg) {
            throw "DSInternals is not installed and no dsinternals*.nupkg found in '$PSScriptRoot'."
        }
        Install-DSInternalsFromNupkg -NupkgPath $dsinternalsNupkg.FullName
    }
    else {
        $dsInfo = Get-Module -ListAvailable DSInternals | Select-Object -First 1
        Write-Host "[=] DSInternals already installed, skipping install. Version: $($dsInfo.Version)"
    }

    if (-not $nugetInstalled) {
        $nugetNupkg = Get-ChildItem -LiteralPath $PSScriptRoot -Filter 'nuget*.nupkg' -File | Select-Object -First 1
        if (-not $nugetNupkg) {
            throw "NuGet module is not installed and no nuget*.nupkg found in '$PSScriptRoot'."
        }
        Install-NuGetModuleFromNupkg -NupkgPath $nugetNupkg.FullName
    }
    else {
        $nugetInfo = Get-Module -ListAvailable NuGet | Select-Object -First 1
        Write-Host "[=] NuGet module already installed, skipping install. Version: $($nugetInfo.Version)"
    }

    Write-Host "===== Done. Missing modules were installed; existing ones left untouched. ====="
}
catch {
    Write-Error "FAILED: $($_.Exception.Message)"
    if ($_.InvocationInfo.PositionMessage) {
        Write-Host $_.InvocationInfo.PositionMessage
    }
    exit 1
}
