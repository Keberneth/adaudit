<#
.SYNOPSIS
  ADAudit-GUI.ps1 - WinForms GUI launcher for AdAudit-PS7.ps1

  Provides a graphical interface to:
    - Select audit checks (or run all)
    - Exclude specific checks when running all
    - Install dependencies online or offline
    - Configure advanced options (DNS zone, delegated permissions, lateral movement baseline)
    - Preview and execute the audit command
    - Launch the Password Audit scripts (Password Audit\Invoke-*Check.ps1), which stay
      separate from the audit run and from -all

  Requirements:
    - PowerShell 7 (pwsh.exe)
    - The complete ADAudit folder next to this script: AdAudit-PS7.ps1, Library\, Checks\
      and (for the password audit) Password Audit\
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# -------------------------
# Validate environment
# -------------------------
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This GUI requires PowerShell 7 (pwsh.exe). Current version: $($PSVersionTable.PSVersion)"
    exit 1
}

Write-Host "Opening GUI..."

$ScriptDir = $PSScriptRoot
$AuditScriptPath = Join-Path $ScriptDir 'AdAudit-PS7.ps1'

if (-not (Test-Path -LiteralPath $AuditScriptPath)) {
    Write-Error "AdAudit-PS7.ps1 not found in '$ScriptDir'. Place this GUI script in the same folder as AdAudit-PS7.ps1."
    exit 1
}
foreach ($required in @('Library\ADAudit.Common.ps1', 'Library\ADAudit.Report.ps1', 'Checks\Invoke-AccountsCheck.ps1')) {
    if (-not (Test-Path -LiteralPath (Join-Path $ScriptDir $required))) {
        Write-Error "'$required' not found under '$ScriptDir'. Copy the whole ADAudit folder (AdAudit-PS7.ps1, Library\, Checks\, Password Audit\), not only the scripts in the root."
        exit 1
    }
}
$PasswordAuditDir = Join-Path $ScriptDir 'Password Audit'
$PwnedScriptPath  = Join-Path $PasswordAuditDir 'Invoke-PwnedPasswordCheck.ps1'
$SameScriptPath   = Join-Path $PasswordAuditDir 'Invoke-SamePasswordCheck.ps1'
$PasswordAuditOutDir = Join-Path (Join-Path $ScriptDir $env:COMPUTERNAME) 'Password Audit'

# -------------------------
# Load WinForms
# -------------------------
Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
Add-Type -AssemblyName System.Drawing      -ErrorAction Stop
[System.Windows.Forms.Application]::EnableVisualStyles()

# -------------------------
# Offline Install Logic (from InstallDeps.ps1)
# -------------------------
function Test-IsAdmin {
    $id  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pri = New-Object Security.Principal.WindowsPrincipal($id)
    return $pri.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-IsAdmin {
    if (-not (Test-IsAdmin)) {
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
    } finally {
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
    $candidates = Get-ChildItem -LiteralPath $SearchRoot -Filter $Pattern -File -ErrorAction SilentlyContinue
    if (-not $candidates) { return $null }
    $best = $null
    $bestVer = $null
    $lastError = $null
    foreach ($f in $candidates) {
        $tmp = $null
        try {
            $tmp = Expand-NupkgToTemp -NupkgPath $f.FullName
            $v = Get-NupkgVersionFromExtracted -ExtractedPath $tmp
            if (-not $bestVer -or $v -gt $bestVer) {
                $bestVer = $v
                $best = [pscustomobject]@{ File = $f; Version = $v }
            }
        } catch { $lastError = $_ } finally {
            if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    if (-not $best -and $lastError) {
        # Files were present but unreadable - the caller must not report MISSING_NUPKG
        throw "Found $(@($candidates).Count) file(s) matching '$Pattern' in '$SearchRoot' but none could be read: $($lastError.Exception.Message)"
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
    # Probe usability in a throwaway child process so we do not permanently load
    # (and lock) the module's assemblies in the GUI process — that would block the
    # installer from replacing the DLLs later.
    try {
        $probe = Start-Process pwsh.exe -ArgumentList '-NoProfile','-NonInteractive','-Command',("Import-Module '" + $manifest + "' -ErrorAction Stop") -Wait -PassThru -WindowStyle Hidden
        return ($probe.ExitCode -eq 0)
    } catch { return $false }
}

function Install-ModuleFromNupkg {
    param(
        [Parameter(Mandatory)][string]$ModuleName,
        [Parameter(Mandatory)][string]$NupkgPath,
        [Parameter(Mandatory)][version]$Version
    )
    # Use the correct modules path for the running PowerShell edition
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $modulesRoot = Join-Path $env:ProgramFiles "PowerShell\Modules"
    } else {
        $modulesRoot = Join-Path $env:ProgramFiles "WindowsPowerShell\Modules"
    }
    $destRoot    = Join-Path $modulesRoot $ModuleName
    $destVerDir  = Join-Path $destRoot  $Version.ToString()
    New-Item -ItemType Directory -Path $destRoot -Force | Out-Null
    # Opportunistically sweep any leftover *_old_* dirs from previous runs whose
    # locks have since been released.
    Get-ChildItem -Path $destRoot -Directory -Filter '*_old_*' -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    $tmp = $null
    try {
        $tmp = Expand-NupkgToTemp -NupkgPath $NupkgPath
        $manifest = Get-ChildItem -Path $tmp -Recurse -Filter ($ModuleName + ".psd1") -File | Select-Object -First 1
        if (-not $manifest) { throw "Manifest '$ModuleName.psd1' not found inside extracted nupkg." }
        $moduleRoot = $manifest.Directory.FullName
        if (Test-Path $destVerDir) {
            try { Remove-DirHard -Path $destVerDir } catch {
                # DLLs may be locked by another session; rename old dir out of the way
                $stale = "${destVerDir}_old_" + [guid]::NewGuid().ToString("n").Substring(0,8)
                Rename-Item -Path $destVerDir -NewName (Split-Path $stale -Leaf) -Force -ErrorAction Stop
                # Try to delete the renamed dir now; if it's still locked it will be
                # swept opportunistically on a future run (see the *_old_* sweep above).
                try { Remove-Item $stale -Recurse -Force -ErrorAction Stop } catch {}
            }
        }
        New-Item -ItemType Directory -Path $destVerDir -Force | Out-Null
        Copy-Item -Path (Join-Path $moduleRoot '*') -Destination $destVerDir -Recurse -Force
        # Fix version mismatch: ensure psd1 ModuleVersion matches the version folder name
        $psd1Path = Join-Path $destVerDir ($ModuleName + ".psd1")
        if (Test-Path $psd1Path) {
            $psd1Content = Get-Content $psd1Path -Raw
            $folderVer = $Version.ToString()
            $psd1Content = $psd1Content -replace "(?<=ModuleVersion\s*=\s*['""])[\d\.]+(?=['""])", $folderVer
            Set-Content -Path $psd1Path -Value $psd1Content -NoNewline
        }
        Get-ChildItem -Path $destVerDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            try { Unblock-File -Path $_.FullName -ErrorAction Stop } catch {}
        }
        Remove-Module -Name $ModuleName -ErrorAction SilentlyContinue
        # Verify module is discoverable; skip Import-Module if assemblies from another version are already loaded
        $m = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $m) { throw "$ModuleName install failed: not discoverable after install." }
        try {
            Import-Module -Name (Join-Path $destVerDir ($ModuleName + ".psd1")) -Force -ErrorAction Stop
        } catch {
            if ($_.Exception.Message -match 'Assembly with same name is already loaded') {
                # Assemblies from a previous version are locked in this session — module files are installed correctly
                # and will load fine in the next PowerShell session or when the audit script runs
            } else { throw }
        }
    } finally {
        if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-OfflineInstall {
    param([string]$SearchRoot)
    try {
        Assert-IsAdmin

        $dsPkg = Get-BestNupkg -Pattern 'dsinternals*.nupkg' -SearchRoot $SearchRoot
        $ngPkg = Get-BestNupkg -Pattern 'nuget*.nupkg'       -SearchRoot $SearchRoot

        if (-not $dsPkg -or -not $ngPkg) {
            throw "MISSING_NUPKG"
        }

        $results = @()

        if (Test-ModuleUsable -ModuleName 'DSInternals') {
            $m = Get-Module -ListAvailable DSInternals | Sort-Object Version -Descending | Select-Object -First 1
            $results += "DSInternals already installed: v$($m.Version)"
        } else {
            Install-ModuleFromNupkg -ModuleName 'DSInternals' -NupkgPath $dsPkg.File.FullName -Version $dsPkg.Version
            $results += "DSInternals installed successfully: v$($dsPkg.Version)"
        }

        if (Test-ModuleUsable -ModuleName 'NuGet') {
            $m = Get-Module -ListAvailable NuGet | Sort-Object Version -Descending | Select-Object -First 1
            $results += "NuGet already installed: v$($m.Version)"
        } else {
            Install-ModuleFromNupkg -ModuleName 'NuGet' -NupkgPath $ngPkg.File.FullName -Version $ngPkg.Version
            $results += "NuGet installed successfully: v$($ngPkg.Version)"
        }

        return $results -join "`n"
    } catch {
        if ($_.Exception.Message -eq 'MISSING_NUPKG') {
            throw "MISSING_NUPKG"
        }
        throw
    }
}

# -------------------------
# Helper: Message boxes
# -------------------------
function Msg-Error([string]$Message) {
    [System.Windows.Forms.MessageBox]::Show(
        $Message, "Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
}
function Msg-Info([string]$Message) {
    [System.Windows.Forms.MessageBox]::Show(
        $Message, "Info",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
}

# -------------------------
# Audit check definitions
# -------------------------
$AuditChecks = [ordered]@{
    hostdetails          = "Retrieve hostname and useful audit information"
    domainaudit          = "Audit AD functional level, delegation, spooler, SMB signing, tombstone"
    trusts               = "Check domain trust relationships"
    accounts             = "Identify account issues (expired, disabled, gMSA, etc.)"
    InactiveComputers    = "Find inactive computer objects"
    passwordpolicy       = "Review password policy configuration"
    oldboxes             = "Find machines running unsupported OS (older than Server 2019)"
    gpo                  = "Export GPOs in XML and HTML format"
    ouperms              = "Check for generic OU permission issues"
    laps                 = "Check if LAPS is deployed"
    authpolsilos         = "Check authentication policies and silos"
    insecurednszone      = "Detect insecure DNS zones allowing unauthenticated updates"
    dnszone              = "Generate DNS zone posture report"
    recentchanges        = "Check for newly created users/groups (last 30 days)"
    adcs                 = "Check for ADCS vulnerabilities (ESC1-4, ESC8)"
    spn                  = "Find kerberoastable high-value accounts"
    asrep                = "Find accounts vulnerable to AS-REP roasting"
    acl                  = "Check for dangerous ACL permissions"
    ldapsecurity         = "Check LDAP security configuration"
    dataextract          = "Export raw AD audit data"
    delegatedpermissions = "Generate AD delegated permissions report"
    highrisk             = "Generate high-risk AD baseline report"
    overlappinggroups    = "Check for overlapping group memberships"
    portconnectivity     = "Test DC TCP ports (RPC/LDAP/LDAPS/Kerberos/SMB/ADWS/WinRM/dynamic RPC) from this host and cross-DC via WinRM"
    adhealth             = "AD platform health check (replication, dcdiag, SYSVOL/DFSR, NTDS, time, services, events, sites, recycle bin, group hygiene)"
    lateralmovement      = "Lateral movement map: group nesting, hidden Tier 0 paths, AGDLP violations, per-user / per-group risk (Invoke-LateralMovementCheck.ps1)"
}

# -------------------------
# Build the form
# -------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "ADAudit - Active Directory Audit Tool"
$form.Size = New-Object System.Drawing.Size(1000, 880)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(800, 600)

# Scrollable panel
$panel = New-Object System.Windows.Forms.Panel
$panel.Dock = 'Fill'
$panel.AutoScroll = $true
$form.Controls.Add($panel) | Out-Null

# Layout constants (matching CreateUser.ps1)
$leftLabel  = 16
$labelWidth = 240
$leftInput  = 266
$inputWidth = 680
$rowHeight  = 28

# -------------------------
# Helper functions (matching CreateUser.ps1 style)
# -------------------------
function Add-Label {
    param([string]$Text, [int]$Top, [int]$Width = $script:labelWidth, [int]$X = $script:leftLabel)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.Location = New-Object System.Drawing.Point($X, $Top)
    $l.Size = New-Object System.Drawing.Size($Width, 20)
    $script:panel.Controls.Add($l) | Out-Null
    return $l
}

function Add-LabelBold {
    param([string]$Text, [int]$Top, [int]$Width = 940, [int]$X = $script:leftLabel)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.Font = New-Object System.Drawing.Font($l.Font, [System.Drawing.FontStyle]::Bold)
    $l.Location = New-Object System.Drawing.Point($X, $Top)
    $l.Size = New-Object System.Drawing.Size($Width, 22)
    $script:panel.Controls.Add($l) | Out-Null
    return $l
}

function Add-TextBox {
    param([int]$Top, [bool]$ReadOnly = $false, [bool]$Multiline = $false, [int]$Height = 22, [int]$Width = $script:inputWidth)
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location = New-Object System.Drawing.Point($script:leftInput, ($Top - 3))
    $t.Size = New-Object System.Drawing.Size($Width, $Height)
    $t.ReadOnly = $ReadOnly
    $t.Multiline = $Multiline
    if ($Multiline) { $t.ScrollBars = 'Vertical' }
    $script:panel.Controls.Add($t) | Out-Null
    return $t
}

function Add-Check {
    param([string]$Text, [int]$Top, [bool]$Checked = $false, [int]$Width = 220, [int]$X = $script:leftInput)
    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text = $Text
    $c.Location = New-Object System.Drawing.Point($X, ($Top - 4))
    $c.Size = New-Object System.Drawing.Size($Width, 22)
    $c.Checked = $Checked
    $script:panel.Controls.Add($c) | Out-Null
    return $c
}

function Add-Button {
    param([string]$Text, [int]$Top, [int]$Width = 200, [int]$Height = 30, [int]$X = $script:leftInput)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Location = New-Object System.Drawing.Point($X, ($Top - 2))
    $b.Size = New-Object System.Drawing.Size($Width, $Height)
    $script:panel.Controls.Add($b) | Out-Null
    return $b
}

function Add-Separator {
    param([int]$Top)
    $sep = New-Object System.Windows.Forms.Label
    $sep.BorderStyle = 'Fixed3D'
    $sep.Location = New-Object System.Drawing.Point(16, $Top)
    $sep.Size = New-Object System.Drawing.Size(940, 2)
    $script:panel.Controls.Add($sep) | Out-Null
}

# -------------------------
# Build UI
# -------------------------
$y = 14

# === HEADER ===
$lblTitle = Add-LabelBold "ADAudit - Active Directory Security Audit" $y
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblTitle.Size = New-Object System.Drawing.Size(940, 30)
$y += 36

$lblVersion = Add-Label "Script: AdAudit-PS7.ps1  |  Location: $ScriptDir" $y 940
$lblVersion.ForeColor = [System.Drawing.Color]::Gray
$y += 30

Add-Separator $y
$y += 12

# === DEPENDENCIES SECTION ===
Add-LabelBold "Dependencies" $y | Out-Null
$y += $rowHeight

Add-Label "Install required modules" $y | Out-Null
$btnOnline  = Add-Button "Install Online"  $y 180 28
$btnOffline = Add-Button "Install Offline" $y 180 28 ($leftInput + 190)
$y += 38

Add-Separator $y
$y += 12

# === AUDIT SELECTION ===
Add-LabelBold "Audit Selection" $y | Out-Null
$y += $rowHeight

# Run All checkbox
$chkAll = Add-Check "Run All Checks (recommended)" $y $true 300 $leftInput
$y += $rowHeight + 4

# Description label for Run All
$lblAllDesc = Add-Label "Runs every audit check. Uncheck to select individual checks below." ($y - 4) $inputWidth $leftInput
$lblAllDesc.ForeColor = [System.Drawing.Color]::Gray
$y += $rowHeight

Add-Separator $y
$y += 12

# === INDIVIDUAL CHECKS ===
Add-LabelBold "Individual Audit Checks" $y 240 | Out-Null
$lblIndivHint = Add-Label "(enabled when 'Run All' is unchecked)" ($y + 2) 300 ($leftLabel + 250)
$lblIndivHint.ForeColor = [System.Drawing.Color]::Gray
$y += $rowHeight + 2

$checkboxes = @{}
foreach ($key in $AuditChecks.Keys) {
    $chk = Add-Check "-$key" $y $false 220 $leftLabel
    $chk.Enabled = $false  # disabled when Run All is checked
    $chk.Tag = $key

    # Description label to the right
    $desc = Add-Label $AuditChecks[$key] ($y + 1) 700 ($leftLabel + 226)
    $desc.ForeColor = [System.Drawing.Color]::DimGray
    $desc.Tag = "desc_$key"

    $checkboxes[$key] = $chk
    $y += $rowHeight
}

$y += 6
Add-Separator $y
$y += 12

# === EXCLUDE SECTION (visible when Run All is checked) ===
$lblExclude = Add-LabelBold "Exclude from 'Run All'" $y
$y += $rowHeight

$lblExcludeHint = Add-Label "Select checks to skip when running all:" ($y - 4) $inputWidth $leftInput
$lblExcludeHint.ForeColor = [System.Drawing.Color]::Gray
$y += 22

$excludeCheckboxes = @{}
# Track the exclude description labels too so the whole section can be hidden/shown
# together with the checkboxes and headers (avoids a heading-less block of greyed
# checkboxes when 'Run All' is unchecked).
$excludeDescLabels = @()
# Display exclude checkboxes in a more compact 2-column layout
$excludeKeys = @($AuditChecks.Keys)
$col = 0
foreach ($key in $excludeKeys) {
    $xPos = if ($col -eq 0) { $leftLabel } else { $leftLabel + 470 }
    $exChk = Add-Check "-$key" $y $false 220 $xPos

    $exDesc = Add-Label $AuditChecks[$key] ($y + 1) 230 ($xPos + 226)
    $exDesc.ForeColor = [System.Drawing.Color]::DimGray
    $excludeDescLabels += $exDesc

    $exChk.Tag = "exclude_$key"
    $excludeCheckboxes[$key] = $exChk

    $col++
    if ($col -ge 2) {
        $col = 0
        $y += 24
    }
}
if ($col -ne 0) { $y += 24 }

$y += 6
Add-Separator $y
$y += 12

# === ADVANCED OPTIONS ===
Add-LabelBold "Advanced Options" $y | Out-Null
$y += $rowHeight

$chkKeepLegacy = Add-Check "-KeepLegacyArtifacts" $y $false 250 $leftLabel
$lblKeepLegacyDesc = Add-Label "Preserve raw data and evidence files" ($y + 1) 500 ($leftLabel + 256)
$lblKeepLegacyDesc.ForeColor = [System.Drawing.Color]::DimGray
$y += $rowHeight + 4

# DNS Zone options
Add-LabelBold "DNS Zone Options" $y 300 | Out-Null
$y += 24

$chkDnsRecordCounts = Add-Check "-DnsIncludeRecordCounts" $y $false 250 $leftLabel
$lblDnsRCDesc = Add-Label "Include record counts in DNS zone report" ($y + 1) 500 ($leftLabel + 256)
$lblDnsRCDesc.ForeColor = [System.Drawing.Color]::DimGray
$y += $rowHeight

$chkDnsSystemZones = Add-Check "-DnsIncludeSystemZones" $y $false 250 $leftLabel
$lblDnsSZDesc = Add-Label "Include system DNS zones in the report" ($y + 1) 500 ($leftLabel + 256)
$lblDnsSZDesc.ForeColor = [System.Drawing.Color]::DimGray
$y += $rowHeight

Add-Label "DNS Zone Output Root:" $y | Out-Null
$txtDnsOutputRoot = Add-TextBox $y
$y += $rowHeight + 4

# Delegated Permissions options
Add-LabelBold "Delegated Permissions Options" $y 300 | Out-Null
$y += 24

$chkDelegSystem = Add-Check "-DelegIncludeSystemTrustees" $y $false 280 $leftLabel
$lblDelegSysDesc = Add-Label "Include system trustees" ($y + 1) 500 ($leftLabel + 286)
$lblDelegSysDesc.ForeColor = [System.Drawing.Color]::DimGray
$y += $rowHeight

$chkDelegDeny = Add-Check "-DelegIncludeDeny" $y $false 250 $leftLabel
$lblDelegDenyDesc = Add-Label "Include deny permissions" ($y + 1) 500 ($leftLabel + 256)
$lblDelegDenyDesc.ForeColor = [System.Drawing.Color]::DimGray
$y += $rowHeight

$chkDelegInherited = Add-Check "-DelegIncludeInherited" $y $false 250 $leftLabel
$lblDelegInhDesc = Add-Label "Include inherited permissions" ($y + 1) 500 ($leftLabel + 256)
$lblDelegInhDesc.ForeColor = [System.Drawing.Color]::DimGray
$y += $rowHeight

Add-Label "Delegated Server:" $y | Out-Null
$txtDelegServer = Add-TextBox $y
$y += $rowHeight + 4

Add-Label "Delegated Output Root:" $y | Out-Null
$txtDelegOutputRoot = Add-TextBox $y
$y += $rowHeight + 8

# Lateral movement options
Add-LabelBold "Lateral Movement Options" $y 300 | Out-Null
$y += 24

Add-Label "Baseline edges CSV:" $y | Out-Null
$txtLateralBaseline = Add-TextBox $y
$y += $rowHeight
$lblLateralBaselineDesc = Add-Label "lateral_movement_edges.csv from a previous run - new / removed group nestings are reported (LM19)" ($y - 6) $inputWidth $leftInput
$lblLateralBaselineDesc.ForeColor = [System.Drawing.Color]::DimGray
$y += 22

Add-Label "Extra Tier 0 groups:" $y | Out-Null
$txtLateralTier0 = Add-TextBox $y
$y += $rowHeight
$lblLateralTier0Desc = Add-Label "Comma-separated group names/SIDs to treat as Tier 0 (PAM groups, AD-Admins, backup infrastructure ...)" ($y - 6) $inputWidth $leftInput
$lblLateralTier0Desc.ForeColor = [System.Drawing.Color]::DimGray
$y += 22 + 8

Add-Separator $y
$y += 12

# === PASSWORD AUDIT (separate from the audit run) ===
Add-LabelBold "Password Audit (separate scripts - not part of 'Run All')" $y | Out-Null
$y += $rowHeight

$lblPwdHint = Add-Label "Reads NTLM hashes through DSInternals replication (Get-ADReplAccount rights needed). Results: <COMPUTERNAME>\Password Audit\" ($y - 4) $inputWidth $leftInput
$lblPwdHint.ForeColor = [System.Drawing.Color]::Gray
$y += 22

$chkPwdPwned = Add-Check "Invoke-PwnedPasswordCheck.ps1" $y $true 280 $leftLabel
$lblPwdPwnedDesc = Add-Label "Accounts whose NTLM hash appears in Have I Been Pwned (k-anonymity range query, hash never sent)" ($y + 1) 660 ($leftLabel + 286)
$lblPwdPwnedDesc.ForeColor = [System.Drawing.Color]::DimGray
$y += $rowHeight

$chkPwdIncludeComputers = Add-Check "-IncludeComputers" $y $false 250 ($leftLabel + 30)
$lblPwdIncDesc = Add-Label "Also check computer accounts" ($y + 1) 500 ($leftLabel + 286)
$lblPwdIncDesc.ForeColor = [System.Drawing.Color]::DimGray
$y += $rowHeight

$chkPwdSame = Add-Check "Invoke-SamePasswordCheck.ps1" $y $true 280 $leftLabel
$lblPwdSameDesc = Add-Label "Accounts that share the same password (identical NTLM hash), grouped" ($y + 1) 660 ($leftLabel + 286)
$lblPwdSameDesc.ForeColor = [System.Drawing.Color]::DimGray
$y += $rowHeight

$chkPwdUsersOnly = Add-Check "-UsersOnly" $y $false 250 ($leftLabel + 30)
$lblPwdUsersDesc = Add-Label "Skip computer accounts" ($y + 1) 500 ($leftLabel + 286)
$lblPwdUsersDesc.ForeColor = [System.Drawing.Color]::DimGray
$y += $rowHeight

$chkPwdSamePwned = Add-Check "-Pwned" $y $false 250 ($leftLabel + 30)
$lblPwdSamePwnedDesc = Add-Label "Also check each duplicate hash against Have I Been Pwned" ($y + 1) 500 ($leftLabel + 286)
$lblPwdSamePwnedDesc.ForeColor = [System.Drawing.Color]::DimGray
$y += $rowHeight

Add-Label "Domain controller (-Server):" $y | Out-Null
$txtPwdServer = Add-TextBox $y
$y += $rowHeight + 4

$txtPwdPreview = Add-TextBox $y -ReadOnly $true -Multiline $true -Height 48 -Width 930
$txtPwdPreview.Location = New-Object System.Drawing.Point(16, ($y - 3))
$txtPwdPreview.Size = New-Object System.Drawing.Size(940, 48)
$txtPwdPreview.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtPwdPreview.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
$y += 56

$btnRunPwd = Add-Button "Run Password Audit" $y 220 32 $leftLabel
$y += 44

Add-Separator $y
$y += 12

# === COMMAND PREVIEW ===
Add-LabelBold "Command Preview" $y | Out-Null
$y += $rowHeight

$txtPreview = Add-TextBox $y -ReadOnly $true -Multiline $true -Height 66 -Width 930
$txtPreview.Location = New-Object System.Drawing.Point(16, ($y - 3))
$txtPreview.Size = New-Object System.Drawing.Size(940, 66)
$txtPreview.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtPreview.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
$y += 76

# === RUN BUTTON ===
$btnRun = Add-Button "Run Audit" $y 220 42 $leftLabel
$btnRun.Font = New-Object System.Drawing.Font($btnRun.Font.FontFamily, 11, [System.Drawing.FontStyle]::Bold)
$btnRun.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$btnRun.ForeColor = [System.Drawing.Color]::White
$btnRun.FlatStyle = 'Flat'
$btnRun.FlatAppearance.BorderSize = 0

$btnCancel = Add-Button "Close" $y 100 42 ($leftLabel + 230)
$y += 60

# Set scroll area
$panel.AutoScrollMinSize = New-Object System.Drawing.Size(0, ($y + 20))

# -------------------------
# Update command preview
# -------------------------
function Update-Preview {
    # Embed runtime values in SINGLE quotes (with embedded quotes doubled): the
    # command runs verbatim in a child pwsh, where double quotes would re-expand
    # $, backticks and embedded quotes inside paths (e.g. 'D:\AD$Reports').
    $cmd = "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & '" + ($script:AuditScriptPath -replace "'", "''") + "'"

    if ($script:chkAll.Checked) {
        $cmd += " -all"

        # Collect excludes
        $excludes = @()
        foreach ($key in $script:excludeCheckboxes.Keys) {
            if ($script:excludeCheckboxes[$key].Checked) {
                $excludes += $key
            }
        }
        if ($excludes.Count -gt 0) {
            $cmd += " -exclude " + ($excludes -join ',')
        }
    } else {
        # Collect selected individual checks
        foreach ($key in $script:checkboxes.Keys) {
            if ($script:checkboxes[$key].Checked) {
                $cmd += " -$key"
            }
        }
    }

    # Advanced options
    if ($script:chkKeepLegacy.Checked)       { $cmd += " -KeepLegacyArtifacts" }
    if ($script:chkDnsRecordCounts.Checked)  { $cmd += " -DnsIncludeRecordCounts" }
    if ($script:chkDnsSystemZones.Checked)   { $cmd += " -DnsIncludeSystemZones" }
    if ($script:txtDnsOutputRoot.Text.Trim().Trim('"')) { $cmd += " -DnsZoneOutputRoot '" + ($script:txtDnsOutputRoot.Text.Trim().Trim('"') -replace "'", "''") + "'" }
    if ($script:chkDelegSystem.Checked)      { $cmd += " -DelegIncludeSystemTrustees" }
    if ($script:chkDelegDeny.Checked)        { $cmd += " -DelegIncludeDeny" }
    if ($script:chkDelegInherited.Checked)   { $cmd += " -DelegIncludeInherited" }
    if ($script:txtDelegServer.Text.Trim().Trim('"'))  { $cmd += " -DelegServer '" + ($script:txtDelegServer.Text.Trim().Trim('"') -replace "'", "''") + "'" }
    if ($script:txtDelegOutputRoot.Text.Trim().Trim('"')) { $cmd += " -DelegatedOutputRoot '" + ($script:txtDelegOutputRoot.Text.Trim().Trim('"') -replace "'", "''") + "'" }
    if ($script:txtLateralBaseline.Text.Trim().Trim('"')) { $cmd += " -LateralBaselinePath '" + ($script:txtLateralBaseline.Text.Trim().Trim('"') -replace "'", "''") + "'" }
    $lateralTier0 = @($script:txtLateralTier0.Text -split '[,;]' | ForEach-Object { $_.Trim().Trim('"').Trim("'") } | Where-Object { $_ })
    if ($lateralTier0.Count -gt 0) { $cmd += " -LateralTier0Groups " + (($lateralTier0 | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ',') }

    $script:txtPreview.Text = $cmd
}

function Update-PasswordPreview {
    # Same quoting rules as Update-Preview: the command runs verbatim in a child pwsh.
    $parts = @()
    $server = $script:txtPwdServer.Text.Trim().Trim('"')
    $serverArg = if ($server) { " -Server '" + ($server -replace "'", "''") + "'" } else { '' }
    $outDir = $script:PasswordAuditOutDir
    if ($script:chkPwdPwned.Checked) {
        $p = "& '" + ($script:PwnedScriptPath -replace "'", "''") + "' -OutCsv '" + ((Join-Path $outDir 'PWNED_PASSWORD_HASH.csv') -replace "'", "''") + "'" + $serverArg
        if ($script:chkPwdIncludeComputers.Checked) { $p += " -IncludeComputers" }
        $parts += $p
    }
    if ($script:chkPwdSame.Checked) {
        $p = "& '" + ($script:SameScriptPath -replace "'", "''") + "' -OutCsv '" + ((Join-Path $outDir 'DUPLICATE_PASSWORDS.csv') -replace "'", "''") + "'" + $serverArg
        if ($script:chkPwdUsersOnly.Checked) { $p += " -UsersOnly" }
        if ($script:chkPwdSamePwned.Checked) { $p += " -Pwned" }
        $parts += $p
    }
    if ($parts.Count -eq 0) { $script:txtPwdPreview.Text = ''; return }
    $script:txtPwdPreview.Text = "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; " + ($parts -join '; ')
}

# -------------------------
# Event handlers
# -------------------------

# Run All toggle - enable/disable individual checks and exclude section
$chkAll.Add_CheckedChanged({
    $allChecked = $this.Checked

    # Toggle individual checkboxes
    foreach ($key in $script:checkboxes.Keys) {
        $script:checkboxes[$key].Enabled = -not $allChecked
        if ($allChecked) {
            $script:checkboxes[$key].Checked = $false
        }
    }

    # Toggle exclude section visibility — hide/show the whole block together so the
    # exclude checkboxes and their description labels do not linger without a heading.
    foreach ($key in $script:excludeCheckboxes.Keys) {
        $script:excludeCheckboxes[$key].Enabled = $allChecked
        $script:excludeCheckboxes[$key].Visible = $allChecked
        if (-not $allChecked) {
            $script:excludeCheckboxes[$key].Checked = $false
        }
    }
    foreach ($lbl in $script:excludeDescLabels) {
        $lbl.Visible = $allChecked
    }
    $script:lblExclude.Visible   = $allChecked
    $script:lblExcludeHint.Visible = $allChecked

    Update-Preview
})

# Wire up individual check changes to update preview
foreach ($key in $checkboxes.Keys) {
    $checkboxes[$key].Add_CheckedChanged({ Update-Preview })
}
foreach ($key in $excludeCheckboxes.Keys) {
    $excludeCheckboxes[$key].Add_CheckedChanged({ Update-Preview })
}
$chkKeepLegacy.Add_CheckedChanged({ Update-Preview })
$chkDnsRecordCounts.Add_CheckedChanged({ Update-Preview })
$chkDnsSystemZones.Add_CheckedChanged({ Update-Preview })
$chkDelegSystem.Add_CheckedChanged({ Update-Preview })
$chkDelegDeny.Add_CheckedChanged({ Update-Preview })
$chkDelegInherited.Add_CheckedChanged({ Update-Preview })
$txtDnsOutputRoot.Add_TextChanged({ Update-Preview })
$txtDelegServer.Add_TextChanged({ Update-Preview })
$txtDelegOutputRoot.Add_TextChanged({ Update-Preview })
$txtLateralBaseline.Add_TextChanged({ Update-Preview })
$txtLateralTier0.Add_TextChanged({ Update-Preview })
foreach ($c in @($chkPwdPwned, $chkPwdIncludeComputers, $chkPwdSame, $chkPwdUsersOnly, $chkPwdSamePwned)) { $c.Add_CheckedChanged({ Update-PasswordPreview }) }
$txtPwdServer.Add_TextChanged({ Update-PasswordPreview })

# Run Password Audit button - launches the selected Password Audit scripts in a new elevated
# PowerShell 7 window. Kept apart from the audit run on purpose: it needs replication rights
# and talks to api.pwnedpasswords.com, so it is never part of -all.
$btnRunPwd.Add_Click({
    $cmd = $script:txtPwdPreview.Text
    if ([string]::IsNullOrWhiteSpace($cmd)) {
        Msg-Error "Select at least one Password Audit script."
        return
    }
    foreach ($p in @($script:PwnedScriptPath, $script:SameScriptPath)) {
        if (-not (Test-Path -LiteralPath $p)) { Msg-Error "Password Audit script not found: $p`nCopy the whole ADAudit folder including 'Password Audit\'."; return }
    }
    try {
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
        Start-Process pwsh.exe -ArgumentList '-NoExit','-EncodedCommand',$encoded -Verb RunAs
        Msg-Info "Password Audit launched in a new PowerShell 7 window.`nResults are written to:`n$($script:PasswordAuditOutDir)"
    } catch {
        Msg-Error "Failed to launch the Password Audit: $($_.Exception.Message)"
    }
})

# Install Online button
$btnOnline.Add_Click({
    $cmd = "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & '" + ($script:AuditScriptPath -replace "'", "''") + "' -installdeps"
    try {
        # Launch via EncodedCommand so paths containing spaces/quotes cannot be
        # corrupted by Start-Process argument joining or child-pwsh quote stripping.
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
        Start-Process pwsh.exe -ArgumentList '-NoExit','-EncodedCommand',$encoded -Verb RunAs
        Msg-Info "Online dependency installation launched in a new PowerShell 7 window."
    } catch {
        Msg-Error "Failed to launch online install: $($_.Exception.Message)"
    }
})

# Install Offline button
$btnOffline.Add_Click({
    if (-not (Test-IsAdmin)) {
        Msg-Error "Offline install must run elevated. Restart the GUI as Administrator to use offline installation."
        return
    }
    try {
        $result = Invoke-OfflineInstall -SearchRoot $script:ScriptDir
        Msg-Info "Offline installation completed successfully.`n`n$result"
    } catch {
        if ($_.Exception.Message -eq 'MISSING_NUPKG') {
            $msg = @"
Offline installation failed: Required .nupkg files not found.

Download NuGet and DSInternals modules from PowerShell Gallery before using this offline installer and place them in the same folder as this script.

NuGet:
https://www.powershellgallery.com/packages/NuGet/

DSInternals:
https://www.powershellgallery.com/packages/DSInternals/

Choose 'Manual Download' on each page. You will get two .nupkg files. Place them in:
$($script:ScriptDir)
"@
            Msg-Error $msg
        } else {
            Msg-Error "Offline installation failed: $($_.Exception.Message)"
        }
    }
})

# Run Audit button
$btnRun.Add_Click({
    $cmd = $script:txtPreview.Text
    if ([string]::IsNullOrWhiteSpace($cmd)) {
        Msg-Error "No audit checks selected. Please select at least one check or enable 'Run All Checks'."
        return
    }

    # Validate that at least one check is selected when not using -all
    if (-not $script:chkAll.Checked) {
        $anySelected = $false
        foreach ($key in $script:checkboxes.Keys) {
            if ($script:checkboxes[$key].Checked) { $anySelected = $true; break }
        }
        if (-not $anySelected) {
            Msg-Error "No audit checks selected. Please select at least one check or enable 'Run All Checks'."
            return
        }
    }

    try {
        # Launch via EncodedCommand so paths containing spaces/quotes cannot be
        # corrupted by Start-Process argument joining or child-pwsh quote stripping.
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
        Start-Process pwsh.exe -ArgumentList '-NoExit','-EncodedCommand',$encoded -Verb RunAs
        # Close the GUI and its PowerShell window after launching the audit
        $script:form.Close()
    } catch {
        Msg-Error "Failed to launch audit: $($_.Exception.Message)"
    }
})

# Close button
$btnCancel.Add_Click({
    $script:form.Close()
})

# Initial state
Update-Preview
Update-PasswordPreview

# Trigger initial state for exclude section visibility
foreach ($key in $excludeCheckboxes.Keys) {
    $excludeCheckboxes[$key].Enabled = $true  # enabled since Run All is checked by default
}

# -------------------------
# Show the form
# -------------------------
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()

# Exit the PowerShell host window when the GUI closes
exit
