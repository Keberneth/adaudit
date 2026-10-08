<#
    .SYNOPSIS
        ADAudit check: Check for ADCS Vulnerabilities

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -adcs). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-AdcsCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select adcs [options]

    .NOTES
        Entry point: Invoke-AdcsCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
Function Get-ADCSVulns {
    #Check for ADCS Vulnerabiltiies, ESC1,2,3,4 and 8. ESC8 will output to a different issues mapped to Nessus. 
    $certutil_output = certutil -v -template 2>&1
    $certutilExit = $LASTEXITCODE
    $certutil_text = ($certutil_output | Out-String)
    # If certutil could not produce template data (no reachable Enterprise CA / AD CS
    # config from this host), do NOT silently report "no ESC vulnerabilities" - that is
    # a false all-clear. Record it as could-not-assess and stop.
    if ($certutilExit -ne 0 -or [string]::IsNullOrWhiteSpace($certutil_text) -or $certutil_text -notmatch 'Template\[') {
        Register-ADAuditNotAssessed -Name 'Get-ADCSVulns' -Switch 'adcs' -RequiresRemotePS -Reason "certutil -v -template returned no usable certificate-template data (exit code $certutilExit). AD CS / Enterprise CA configuration could not be read from this host, so ESC1-4 were NOT assessed (this is not 'no ADCS template vulnerabilities')."
        return
    }
    $certutil_lines = $certutil_text.Trim().Split("`n")
    $templates = @()
    $current_template = ""

    function ConvertFrom-CertutilTemplateBlock {
        param([string]$Block)
        if (-not $Block) { return $null }
        $template_unparsed = $Block.TrimEnd(",").Split(",")
        $SuppliesSubjectCheck = $false
        $ClientAuthCheck = $false
        $AllowEnrollCheck = $false
        $AnyPurposeCheck = $false
        $AllowWriteCheck = $false
        $AllowFullControl = $false
        $CertificateRequestAgentCheck = $false
        $TemplatePropCommonName = $null

        foreach ($detail in $template_unparsed) {
            if ($detail -like "*TemplatePropCommonName =*") { $TemplatePropCommonName = $detail.Split("=")[1].Trim() }
            if ($detail -like "*CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 1*") { $SuppliesSubjectCheck = $true }
            if ($detail -like "*Client Authentication*") { $ClientAuthCheck = $true }
            if ($detail -match "^\s*Allow Enroll\s+.*\\Authenticated Users\s*$|^\s*Allow Enroll\s+.*\\Domain Users\s*$") { $AllowEnrollCheck = $true }
            if ($detail -like "*2.5.29.37.0 Any Purpose*") { $AnyPurposeCheck = $true }
            if ($detail -match "^\s*Allow Write\s+.*\\Authenticated Users\s*$|^\s*Allow Write\s+.*\\Domain Users\s*$") { $AllowWriteCheck = $true }
            if ($detail -match "^\s*Allow Full Control\s+.*\\Authenticated Users\s*$|^\s*Allow Full Control\s+.*\\Domain Users\s*$") { $AllowFullControl = $true }
            if ($detail -like "*Certificate Request Agent (1.3.6.1.4.1.311.20.2.1)*") { $CertificateRequestAgentCheck = $true }
        }

        return [pscustomobject]@{
            SuppliesSubjectCheck         = $SuppliesSubjectCheck
            ClientAuthCheck              = $ClientAuthCheck
            AllowEnrollCheck             = $AllowEnrollCheck
            AnyPurposeCheck              = $AnyPurposeCheck
            AllowWriteCheck              = $AllowWriteCheck
            AllowFullControl             = $AllowFullControl
            TemplatePropCommonName       = $TemplatePropCommonName
            CertificateRequestAgentCheck = $CertificateRequestAgentCheck
        }
    }

    foreach ($line in $certutil_lines) {
        if ($line.StartsWith("Template[")) {
            if ($current_template) {
                $templates += ConvertFrom-CertutilTemplateBlock $current_template
            }
            $current_template = $line + ","
        } else {
            $current_template += $line + ","
        }
    }
    # Flush the final template. The loop only parses a template when it reaches the
    # NEXT 'Template[' header, so without this trailing flush the last template in the
    # certutil output was silently dropped (false negative for ESC1/2/3/4).
    if ($current_template) {
        $templates += ConvertFrom-CertutilTemplateBlock $current_template
    }

    # Check for ESC1
    # ESC1 = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1 and  Client Authentication and ( enroll or full control )

    $ESC1 = @()
    $ESC1e = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowEnrollCheck }
    $ESC1f = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowFullControl }
    $ESC1w = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowWriteCheck }
    $ESC1 += $ESC1e
    $ESC1 += $ESC1f
    $ESC1 += $ESC1w
    # Remove duplicates
    $ESC1 = $ESC1 | Select-Object -Property TemplatePropCommonName -unique
    $ESC2 = $templates | Where-Object { $_.AnyPurposeCheck -and $_.AllowEnrollCheck }
    $ESC3 = $templates | Where-Object { $_.CertificateRequestAgentCheck -and $_.AllowEnrollCheck }
    $ESC4 = $templates | Where-Object { $_.AllowWriteCheck -or $_.AllowFullControl }

    $template_path = Get-EvidencePath 'vulnerable_templates.txt'
    $web_enrollment_path = Get-EvidencePath 'web_enrollment.txt'

    foreach ($template in $ESC1) {
        $ESC1line = "ESC1 Vulnerable Templates:" + $template.TemplatePropCommonName
        Add-Content -Path $template_path -Value $ESC1line
        Write-Both "    [!] $ESC1line"
    }
    foreach ($template in $ESC2) {
        $ESC2line = "ESC2 Vulnerable Templates:" + $template.TemplatePropCommonName
        Add-Content -Path $template_path -Value $ESC2line
        Write-Both "    [!] $ESC2line"
    }
    foreach ($template in $ESC3) {
        $ESC3line = "ESC3 Vulnerable Templates:" + $template.TemplatePropCommonName
        Add-Content -Path $template_path -Value $ESC3line
        Write-Both "    [!] $ESC3line"
    }
    foreach ($template in $ESC4) {
        $ESC4line = "ESC4 Vulnerable Templates:" + $template.TemplatePropCommonName
        Add-Content -Path $template_path -Value $ESC4line
        Write-Both "    [!] $ESC4line"
    }
    # ESC8 Check, If error 401 and response is unauthorized, then vulnerable
    try {
        $certInfo = & certutil
        $serverName = ($certInfo | Select-String 'Server:' | Select-Object -First 1).ToString().Split(':')[1].Trim().Replace('"', '')
        $response = Invoke-WebRequest -Uri ("http://$serverName/certsrv/") -ErrorAction Stop
        $response
    }
    catch {
        # If error and response is unauthorised, then vulnerable
        if ($_.Exception.Response.StatusCode -eq 401) {
            Add-Content -Path $web_enrollment_path -Value "ESC8 Vulnerable: Endpoint located at http://$serverName/certsrv/"
            Write-Both "    [!] ESC8 Vulnerable: Endpoint located at http://$serverName/certsrv/"
        }
        else {
            Write-Both "    [+] ESC8 not vulnerable"
        }
    }
    if (Test-Path (Get-EvidencePath 'web_enrollment.txt')) {
        Write-Nessus-Finding "Active Directory Certificate Service Web Enrollment Enabled in HTTP" "KB1095" ([System.IO.File]::ReadAllText((Get-EvidencePath 'web_enrollment.txt')))
    }
    if (Test-Path (Get-EvidencePath 'vulnerable_templates.txt')) {
        Write-Nessus-Finding "Active Directory Certificate Service Vulnerable Templates" "KB1096" ([System.IO.File]::ReadAllText((Get-EvidencePath 'vulnerable_templates.txt')))
    }
}

function Invoke-AdcsCheck {
    Get-ADCSVulns
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select adcs @args
}