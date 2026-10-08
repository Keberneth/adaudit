<#
    .SYNOPSIS
        ADAudit check: Check For Existence DNS Zones allowing insecure updates

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -insecurednszone). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-InsecureDnsZonesCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select insecurednszone [options]

    .NOTES
        Entry point: Invoke-InsecureDnsZonesCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory, DnsServer.
#>
Function Get-DNSZoneInsecure {
    # Check DNS zones allowing insecure updates on all DNS servers in the domain

    try {
        Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null
        Import-ADAuditModule -Name DnsServer -Required | Out-Null
    }
    catch {
        Register-ADAuditNotAssessed -Name 'Get-DNSZoneInsecure' -Switch 'insecurednszone' -Reason "Required modules (ActiveDirectory/DnsServer RSAT) could not be loaded: $($_.Exception.Message)"
        return
    }

    # Get all domain controllers; we'll probe each one to see if DNS is installed
    try {
        $dcList = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    }
    catch {
        Register-ADAuditNotAssessed -Name 'Get-DNSZoneInsecure' -Switch 'insecurednszone' -Reason "Failed to enumerate domain controllers from AD: $($_.Exception.Message)"
        return
    }

    if (-not $dcList -or $dcList.Count -eq 0) {
        Register-ADAuditNotAssessed -Name 'Get-DNSZoneInsecure' -Switch 'insecurednszone' -Reason "No domain controllers found to probe for insecure DNS zones."
        return
    }

    $globalInsecureZonesFile = Get-EvidencePath 'insecure_dns_zones.txt'
    if (Test-Path $globalInsecureZonesFile) {
        Remove-Item $globalInsecureZonesFile -Force
    }

    $totalcount = 0
    $assessed = 0

    foreach ($dnsServer in $dcList) {

        Write-Both "    [*] Checking potential DNS server: $dnsServer"

        # Optional: check remote OS version to skip 2008 if needed
        $skipServer = $false
        try {
            $os = Get-ADAuditCimInstance -ClassName Win32_OperatingSystem -ComputerName $dnsServer -UseWsmanFallback
            $osCaption = $os.Caption
            if ($osCaption -like "Windows Server 2008*") {
                Write-Both "        [-] $dnsServer is Windows Server 2008, skipping Get-DNSZoneInsecure check on this server."
                $skipServer = $true
            }
        }
        catch {
            Write-Both "        [!] Could not determine OS version for $dnsServer, continuing anyway. $_"
        }

        if ($skipServer) { continue }

        # Try to query DNS zones; if DNS role is not installed, this will fail and we skip
        try {
            $insecurezones = Get-DnsServerZone -ComputerName $dnsServer -ErrorAction Stop |
                             Where-Object { $_.DynamicUpdate -like '*nonsecure*' }
        }
        catch {
            Write-Both "        [-] $dnsServer does not appear to have the DNS role (or access failed), skipping. $_"
            continue
        }
        $assessed++

        if ($insecurezones) {
            foreach ($insecurezone in $insecurezones) {
                Add-Content -Path $globalInsecureZonesFile -Value (
"The DNS Zone {0} on DNS server {1} allows insecure updates ({2})" -f `
                    $insecurezone.ZoneName, $dnsServer, $insecurezone.DynamicUpdate
                )
                $totalcount++
            }
        }
        else {
            Write-Both "        [-] No insecure DNS zones found on $dnsServer."
        }
    }

    if ($totalcount -gt 0) {
        Write-Both "    [!] There were $totalcount DNS zones configured to allow insecure updates (KB842) across all DNS servers."
        Write-Nessus-Finding "InsecureDNSZone" "KB842" ([System.IO.File]::ReadAllText($globalInsecureZonesFile))
    }
    elseif ($assessed -eq 0) {
        Register-ADAuditNotAssessed -Name 'Get-DNSZoneInsecure' -Switch 'insecurednszone' -RequiresRemotePS -Reason "No DNS server could be queried (DnsServer RPC/WinRM to the DCs unavailable from this host); insecure-zone posture is unknown, not 'clean'."
    }
    else {
        Write-Both "    [-] No insecure DNS zones found on any of the $assessed discovered DNS server(s)."
    }
}

function Invoke-InsecureDnsZonesCheck {
    Get-DNSZoneInsecure
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select insecurednszone @args
}