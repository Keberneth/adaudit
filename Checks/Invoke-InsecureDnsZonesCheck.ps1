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
        $dcList = @(Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName)
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
    $coverage = [System.Collections.Generic.List[object]]::new()
    $zoneRows = [System.Collections.Generic.List[object]]::new()

    foreach ($dnsServer in $dcList) {
        if ($script:ADAuditIsolatedClone -and -not (Test-ADAuditLocalComputer -ComputerName $dnsServer)) {
            $reason = 'Remote DNS server collection is outside isolated-clone scope.'
            Register-ADAuditNotAssessed -Name 'DNS zone security' -Switch 'insecurednszone' -Target $dnsServer -Reason $reason
            $coverage.Add([pscustomobject]@{Target=$dnsServer; Status='NotAssessed'; Detail=$reason})
            continue
        }
        Write-ADAuditProgress -Activity 'DNS zone security' -Status "Reading $dnsServer"
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

        if ($skipServer) {
            Register-ADAuditNotAssessed -Name 'DNS zone security' -Switch 'insecurednszone' -Target $dnsServer -Reason 'Legacy server skipped; dynamic update security was not assessed.'
            $coverage.Add([pscustomobject]@{Target=$dnsServer; Status='NotAssessed'; Detail='Unsupported legacy server'})
            continue
        }

        # Try to query DNS zones; if DNS role is not installed, this will fail and we skip
        try {
            $zones = @(Get-ADAuditDnsServerZones -ComputerName $dnsServer)
            $insecurezones = @($zones | Where-Object { $_.DynamicUpdate -like '*nonsecure*' })
            foreach ($zone in $zones) {
                $zoneRows.Add([pscustomobject]@{Target=$dnsServer; Zone=$zone.ZoneName; DynamicUpdate=$zone.DynamicUpdate; Status=$(if ($zone.DynamicUpdate -like '*nonsecure*') {'Finding'} else {'NoInsecureUpdatesDetected'})})
            }
        }
        catch {
            Write-Both "        [-] $dnsServer does not appear to have the DNS role (or access failed), skipping. $_"
            Register-ADAuditNotAssessed -Name 'DNS zone security' -Switch 'insecurednszone' -Target $dnsServer -Reason "DNS role absent or access failed; cannot distinguish from this query: $($_.Exception.Message)"
            $coverage.Add([pscustomobject]@{Target=$dnsServer; Status='NotAssessed'; Detail=$_.Exception.Message})
            continue
        }
        $assessed++
        $coverage.Add([pscustomobject]@{Target=$dnsServer; Status='Assessed'; Detail="$($zones.Count) zone instance(s) enumerated"})

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
        Write-Both "    [!] $totalcount DNS zone instance(s) allow insecure updates (KB842); replicated copies may refer to the same zone."
        Write-Nessus-Finding "InsecureDNSZone" "KB842" ([System.IO.File]::ReadAllText($globalInsecureZonesFile))
    }
    elseif ($assessed -eq 0) {
        Register-ADAuditNotAssessed -Name 'Get-DNSZoneInsecure' -Switch 'insecurednszone' -RequiresRemotePS -Reason "No DNS server could be queried (DnsServer RPC/WinRM to the DCs unavailable from this host); insecure-zone posture is unknown, not 'clean'."
    }
    else {
        Write-Both "    [-] No insecure DNS zones found on any of the $assessed discovered DNS server(s)."
    }
    $coverage | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Get-EvidencePath 'dns_security_coverage.csv')
    $zoneRows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Get-EvidencePath 'dns_zone_security.csv')
    Write-Both "    [*] DNS coverage: $assessed/$($dcList.Count) DC-hosted DNS candidates assessed. Non-DC DNS servers were not discovered by this check."
}

function Get-ADAuditDnsServerZones {
    # Bounded zone enumeration. The DnsServer cmdlets use WSMan/CIM and cannot be
    # cancelled reliably inside a runspace; remote servers are read in a child process
    # that is killed when the deadline expires. Local zones are read in-process.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName)
    Assert-ADAuditRemoteTargetAllowed -ComputerName $ComputerName
    $query = {
        param($Server, $Local)
        if (-not (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) { Import-Module DnsServer -ErrorAction Stop }
        $zones = if ($Local) { Get-DnsServerZone -ErrorAction Stop } else { Get-DnsServerZone -ComputerName $Server -ErrorAction Stop }
        ,@($zones | Select-Object ZoneName, ZoneType, DynamicUpdate, IsDsIntegrated, IsReverseLookupZone, IsAutoCreated)
    }
    if (Test-ADAuditLocalComputer $ComputerName) { $zones = & $query $ComputerName $true; return @($zones) }
    $result = Invoke-ADAuditBoundedOperation -Target $ComputerName -Operation 'DNS zone enumeration' -Transport 'Wsman' -Isolation Process -Activity 'DNS zone security' -ScriptBlock $query -ArgumentList @($ComputerName, $false)
    $zones = Receive-ADAuditOperationResult -Result $result
    @($zones)
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
