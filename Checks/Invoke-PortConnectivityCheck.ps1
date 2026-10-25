<#
    .SYNOPSIS
        ADAudit check: Domain Controller TCP endpoint connectivity

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -portconnectivity). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-PortConnectivityCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select portconnectivity [options]

    .NOTES
        Entry point: Invoke-PortConnectivityCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
function Test-ADAuditPortEndpoint {
    param([string]$Target, [int]$Port, [int]$TimeoutMs = 1500)
    Assert-ADAuditRemoteTargetAllowed -ComputerName $Target
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $tcp.BeginConnect($Target, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return [pscustomobject]@{Open=$false; Error='timeout'} }
        $tcp.EndConnect($async)
        [pscustomobject]@{Open=$true; Error=$null}
    } catch {
        [pscustomobject]@{Open=$false; Error=$_.Exception.Message}
    } finally { $tcp.Close() }
}

function Test-ADAuditPortTargetResolution {
    param([string]$Target)
    if (Test-ADAuditLocalComputer $Target) { return $true }
    Assert-ADAuditRemoteTargetAllowed -ComputerName $Target
    try { $null = [System.Net.Dns]::GetHostAddresses($Target); return $true } catch { return $false }
}

Function Test-DCPortConnectivity {
    <#
        Tests TCP connectivity from the running host (and, if WinRM is
        available, from each DC) to every DC on the standard set of ports an
        AD environment uses. A blocked endpoint is evidence for that source
        and target only. Role-specific and optional endpoints are inventory;
        reachability does not establish authentication or transport security.

        Output:
            dc_port_connectivity.txt  - human readable findings with WHY/FIX
            dc_port_connectivity.csv  - machine readable per-(source,target,port) rows
        Plus a Nessus finding (KB1310) for required endpoint failures and
        coverage records when cross-DC collection cannot run.

        WinRM dependency: cross-DC tests REQUIRE WinRM 5985/5986 to be open
        from this host to each DC. If WinRM is unavailable we still run the
        local-host -> DC tests and clearly note that the cross-DC matrix was
        skipped (and why) in the output, rather than failing.
    #>
    [CmdletBinding()]
    param()

    $evidencePath = Get-EvidencePath 'dc_port_connectivity.txt'
    $csvPath      = Get-EvidencePath 'dc_port_connectivity.csv'
    Remove-Item -LiteralPath $evidencePath,$csvPath -Force -ErrorAction SilentlyContinue

    # Required port catalog. Each entry has a friendly name, a security
    # criticality (Critical / High / Medium / Low), and a short rationale.
    # The criticality drives both the severity in the report and how a
    # closed port is presented to the operator (some ports are advisory,
    # most are operationally required).
    $portCatalog = @(
        [pscustomobject]@{ Port=53;    Proto='tcp'; Name='DNS';                          Severity='Information'; Why='DNS is a separate role and need not be installed on every DC. Validate the configured DNS servers separately.'; Required=$false }
        [pscustomobject]@{ Port=88;    Proto='tcp'; Name='Kerberos';                     Severity='Critical'; Why='Kerberos AS/TGS exchanges. If blocked, no Kerberos auth happens.'; Required=$true }
        [pscustomobject]@{ Port=135;   Proto='tcp'; Name='RPC endpoint mapper';          Severity='Critical'; Why='Endpoint mapper for AD replication, Netlogon, RPC over TCP. Without it most AD operations fail.'; Required=$true }
        [pscustomobject]@{ Port=389;   Proto='tcp'; Name='LDAP / STARTTLS';              Severity='Medium';   Why='Directory protocol endpoint. Port 389 supports STARTTLS and SASL sealing; TCP reachability does not establish signing or confidentiality.'; Required=$true }
        [pscustomobject]@{ Port=445;   Proto='tcp'; Name='SMB';                          Severity='Critical'; Why='SYSVOL/NETLOGON shares, GPO download. Without it clients cannot apply Group Policy.'; Required=$true }
        [pscustomobject]@{ Port=464;   Proto='tcp'; Name='Kerberos password change';     Severity='High';     Why='kpasswd. Required for password changes through Kerberos (Set-ADAccountPassword, ALTER DOMAIN PASSWORD, etc).'; Required=$true }
        [pscustomobject]@{ Port=636;   Proto='tcp'; Name='LDAPS (LDAP over TLS)';        Severity='Information'; Why='TLS endpoint, required only for clients configured to use LDAPS. A closed listener does not imply plaintext on port 389.'; Required=$false }
        [pscustomobject]@{ Port=3268;  Proto='tcp'; Name='Global Catalog (LDAP)';        Severity='Critical'; Why='GC queries used by Exchange, multi-domain forest auth. Closed GC breaks login in multi-domain forests.'; Required=$true }
        [pscustomobject]@{ Port=3269;  Proto='tcp'; Name='Global Catalog (LDAPS)';       Severity='Information'; Why='TLS Global Catalog endpoint; applicability depends on the GC role and client requirements.'; Required=$false }
        [pscustomobject]@{ Port=9389;  Proto='tcp'; Name='AD Web Services (ADWS)';       Severity='High';     Why='Used by the ActiveDirectory PowerShell module and Get-AD* cmdlets. Closed ADWS breaks every PowerShell-based admin tool.'; Required=$true }
        [pscustomobject]@{ Port=5985;  Proto='tcp'; Name='WinRM HTTP';                   Severity='Information'; Why='Optional management transport used by this audit. A closed port limits collection and is not an AD security finding.'; Required=$false }
        [pscustomobject]@{ Port=5986;  Proto='tcp'; Name='WinRM HTTPS';                  Severity='Information'; Why='Optional TLS management endpoint. WinRM HTTP can also protect messages with Kerberos; this TCP probe does not assess session security.'; Required=$false }
        [pscustomobject]@{ Port=139;   Proto='tcp'; Name='NetBIOS Session';              Severity='Low';      Why='Legacy NetBIOS. Modern clients use 445; can be closed if no down-level systems remain.'; Required=$false }
    )

    # Discover DCs
    $dcs = @()
    try {
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop |
                 Sort-Object Name |
                  Select-Object Name,HostName,IPv4Address,IsGlobalCatalog)
    } catch {
        Add-Content -Path $evidencePath -Value "ERROR: could not enumerate DCs via Get-ADDomainController: $($_.Exception.Message)"
        Write-Both "    [!] DC port check: could not enumerate DCs: $($_.Exception.Message)"
        Register-ADAuditNotAssessed -Name 'DC port connectivity' -Switch 'portconnectivity' -Reason $_.Exception.Message
        return
    }
    if ($dcs.Count -eq 0) {
        Add-Content -Path $evidencePath -Value 'No domain controllers were returned by Get-ADDomainController.'
        Write-Both '    [!] DC port check: no DCs returned.'
        Register-ADAuditNotAssessed -Name 'DC port connectivity' -Switch 'portconnectivity' -Reason 'No domain controllers returned.'
        return
    }

    if ($script:ADAuditIsolatedClone) {
        foreach ($dc in $dcs) {
            $targetName = if ($dc.HostName) { [string]$dc.HostName } else { [string]$dc.Name }
            if (-not (Test-ADAuditLocalComputer $targetName)) {
                Register-ADAuditNotAssessed -Name 'DC port connectivity' -Switch 'portconnectivity' -Target $targetName -Reason 'Isolated-clone mode: remote DC endpoint probes and cross-DC sources were intentionally excluded.'
            }
        }
        $dcs = @($dcs | Where-Object { Test-ADAuditLocalComputer $(if ($_.HostName) { $_.HostName } else { $_.Name }) })
        if ($dcs.Count -eq 0) {
            Register-ADAuditNotAssessed -Name 'DC port connectivity' -Switch 'portconnectivity' -Reason 'No local DC identity matched in isolated-clone mode; no endpoint probes were run.'
            Set-Content -LiteralPath $evidencePath -Value 'Isolated-clone mode: no local DC matched; current production connectivity is not assessed.'
            return
        }
    }

    # Run local probes from this host to each DC. We DNS-resolve each DC name
    # first; if the name does not resolve we emit ONE "host unresolvable"
    # row instead of 14 noisy "CLOSED (No such host is known)" rows. The user
    # still gets a clear finding ("DC unreachable: name resolution failed")
    # and we skip the per-port probes for that DC. If the name resolves but
    # the host is down (e.g. firewall drops everything) the per-port loop
    # still runs and produces normal closed-port findings.
    Write-Both ("    [+] Probing {0} DC(s) from this host on {1} TCP endpoints..." -f $dcs.Count, $portCatalog.Count)
    $rows           = New-Object System.Collections.Generic.List[object]
    $unresolvedDcs  = New-Object System.Collections.Generic.List[string]
    $probeIndex = 0
    $probeTotal = $dcs.Count * $portCatalog.Count
    foreach ($dc in $dcs) {
        $tgt = if ($dc.HostName) { [string]$dc.HostName } else { [string]$dc.Name }
        Write-ADAuditProgress -Activity 'DC port connectivity' -Status "Resolving $tgt" -PercentComplete ([int](70 * $probeIndex / $probeTotal))
        if (-not (Test-ADAuditPortTargetResolution -Target $tgt)) {
            $probeIndex += $portCatalog.Count
            $unresolvedDcs.Add($tgt) | Out-Null
            $rows.Add([pscustomobject]@{
                Source     = $env:COMPUTERNAME
                Target     = $tgt
                Port       = 0
                Proto      = '-'
                PortName   = 'DC unreachable (DNS resolution failed)'
                Severity   = 'Critical'
                Required   = $true
                Open       = $false
                Error      = "Name '$tgt' did not resolve via DNS from this host."
                Why        = 'Before any port test we resolve the DC FQDN. If resolution fails the DC cannot be queried at all - usually one of: the DNS server cannot be reached from this host, the DC is decommissioned but still listed in AD, or split-DNS is missing the record.'
                ProbeFrom  = 'this host'
            }) | Out-Null
            continue
        }
        foreach ($p in $portCatalog) {
            Write-ADAuditProgress -Activity 'DC port connectivity' -Status "$tgt TCP $($p.Port) ($($p.Name))" -PercentComplete ([int](70 * $probeIndex / $probeTotal))
            $r = Test-ADAuditPortEndpoint -Target $tgt -Port $p.Port
            $probeIndex++
            $rows.Add([pscustomobject]@{
                Source     = $env:COMPUTERNAME
                Target     = $tgt
                Port       = $p.Port
                Proto      = $p.Proto
                PortName   = $p.Name
                Severity   = $p.Severity
                Required   = $p.Required
                Open       = $r.Open
                Error      = $r.Error
                Why        = $p.Why
                ProbeFrom  = 'this host'
            }) | Out-Null
        }
    }
    if ($unresolvedDcs.Count -gt 0) {
        Write-Both ("    [!] {0} DC(s) could not be resolved via DNS - per-port checks skipped: {1}" -f $unresolvedDcs.Count, ($unresolvedDcs -join ', '))
    }

    # Cross-DC tests via WinRM. If WinRM is unavailable, mark cross-DC as
    # skipped and continue (do NOT fail the whole check).
    $crossRows = New-Object System.Collections.Generic.List[object]
    $winrmSkippedReason = $null

    $winrmAvailableDcs = @()
    $localSources = @()
    $winrmSsl = @{}
    foreach ($dc in $dcs) {
        $tgt = if ($dc.HostName) { [string]$dc.HostName } else { [string]$dc.Name }
        if (Test-ADAuditLocalComputer $tgt) {
            # This process already probes from this DC. Reuse those observations
            # instead of requiring WinRM to connect back to the same computer.
            $localSources += $tgt
            foreach ($row in $rows) {
                if (-not (Test-ADAuditLocalComputer $row.Target)) { $row.ProbeFrom = "local DC '$env:COMPUTERNAME' (cross-DC origin)" }
            }
            continue
        }
        $winrmRow = $rows | Where-Object { $_.Target -eq $tgt -and $_.Port -eq 5985 }
        $winrmTlsRow = $rows | Where-Object { $_.Target -eq $tgt -and $_.Port -eq 5986 }
        if ($winrmTlsRow -and $winrmTlsRow.Open) { $winrmAvailableDcs += $tgt; $winrmSsl[$tgt] = $true }
        elseif ($winrmRow -and $winrmRow.Open) { $winrmAvailableDcs += $tgt; $winrmSsl[$tgt] = $false }
        elseif ($dcs.Count -gt 1) { Register-ADAuditNotAssessed -Name 'Cross-DC port connectivity' -Switch 'portconnectivity' -Target $tgt -Reason 'Neither WinRM HTTP nor HTTPS is reachable from the auditing host; no probes were run from this DC.' }
    }

    if ($winrmAvailableDcs.Count -eq 0 -and $localSources.Count -eq 0) {
        $winrmSkippedReason = "WinRM (TCP 5985/5986) is not reachable from this host to any DC, so the cross-DC port matrix was not assessed. Local-host probes are recorded separately."
        Write-Both "    [!] WinRM is not reachable to any DC - skipping cross-DC port matrix. $winrmSkippedReason"
    } elseif ($winrmAvailableDcs.Count -gt 0) {
        Write-Both ("    [+] WinRM reachable to {0} DC(s) - running cross-DC port matrix..." -f $winrmAvailableDcs.Count)
        # Run a probe FROM each WinRM-reachable DC TO every other DC. Drop any
        # DC that did not resolve via DNS from this host - the remote probe
        # would just emit "No such host is known" 14 times for it. The local
        # "DC unreachable" row for that target already surfaces it.
        $allTargets = @($dcs | ForEach-Object { if ($_.HostName) { [string]$_.HostName } else { [string]$_.Name } } | Where-Object { $unresolvedDcs -notcontains $_ })

        foreach ($srcDc in $winrmAvailableDcs) {
            Write-ADAuditProgress -Activity 'DC port connectivity' -Status "Cross-DC source $srcDc" -PercentComplete 75
            try {
                Assert-ADAuditRemoteTargetAllowed -ComputerName $srcDc
                $transport = @{ UseSSL = [bool]$winrmSsl[$srcDc] }
                $remoteResults = Invoke-Command -ComputerName $srcDc @transport -ErrorAction Stop -ArgumentList $allTargets,$portCatalog -ScriptBlock {
                    param($Targets, $Catalog)
                    $local = $env:COMPUTERNAME
                    $out = New-Object System.Collections.Generic.List[object]
                    foreach ($t in $Targets) {
                        if ($t -eq $local -or $t -like "$local.*") { continue } # skip self
                        foreach ($p in $Catalog) {
                            $tcp = New-Object System.Net.Sockets.TcpClient
                            $open = $false; $err = $null
                            try {
                                $async = $tcp.BeginConnect($t, [int]$p.Port, $null, $null)
                                $ok = $async.AsyncWaitHandle.WaitOne(1500, $false)
                                if (-not $ok) { $err = 'timeout' }
                                else {
                                    try { $tcp.EndConnect($async); $open = $true }
                                    catch { $err = $_.Exception.Message }
                                }
                            } catch {
                                $err = $_.Exception.Message
                            } finally {
                                try { $tcp.Close() } catch {}
                            }
                            $out.Add([pscustomobject]@{
                                Source   = $local
                                Target   = $t
                                Port     = $p.Port
                                Proto    = $p.Proto
                                PortName = $p.Name
                                Severity = $p.Severity
                                Required = $p.Required
                                Open     = $open
                                Error    = $err
                                Why      = $p.Why
                                ProbeFrom = "DC '$local' (cross-DC via WinRM)"
                            }) | Out-Null
                        }
                    }
                    ,$out.ToArray()
                }
                if ($remoteResults) { foreach ($rr in $remoteResults) { $crossRows.Add($rr) | Out-Null } }
            } catch {
                Write-Both ("    [!] Cross-DC probe from {0} failed: {1}" -f $srcDc, $_.Exception.Message)
                Register-ADAuditNotAssessed -Name 'Cross-DC port connectivity' -Switch 'portconnectivity' -Target $srcDc -Reason $_.Exception.Message
            }
        }
    }

    $allRows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows)      { $allRows.Add($r) | Out-Null }
    foreach ($r in $crossRows) { $allRows.Add($r) | Out-Null }
    foreach ($row in $allRows) {
        $targetDc = $dcs | Where-Object { $_.HostName -eq $row.Target -or $_.Name -eq $row.Target } | Select-Object -First 1
        if ($row.Port -in 3268,3269 -and -not $targetDc.IsGlobalCatalog) { $row.Required=$false; $row.Severity='Information'; $row.Why='Target is not a Global Catalog; no GC listener is required.' }
        if (-not $row.Required) { $row.Severity='Information' }
        elseif ($row.ProbeFrom -eq 'this host') { $row.Severity='Medium'; $row.Why += ' This is a management-host path observation, not proof of a DC-wide outage.' }
    }

    # Persist machine-readable CSV
    if ($allRows.Count -gt 0) {
        $allRows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    }

    # Build the human-readable evidence file
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(' DOMAIN CONTROLLER PORT CONNECTIVITY')
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(" Generated      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine(" Probed from    : $env:COMPUTERNAME")
    [void]$sb.AppendLine(" DC count       : $($dcs.Count)")
    [void]$sb.AppendLine(" Ports per DC   : $($portCatalog.Count)")
    [void]$sb.AppendLine(" Local DC source: $(if ($localSources.Count) { $localSources -join ', ' } else { 'not running on a DC' })")
    [void]$sb.AppendLine(" Remote sources : $(if ($winrmAvailableDcs.Count -gt 0) { 'via WinRM from ' + ($winrmAvailableDcs -join ', ') } else { 'none collected' })")
    if ($script:ADAuditIsolatedClone) { [void]$sb.AppendLine(' Scope          : isolated clone, local listeners only; production connectivity and peer availability are not assessed.') }
    if ($winrmSkippedReason) { [void]$sb.AppendLine("                  Reason: $winrmSkippedReason") }
    [void]$sb.AppendLine('---------------------------------------------------------------------')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('How to read this file:')
    [void]$sb.AppendLine(' - Each section below groups the closed-port findings by severity.')
    [void]$sb.AppendLine(' - "Closed" means the TCP probe could not establish a connection from')
    [void]$sb.AppendLine('   the named source to the named target on that port within 1.5s.')
    [void]$sb.AppendLine(' - LDAP 389 supports STARTTLS and SASL sealing. TCP probes do not test session protection.')
    [void]$sb.AppendLine(' - Optional listeners are informational. UDP and dynamic RPC endpoint/range access are not assessed.')
    [void]$sb.AppendLine(' - Failed probes describe only the named source/target path; validate requirements before changing firewall rules.')
    [void]$sb.AppendLine('')

    # Closed-port findings, grouped by severity (highest first)
    $closed = @($allRows | Where-Object { -not $_.Open })
    $sevOrder = @{ 'Critical'=0; 'High'=1; 'Medium'=2; 'Low'=3; 'Information'=4 }
    $closedBySeverity = $closed | Group-Object Severity | Sort-Object @{Expression={$sevOrder[$_.Name]}}

    if ($closed.Count -eq 0) {
        [void]$sb.AppendLine('All probed ports were reachable from every probe source. No closed-port findings.')
        [void]$sb.AppendLine('')
    } else {
        foreach ($g in $closedBySeverity) {
            [void]$sb.AppendLine("[$($g.Name)] Closed ports - $($g.Count) finding(s)")
            [void]$sb.AppendLine('---------------------------------------------------------------------')
            $byPort = $g.Group | Group-Object PortName | Sort-Object Name
            foreach ($pg in $byPort) {
                $first = $pg.Group | Select-Object -First 1
                [void]$sb.AppendLine("  Port $($first.Port)/$($first.Proto) - $($first.PortName)")
                [void]$sb.AppendLine("    Why : $($first.Why)")
                $fix = switch -Regex ($first.PortName) {
                    '^LDAPS' { 'Confirm that this source is expected to use LDAPS. If so, inspect the listener and certificate chain/name/expiry with ldp.exe before changing policy or services.'; break }
                    'LDAP \(plaintext\)' { 'LDAP itself must be open (clients still use 389). The risk is unsigned/cleartext binds. Enforce LDAP signing (HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=2) and channel binding (LdapEnforceChannelBinding=2) - both should already be on per the LDAPSecurity check above.' ; break }
                    'WinRM HTTP|WinRM HTTPS' { 'Collection requires an approved WinRM transport from the audit host. Coordinate scoped access or run collection from an approved management host; do not expose management ports broadly.'; break }
                    'AD Web Services' { 'Verify the ADWS service is running on the DC (`Get-Service ADWS`). Open TCP 9389 from any host that uses the ActiveDirectory PowerShell module.' ; break }
                    'RPC endpoint' { 'Open TCP 135 from the source to the target. Most AD operations (replication, secure channel, Netlogon) start by hitting the RPC endpoint mapper here. Without it almost everything below fails.' ; break }
                    'Dynamic RPC' { 'Open the dynamic RPC range (TCP 49152-65535) or pin a static replication port via the RPC dynamic-port restriction registry value. Sampling 49152 alone is heuristic - one closed sample does not prove the entire range is blocked.' ; break }
                    'Kerberos password change' { 'Open TCP/UDP 464 between the DC and any host that does password changes (clients changing passwords, Set-ADAccountPassword from a remote DC).' ; break }
                    'Kerberos\b' { 'Open TCP/UDP 88 between the source and the DC. Kerberos auth fails completely without it.' ; break }
                    'Global Catalog' { 'Confirm the target GC role and client path requirements. Validate GC 3268 or its TLS endpoint before requesting scoped firewall changes.'; break }
                    'DNS\b' { 'Confirm this DC hosts the DNS role and that the named source is expected to query it; otherwise no listener is required.'; break }
                    'SMB\b' { 'Open TCP 445 between the source and the DC. SYSVOL, NETLOGON, GPO download all use SMB.' ; break }
                    'NetBIOS' { 'TCP 139 is legacy. If only modern clients exist this is fine to leave closed; otherwise open it.' ; break }
                    default { 'Open this port from the source to the target on the DC firewall and any path firewall.' }
                }
                [void]$sb.AppendLine("    Fix : $fix")
                foreach ($r in ($pg.Group | Sort-Object Source,Target)) {
                    $errTxt = if ($r.Error) { " ($($r.Error))" } else { '' }
                    [void]$sb.AppendLine("    -> [$($r.ProbeFrom)] $($r.Source) -> $($r.Target):$($r.Port)  CLOSED$errTxt")
                }
                [void]$sb.AppendLine('')
            }
            [void]$sb.AppendLine('')
        }
    }

    # LDAP / LDAPS posture summary - this is the question the user explicitly
    # asked about. Restate it as a dedicated, easy-to-find block.
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(' LDAP / LDAPS POSTURE')
    [void]$sb.AppendLine('=====================================================================')
    foreach ($dc in $dcs) {
        $tgt = if ($dc.HostName) { [string]$dc.HostName } else { [string]$dc.Name }
        $ldap  = $rows | Where-Object { $_.Target -eq $tgt -and $_.Port -eq 389 }
        $ldaps = $rows | Where-Object { $_.Target -eq $tgt -and $_.Port -eq 636 }
        $ldapState  = if ($ldap  -and $ldap.Open)  { 'OPEN' } else { 'CLOSED' }
        $ldapsState = if ($ldaps -and $ldaps.Open) { 'OPEN' } else { 'CLOSED' }
        $verdict =
            if ($ldapsState -eq 'OPEN' -and $ldapState -eq 'OPEN') { 'OK (both available - enforce LDAP signing + channel binding)' }
            elseif ($ldapsState -eq 'OPEN' -and $ldapState -eq 'CLOSED') { 'LDAPS reachable; LDAP 389 unavailable on this source path. Validate client requirements.' }
            elseif ($ldapsState -eq 'CLOSED' -and $ldapState -eq 'OPEN') { 'LDAP 389 reachable; LDAPS unavailable on this source path. STARTTLS/SASL sealing and effective protections require separate assessment.' }
            else { 'Neither LDAP listener was reached from this host; directory access and protection were not established.' }
        [void]$sb.AppendLine(("  {0,-40} 389={1,-6} 636={2,-6}  =>  {3}" -f $tgt, $ldapState, $ldapsState, $verdict))
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Notes:')
    [void]$sb.AppendLine(' - LDAPS reachable but no certificate trusted = LDAPS effectively broken;')
    [void]$sb.AppendLine('   the Get-LDAPSecurity check earlier in this report verifies the cert side.')
    [void]$sb.AppendLine(' - LDAP signing + channel binding requirements live in the registry under')
    [void]$sb.AppendLine('   HKLM\System\CurrentControlSet\Services\NTDS\Parameters (LDAPServerIntegrity,')
    [void]$sb.AppendLine('   LdapEnforceChannelBinding). Both should be set to 2 (Required).')
    [void]$sb.AppendLine('')

    Set-Content -LiteralPath $evidencePath -Value $sb.ToString() -Encoding UTF8

    $closedReq = @($closed | Where-Object { $_.Required })
    if ($closedReq.Count -gt 0) {
        Write-Both ("    [!] {0} required port(s) are closed across the DC fleet - see dc_port_connectivity.txt" -f $closedReq.Count)
    } else {
        Write-Both '    [+] All required DC ports are reachable from this host (and any cross-DC sources tested).'
    }

    try {
        if ($closedReq.Count -gt 0) { Write-Nessus-Finding "DCPortConnectivity" "KB1310" ([System.IO.File]::ReadAllText($evidencePath)) 'Medium' }
    } catch {}
    Write-ADAuditProgress -Activity 'DC port connectivity' -Status 'Connectivity evidence written' -PercentComplete 100 -Completed
}

function Invoke-PortConnectivityCheck {
    Test-DCPortConnectivity
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select portconnectivity @args
}
