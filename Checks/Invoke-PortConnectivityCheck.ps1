<#
    .SYNOPSIS
        ADAudit check: Domain Controller port connectivity check (RPC/LDAP/LDAPS/Kerberos/SMB/ADWS/WinRM/dynamic RPC)

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
Function Test-DCPortConnectivity {
    <#
        Tests TCP connectivity from the running host (and, if WinRM is
        available, from each DC) to every DC on the standard set of ports an
        AD environment needs. Closed ports here directly limit AD
        functionality (replication, authentication, DNS, group policy, AD
        Web Services for the PowerShell module). LDAP/LDAPS are also flagged
        as risk findings because plaintext LDAP enables MITM/relay attacks.

        Output:
            dc_port_connectivity.txt  - human readable findings with WHY/FIX
            dc_port_connectivity.csv  - machine readable per-(source,target,port) rows
        Plus a Nessus finding (KB1310) and a CheckFailures entry for each DC
        that could not be reached at all.

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
        [pscustomobject]@{ Port=53;    Proto='tcp'; Name='DNS';                          Severity='Critical'; Why='DC must serve DNS for SRV/A records used by clients to find DCs.'; Required=$true }
        [pscustomobject]@{ Port=88;    Proto='tcp'; Name='Kerberos';                     Severity='Critical'; Why='Kerberos AS/TGS exchanges. If blocked, no Kerberos auth happens.'; Required=$true }
        [pscustomobject]@{ Port=135;   Proto='tcp'; Name='RPC endpoint mapper';          Severity='Critical'; Why='Endpoint mapper for AD replication, Netlogon, RPC over TCP. Without it most AD operations fail.'; Required=$true }
        [pscustomobject]@{ Port=389;   Proto='tcp'; Name='LDAP (plaintext)';             Severity='Medium';   Why='Plaintext LDAP; required for legacy clients but should NEVER be the only AD lookup path. Channel binding/LDAP signing must be enforced.'; Required=$true }
        [pscustomobject]@{ Port=445;   Proto='tcp'; Name='SMB';                          Severity='Critical'; Why='SYSVOL/NETLOGON shares, GPO download. Without it clients cannot apply Group Policy.'; Required=$true }
        [pscustomobject]@{ Port=464;   Proto='tcp'; Name='Kerberos password change';     Severity='High';     Why='kpasswd. Required for password changes through Kerberos (Set-ADAccountPassword, ALTER DOMAIN PASSWORD, etc).'; Required=$true }
        [pscustomobject]@{ Port=636;   Proto='tcp'; Name='LDAPS (LDAP over TLS)';        Severity='High';     Why='Encrypted LDAP. Required to protect bind credentials and search content. CLOSED = a real risk because plaintext LDAP can be intercepted/relayed.'; Required=$true }
        [pscustomobject]@{ Port=3268;  Proto='tcp'; Name='Global Catalog (LDAP)';        Severity='Critical'; Why='GC queries used by Exchange, multi-domain forest auth. Closed GC breaks login in multi-domain forests.'; Required=$true }
        [pscustomobject]@{ Port=3269;  Proto='tcp'; Name='Global Catalog (LDAPS)';       Severity='High';     Why='Encrypted GC. Same role as 3268 but over TLS. Should be open if 3268 is open.'; Required=$true }
        [pscustomobject]@{ Port=9389;  Proto='tcp'; Name='AD Web Services (ADWS)';       Severity='High';     Why='Used by the ActiveDirectory PowerShell module and Get-AD* cmdlets. Closed ADWS breaks every PowerShell-based admin tool.'; Required=$true }
        [pscustomobject]@{ Port=5985;  Proto='tcp'; Name='WinRM HTTP';                   Severity='Medium';   Why='Remote PowerShell. This audit script and many ops tools depend on it for cross-DC checks. Required for some cross-DC checks in THIS report.'; Required=$true }
        [pscustomobject]@{ Port=5986;  Proto='tcp'; Name='WinRM HTTPS';                  Severity='Low';      Why='Encrypted WinRM. Optional but recommended over 5985.'; Required=$false }
        [pscustomobject]@{ Port=139;   Proto='tcp'; Name='NetBIOS Session';              Severity='Low';      Why='Legacy NetBIOS. Modern clients use 445; can be closed if no down-level systems remain.'; Required=$false }
        [pscustomobject]@{ Port=49152; Proto='tcp'; Name='Dynamic RPC (sample)';         Severity='High';     Why='Sample of the dynamic RPC range (49152-65535) used for AD replication, DRS, FRS/DFSR. If 49152 is closed but the RPC firewall rule is open the actual replication may still be allowed; investigate before remediating.'; Required=$true }
    )

    # Discover DCs
    $dcs = @()
    try {
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop |
                 Sort-Object Name |
                 Select-Object Name,HostName,IPv4Address)
    } catch {
        Add-Content -Path $evidencePath -Value "ERROR: could not enumerate DCs via Get-ADDomainController: $($_.Exception.Message)"
        Write-Both "    [!] DC port check: could not enumerate DCs: $($_.Exception.Message)"
        return
    }
    if ($dcs.Count -eq 0) {
        Add-Content -Path $evidencePath -Value 'No domain controllers were returned by Get-ADDomainController.'
        Write-Both '    [!] DC port check: no DCs returned.'
        return
    }

    # Helper: TCP probe with short timeout
    function _Test-TcpPort {
        param([string]$Target, [int]$Port, [int]$TimeoutMs = 1500)
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $tcp.BeginConnect($Target, $Port, $null, $null)
            $ok = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
            if (-not $ok) { return [pscustomobject]@{ Open=$false; Error='timeout' } }
            try { $tcp.EndConnect($async) } catch { return [pscustomobject]@{ Open=$false; Error=$_.Exception.Message } }
            return [pscustomobject]@{ Open=$true; Error=$null }
        } catch {
            return [pscustomobject]@{ Open=$false; Error=$_.Exception.Message }
        } finally {
            try { $tcp.Close() } catch {}
        }
    }

    # Run local probes from this host to each DC. We DNS-resolve each DC name
    # first; if the name does not resolve we emit ONE "host unresolvable"
    # row instead of 14 noisy "CLOSED (No such host is known)" rows. The user
    # still gets a clear finding ("DC unreachable: name resolution failed")
    # and we skip the per-port probes for that DC. If the name resolves but
    # the host is down (e.g. firewall drops everything) the per-port loop
    # still runs and produces normal closed-port findings.
    function _Test-HostResolves {
        param([string]$Target)
        try {
            $null = [System.Net.Dns]::GetHostAddresses($Target)
            return $true
        } catch {
            return $false
        }
    }

    Write-Both ("    [+] Probing {0} DC(s) from this host on {1} required ports..." -f $dcs.Count, $portCatalog.Count)
    $rows           = New-Object System.Collections.Generic.List[object]
    $unresolvedDcs  = New-Object System.Collections.Generic.List[string]
    foreach ($dc in $dcs) {
        $tgt = if ($dc.HostName) { [string]$dc.HostName } else { [string]$dc.Name }
        if (-not (_Test-HostResolves -Target $tgt)) {
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
            $r = _Test-TcpPort -Target $tgt -Port $p.Port
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
    foreach ($dc in $dcs) {
        $tgt = if ($dc.HostName) { [string]$dc.HostName } else { [string]$dc.Name }
        $winrmRow = $rows | Where-Object { $_.Target -eq $tgt -and $_.Port -eq 5985 }
        if ($winrmRow -and $winrmRow.Open) { $winrmAvailableDcs += $tgt }
    }

    if ($winrmAvailableDcs.Count -eq 0) {
        $winrmSkippedReason = "WinRM (TCP 5985) is not reachable from this host to any DC, so we cannot run a cross-DC port matrix. Local-host probes above are still complete."
        Write-Both "    [!] WinRM is not reachable to any DC - skipping cross-DC port matrix. $winrmSkippedReason"
    } else {
        Write-Both ("    [+] WinRM reachable to {0} DC(s) - running cross-DC port matrix..." -f $winrmAvailableDcs.Count)
        # Run a probe FROM each WinRM-reachable DC TO every other DC. Drop any
        # DC that did not resolve via DNS from this host - the remote probe
        # would just emit "No such host is known" 14 times for it. The local
        # "DC unreachable" row for that target already surfaces it.
        $allTargets = @($dcs | ForEach-Object { if ($_.HostName) { [string]$_.HostName } else { [string]$_.Name } } | Where-Object { $unresolvedDcs -notcontains $_ })

        foreach ($srcDc in $winrmAvailableDcs) {
            try {
                $remoteResults = Invoke-Command -ComputerName $srcDc -ErrorAction Stop -ArgumentList $allTargets,$portCatalog -ScriptBlock {
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
            }
        }
    }

    $allRows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows)      { $allRows.Add($r) | Out-Null }
    foreach ($r in $crossRows) { $allRows.Add($r) | Out-Null }

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
    [void]$sb.AppendLine(" Cross-DC probe : $(if ($winrmAvailableDcs.Count -gt 0) { 'yes via WinRM from ' + ($winrmAvailableDcs -join ', ') } else { 'SKIPPED' })")
    if ($winrmSkippedReason) { [void]$sb.AppendLine("                  Reason: $winrmSkippedReason") }
    [void]$sb.AppendLine('---------------------------------------------------------------------')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('How to read this file:')
    [void]$sb.AppendLine(' - Each section below groups the closed-port findings by severity.')
    [void]$sb.AppendLine(' - "Closed" means the TCP probe could not establish a connection from')
    [void]$sb.AppendLine('   the named source to the named target on that port within 1.5s.')
    [void]$sb.AppendLine(' - LDAP (389) and LDAPS (636) are special: 389 OPEN is normal but a')
    [void]$sb.AppendLine('   risk if LDAP signing/channel-binding is not enforced; 636 CLOSED')
    [void]$sb.AppendLine('   is treated as a real finding because it forces all LDAP to plain.')
    [void]$sb.AppendLine('')

    # Closed-port findings, grouped by severity (highest first)
    $closed = @($allRows | Where-Object { -not $_.Open })
    $sevOrder = @{ 'Critical'=0; 'High'=1; 'Medium'=2; 'Low'=3 }
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
                    '^LDAPS' { 'Issue an LDAPS certificate to the DC (Server Authentication EKU, subject = DC FQDN), reload the DC schannel store (e.g. restart NTDS), and verify with `ldp.exe` to <DC>:636.' ; break }
                    'LDAP \(plaintext\)' { 'LDAP itself must be open (clients still use 389). The risk is unsigned/cleartext binds. Enforce LDAP signing (HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=2) and channel binding (LdapEnforceChannelBinding=2) - both should already be on per the LDAPSecurity check above.' ; break }
                    'WinRM HTTP|WinRM HTTPS' { 'Enable WinRM (`Enable-PSRemoting -Force`) or open TCP 5985/5986 on the DC firewall to the management subnet. Cross-DC checks in this audit need 5985 reachable from the audit host.' ; break }
                    'AD Web Services' { 'Verify the ADWS service is running on the DC (`Get-Service ADWS`). Open TCP 9389 from any host that uses the ActiveDirectory PowerShell module.' ; break }
                    'RPC endpoint' { 'Open TCP 135 from the source to the target. Most AD operations (replication, secure channel, Netlogon) start by hitting the RPC endpoint mapper here. Without it almost everything below fails.' ; break }
                    'Dynamic RPC' { 'Open the dynamic RPC range (TCP 49152-65535) or pin a static replication port via the RPC dynamic-port restriction registry value. Sampling 49152 alone is heuristic - one closed sample does not prove the entire range is blocked.' ; break }
                    'Kerberos password change' { 'Open TCP/UDP 464 between the DC and any host that does password changes (clients changing passwords, Set-ADAccountPassword from a remote DC).' ; break }
                    'Kerberos\b' { 'Open TCP/UDP 88 between the source and the DC. Kerberos auth fails completely without it.' ; break }
                    'Global Catalog' { "Open the GC port (3268 plain / 3269 TLS) from the source to the DC. Multi-domain forest logons and Exchange use GC; closed GC breaks them." ; break }
                    'DNS\b' { 'Open TCP/UDP 53 from clients to the DC. Without it clients cannot find DCs (no SRV records).' ; break }
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
            elseif ($ldapsState -eq 'OPEN' -and $ldapState -eq 'CLOSED') { 'OK (LDAPS only, plaintext blocked - rare but ideal)' }
            elseif ($ldapsState -eq 'CLOSED' -and $ldapState -eq 'OPEN') { 'RISK: LDAPS not reachable - all LDAP traffic forced to plaintext on 389' }
            else { 'CRITICAL: neither LDAP nor LDAPS reachable - no AD lookups possible from this host' }
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
        Write-Nessus-Finding "DCPortConnectivity" "KB1310" ([System.IO.File]::ReadAllText($evidencePath))
    } catch {}
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