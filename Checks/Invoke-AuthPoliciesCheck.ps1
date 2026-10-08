<#
    .SYNOPSIS
        ADAudit check: Check For Existence of Authentication Polices and Silos

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -authpolsilos). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-AuthPoliciesCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select authpolsilos [options]

    .NOTES
        Entry point: Invoke-AuthPoliciesCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
Function Get-AuthenticationPoliciesAndSilos {
    # Authentication Policies and Silos require Domain Functional Level
    # Windows Server 2012 R2 (the AD schema features and KDC enforcement
    # ship at that DFL). Forest level is NOT required - only the domain.
    # Earlier versions of this script gated on Windows2019Domain, which
    # incorrectly skipped the check on perfectly capable estates.
    $DomainLevel = (Get-ADDomain).DomainMode
    $evPath = Get-EvidencePath 'auth_policies_silos.txt'

    if (Test-ADAuditFunctionalLevelAtLeast -Mode $DomainLevel -MinimumMode 'Windows2012R2Domain') {
        try {
            $policies = @(Get-ADAuthenticationPolicy -Filter *)
            $silos    = @(Get-ADAuthenticationPolicySilo -Filter *)
        } catch {
            Write-Both "    [!] Could not enumerate Authentication Policies / Silos: $($_.Exception.Message)"
            return
        }

        foreach ($policy in $policies)   { Write-Both "    [+] Found Authentication Policy: $($policy.Name)" }
        foreach ($silo   in $silos)      { Write-Both "    [+] Found Authentication Policy Silo: $($silo.Name)" }

        if ($policies.Count -eq 0 -and $silos.Count -eq 0) {
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine('No Authentication Policies and no Authentication Policy Silos exist in this domain.')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("Domain functional level: $DomainLevel (>= Windows2012R2Domain - the feature is supported).")
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('Why this matters:')
            [void]$sb.AppendLine(' - Authentication Silos let you fence off Tier0 (Domain Admins, KRBTGT, the')
            [void]$sb.AppendLine('   forest root) so those accounts can ONLY sign in to a small, controlled set')
            [void]$sb.AppendLine('   of jump hosts and DCs. Combined with Protected Users, this is the strongest')
            [void]$sb.AppendLine('   "no admin creds on workstations" control Microsoft ships out of the box.')
            [void]$sb.AppendLine(' - Without silos, an attacker who phishes any admin can use that ticket from')
            [void]$sb.AppendLine('   any compromised endpoint - there is no policy preventing it.')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('How to fix:')
            [void]$sb.AppendLine(' - Plan a Tier0 silo containing your DCs and a small number of PAW jump hosts.')
            [void]$sb.AppendLine(' - Create a policy + silo in audit mode first, monitor for breakage, then enforce.')
            [void]$sb.AppendLine('   Reference: https://learn.microsoft.com/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('Consequences if NOT fixed:')
            [void]$sb.AppendLine(' - Admins can interactively log on to any workstation. Their tickets can be')
            [void]$sb.AppendLine('   stolen and reused (golden ticket / silver ticket / ticket reuse paths).')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('Consequences AFTER you implement (test before enforcing):')
            [void]$sb.AppendLine(' - Accounts assigned to the silo can no longer sign in to systems outside it.')
            [void]$sb.AppendLine('   If the silo is misconfigured admins can lock themselves out of every system,')
            [void]$sb.AppendLine('   including the silo members. Always pilot in audit mode first.')
            [void]$sb.AppendLine(' - Service accounts that need to authenticate from many sources usually do NOT')
            [void]$sb.AppendLine('   belong in a Tier0 silo - put them in a separate silo or leave them out.')
            Set-Content -LiteralPath $evPath -Value $sb.ToString() -Encoding UTF8
            Write-Both "    [!] No Authentication Policies / Silos defined - Tier0 isolation is not enforced. See auth_policies_silos.txt for context, fix, and trade-offs."
            Write-Nessus-Finding "AuthPoliciesSilosMissing" "KB549" ([System.IO.File]::ReadAllText($evPath))
        }
    }
    else {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("Authentication Policies / Silos check SKIPPED - Domain Functional Level ($DomainLevel) is below Windows2012R2Domain.")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Why this matters:')
        [void]$sb.AppendLine(' - Authentication Policies and Silos let you fence Tier0 admins to specific,')
        [void]$sb.AppendLine('   controlled hosts. They require DFL 2012R2 - they simply do not exist below.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('How to fix:')
        [void]$sb.AppendLine(' - Raise the Domain Functional Level (see the ProtectedUsers finding for the')
        [void]$sb.AppendLine('   exact PowerShell). Then plan a Tier0 silo (DCs + PAW jump hosts only).')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Consequences if NOT fixed:')
        [void]$sb.AppendLine(' - No mechanism to restrict where Tier0 accounts can sign in. Pass-the-hash and')
        [void]$sb.AppendLine('   ticket-reuse attacks against admins are not contained at the policy layer.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Consequences AFTER raising DFL (review before doing it):')
        [void]$sb.AppendLine(' - DFL is one-way - cannot be lowered. Remove all DCs running an OS below the')
        [void]$sb.AppendLine('   target DFL BEFORE raising. Inventory legacy clients and apps for compatibility.')
        Set-Content -LiteralPath $evPath -Value $sb.ToString() -Encoding UTF8
        Write-Both "    [!] Authentication Policies / Silos check skipped - DFL is $DomainLevel (need Windows2012R2Domain). See auth_policies_silos.txt for context, fix, and trade-offs."
        Write-Nessus-Finding "AuthPoliciesSilosDflTooLow" "KB549" ([System.IO.File]::ReadAllText($evPath))
    }
}

function Invoke-AuthPoliciesCheck {
    Get-AuthenticationPoliciesAndSilos
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select authpolsilos @args
}