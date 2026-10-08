<#
    .SYNOPSIS
        ADAudit check: Domain Trust Audit

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -trusts). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-TrustsCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select trusts [options]

    .NOTES
        Entry point: Invoke-TrustsCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
Function Get-DomainTrusts {
    #Lists domain trusts and flags the risk of inbound/bidirectional (outbound-from-us) trusts
    foreach ($trust in (Get-ADObject -Filter { objectClass -eq "trustedDomain" } -Properties TrustPartner, TrustDirection, trustType, trustAttributes)) {
        # Direction 2 = Outbound, 3 = Bidirectional. In both, THIS domain trusts the partner,
        # so the partner's principals can be authorised here (the risky direction for us).
        # Direction 1 = Inbound-only (partner trusts us) is not flagged.
        if ($trust.TrustDirection -eq 2 -or $trust.TrustDirection -eq 3) {
            if (($trust.TrustAttributes -band 0x1) -or ($trust.TrustAttributes -band 0x4)) {
                # 0x1 = non-transitive, 0x4 = quarantined/SID-filtered: partner access is contained.
                Write-Both "    [!] $env:UserDomain trusts the domain $($trust.Name) (non-transitive or SID-filtered - contained, but confirm the business need). (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "$env:UserDomain trusts the domain $($trust.Name). Trust is non-transitive or SID-filtered (contained). Review the business justification."
            }
            else {
                Write-Both "    [!] $env:UserDomain trusts the domain $($trust.Name) and the trust is TRANSITIVE with no SID filtering - principals from $($trust.Name) (and domains it trusts) can be authorised here, so a compromise there can pivot into this domain. (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "$env:UserDomain trusts the domain $($trust.Name); the trust is TRANSITIVE with no SID filtering, so principals from the trusted forest (and its onward trusts) can be authorised in this domain. Enable SID filtering / quarantine unless a business need requires otherwise."
            }
        }
    }
}

function Invoke-TrustsCheck {
    Get-DomainTrusts
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select trusts @args
}