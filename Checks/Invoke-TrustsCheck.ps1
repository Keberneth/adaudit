<# Trust inventory separates authentication direction, trust boundary and hardening flags. #>
function Get-ADAuditTrustAssessment {
    param($Trust)
    $attributes = [int]$Trust.trustAttributes
    $direction = switch ([int]$Trust.trustDirection) { 1 {'Inbound: partner trusts this domain'} 2 {'Outbound: this domain trusts partner'} 3 {'Bidirectional'} default {'Disabled/unknown'} }
    $within = ($attributes -band 0x20) -ne 0
    $forest = ($attributes -band 0x08) -ne 0
    $boundary = if ($within) {'WithinForest'} elseif ($forest) {'CrossForest'} elseif ([int]$Trust.trustType -eq 3) {'KerberosRealm'} else {'ExternalOrLegacy'}
    $quarantined = ($attributes -band 0x04) -ne 0
    $externalFiltering = ($attributes -band 0x40) -ne 0
    $selective = ($attributes -band 0x10) -ne 0
    $tgtDelegation = ($attributes -band 0x800) -ne 0
    $finding = (-not $within -and ($tgtDelegation -or ($forest -and $externalFiltering)))
    [pscustomobject]@{
        Partner = $Trust.Name
        Direction = $direction
        TrustType = $Trust.trustType
        Boundary = $boundary
        Attributes = ('0x{0:X8}' -f $attributes)
        Quarantined = $quarantined
        SelectiveAuthentication = $selective
        TreatAsExternal = $externalFiltering
        TgtDelegationEnabled = $tgtDelegation
        Status = if ($finding) {'Finding'} else {'Review'}
        Severity = if ($finding) {'High'} else {'Info'}
        Detail = if ($within) {'Expected intra-forest trust boundary; forest domains share the forest security boundary. Review business topology and privilege separation.'} elseif ($forest) {'Cross-forest SID filtering applies according to the trust boundary and flags; absence of quarantine does not mean no filtering. Forest transitivity covers domains in the two forests, not onward third-forest trusts. Review selective authentication, permitted resource access and business need.'} else {'Determine the external/realm trust boundary and effective filtering before recommending changes. Absence of quarantine alone does not establish absence of SID filtering. Review permitted resource access and business need.'}
    }
}
function Get-DomainTrusts {
    try { $trusts = @(Get-ADObject -Filter { objectClass -eq 'trustedDomain' } -Properties TrustPartner,TrustDirection,trustType,trustAttributes -ErrorAction Stop) }
    catch { Register-ADAuditNotAssessed -Name 'Trust inventory' -Switch 'trusts' -Reason $_.Exception.Message; return }
    $rows = @($trusts | ForEach-Object { Get-ADAuditTrustAssessment $_ })
    Export-ADAuditSecurityCsv -Rows $rows -Columns @('Partner','Direction','TrustType','Boundary','Attributes','Quarantined','SelectiveAuthentication','TreatAsExternal','TgtDelegationEnabled','Status','Severity','Detail') -Path (Get-EvidencePath 'trust_inventory.csv')
    foreach ($row in $rows) {
        Write-Both "    [$($row.Status)] Trust $($row.Partner): $($row.Direction); $($row.Boundary). $($row.Detail)"
        if ($row.Status -eq 'Finding') {
            $detail = "$($row.Partner): explicit TGT delegation=$($row.TgtDelegationEnabled); forest filtering relaxed to external=$($row.TreatAsExternal). Review these high-impact exceptions against the trust design. $($row.Detail)"
            Write-Nessus-Finding 'DomainTrusts' 'KB250' $detail $row.Severity
        }
    }
    Write-Both "    [*] $($rows.Count) trust object(s) inventoried in the current domain; partner-side policies and actual resource permissions were not assessed."
}
function Invoke-TrustsCheck { Get-DomainTrusts }
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select trusts @args
}
