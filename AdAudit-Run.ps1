while ($true) {
    Write-Host "1: Install Dependencies"
    Write-Host "2: Install Dependencies Offline"
    Write-Host "3: Host Details"
    Write-Host "4: Domain Audit"
    Write-Host "5: Trusts"
    Write-Host "6: Accounts"
    Write-Host "7: Inactive Computers"
    Write-Host "8: Password Policy"
    Write-Host "9: NTDS"
    Write-Host "10: Old Boxes"
    Write-Host "11: GPO"
    Write-Host "12: OU Perms"
    Write-Host "13: LAPS"
    Write-Host "14: Auth Pol Silos"
    Write-Host "15: Insecure DNS Zone"
    Write-Host "16: Recent Changes"
    Write-Host "17: ADCS"
    Write-Host "18: SPN"
    Write-Host "19: ASREP"
    Write-Host "20: ACL"
    Write-Host "21: LDAP Security"
    Write-Host "22: Delegated Permissions"
    Write-Host "23: DNS Zone"
    Write-Host "24: Run All Checks"
    Write-Host "Q: Quit"

    $choice = Read-Host "Enter your choice"
    $scriptPath           = Join-Path $PSScriptRoot 'AdAudit.ps1'
    $offlineScriptPath    = Join-Path $PSScriptRoot 'InstallDeps.ps1'

    switch ($choice) {

        '1'  { & $scriptPath -installdeps; break }

        '2'  {
            if (Test-Path $offlineScriptPath) { & $offlineScriptPath }
            else { Write-Host "Offline dependency script not found at '$offlineScriptPath'" -ForegroundColor Red }
            break
        }

        '3'  { & $scriptPath -hostdetails; break }
        '4'  { & $scriptPath -domainaudit; break }
        '5'  { & $scriptPath -trusts; break }
        '6'  { & $scriptPath -accounts; break }
        '7'  { & $scriptPath -inactivecomputers; break }
        '8'  { & $scriptPath -passwordpolicy; break }
        '9'  { & $scriptPath -ntds; break }
        '10' { & $scriptPath -oldboxes; break }
        '11' { & $scriptPath -gpo; break }
        '12' { & $scriptPath -ouperms; break }
        '13' { & $scriptPath -laps; break }
        '14' { & $scriptPath -authpolsilos; break }
        '15' { & $scriptPath -insecurednszone; break }
        '16' { & $scriptPath -recentchanges; break }
        '17' { & $scriptPath -adcs; break }
        '18' { & $scriptPath -spn; break }
        '19' { & $scriptPath -asrep; break }
        '20' { & $scriptPath -acl; break }
        '21' { & $scriptPath -ldapsecurity; break }
        '22' { & $scriptPath -delegatedpermissions; break }
        '23' { & $scriptPath -dnszone; break }
        '24' { & $scriptPath -all; break }
        'Q' { exit }

        default { Write-Host "Invalid choice, please try again." }
    }
}   
