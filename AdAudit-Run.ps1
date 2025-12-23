while ($true) {
    Write-Host "1: Install Dependencies"
    Write-Host "2: Install Dependencies Offline"
    Write-Host "3: Host Details"
    Write-Host "4: Domain Audit"
    Write-Host "5: Trusts"
    Write-Host "6: Accounts"
    Write-Host "7: Password Policy"
    Write-Host "8: NTDS"
    Write-Host "9: Old Boxes"
    Write-Host "10: GPO"
    Write-Host "11: OU Perms"
    Write-Host "12: LAPS"
    Write-Host "13: Auth Pol Silos"
    Write-Host "14: Insecure DNS Zone"
    Write-Host "15: Recent Changes"
    Write-Host "16: ADCS"
    Write-Host "17: SPN"
    Write-Host "18: ASREP"
    Write-Host "19: ACL"
    Write-Host "20: LDAP Security"
    Write-Host "21: Delegated Permissions"
    Write-Host "22: Run All Checks"
    Write-Host "Q: Quit"

    $choice = Read-Host "Enter your choice"
    $scriptPath           = Join-Path $PSScriptRoot 'AdAudit.ps1'
    $offlineScriptPath    = Join-Path $PSScriptRoot 'InstallDeps.ps1'
    $delegatedScriptPath  = Join-Path $PSScriptRoot 'Deligated_Permissions.ps1'

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
        '7'  { & $scriptPath -passwordpolicy; break }
        '8'  { & $scriptPath -ntds; break }
        '9'  { & $scriptPath -oldboxes; break }
        '10' { & $scriptPath -gpo; break }
        '11' { & $scriptPath -ouperms; break }
        '12' { & $scriptPath -laps; break }
        '13' { & $scriptPath -authpolsilos; break }
        '14' { & $scriptPath -insecurednszone; break }
        '15' { & $scriptPath -recentchanges; break }
        '16' { & $scriptPath -adcs; break }
        '17' { & $scriptPath -spn; break }
        '18' { & $scriptPath -asrep; break }
        '19' { & $scriptPath -acl; break }
        '20' { & $scriptPath -ldapsecurity; break }

        '21' {
            if (Test-Path $delegatedScriptPath) { & $delegatedScriptPath }
            else { Write-Host "Delegated permissions script not found at '$delegatedScriptPath'" -ForegroundColor Red }
            break
        }

        '22' {
            & $scriptPath -all
            if (Test-Path $delegatedScriptPath) { & $delegatedScriptPath }
            else { Write-Host "Delegated permissions script not found at '$delegatedScriptPath'" -ForegroundColor Red }
            break
        }

        'Q' { exit }

        default { Write-Host "Invalid choice, please try again." }
    }
}   
