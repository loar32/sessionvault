param(
    [string]$VmName = 'sv-test',
    [string]$UserPassword = 'Sv-Tester-1!',
    [string]$AdminPassword = 'Sv-Admin-1!'
)
# Чекпойнт clean: в интерактивной сессии работает обычный tester (как у реального пользователя).
# Админ-действия svadmin идёт через PowerShell Direct, рабочий стол ему не нужен.
$ErrorActionPreference = 'Stop'
$admin = New-Object pscredential('svadmin', (ConvertTo-SecureString $AdminPassword -AsPlainText -Force))

if ((Get-VM $VmName).State -ne 'Running') { Start-VM $VmName }
while ((Get-VM $VmName).Heartbeat -notmatch 'Ok') { Start-Sleep 3 }
Start-Sleep 15
Invoke-Command -VMName $VmName -Credential $admin -ArgumentList $UserPassword {
    param($pw)
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty $k AutoAdminLogon 1
    Set-ItemProperty $k DefaultUserName tester
    Set-ItemProperty $k DefaultPassword $pw
    Set-ItemProperty $k DefaultDomainName .
    Remove-ItemProperty $k AutoLogonCount -ErrorAction SilentlyContinue
    Restart-Computer -Force
}
Start-Sleep 20
$end = (Get-Date).AddMinutes(5)
while ((Get-Date) -lt $end) {
    try {
        $u = Invoke-Command -VMName $VmName -Credential $admin { (Get-Process explorer -IncludeUserName -ErrorAction SilentlyContinue).UserName } -ErrorAction Stop
        if ($u -like '*tester') { break }
    } catch {}
    Start-Sleep 5
}
if ($u -notlike '*tester') { throw 'tester не вошёл в систему' }
Get-VMSnapshot $VmName -Name clean -ErrorAction SilentlyContinue | Remove-VMSnapshot
Checkpoint-VM $VmName -SnapshotName clean
Write-Host "чекпойнт clean: в сессии работает $u"
