param(
    [string]$VmName = 'sv-test',
    [string]$Checkpoint = 'clean',
    [string]$AdminPassword = 'Sv-Admin-1!',
    [string]$UserPassword = 'Sv-Tester-1!'
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path "$PSScriptRoot\..\.."
$dist = Join-Path $root 'dist'

function Cred($name, $pw) {
    New-Object pscredential($name, (ConvertTo-SecureString $pw -AsPlainText -Force))
}
$admin = Cred 'svadmin' $AdminPassword
$user = Cred 'tester' $UserPassword

Restore-VMCheckpoint -VMName $VmName -Name $Checkpoint -Confirm:$false
Start-VM $VmName
while ((Get-VM $VmName).Heartbeat -notmatch 'Ok') { Start-Sleep 3 }
Start-Sleep 20

$a = New-PSSession -VMName $VmName -Credential $admin
$u = New-PSSession -VMName $VmName -Credential $user
while (-not (Invoke-Command $a { Get-Process explorer -ErrorAction SilentlyContinue })) { Start-Sleep 2 }

Invoke-Command $a { New-Item -ItemType Directory -Force C:\sv, C:\sv\ctl | Out-Null }
foreach ($f in 'sessionvault', 'access-check', 'standin') {
    Copy-Item "$dist\$f.exe" -Destination C:\sv\ -ToSession $a
}

# «Telegram» основной учётки: tdata с одним файлом
Invoke-Command $u {
    $d = "$env:APPDATA\TestTelegram\tdata"
    New-Item -ItemType Directory -Force $d | Out-Null
    Set-Content "$d\key_datas" 'секретные данные сессии'
}
$tdata = Invoke-Command $u { "$env:APPDATA\TestTelegram\tdata" }

$out = Invoke-Command $a {
    param($tdata)
    & C:\sv\sessionvault.exe setup tester
    & C:\sv\sessionvault.exe import-tdata $tdata
    # Запуск от vault требует интерактивного рабочего стола, которого нет у сессии PowerShell Direct
    Remove-Item C:\sv\run.out -ErrorAction SilentlyContinue
    schtasks /Create /TN svrun /SC ONCE /ST 00:00 /RL HIGHEST /IT /F /TR 'cmd /c C:\sv\sessionvault.exe run telegram -exe C:\sv\standin.exe > C:\sv\run.out 2>&1' 2>$null | Out-Null
    schtasks /Run /TN svrun 2>$null | Out-Null
    while (-not (Test-Path C:\sv\run.out) -or -not (Select-String -Path C:\sv\run.out -Pattern 'pid:' -Quiet)) { Start-Sleep 1 }
    Get-Content C:\sv\run.out
} -ArgumentList $tdata
$out
$vaultPid = ($out | Select-String 'pid: (\d+)').Matches[0].Groups[1].Value

Invoke-Command $a { Set-Content C:\sv\ctl\f.txt 'открытый файл' }
$ctlPid = Invoke-Command $u { (Start-Process C:\sv\standin.exe -PassThru).Id }

Write-Host '--- access-check из tester: защищённые данные (ждём код 0) ---'
$code = Invoke-Command $u { param($p) & C:\sv\access-check.exe -pid $p; $LASTEXITCODE } -ArgumentList $vaultPid
$code | Select-Object -SkipLast 1
$real = $code[-1]

Write-Host '--- контроль: открытые данные и свой процесс (ждём код 1) ---'
$code = Invoke-Command $u {
    param($p)
    & C:\sv\access-check.exe -dir C:\sv\ctl -file C:\sv\ctl\f.txt -pwd C:\sv\ctl\f.txt -pid $p
    $LASTEXITCODE
} -ArgumentList $ctlPid
$code | Select-Object -SkipLast 1
$control = $code[-1]

Write-Host "access-check: защита=$real (ждём 0), контроль=$control (ждём 1)"
if ($real -eq 0 -and $control -eq 1) { Write-Host 'ТЕСТ ПРОЙДЕН'; exit 0 }
Write-Host 'ТЕСТ ПРОВАЛЕН'; exit 1
