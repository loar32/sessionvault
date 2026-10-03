param(
    [string]$VmName = 'sv-test',
    [string]$Checkpoint = 'clean',
    [string]$AdminPassword = 'Sv-Admin-1!',
    [string]$UserPassword = 'Sv-Tester-1!',
    [string]$MasterPassword = 'Master-Pass-1'
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path "$PSScriptRoot\..\.."
$dist = Join-Path $root 'dist'

function Cred($name, $pw) {
    New-Object pscredential($name, (ConvertTo-SecureString $pw -AsPlainText -Force))
}
$admin = Cred 'svadmin' $AdminPassword
$user = Cred 'tester' $UserPassword

$fails = @()
function Check($ok, $msg) {
    if ($ok) { Write-Host "  ok: $msg" } else { Write-Host "  ПРОВАЛ: $msg"; $script:fails += $msg }
}

Restore-VMCheckpoint -VMName $VmName -Name $Checkpoint -Confirm:$false
Start-VM $VmName 3>$null
while ((Get-VM $VmName).Heartbeat -notmatch 'Ok') { Start-Sleep 3 }
Start-Sleep 20

$a = New-PSSession -VMName $VmName -Credential $admin
$u = New-PSSession -VMName $VmName -Credential $user
while (-not (Invoke-Command $a { Get-Process explorer -ErrorAction SilentlyContinue })) { Start-Sleep 2 }

Invoke-Command $a { New-Item -ItemType Directory -Force C:\sv, C:\sv\ctl | Out-Null }
foreach ($f in 'sessionvault', 'access-check', 'standin') {
    Copy-Item "$dist\$f.exe" -Destination C:\sv\ -ToSession $a
}

# Помощники на стороне ВМ. Запуск от vault требует интерактивного рабочего стола, которого нет у сессии
# PowerShell Direct, поэтому sessionvault run идёт задачей планировщика в сессии svadmin; пароль — через файл на stdin.
$helpers = @'
$v = 'C:\ProgramData\SessionVault\vault\telegram'
function StartRun($pw) {
    [IO.File]::WriteAllText('C:\sv\pw.txt', "$pw`r`n")
    [IO.File]::Delete('C:\sv\run.out')
    $cmd = 'cmd /c C:\sv\sessionvault.exe run telegram -exe C:\sv\standin.exe -password-stdin < C:\sv\pw.txt > C:\sv\run.out 2>&1'
    schtasks /Create /TN svrun /SC ONCE /ST 00:00 /RL HIGHEST /IT /F /TR $cmd 2>$null | Out-Null
    schtasks /Run /TN svrun 2>$null | Out-Null
}
function WaitOut($pattern, $sec = 90) {
    $end = (Get-Date).AddSeconds($sec)
    while ((Get-Date) -lt $end) {
        if ((Test-Path C:\sv\run.out) -and (Get-Content C:\sv\run.out -Encoding UTF8 | Select-String $pattern -Quiet)) { return $true }
        Start-Sleep 1
    }
    return $false
}
function RunPid() { [int]((Get-Content C:\sv\run.out -Encoding UTF8 | Select-String 'pid: (\d+)').Matches[0].Groups[1].Value) }
function Files() { (Get-ChildItem $v -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'running.lock' } | ForEach-Object { $_.FullName.Substring($v.Length + 1) }) -join ',' }
'@

function Vm($block, $ar = @()) {
    Invoke-Command $a -ScriptBlock { param($h, $b, $x) . ([scriptblock]::Create($h)); & ([scriptblock]::Create($b)) @x } -ArgumentList $helpers, $block.ToString(), $ar
}

# «Telegram» основной учётки: tdata с одним файлом
Invoke-Command $u {
    $d = "$env:APPDATA\TestTelegram\tdata"
    New-Item -ItemType Directory -Force $d | Out-Null
    Set-Content "$d\key_datas" 'secret-session-data'
}
$tdata = Invoke-Command $u { "$env:APPDATA\TestTelegram\tdata" }

Write-Host '--- 1. setup и import-tdata: на диске только шифр ---'
$r = Vm {
    param($tdata, $pw)
    & C:\sv\sessionvault.exe setup tester | Out-Null
    $pw | & C:\sv\sessionvault.exe import-tdata -password-stdin $tdata | Out-Null
    [pscustomobject]@{ files = (Files); old = (Test-Path $tdata); plain = [bool](Select-String -Path "$v\data.enc" -Pattern 'secret-session' -Quiet -Encoding UTF8) }
} @($tdata, $MasterPassword)
Check ($r.files -eq 'data.enc,vault.json') "в хранилище только data.enc и vault.json (есть: $($r.files))"
Check (-not $r.old) 'исходная tdata перенесена, на старом месте её нет'
Check (-not $r.plain) 'в data.enc нет открытого текста'

Write-Host '--- 2. run: данные расшифрованы, приложение под vault ---'
$r = Vm {
    param($pw)
    StartRun $pw
    if (-not (WaitOut 'pid:')) { return @{ started = $false } }
    $p = RunPid; Start-Sleep 2
    $proc = Get-Process -Id $p -IncludeUserName -ErrorAction SilentlyContinue
    @{ started = $true; pid = $p; user = $proc.UserName; key = (Get-Content "$v\tdata\key_datas" -Encoding UTF8 -ErrorAction SilentlyContinue); open = (Test-Path "$v\open") }
} @($MasterPassword)
Check $r.started 'run запустил приложение'
Check ($r.user -like '*\vault') "приложение работает от vault ($($r.user))"
Check ($r.key -eq 'secret-session-data') 'после расшифровки данные совпали'
Check $r.open 'маркер открытых данных создан'
$vaultPid = $r.pid

Write-Host '--- 3. access-check из tester, пока приложение открыто (ждём код 0) ---'
$code = Invoke-Command $u { param($p) & C:\sv\access-check.exe -pid $p; $LASTEXITCODE } -ArgumentList $vaultPid
$code | Select-Object -SkipLast 1
$real = $code[-1]
Check ($real -eq 0) "access-check: защита=$real"

Write-Host '--- 4. закрытие приложения: снова только шифр ---'
$r = Vm {
    param($p)
    Stop-Process -Id $p -Force
    $done = WaitOut 'зашифрованы' 60
    @{ done = $done; files = (Files) }
} @($vaultPid)
Check $r.done 'run дождался выхода и зашифровал данные'
Check ($r.files -eq 'data.enc,vault.json') "после закрытия на диске только шифр (есть: $($r.files))"

Write-Host '--- 5. сбой: убиваем run и приложение, затем дошифровка ---'
$r = Vm {
    param($pw)
    StartRun $pw
    if (-not (WaitOut 'pid:')) { return @{ started = $false } }
    $p = RunPid; Start-Sleep 2
    Stop-Process -Name sessionvault -Force
    Stop-Process -Id $p -Force
    Start-Sleep 3
    @{ started = $true; files = (Files) }
} @($MasterPassword)
Check ($r.files -match 'tdata' -and $r.files -match 'open') "после сбоя остались открытые данные и маркер (есть: $($r.files))"
$r = Vm {
    param($pw)
    StartRun $pw
    $started = WaitOut 'pid:'
    $recovered = WaitOut 'дошифровываю' 5
    $p = RunPid; Start-Sleep 2
    $key = Get-Content "$v\tdata\key_datas" -Encoding UTF8 -ErrorAction SilentlyContinue
    Stop-Process -Id $p -Force
    $done = WaitOut 'зашифрованы' 60
    @{ started = $started; recovered = $recovered; key = $key; done = $done; files = (Files) }
} @($MasterPassword)
Check $r.recovered 'run заметил остаток и дошифровал'
Check ($r.key -eq 'secret-session-data') 'данные после сбоя не потеряны'
Check ($r.done -and $r.files -eq 'data.enc,vault.json') "после дошифровки и закрытия только шифр (есть: $($r.files))"

Write-Host '--- 6. неверный пароль ---'
$r = Vm {
    StartRun 'Wrong-Pass-9'
    @{ refused = (WaitOut 'неверный пароль' 60); files = (Files) }
}
Check $r.refused 'неверный пароль отклонён'
Check ($r.files -eq 'data.enc,vault.json') 'при неверном пароле открытых данных не появилось'

Write-Host '--- 7. access-check из tester, приложение закрыто (ждём код 0) ---'
$code = Invoke-Command $u { & C:\sv\access-check.exe; $LASTEXITCODE }
$code | Select-Object -SkipLast 1
Check ($code[-1] -eq 0) "access-check: защита=$($code[-1])"

Write-Host '--- 8. контроль: открытые данные и свой процесс (ждём код 1) ---'
Invoke-Command $a { Set-Content C:\sv\ctl\f.txt 'открытый файл' }
$ctlPid = Invoke-Command $u { (Start-Process C:\sv\standin.exe -PassThru).Id }
$code = Invoke-Command $u {
    param($p)
    & C:\sv\access-check.exe -dir C:\sv\ctl -file C:\sv\ctl\f.txt -enc C:\sv\ctl\f.txt -meta C:\sv\ctl\f.txt -pwd C:\sv\ctl\f.txt -pid $p
    $LASTEXITCODE
} -ArgumentList $ctlPid
$code | Select-Object -SkipLast 1
Check ($code[-1] -eq 1) "контроль=$($code[-1]) (ждём 1: проверка действительно видит утечки)"

if ($fails.Count -eq 0) { Write-Host 'ТЕСТ ПРОЙДЕН'; exit 0 }
Write-Host "ТЕСТ ПРОВАЛЕН ($($fails.Count))"; exit 1
