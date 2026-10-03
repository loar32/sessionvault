param(
    [string]$VmName = 'sv-test',
    [string]$Checkpoint = 'clean',
    [string]$AdminPassword = 'Sv-Admin-1!',
    [string]$MasterPassword = 'Master-Pass-1'
)
# Автотест службы. В интерактивной сессии работает обычный tester, админ-действия идут через PowerShell Direct (svadmin).
# Пароль в окно службы вводится клавиатурой Hyper-V с хоста: в самой программе тестовых лазеек нет.
$ErrorActionPreference = 'Stop'
$root = Resolve-Path "$PSScriptRoot\..\.."
$dist = Join-Path $root 'dist'
$admin = New-Object pscredential('svadmin', (ConvertTo-SecureString $AdminPassword -AsPlainText -Force))

$fails = @()
function Check($ok, $msg) {
    if ($ok) { Write-Host "  ok: $msg" } else { Write-Host "  ПРОВАЛ: $msg"; $script:fails += $msg }
}

Restore-VMCheckpoint -VMName $VmName -Name $Checkpoint -Confirm:$false
Start-VM $VmName 3>$null
while ((Get-VM $VmName).Heartbeat -notmatch 'Ok') { Start-Sleep 3 }
Start-Sleep 15
$a = New-PSSession -VMName $VmName -Credential $admin
while (-not (Invoke-Command $a { (Get-Process explorer -IncludeUserName -ErrorAction SilentlyContinue).UserName -like '*tester' })) { Start-Sleep 2 }

$kb = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "Name='$((Get-VM $VmName).Id)'" |
    Get-CimAssociatedInstance -ResultClassName Msvm_Keyboard
$mouse = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "Name='$((Get-VM $VmName).Id)'" |
    Get-CimAssociatedInstance -ResultClassName Msvm_SyntheticMouse | Select-Object -First 1
# Свежая оболочка в первые минуты сама перехватывает передний план, поэтому перед вводом кликаем по полю окна (центр экрана, 1024x768).
function ClickPrompt() {
    Invoke-CimMethod $mouse -MethodName SetAbsolutePosition -Arguments @{ HorizontalPosition = [int]32768; VerticalPosition = [int](272 * 65535 / 768) } | Out-Null
    Start-Sleep -Milliseconds 300
    Invoke-CimMethod $mouse -MethodName ClickButton -Arguments @{ ButtonIndex = [uint32]1 } | Out-Null
    Start-Sleep -Milliseconds 700
}
function TypeInVm($text) {
    ClickPrompt
    Invoke-CimMethod $kb -MethodName TypeText -Arguments @{ asciiText = $text } | Out-Null
    Start-Sleep -Milliseconds 500
    Invoke-CimMethod $kb -MethodName PressKey -Arguments @{ keyCode = 13 } | Out-Null
    Invoke-CimMethod $kb -MethodName ReleaseKey -Arguments @{ keyCode = 13 } | Out-Null
}

Invoke-Command $a { New-Item -ItemType Directory -Force C:\sv | Out-Null }
foreach ($f in 'sessionvault', 'access-check', 'standin') {
    Copy-Item "$dist\$f.exe" -Destination C:\sv\ -ToSession $a
}

# Помощники на стороне ВМ. Клиент pipe должен работать в интерактивной сессии tester (иначе окну пароля некуда
# появиться), поэтому команды tester идут задачами планировщика с /IT.
$helpers = @'
$v = 'C:\ProgramData\SessionVault\vault\telegram'
$exe = 'C:\Program Files\SessionVault\sessionvault.exe'
function AsTester($name, $cmd) {
    [IO.File]::Delete("C:\sv\$name.out")
    [IO.File]::WriteAllText("C:\sv\$name.cmd", "@echo off`r`n$cmd > C:\sv\$name.out 2>&1`r`n(echo EXIT=%ERRORLEVEL%) >> C:\sv\$name.out`r`n")
    # Без видимой консоли: иначе её окно забирает фокус у окна пароля, чего в жизни не бывает.
    $act = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument "--headless cmd.exe /c C:\sv\$name.cmd"
    $pr = New-ScheduledTaskPrincipal -UserId 'SV-TEST\tester' -LogonType Interactive
    Register-ScheduledTask -TaskName "svt-$name" -Action $act -Principal $pr -Force | Out-Null
    Start-ScheduledTask -TaskName "svt-$name"
}
function Out($name) { if (Test-Path "C:\sv\$name.out") { Get-Content "C:\sv\$name.out" -Encoding UTF8 -Raw } }
function WaitFor($sb, $sec = 60) {
    $end = (Get-Date).AddSeconds($sec)
    while ((Get-Date) -lt $end) { if (& $sb) { return $true }; Start-Sleep 1 }
    return $false
}
function Done($name, $sec = 60) { WaitFor { (Out $name) -match 'EXIT=' } $sec }
function PromptUp() { [bool](Get-CimInstance Win32_Process -Filter "Name='sessionvault.exe'" | Where-Object { $_.CommandLine -like '* prompt *' }) }
function Files() { (Get-ChildItem $v -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'running.lock' } | ForEach-Object { $_.FullName.Substring($v.Length + 1) }) -join ',' }
function Standin() { Get-Process standin -IncludeUserName -ErrorAction SilentlyContinue | Select-Object -First 1 }
'@
function Vm($block, $ar = @()) {
    Invoke-Command $a -ScriptBlock { param($h, $b, $x) . ([scriptblock]::Create($h)); & ([scriptblock]::Create($b)) @x } -ArgumentList $helpers, $block.ToString(), $ar
}
function WaitPrompt() { Vm { WaitFor { PromptUp } 30 } }

Write-Host '--- 1. установка службы ---'
$r = Vm {
    param($tg)
    $out = & C:\sv\sessionvault.exe install -user tester -telegram-exe $tg 2>&1
    Start-Sleep 3
    @{ out = ($out -join ' '); svc = (Get-Service SessionVault).Status.ToString(); exe = (Test-Path $exe) }
} @('C:\sv\standin.exe')
Check ($r.svc -eq 'Running') "служба запущена ($($r.svc)); $($r.out)"
Check $r.exe 'бинарник в Program Files'

Write-Host '--- 2. tdata переносится в хранилище ---'
Invoke-Command $a {
    $d = 'C:\Users\tester\AppData\Roaming\TestTelegram\tdata'
    New-Item -ItemType Directory -Force $d | Out-Null
    Set-Content "$d\key_datas" 'secret-session-data'
}
$r = Vm {
    param($pw)
    $pw | & C:\sv\sessionvault.exe import-tdata -password-stdin C:\Users\tester\AppData\Roaming\TestTelegram\tdata | Out-Null
    @{ files = (Files) }
} @($MasterPassword)
Check ($r.files -eq 'data.enc,vault.json') "в хранилище только шифр (есть: $($r.files))"

Write-Host '--- 3. status до разблокировки ---'
$r = Vm { AsTester 'st' "`"$exe`" status"; Done 'st' | Out-Null; Out 'st' }
Check ($r -match '(?m)^locked') "status: locked ($("$r" -replace '\s+',' '))"

Write-Host '--- 4. run: окно пароля, пароль вводится клавиатурой ---'
Vm { AsTester 'run1' "`"$exe`" run telegram" }
Check (WaitPrompt) 'служба показала окно пароля'
Start-Sleep 3
Write-Host '  (пока окно открыто) пробы pipe из tester:'
$probe = Vm { AsTester 'pp' 'C:\sv\access-check.exe -pipe'; Done 'pp' 120 | Out-Null; Out 'pp' }
($probe -split "`n" | Where-Object { $_ -match 'pipe пароля|служба жива|УТЕЧКА|EXIT' }) | ForEach-Object { "    $_" }
Check ($probe -match 'EXIT=0') 'access-check -pipe: утечек нет, служба жива, pipe пароля закрыт'
TypeInVm 'Wrong-Pass-9'
Start-Sleep 5
Check (Vm { PromptUp }) 'после неверного пароля окно осталось для повторной попытки'
TypeInVm $MasterPassword
$r = Vm {
    $ok = Done 'run1' 90
    Start-Sleep 3
    $p = Standin
    @{ done = $ok; out = (Out 'run1'); user = $p.UserName; session = $p.SessionId; key = (Get-Content "$v\work\tdata\key_datas" -ErrorAction SilentlyContinue); pid = $p.Id }
}
Check ($r.out -match 'ok' -and $r.out -match 'EXIT=0') "run вернул ok ($("$($r.out)" -replace '\s+',' '))"
Check ($r.user -like '*\vault' -and $r.session -ne 0) "приложение от vault в сессии пользователя ($($r.user), сессия $($r.session))"
Check ($r.key -eq 'secret-session-data') 'данные расшифрованы и совпали'
$vaultPid = $r.pid

Write-Host '--- 5. защита, пока приложение открыто ---'
$r = Vm { param($p) AsTester 'ac' "C:\sv\access-check.exe -pid $p"; Done 'ac' | Out-Null; Out 'ac' } @($vaultPid)
Check ($r -match 'EXIT=0') 'access-check из tester: утечек нет'
$r = Vm { (icacls $v) -join ' ' }
Check ($r -notmatch 'vault:') 'у vault нет доступа к метаданным профиля (vault.json, data.enc)'
$r = Vm { (icacls "$v\work") -join ' ' }
Check ($r -match 'vault:') 'у vault есть доступ к рабочей папке'

Write-Host '--- 6. закрытие приложения: снова только шифр, ключ в службе остаётся ---'
$r = Vm {
    Stop-Process -Name standin -Force
    $ok = WaitFor { (Files) -eq 'data.enc,vault.json' } 60
    AsTester 'st' "`"$exe`" status"; Done 'st' | Out-Null
    @{ ok = $ok; files = (Files); st = (Out 'st') }
}
Check $r.ok "после закрытия на диске только шифр (есть: $($r.files))"
Check ($r.st -match 'unlocked') 'status: unlocked (ключ в памяти службы)'

Write-Host '--- 7. повторный run без пароля ---'
$r = Vm {
    AsTester 'run2' "`"$exe`" run telegram"
    $ok = Done 'run2' 60
    @{ ok = $ok; out = (Out 'run2'); prompt = (PromptUp) }
}
Check ($r.out -match 'EXIT=0' -and -not $r.prompt) 'пока разблокировано, пароль не спрашивается'
Vm { Stop-Process -Name standin -Force; WaitFor { (Files) -eq 'data.enc,vault.json' } 60 | Out-Null } | Out-Null

Write-Host '--- 8. автоблокировка (1 минута) ---'
$r = Vm {
    Stop-Service SessionVault
    $c = Get-Content C:\ProgramData\SessionVault\config.json -Raw | ConvertFrom-Json
    $c.idle_minutes = 1
    $c | ConvertTo-Json | Set-Content C:\ProgramData\SessionVault\config.json
    Start-Service SessionVault
    Start-Sleep 2
    AsTester 'run3' "`"$exe`" run telegram"
    @{ prompt = (WaitFor { PromptUp } 30) }
}
Check $r.prompt 'после перезапуска службы снова нужен пароль'
Start-Sleep 3
TypeInVm $MasterPassword
$r = Vm {
    Done 'run3' 90 | Out-Null
    Start-Sleep 2
    Stop-Process -Name standin -Force
    WaitFor { (Files) -eq 'data.enc,vault.json' } 60 | Out-Null
    $start = Get-Date
    $locked = WaitFor { AsTester 'st' "`"$exe`" status"; Done 'st' 20 | Out-Null; (Out 'st') -match '(?m)^locked' } 150
    @{ locked = $locked; secs = [int]((Get-Date) - $start).TotalSeconds }
}
Check $r.locked "хранилище заблокировалось по бездействию (через $($r.secs) с)"

Write-Host '--- 9. сбой службы: приложение гаснет вместе с ней, остаток дошифровывается ---'
Vm { AsTester 'run4' "`"$exe`" run telegram" }
Check (WaitPrompt) 'окно пароля (после блокировки)'
Start-Sleep 3
TypeInVm $MasterPassword
$r = Vm {
    Done 'run4' 90 | Out-Null
    Start-Sleep 2
    $svcPid = (Get-CimInstance Win32_Process -Filter "Name='sessionvault.exe'" | Where-Object { $_.CommandLine -like '* service' }).ProcessId
    Stop-Process -Id $svcPid -Force
    Start-Sleep 4
    @{ appAlive = [bool](Standin); files = (Files) }
}
Check (-not $r.appAlive) 'приложение завершилось вместе со службой (job object)'
Check ($r.files -match 'work' -and $r.files -match 'open') "после сбоя остались открытые данные и маркер ($($r.files))"
Vm { Start-Service SessionVault; Start-Sleep 3; AsTester 'run5' "`"$exe`" run telegram" }
Check (WaitPrompt) 'после сбоя снова запрос пароля'
Start-Sleep 3
TypeInVm $MasterPassword
$r = Vm {
    Done 'run5' 90 | Out-Null
    Start-Sleep 3
    $log = Get-Content C:\ProgramData\SessionVault\service.log -Encoding UTF8 -Raw
    @{ recovered = ($log -match 'дошифровываю'); key = (Get-Content "$v\work\tdata\key_datas" -ErrorAction SilentlyContinue) }
}
Check $r.recovered 'служба заметила остаток и дошифровала'
Check ($r.key -eq 'secret-session-data') 'данные после сбоя не потеряны'
Vm { Stop-Process -Name standin -Force; WaitFor { (Files) -eq 'data.enc,vault.json' } 60 | Out-Null } | Out-Null

Write-Host '--- 10. pipe недоступен чужой учётке ---'
$r = Invoke-Command $a {
    try {
        $p = New-Object IO.Pipes.NamedPipeClientStream('.', 'SessionVault', 'InOut')
        $p.Connect(2000)
        'connected'
    } catch { $_.Exception.GetType().Name }
}
Check ($r -ne 'connected') "svadmin (не основная учётка) не может подключиться к pipe команд ($r)"

Write-Host '--- 11. защита файлов при закрытом приложении ---'
$r = Vm { AsTester 'ac2' 'C:\sv\access-check.exe -pipe'; Done 'ac2' 120 | Out-Null; Out 'ac2' }
Check ($r -match 'EXIT=0') 'access-check (+ пробы pipe) из tester: утечек нет'

if ($fails.Count -eq 0) { Write-Host 'ТЕСТ ПРОЙДЕН'; exit 0 }
Write-Host "ТЕСТ ПРОВАЛЕН ($($fails.Count))"; exit 1
