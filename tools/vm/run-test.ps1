param(
    [string]$VmName = 'sv-test',
    [string]$Checkpoint = 'clean',
    [string]$AdminPassword = 'Sv-Admin-1!',
    [string]$MasterPassword = 'Master-Pass-1',
    [string]$HelloPin = '135790'   # PIN Windows Hello у tester в чекпойнте hello (tools/vm/prepare-hello.ps1)
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
# Hyper-V-клавиатура иногда теряет клавиши: то текст не доходит до поля, то пропадает Enter. Результат ввода
# проверяем по журналу службы (пароль принят или отвергнут) и при необходимости повторяем: Enter, затем заново.
function LogCount($pat = 'неверный пароль|разблокировано') { Invoke-Command $a { param($p) @(Get-Content C:\ProgramData\SessionVault\service.log -Encoding UTF8 -ErrorAction SilentlyContinue | Select-String $p).Count } -ArgumentList $pat }
function PressEnter() {
    Invoke-CimMethod $kb -MethodName PressKey -Arguments @{ keyCode = 13 } | Out-Null
    Invoke-CimMethod $kb -MethodName ReleaseKey -Arguments @{ keyCode = 13 } | Out-Null
}
# Обычный тест (чекпойнт browsers): свежая оболочка перехватывает фокус, поэтому перед вводом кликаем по полю. Проверено в v0.6.
function TypeInVmClick($text) {
    $before = LogCount
    foreach ($step in 'type', 'enter', 'retype', 'enter') {
        ClickPrompt
        if ($step -eq 'retype') {
            foreach ($i in 1..30) {
                Invoke-CimMethod $kb -MethodName PressKey -Arguments @{ keyCode = 8 } | Out-Null
                Invoke-CimMethod $kb -MethodName ReleaseKey -Arguments @{ keyCode = 8 } | Out-Null
            }
        }
        if ($step -ne 'enter') {
            Invoke-CimMethod $kb -MethodName TypeText -Arguments @{ asciiText = $text } | Out-Null
            Start-Sleep -Milliseconds 1500
        }
        PressEnter
        for ($i = 0; $i -lt 8; $i++) {
            Start-Sleep 1
            if ((LogCount) -gt $before) { return }
        }
        Write-Host "  (ввод не дошёл до окна, шаг '$step': повтор)"
    }
}
# Чекпойнт hello (SV_HELLO_ONLY=1): клик по окну там сбивает фокус, поэтому ввод без клика (TypeInVmHello).
function TypeInVm($text) { if ($env:SV_HELLO_ONLY -eq '1') { TypeInVmHello $text } else { TypeInVmClick $text } }
function TypeInVmHello($text) {
    # Верный пароль считается принятым только по «разблокировано»: потерянная клавиша даёт «неверный пароль», и ввод надо повторить.
    $pat = if ($text -eq $MasterPassword) { 'разблокировано' } else { 'неверный пароль|разблокировано' }
    $before = LogCount $pat
    Start-Sleep 5   # процесс помощника появляется раньше окна: ввод в этот промежуток теряется
    # Первая клавиша в только что созданное окно может потеряться: приносим в жертву безвредную (Home), пароль вводится следом.
    Invoke-CimMethod $kb -MethodName PressKey -Arguments @{ keyCode = 36 } | Out-Null
    Invoke-CimMethod $kb -MethodName ReleaseKey -Arguments @{ keyCode = 36 } | Out-Null
    Start-Sleep -Milliseconds 700
    foreach ($step in 'type', 'retype', 'retype') {
        # Повтор: поле очищается и пароль вводится заново (клик не нужен: окно само активно, а в чекпойнте hello клик сбивает фокус).
        if ($step -eq 'retype') {
            foreach ($i in 1..30) {
                Invoke-CimMethod $kb -MethodName PressKey -Arguments @{ keyCode = 8 } | Out-Null
                Invoke-CimMethod $kb -MethodName ReleaseKey -Arguments @{ keyCode = 8 } | Out-Null
            }
        }
        Invoke-CimMethod $kb -MethodName TypeText -Arguments @{ asciiText = $text } | Out-Null
        Start-Sleep -Milliseconds 1500
        PressEnter
        for ($i = 0; $i -lt 8; $i++) {
            Start-Sleep 1
            if ((LogCount $pat) -gt $before) { return }
        }
        Write-Host "  (ввод не дошёл до окна, шаг '$step': повтор)"
    }
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
function HelloUp() { [bool](Get-CimInstance Win32_Process -Filter "Name='sessionvault.exe'" | Where-Object { $_.CommandLine -like '* hello-*' }) }
function PromptUp() { [bool](Get-CimInstance Win32_Process -Filter "Name='sessionvault.exe'" | Where-Object { $_.CommandLine -like '* prompt *' }) }
function Files() { (Get-ChildItem $v -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin 'running.lock', 'data.enc.bak' } | ForEach-Object { $_.FullName.Substring($v.Length + 1) }) -join ',' }
function Standin() { Get-Process standin -IncludeUserName -ErrorAction SilentlyContinue | Select-Object -First 1 }
'@
function Vm($block, $ar = @()) {
    Invoke-Command $a -ScriptBlock { param($h, $b, $x) . ([scriptblock]::Create($h)); & ([scriptblock]::Create($b)) @x } -ArgumentList $helpers, $block.ToString(), $ar
}
function WaitPrompt() { Vm { WaitFor { PromptUp } 40 } }

# --- Windows Hello (чекпойнт hello: у tester настроен PIN) ---
# Окна Hello показывает помощник под пользователем; PIN вводится клавиатурой ВМ.
function HelloPin($name) {
    for ($i = 0; $i -lt 4; $i++) {
        Start-Sleep 7
        Invoke-CimMethod $kb -MethodName TypeText -Arguments @{ asciiText = $HelloPin } | Out-Null
        Start-Sleep -Milliseconds 800
        PressEnter
        Start-Sleep 4
        if (Vm { param($n) (Out $n) -match 'EXIT=' } @($name)) { return }
    }
}
function HelloBlock() {
    Write-Host '--- 11b. вход через Windows Hello ---'
    # Слот Hello создаётся офлайн, без окон пароля: секрет получает hello-spike в сеансе tester (жест — PIN),
    # мастер-пароль идёт на stdin. Включение через окно пароля и команду hello проверяется вручную.
    $challenge = '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'
    Copy-Item "$PSScriptRoot\ipc-call.ps1" -Destination C:\sv\ -ToSession $a
    Copy-Item "$dist\hello-spike.exe" -Destination C:\sv\ -ToSession $a
    Vm { param($c) AsTester 'hs' "C:\sv\hello-spike.exe secret $c" } @($challenge)
    HelloPin 'hs'
    $sec = ([regex]::Match((Vm { Out 'hs' }), 'secret=([0-9a-f]+)')).Groups[1].Value
    Check ($sec.Length -ge 256) "hello: секрет получен от ключа Windows Hello ($($sec.Length / 2) байт)"
    $r = Vm { param($pw, $c, $s) $o = $pw | & C:\sv\hello-spike.exe enable telegram $c $s 2>&1 | Out-String; @{ out = ($o -replace '\s+', ' '); hello = ((Get-Content "$v\vault.json" -Raw | ConvertFrom-Json).Hello.Name) } } @($MasterPassword, $challenge, $sec)
    Check ($r.hello -eq 'SessionVault') "hello: слот записан в vault.json ($($r.out))"

    Vm { Restart-Service SessionVault; Start-Sleep 3; AsTester 'rh' "`"$exe`" run telegram" }
    Check (Vm { WaitFor { HelloUp } 40 }) 'run после блокировки открывает окно Windows Hello (помощник под токеном пользователя)'
    Check (-not (Vm { PromptUp })) 'окно мастер-пароля при этом не показано'
    HelloPin 'rh'
    $r = Vm {
        Done 'rh' 90 | Out-Null
        Start-Sleep 3
        @{ out = ((Out 'rh') -replace '\s+', ' '); user = (Standin).UserName; log = [bool](Get-Content C:\ProgramData\SessionVault\service.log -Tail 40 -Encoding UTF8 | Select-String 'через Windows Hello') }
    }
    Check ($r.out -match 'ok' -and $r.user -like '*\vault') "Hello открыл хранилище без пароля, приложение от vault ($($r.out))"
    Check $r.log 'служба записала в журнал разблокировку через Windows Hello'
    Vm { Stop-Process -Name standin -Force; WaitFor { (Files) -eq 'data.enc,vault.json' } 60 | Out-Null } | Out-Null

    # Отмена Hello: вместо окна пароля сразу не должно быть ничего лишнего, затем открывается окно пароля.
    Vm { Restart-Service SessionVault; Start-Sleep 3; AsTester 'rc' "`"$exe`" run telegram" }
    Check (Vm { WaitFor { HelloUp } 40 }) 'отмена Hello: окно Hello показано'
    Start-Sleep 8
    Invoke-CimMethod $kb -MethodName PressKey -Arguments @{ keyCode = 27 } | Out-Null
    Invoke-CimMethod $kb -MethodName ReleaseKey -Arguments @{ keyCode = 27 } | Out-Null
    Check (WaitPrompt) 'после отмены Hello открывается окно мастер-пароля (запасной способ)'
    Vm { Get-Process sessionvault -ErrorAction SilentlyContinue | Where-Object { (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine -like '* prompt *' } | Stop-Process -Force; Restart-Service SessionVault; Start-Sleep 3 } | Out-Null

    # Таймаут: жеста нет. Помощник сам отменяет операцию (70 с), окно Hello закрывается, затем открывается окно пароля.
    Copy-Item "$PSScriptRoot\enum-windows.ps1" -Destination C:\sv\ -ToSession $a
    Vm { Restart-Service SessionVault; Start-Sleep 3; AsTester 'rt' "`"$exe`" run telegram" }
    Check (Vm { WaitFor { HelloUp } 40 }) 'таймаут Hello: окно Hello показано'
    Check (Vm { WaitFor { PromptUp } 120 }) 'таймаут Hello: без жеста открывается окно мастер-пароля'
    $w = Vm { AsTester 'ew' 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\sv\enum-windows.ps1'; Done 'ew' 40 | Out-Null; Out 'ew' }
    Check ($w -notmatch 'Credential Dialog Xaml Host') 'таймаут Hello: окно Hello закрыто, а не осталось висеть на экране'
    Vm { Get-Process sessionvault -ErrorAction SilentlyContinue | Where-Object { (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine -like '* prompt *' } | Stop-Process -Force; Restart-Service SessionVault; Start-Sleep 3 } | Out-Null

    $r = Vm { $o = & $exe hello disable 2>&1 | Out-String; @{ out = ($o -replace '\s+', ' '); hello = ((Get-Content "$v\vault.json" -Raw | ConvertFrom-Json).Hello) } }
    Check ($null -eq $r.hello) "hello disable убрал слот ($($r.out))"
    Vm { Restart-Service SessionVault; Start-Sleep 3 }

    # Включение через службу, как из трея: мастер-пароль, затем Hello создаёт ключ (прежний удалён) и подписывает challenge.
    Vm { AsTester 'hd' 'C:\sv\hello-spike.exe delete' } | Out-Null
    Vm { Done 'hd' 40 | Out-Null } | Out-Null
    Vm { Restart-Service SessionVault; Start-Sleep 3; AsTester 'he' 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\sv\ipc-call.ps1 "hello telegram"' }
    Check (WaitPrompt) 'включение Hello: служба просит мастер-пароль'
    TypeInVm $MasterPassword
    Check (Vm { WaitFor { HelloUp } 40 }) 'включение Hello: помощник показал окно Windows Hello'
    HelloPin 'he'
    $r = Vm { Done 'he' 60 | Out-Null; @{ out = ((Out 'he') -replace '\s+', ' '); hello = ((Get-Content "$v\vault.json" -Raw | ConvertFrom-Json).Hello.Name) } }
    Check ($r.out -match 'ok' -and $r.hello -eq 'SessionVault') "включение Hello через службу: ключ создан, слот записан ($($r.out))"
    Vm { Restart-Service SessionVault; Start-Sleep 3; AsTester 'rn' "`"$exe`" run telegram" }
    Check (Vm { WaitFor { HelloUp } 40 }) 'новый слот: окно Hello показано'
    HelloPin 'rn'
    $r = Vm { Done 'rn' 90 | Out-Null; Start-Sleep 3; @{ out = ((Out 'rn') -replace '\s+', ' '); user = (Standin).UserName } }
    Check ($r.out -match 'ok' -and $r.user -like '*\vault') 'слот, созданный службой, открывает хранилище'
    Vm { Stop-Process -Name standin -Force; WaitFor { (Files) -eq 'data.enc,vault.json' } 60 | Out-Null } | Out-Null
    Vm { & $exe hello disable 2>&1 | Out-Null; Restart-Service SessionVault; Start-Sleep 3 } | Out-Null
}


Write-Host '--- 1. установка службы ---'
$r = Vm {
    param($tg)
    $env:SESSIONVAULT_SKIP_SIGNATURE = '1'
    $out = & C:\sv\sessionvault.exe install -user tester -telegram-exe $tg 2>&1
    Start-Sleep 3
    @{ out = ($out -join ' '); svc = (Get-Service SessionVault).Status.ToString(); exe = (Test-Path $exe) }
} @('C:\sv\standin.exe')
Check ($r.svc -eq 'Running') "служба запущена ($($r.svc)); $($r.out)"
Check $r.exe 'бинарник в Program Files'
$r = Vm {
    secedit /export /cfg C:\sv\sec.inf /areas USER_RIGHTS | Out-Null
    $sid = (New-Object Security.Principal.NTAccount('vault')).Translate([Security.Principal.SecurityIdentifier]).Value
    $t = Get-Content C:\sv\sec.inf
    @{ net = [bool]($t -match "SeDenyNetworkLogonRight.*(\*$sid|\bvault\b)"); rdp = [bool]($t -match "SeDenyRemoteInteractiveLogonRight.*(\*$sid|\bvault\b)") }
}
Check ($r.net -and $r.rdp) 'vault: сетевой и удалённый вход запрещены'

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
$r = Vm { $m = Get-Content "$v\vault.json" -Raw | ConvertFrom-Json; $h = [IO.File]::ReadAllBytes("$v\data.enc")[0..3]; @{ ver = $m.Version; cnt = $m.Counter; magic = [Text.Encoding]::ASCII.GetString($h) } }
Check ($r.ver -eq 2 -and $r.cnt -eq 1 -and $r.magic -eq 'SVD2') "хранилище версии 2: счётчик записей $($r.cnt), заголовок $($r.magic)"

if ($env:SV_HELLO_ONLY -eq '1') {
    HelloBlock
    if ($fails.Count -eq 0) { Write-Host 'ТЕСТ HELLO ПРОЙДЕН'; exit 0 }
    Write-Host "ТЕСТ HELLO ПРОВАЛЕН ($($fails.Count))"; exit 1
}
Write-Host '--- 3. status до разблокировки ---'
$r = Vm { AsTester 'st' "`"$exe`" status"; Done 'st' | Out-Null; Out 'st' }
Check ($r -match '(?m)^locked') "status: locked ($("$r" -replace '\s+',' '))"

# Отладка: SV_STOP_BEFORE=4 оставляет ВМ в состоянии перед блоком 4 (служба установлена, tdata перенесена).
if ($env:SV_STOP_BEFORE -eq '4') { Write-Host 'остановлено перед блоком 4'; exit 0 }
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
    @{ prompt = (WaitFor { PromptUp } 40) }
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

if ($env:SV_HELLO -eq '1') { HelloBlock } else { Write-Host '--- 11b. Windows Hello: пропущено (нужен чекпойнт hello, SV_HELLO=1) ---' }

Write-Host '--- 12. трей ---'
$r = Vm {
    $act = New-ScheduledTaskAction -Execute $exe -Argument 'tray'
    $pr = New-ScheduledTaskPrincipal -UserId 'SV-TEST\tester' -LogonType Interactive
    Register-ScheduledTask -TaskName 'svt-tray' -Action $act -Principal $pr -Force | Out-Null
    Start-ScheduledTask -TaskName 'svt-tray'
    Start-Sleep 5
    Start-ScheduledTask -TaskName 'svt-tray'   # второй экземпляр должен тихо выйти
    Start-Sleep 4
    $tray = @(Get-CimInstance Win32_Process -Filter "Name='sessionvault.exe'" | Where-Object { $_.CommandLine -match 'sessionvault.exe"?\s+tray' })
    $sid = (Get-LocalUser tester).SID.Value
    $icon = Get-ChildItem "Registry::HKEY_USERS\$sid\Control Panel\NotifyIconSettings" -ErrorAction SilentlyContinue |
        Where-Object { (Get-ItemProperty $_.PSPath).ExecutablePath -like '*sessionvault.exe' }
    @{ count = $tray.Count; session = $tray[0].SessionId; icon = [bool]$icon }
}
Check ($r.count -eq 1 -and $r.session -ne 0) "трей запущен в сессии пользователя, второй экземпляр не плодится ($($r.count))"
Check $r.icon 'Windows зарегистрировала иконку в области уведомлений'
Vm {
    $ps1 = @'
Add-Type @"
using System; using System.Runtime.InteropServices;
public class W { [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string c, string t);
 [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l); }
"@
$h = [IntPtr]::Zero
for ($i = 0; $i -lt 40 -and $h -eq [IntPtr]::Zero; $i++) { $h = [W]::FindWindow('SessionVaultTray', 'SessionVault'); Start-Sleep -Milliseconds 500 }
[void][W]::PostMessage($h, 0x111, [IntPtr]1001, [IntPtr]0)
'@
    Set-Content C:\sv\menu.ps1 $ps1 -Encoding UTF8
    $act = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument '--headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\sv\menu.ps1'
    $pr = New-ScheduledTaskPrincipal -UserId 'SV-TEST\tester' -LogonType Interactive
    Register-ScheduledTask -TaskName 'svt-menu' -Action $act -Principal $pr -Force | Out-Null
    # Пункт меню «Запустить Telegram» = команда 1001 окну трея.
    Start-ScheduledTask -TaskName 'svt-menu'
} | Out-Null
$prompted = WaitPrompt
if ($prompted) { Start-Sleep 3; TypeInVm $MasterPassword }
$r = Vm {
    $up = WaitFor { Standin } 40
    Start-Sleep 1
    @{ up = $up; user = (Standin).UserName }
}
Check ($r.up -and $r.user -like '*\vault') "пункт меню трея запустил приложение от vault ($($r.user))"
Vm { Stop-Process -Name standin -Force; WaitFor { (Files) -eq 'data.enc,vault.json' } 60 | Out-Null } | Out-Null

Write-Host '--- 13. приманка на прежнем месте tdata ---'
# Проверки приманки читают только атрибуты и права: любое чтение содержимого или списка файлов (даже администратором) — тревога.
$dec = 'C:\Users\tester\AppData\Roaming\TestTelegram\tdata'
$r = Vm {
    param($d)
    $up = WaitFor { Test-Path "$d\key_datas" } 60
    Start-Sleep 2
    $len = (Get-Item "$d\key_datas" -ErrorAction SilentlyContinue).Length
    @{
        up = $up; len = $len; owner = (Get-Acl $d).Owner
        parts = @('D877F783D5D3EF8Cs', 'D877F783D5D3EF8C\maps', 'settingss', 'usertag' | ForEach-Object { Test-Path "$d\$_" }) -notcontains $false
        sacl = $(try { @((Get-Acl $d -Audit -ErrorAction Stop).Audit).Count -gt 0 } catch { $false })
        policy = ((auditpol /get /subcategory:"File System") -join ' ')
        alerts = (Test-Path C:\ProgramData\SessionVault\alerts.log)
        key = (Test-Path "C:\ProgramData\SessionVault\vault\telegram\work\tdata\key_datas")
    }
} @($dec)
Check ($r.up -and $r.len -ge 1500 -and $r.len -le 3500 -and $r.parts) "приманка появилась, структура как у tdata (key_datas $($r.len) Б)"
Check ($r.owner -like '*tester') "владелец приманки — основная учётка ($($r.owner))"
Check $r.sacl 'на приманке стоит аудит чтения (SACL)'
Check ($r.policy -match 'Success|Успех') 'политика аудита файловой системы включена'
Check (-not $r.alerts) 'ложных тревог нет (Defender и оболочка приманку не задели)'

Write-Host '  белый список: процесс из config.json читает приманку без тревоги'
$r = Vm {
    param($d)
    Stop-Service SessionVault
    $c = Get-Content C:\ProgramData\SessionVault\config.json -Raw | ConvertFrom-Json
    $c | Add-Member -NotePropertyName decoy_allow -NotePropertyValue @(@{ path = 'C:\Program Files\SessionVault\ac-allowed.exe' }) -Force
    $c | ConvertTo-Json -Depth 5 | Set-Content C:\ProgramData\SessionVault\config.json
    Copy-Item C:\sv\access-check.exe 'C:\Program Files\SessionVault\ac-allowed.exe'
    Start-Service SessionVault
    Start-Sleep 4
    AsTester 'okc' "`"C:\Program Files\SessionVault\ac-allowed.exe`" -decoy `"$d`""
    Done 'okc' 30 | Out-Null
    Start-Sleep 5
    @{ out = (Out 'okc'); alerts = (Test-Path C:\ProgramData\SessionVault\alerts.log) }
} @($dec)
Check ($r.out -match 'приманка прочитана') "процесс из белого списка прочитал приманку ($("$($r.out)" -replace '\s+',' '))"
Check (-not $r.alerts) 'тревоги нет'

Write-Host '  тревога: стилер-имитация читает приманку, пока приложение открыто'
Vm { AsTester 'run6' "`"$exe`" run telegram" }
Check (WaitPrompt) 'окно пароля (после перезапуска службы)'
Start-Sleep 3
TypeInVm $MasterPassword
$r = Vm { Done 'run6' 90 | Out-Null; @{ up = [bool](WaitFor { Standin } 30) } }
Check $r.up 'приложение запущено от vault'
$r = Vm {
    param($d)
    AsTester 'dc' "C:\sv\access-check.exe -decoy `"$d`""
    WaitFor { (Out 'dc') -match 'READ_AT=\d+' } 30 | Out-Null
    $readAt = [int64][regex]::Match((Out 'dc'), 'READ_AT=(\d+)').Groups[1].Value
    $end = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $end -and (Standin)) { Start-Sleep -Milliseconds 20 }
    $deadAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $appDead = -not (Standin)
    $enc = WaitFor { (Files) -eq 'data.enc,vault.json' } 30
    $lockedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    AsTester 'st' "`"$exe`" status"; Done 'st' | Out-Null
    $line = Get-Content C:\ProgramData\SessionVault\alerts.log -Encoding UTF8 -ErrorAction SilentlyContinue | Select-Object -First 1
    $win = @(Get-CimInstance Win32_Process -Filter "Name='sessionvault.exe'" | Where-Object { $_.CommandLine -like '* alert *' })
    @{ ms = ($deadAt - $readAt); appDead = $appDead; enc = $enc; files = (Files); st = (Out 'st'); line = $line; win = $win.Count; winSession = $win[0].SessionId; lockedMs = ($lockedAt - $readAt) }
} @($dec)
Check ($r.appDead -and $r.ms -lt 2000) "приложение закрыто через $($r.ms) мс после чтения приманки (нужно < 2000)"
Check $r.enc "данные зашифрованы обратно (через $($r.lockedMs) мс; на диске: $($r.files))"
Check ($r.st -match '(?m)^alarm') "status: alarm ($("$($r.st)" -replace '\s+',' '))"
Check ($r.line -match 'access-check\.exe' -and $r.line -match '[0-9a-f]{64}') "в журнале тревог процесс, путь и SHA-256: $($r.line)"
Check ($r.win -ge 1 -and $r.winSession -ne 0) "окно тревоги показано в сессии пользователя ($($r.win), сессия $($r.winSession))"
& "$PSScriptRoot\screenshot.ps1" -VmName $VmName -Path "$env:TEMP\sv-alarm.png" | Out-Null
Write-Host "  снимок экрана: $env:TEMP\sv-alarm.png"
Vm { Get-CimInstance Win32_Process -Filter "Name='sessionvault.exe'" | Where-Object { $_.CommandLine -like '* alert *' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force } } | Out-Null

Write-Host '  после тревоги служба работает: хранилище заблокировано, запуск снова просит пароль'
Vm { AsTester 'run7' "`"$exe`" run telegram" }
Check (WaitPrompt) 'окно пароля после тревоги'
Start-Sleep 3
TypeInVm $MasterPassword
$r = Vm {
    Done 'run7' 90 | Out-Null
    $up = WaitFor { Standin } 30
    Start-Sleep 2
    @{ up = [bool]$up; key = (Get-Content "C:\ProgramData\SessionVault\vault\telegram\work\tdata\key_datas" -ErrorAction SilentlyContinue) }
}
Check ($r.up -and $r.key -eq 'secret-session-data') 'после тревоги приложение снова запускается, данные целы'
Vm { Stop-Process -Name standin -Force; WaitFor { (Files) -eq 'data.enc,vault.json' } 60 | Out-Null } | Out-Null

function BrowserTest($app, $title, $exePath, $proc, $originRel, $required) {
    Write-Host "--- 14. браузер ${title}: protect, запуск от vault, шифрование, приманка ---"
    $origin = "C:\Users\tester\$originRel"
    $r = Vm { param($e) @{ ok = (Test-Path $e) } } @($exePath)
    if (-not $r.ok -and -not $required) { Write-Host "  пропуск: $title не установлен в ВМ"; return }
    Check $r.ok "$title установлен в ВМ"
    if (-not $r.ok) { return }
    # Предыдущая тревога блокирует разбор новых на 30 секунд (одна серия чтений = одна тревога).
    Start-Sleep 35
    Invoke-Command $a {
        param($o)
        $d = "$o\Default"
        New-Item -ItemType Directory -Force $d | Out-Null
        Set-Content "$d\Cookies" 'old-cookie'
    } -ArgumentList $origin
    $r = Vm {
        param($pw, $app, $o)
        # Подпись браузера проверяется по-настоящему: пропуск проверки нужен только подставному Telegram.
        Remove-Item Env:SESSIONVAULT_SKIP_SIGNATURE -ErrorAction SilentlyContinue
        # exe собран для подсистемы Windows: без конвейера PowerShell его не дожидается.
        $out = $pw | & C:\sv\sessionvault.exe protect $app -yes -password-stdin 2>&1 | Out-String
        $code = $LASTEXITCODE
        $ve = "C:\ProgramData\SessionVault\vault\$app"
        @{ code = $code; out = ($out -replace '\s+', ' ')
           files = (Get-ChildItem $ve -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin 'running.lock', 'data.enc.bak' } | ForEach-Object { $_.FullName.Substring($ve.Length + 1) }) -join ','
           aside = (Test-Path "$o.sessionvault-delete")
           oldCookie = (Test-Path "$o\Default\Cookies") }
    } @($MasterPassword, $app, $origin)
    Check ($r.code -eq 0) "protect $app завершился успешно"
    Check ($r.files -eq 'data.enc,vault.json') "в хранилище $title только шифр (есть: $($r.files))"
    Check (-not $r.aside -and -not $r.oldCookie) "прежний профиль $title удалён из основной учётки"
    $r = Vm {
        param($o)
        # Файлы приманки создаются по очереди: ждём последний и владельца. Содержимое не читаем: это настоящая тревога.
        $ok = WaitFor { Test-Path "$o\Default\Network\Cookies" } 90
        Start-Sleep 3
        $c = Get-Item "$o\Default\Network\Cookies" -ErrorAction SilentlyContinue
        @{ ok = $ok; size = $c.Length; old = (Test-Path "$o\Default\Cookies"); owner = (Get-Acl $o).Owner }
    } @($origin)
    Check ($r.ok -and $r.size -ge 24576 -and -not $r.old) "приманка Chromium на месте прежнего профиля (Cookies $($r.size) Б)"
    Check ($r.owner -like '*\tester') "владелец приманки — основная учётка ($($r.owner))"

    Write-Host "  запуск $title от vault"
    Vm { param($app) AsTester 'runB' "`"$exe`" run $app" } @($app)
    Check (WaitPrompt) "окно пароля для $title"
    Start-Sleep 3
    TypeInVm $MasterPassword
    $r = Vm {
        param($app, $proc)
        Done 'runB' 90 | Out-Null
        $up = WaitFor { [bool](Get-Process $proc -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -like '*\vault' }) } 60
        $ud = "C:\ProgramData\SessionVault\vault\$app\work\User Data"
        $ok = WaitFor { Test-Path "$ud\Local State" } 60
        Start-Sleep 5
        $cl = (Get-CimInstance Win32_Process -Filter "Name='$proc.exe'" | Select-Object -First 1).CommandLine
        $vp = (Get-Process $proc -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -like '*\vault' } | Select-Object -First 1).Id
        if ($ok) { Set-Content "$ud\marker.txt" 'browser-session-marker' }
        @{ out = (Out 'runB'); up = [bool]$up; profile = $ok; cmd = $cl; vp = $vp }
    } @($app, $proc)
    Check ($r.out -match 'ok' -and $r.up) "$title запущен от vault ($("$($r.out)" -replace '\s+',' '))"
    Check ($r.profile -and $r.cmd -like "*vault\$app\work\User Data*") "$title работает с профилем в защищённой папке"

    # Пока браузер работает, обычная учётка не должна дотянуться ни до файлов, ни до памяти его процесса.
    $ac = Vm {
        param($app, $vp)
        $ve = "C:\ProgramData\SessionVault\vault\$app"
        AsTester 'acB' "C:\sv\access-check.exe -file `"$ve\work\User Data\Local State`" -enc `"$ve\data.enc`" -meta `"$ve\vault.json`" -pid $vp"
        Done 'acB' 120 | Out-Null
        Out 'acB'
    } @($app, $r.vp)
    Check ($ac -match 'EXIT=0') "access-check при работающем ${title}: утечек нет ($((($ac -split "`n") | Where-Object { $_ -match 'УТЕЧКА' }) -join '; '))"

    $r = Vm {
        param($app, $proc)
        Get-Process $proc -ErrorAction SilentlyContinue | Stop-Process -Force
        $ve = "C:\ProgramData\SessionVault\vault\$app"
        $enc = WaitFor { -not (Test-Path "$ve\work") -and (Test-Path "$ve\data.enc") } 60
        @{ enc = $enc; left = @(Get-Process $proc -ErrorAction SilentlyContinue).Count }
    } @($app, $proc)
    Check ($r.enc -and $r.left -eq 0) "после закрытия $title данные зашифрованы, фоновых процессов нет"

    # Ссылка открывается в первом защищённом браузере из chrome, edge, brave: при запертом хранилище служба сама просит пароль.
    $link = ($app -ne 'brave')
    if ($link) { Write-Host '  повторный запуск через sessionvault open: данные сохранились' } else { Write-Host '  повторный запуск: данные сохранились' }
    $cmdB = if ($link) { "open https://example.com/sv-open-$app" } else { "run $app" }
    Vm { param($c) AsTester 'runB2' "`"$exe`" $c" } @($cmdB)
    $r = Vm {
        param($app, $proc)
        Done 'runB2' 90 | Out-Null
        $up = WaitFor { [bool](Get-Process $proc -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -like '*\vault' }) } 60
        Start-Sleep 3
        @{ out = (Out 'runB2'); up = [bool]$up; marker = (Get-Content "C:\ProgramData\SessionVault\vault\$app\work\User Data\marker.txt" -ErrorAction SilentlyContinue) }
    } @($app, $proc)
    Check ($r.up -and $r.marker -eq 'browser-session-marker') "профиль $title сохранился между запусками ($("$($r.out)" -replace '\s+',' '))"
    if ($link) {
        $r = Vm {
            param($proc, $app)
            $c = (Get-CimInstance Win32_Process -Filter "Name='$proc.exe'" | Where-Object { $_.CommandLine -like "*sv-open-$app*" } | Select-Object -First 1).CommandLine
            # Браузер уже запущен: вторая ссылка не требует пароля, Chromium открывает вкладку в работающем экземпляре.
            AsTester 'openB' "`"$exe`" open https://example.com/sv-open2-$app"; Done 'openB' 30 | Out-Null
            AsTester 'openBad' "`"$exe`" open --remote-debugging-port=9222"; Done 'openBad' 30 | Out-Null
            AsTester 'openBad2' "`"$exe`" open file:///C:/Windows/win.ini"; Done 'openBad2' 30 | Out-Null
            @{ first = $c; second = (Out 'openB'); bad = (Out 'openBad'); bad2 = (Out 'openBad2'); prompt = (PromptUp) }
        } @($proc, $app)
        Check ($r.first -like "*sv-open-$app*") "ссылка передана браузеру $title в командной строке запуска"
        Check ($r.second -match 'ok' -and -not $r.prompt) "вторая ссылка открыта без нового окна пароля ($("$($r.second)" -replace '\s+',' '))"
        Check ($r.bad -notmatch 'EXIT=0' -and $r.bad2 -notmatch 'EXIT=0') 'ссылки не http(s) отклонены клиентом'
    }

    Write-Host "  тревога: стилер-имитация читает приманку $title"
    $before = Vm { @(Get-Content C:\ProgramData\SessionVault\alerts.log -Encoding UTF8 -ErrorAction SilentlyContinue).Count }
    $r = Vm {
        param($d, $app, $proc)
        AsTester 'dcB' "C:\sv\access-check.exe -decoy `"$d`""
        WaitFor { (Out 'dcB') -match 'READ_AT=\d+' } 30 | Out-Null
        $dead = WaitFor { -not (Get-Process $proc -ErrorAction SilentlyContinue) } 20
        $ve = "C:\ProgramData\SessionVault\vault\$app"
        $enc = WaitFor { -not (Test-Path "$ve\work") -and (Test-Path "$ve\data.enc") } 40
        AsTester 'stB' "`"$exe`" status"; Done 'stB' | Out-Null
        @{ dead = $dead; enc = $enc; st = (Out 'stB'); alerts = @(Get-Content C:\ProgramData\SessionVault\alerts.log -Encoding UTF8 -ErrorAction SilentlyContinue).Count }
    } @($origin, $app, $proc)
    Check ($r.dead -and $r.enc) "тревога по приманке ${title}: браузер закрыт, данные зашифрованы"
    Check ($r.st -match '(?m)^alarm' -and $r.alerts -gt $before) "status: alarm и новая запись в журнале тревог ($($before) -> $($r.alerts))"
    $alertsBefore = $r.alerts
    Vm { Get-CimInstance Win32_Process -Filter "Name='sessionvault.exe'" | Where-Object { $_.CommandLine -like '* alert *' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force } } | Out-Null

    Write-Host "  обычный $title основной учётки не вызывает тревогу"
    $r = Vm {
        param($e, $o, $proc)
        AsTester 'userB' "`"$e`" --headless --disable-gpu --user-data-dir=`"$o`" about:blank"
        Start-Sleep 12
        Get-Process $proc -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep 3
        @{ alerts = @(Get-Content C:\ProgramData\SessionVault\alerts.log -Encoding UTF8 -ErrorAction SilentlyContinue).Count }
    } @($exePath, $origin, $proc)
    Check ($r.alerts -eq $alertsBefore) "чтение профиля подписанным $title не создало новых тревог ($($r.alerts) = $alertsBefore)"
}

$browsers = @(
    @{ app = 'edge'; title = 'Microsoft Edge'; exePath = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'; proc = 'msedge'; originRel = 'AppData\Local\Microsoft\Edge\User Data'; required = $true },
    @{ app = 'chrome'; title = 'Google Chrome'; exePath = 'C:\Program Files\Google\Chrome\Application\chrome.exe'; proc = 'chrome'; originRel = 'AppData\Local\Google\Chrome\User Data'; required = $false },
    @{ app = 'brave'; title = 'Brave'; exePath = 'C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe'; proc = 'brave'; originRel = 'AppData\Local\BraveSoftware\Brave-Browser\User Data'; required = $false }
)
foreach ($b in $browsers) { BrowserTest @b }

Write-Host '--- 15. попытки обычной учётки обойти защиту ---'
# Хранилище после тревоги заблокировано: спам run должен дать одно окно пароля, а не десять.
$r = Vm {
    1..12 | ForEach-Object { AsTester "sp$_" "`"$exe`" run telegram" }
    Start-Sleep 12
    $n = @(Get-CimInstance Win32_Process -Filter "Name='sessionvault.exe'" | Where-Object { $_.CommandLine -like '* prompt *' }).Count
    $busy = 0
    1..12 | ForEach-Object { if ((Out "sp$_") -match 'busy') { $busy++ } }
    Get-CimInstance Win32_Process -Filter "Name='sessionvault.exe'" | Where-Object { $_.CommandLine -like '* prompt *' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    Start-Sleep 5
    @{ prompts = $n; busy = $busy }
}
Check ($r.prompts -le 1) "12 запросов run подряд дали окон пароля: $($r.prompts) (должно быть не больше одного), ответов busy: $($r.busy)"

# Прямой запуск помощника launch: пароль vault читает только SYSTEM.
$r = Vm {
    AsTester 'ln' "`"$exe`" launch telegram"
    Done 'ln' 30 | Out-Null
    @{ out = (Out 'ln'); vaultProc = @(Get-Process standin -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -like '*\vault' }).Count }
}
Check ($r.out -notmatch 'EXIT=0' -and $r.vaultProc -eq 0) "launch из обычной учётки не запускает приложение ($("$($r.out)" -replace '\s+',' '))"

# Метаданные службы закрыты для обычной учётки.
$r = Vm {
    AsTester 'rd' 'cmd /c type C:\ProgramData\SessionVault\profiles\telegram.json & type C:\ProgramData\SessionVault\config.json & type C:\ProgramData\SessionVault\vault.pwd'
    Done 'rd' 30 | Out-Null
    Out 'rd'
}
Check ($r -notmatch 'main_user' -and $r -notmatch 'launch_args') "profiles, config.json и vault.pwd недоступны обычной учётке"

# Список защищённых приложений для трея: только имена.
$r = Vm {
    $ps1 = @'
$p = New-Object IO.Pipes.NamedPipeClientStream('.', 'SessionVault', [IO.Pipes.PipeAccessRights]'ReadData,WriteData', [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::None, [IO.HandleInheritability]::None)
$p.Connect(5000)
$w = New-Object IO.StreamWriter($p); $w.WriteLine('list'); $w.Flush()
(New-Object IO.StreamReader($p)).ReadLine()
'@
    Set-Content C:\sv\list.ps1 $ps1 -Encoding UTF8
    AsTester 'ls' 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\sv\list.ps1'
    Done 'ls' 30 | Out-Null
    Out 'ls'
}
Check ($r -match 'telegram' -and $r -match 'edge' -and $r -notmatch '\\' -and $r -notmatch ':') "list отдаёт только имена профилей ($("$r" -replace '\s+',' '))"

# Проверка защиты: отчёт приходит от службы, check.json для обычной учётки закрыт.
$r = Vm {
    AsTester 'ck' '"C:\Program Files\SessionVault\sessionvault.exe" check -json'
    Done 'ck' 60 | Out-Null
    $json = (Out 'ck') -replace 'EXIT=\d+', ''
    AsTester 'ckf' 'type C:\ProgramData\SessionVault\check.json'
    Done 'ckf' 30 | Out-Null
    @{ json = $json; file = (Out 'ckf'); starts = @(Select-String -Path C:\ProgramData\SessionVault\service.log -Pattern 'проверка защиты выполнена' -Encoding UTF8).Count; saved = (Test-Path C:\ProgramData\SessionVault\check.json) }
}
$rep = try { $r.json | ConvertFrom-Json } catch { $null }
$ids = if ($rep) { ($rep.items | ForEach-Object { $_.id }) -join ',' } else { '' }
Check ($rep -and $ids -match 'user,windows,defender,bitlocker,hvci,secureboot,blocklist,audit,harden,hello,telegram') "check -json: отчёт от службы со всеми пунктами ($ids)"
Check ($rep -and ($rep.items | Where-Object { $_.id -eq 'user' }).level -eq 'ok' -and ($rep.items | Where-Object { $_.id -eq 'audit' }).level -eq 'ok') "check: основная учётка не админ, аудит работает"
Check ($rep -and ($rep.items | Where-Object { $_.id -eq 'hvci' }).level -eq 'warn') "check: выключенная HVCI найдена (жёлтый пункт)"
Check ($r.saved -and $r.file -notmatch 'items') "check.json создан и недоступен обычной учётке"
Check ($r.starts -ge 1) "в service.log есть запись о проверке при старте ($($r.starts))"

# Подмена пути приманки ссылкой: SYSTEM не должен ставить аудит на чужую папку.
$r = Vm {
    $edgeDir = 'C:\Users\tester\AppData\Local\Microsoft\Edge'
    [IO.Directory]::CreateDirectory('C:\sv\jt\User Data') | Out-Null
    Set-Content 'C:\sv\jt\file.txt' 'x'
    cmd /c "rmdir /s /q `"$edgeDir`"" | Out-Null
    cmd /c "mklink /J `"$edgeDir`" C:\sv\jt" | Out-Null
    # Проверка раз в 5 минут: просим службу проверить сейчас тем же событием, что и protect.
    $ev = [Threading.EventWaitHandle]::OpenExisting('Global\SessionVaultSync'); [void]$ev.Set(); $ev.Dispose()
    Start-Sleep 15
    $acl = Get-Acl 'C:\sv\jt\User Data' -Audit
    $log = Get-Content C:\ProgramData\SessionVault\service.log -Tail 30 -Encoding UTF8 | Where-Object { $_ -match 'ссылка или junction' }
    @{ audit = @($acl.Audit).Count; logged = @($log).Count }
}
Check ($r.audit -eq 0) "аудит не поставлен на папку, на которую указывает подменённый путь (записей аудита: $($r.audit))"
Check ($r.logged -ge 1) 'служба записала в журнал, что на пути приманки ссылка'

$r = Vm {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    $before = (Get-ItemProperty $k).CrashDumpEnabled
    AsTester 'hd' "`"$exe`" harden -off"
    Done 'hd' 20 | Out-Null
    @{ out = ((Out 'hd') -replace '\s+', ' '); same = ((Get-ItemProperty $k).CrashDumpEnabled -eq $before) }
}
Check ($r.out -match 'администратора' -and $r.same) "harden из обычной учётки отказывает и ничего не меняет ($($r.out))"

Write-Host '--- 15b. тихие меры ОС и блокировка по событию ---'
$r = Vm {
    $keys = @(
        @('HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem', 'NtfsEncryptPagingFile'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl', 'CrashDumpEnabled'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Power', 'HibernateEnabled'))
    $before = $keys | ForEach-Object { "$((Get-ItemProperty $_[0] -Name $_[1] -ErrorAction SilentlyContinue).($_[1]))" }
    $out = & C:\sv\sessionvault.exe harden 2>&1 | Out-String
    $code = $LASTEXITCODE
    $after = $keys | ForEach-Object { "$((Get-ItemProperty $_[0] -Name $_[1] -ErrorAction SilentlyContinue).($_[1]))" }
    @{ code = $code; out = ($out -replace '\s+', ' '); before = ($before -join ','); after = ($after -join ',') }
}
$global:hardenBefore = $r.before
Check ($r.code -eq 0 -and $r.after -match '^1,0,[0]?$') "harden включил шифрование подкачки, выключил дампы и гибернацию (было $($r.before), стало $($r.after): $($r.out))"

# Блокировка сеанса при запущенном приложении: ключ нужен для шифрования при выходе, поэтому хранилище
# блокируется не сразу, а после закрытия приложения. Сессия после Win+L остаётся заблокированной: это последний интерактивный шаг.
Start-Sleep 12
Vm { AsTester 'runL' "`"$exe`" run telegram" }
Check (WaitPrompt) 'окно пароля перед проверкой блокировки при запущенном приложении'
Start-Sleep 3
TypeInVm $MasterPassword
$r = Vm {
    Done 'runL' 90 | Out-Null
    $up = WaitFor { [bool](Get-Process standin -ErrorAction SilentlyContinue) } 30
    $logF = 'C:\ProgramData\SessionVault\service.log'
    $n = @(Get-Content $logF -Encoding UTF8 | Select-String 'заблокировано').Count
    AsTester 'lk' 'rundll32.exe user32.dll,LockWorkStation'
    Start-Sleep 8
    $early = @(Get-Content $logF -Encoding UTF8 | Select-String 'заблокировано').Count -gt $n
    $alive = [bool](Get-Process standin -ErrorAction SilentlyContinue)
    Stop-Process -Name standin -Force
    $ok = WaitFor { @(Get-Content $logF -Encoding UTF8 | Select-String 'заблокировано после выхода').Count -ge 1 } 40
    @{ up = $up; early = $early; alive = $alive; ok = $ok }
}
Check ($r.up -and -not $r.early -and $r.alive) 'Win+L при запущенном приложении: хранилище пока не заблокировано'
Check $r.ok 'после закрытия приложения хранилище заблокировалось (блокировка отложена)'

Write-Host '--- 16. удаление программы возвращает данные браузеров ---'
# Путь приманки Edge подменён ссылкой (блок 15): удаление должно отказаться и ничего не увести в чужую папку.
$r = Vm {
    param($pw)
    $out = $pw | & C:\sv\sessionvault.exe uninstall -password-stdin 2>&1 | Out-String
    $code = $LASTEXITCODE
    Start-Sleep 5
    @{ code = $code; out = ($out -replace '\s+', ' ')
       svc = [bool](Get-Service SessionVault -ErrorAction SilentlyContinue)
       edgeVault = (Test-Path 'C:\ProgramData\SessionVault\vault\edge\data.enc')
       target = @(Get-ChildItem 'C:\sv\jt\User Data' -Force -ErrorAction SilentlyContinue).Count }
} @($MasterPassword)
Check ($r.code -ne 0 -and $r.svc -and $r.edgeVault -and $r.target -eq 0) "удаление при подменённом пути отказало: служба на месте, данные Edge в хранилище, чужая папка пуста ($($r.out))"

# Ссылку убрали: удаление проходит и возвращает профили на прежние места.
$r = Vm {
    param($pw)
    cmd /c 'rmdir "C:\Users\tester\AppData\Local\Microsoft\Edge"' | Out-Null
    $out = $pw | & C:\sv\sessionvault.exe uninstall -password-stdin 2>&1 | Out-String
    $code = $LASTEXITCODE
    Start-Sleep 5
    $m = @{}
    foreach ($p in @{ edge = 'C:\Users\tester\AppData\Local\Microsoft\Edge\User Data'; chrome = 'C:\Users\tester\AppData\Local\Google\Chrome\User Data'; brave = 'C:\Users\tester\AppData\Local\BraveSoftware\Brave-Browser\User Data' }.GetEnumerator()) {
        $m[$p.Key] = (Get-Content "$($p.Value)\marker.txt" -ErrorAction SilentlyContinue)
    }
    @{ code = $code; out = ($out -replace '\s+', ' '); svc = [bool](Get-Service SessionVault -ErrorAction SilentlyContinue)
       base = (Test-Path 'C:\ProgramData\SessionVault'); markers = $m
       owner = (Get-Acl 'C:\Users\tester\AppData\Local\Google\Chrome\User Data').Owner }
} @($MasterPassword)
Check ($r.code -eq 0 -and -not $r.svc -and -not $r.base) "удаление после устранения ссылки прошло: служба и каталог данных убраны ($($r.out))"
Check ($r.markers.edge -eq 'browser-session-marker' -and $r.markers.chrome -eq 'browser-session-marker' -and $r.markers.brave -eq 'browser-session-marker') 'профили Edge, Chrome и Brave возвращены на прежние места с данными'
Check ($r.owner -like '*\tester') "владелец вернувшихся данных — основная учётка ($($r.owner))"

$r = Vm {
    $keys = @(
        @('HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem', 'NtfsEncryptPagingFile'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl', 'CrashDumpEnabled'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Power', 'HibernateEnabled'))
    ($keys | ForEach-Object { "$((Get-ItemProperty $_[0] -Name $_[1] -ErrorAction SilentlyContinue).($_[1]))" }) -join ','
}
Check ($r -eq $hardenBefore) "удаление вернуло системные меры (было $hardenBefore, стало $r)"

if ($fails.Count -eq 0) { Write-Host 'ТЕСТ ПРОЙДЕН'; exit 0 }
Write-Host "ТЕСТ ПРОВАЛЕН ($($fails.Count))"; exit 1
