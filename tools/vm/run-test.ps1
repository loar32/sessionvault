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
# Hyper-V-клавиатура иногда теряет клавиши: то текст не доходит до поля, то пропадает Enter. Результат ввода
# проверяем по журналу службы (пароль принят или отвергнут) и при необходимости повторяем: Enter, затем заново.
function LogCount() { Invoke-Command $a { @(Get-Content C:\ProgramData\SessionVault\service.log -Encoding UTF8 -ErrorAction SilentlyContinue | Select-String 'неверный пароль|разблокировано').Count } }
function PressEnter() {
    Invoke-CimMethod $kb -MethodName PressKey -Arguments @{ keyCode = 13 } | Out-Null
    Invoke-CimMethod $kb -MethodName ReleaseKey -Arguments @{ keyCode = 13 } | Out-Null
}
function TypeInVm($text) {
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
function Files() { (Get-ChildItem $v -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin 'running.lock', 'data.enc.bak' } | ForEach-Object { $_.FullName.Substring($v.Length + 1) }) -join ',' }
function Standin() { Get-Process standin -IncludeUserName -ErrorAction SilentlyContinue | Select-Object -First 1 }
'@
function Vm($block, $ar = @()) {
    Invoke-Command $a -ScriptBlock { param($h, $b, $x) . ([scriptblock]::Create($h)); & ([scriptblock]::Create($b)) @x } -ArgumentList $helpers, $block.ToString(), $ar
}
function WaitPrompt() { Vm { WaitFor { PromptUp } 30 } }

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

if ($fails.Count -eq 0) { Write-Host 'ТЕСТ ПРОЙДЕН'; exit 0 }
Write-Host "ТЕСТ ПРОВАЛЕН ($($fails.Count))"; exit 1
