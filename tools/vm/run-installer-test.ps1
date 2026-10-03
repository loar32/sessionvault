param(
    [string]$VmName = 'sv-test',
    [string]$Checkpoint = 'clean',
    [string]$AdminPassword = 'Sv-Admin-1!',
    [string]$MasterPassword = 'Master-Pass-1'
)
# Автотест установщика: тихая установка Setup.exe, перенос tdata, запуск из трея, неверный пароль при удалении,
# удаление с возвратом данных. Обычный tester в интерактивной сессии, админ-действия через PowerShell Direct.
$ErrorActionPreference = 'Stop'
$root = Resolve-Path "$PSScriptRoot\..\.."
$dist = Join-Path $root 'dist'
$admin = New-Object pscredential('svadmin', (ConvertTo-SecureString $AdminPassword -AsPlainText -Force))
$tester = New-Object pscredential('tester', (ConvertTo-SecureString 'Sv-Tester-1!' -AsPlainText -Force))
$pf = 'C:\Program Files\SessionVault'
$exe = "$pf\sessionvault.exe"

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

$cs = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "Name='$((Get-VM $VmName).Id)'"
$kb = Get-CimAssociatedInstance $cs -ResultClassName Msvm_Keyboard | Select-Object -First 1
$mouse = Get-CimAssociatedInstance $cs -ResultClassName Msvm_SyntheticMouse | Select-Object -First 1
function TypeInVm($text) {
    # Свежая оболочка перехватывает передний план: кликаем по полю окна пароля (центр экрана, 1024x768).
    Invoke-CimMethod $mouse -MethodName SetAbsolutePosition -Arguments @{ HorizontalPosition = [int]32768; VerticalPosition = [int](272 * 65535 / 768) } | Out-Null
    Start-Sleep -Milliseconds 300
    Invoke-CimMethod $mouse -MethodName ClickButton -Arguments @{ ButtonIndex = [uint32]1 } | Out-Null
    Start-Sleep -Milliseconds 700
    Invoke-CimMethod $kb -MethodName TypeText -Arguments @{ asciiText = $text } | Out-Null
    Start-Sleep -Milliseconds 500
    Invoke-CimMethod $kb -MethodName PressKey -Arguments @{ keyCode = 13 } | Out-Null
    Invoke-CimMethod $kb -MethodName ReleaseKey -Arguments @{ keyCode = 13 } | Out-Null
}

Invoke-Command $a { New-Item -ItemType Directory -Force C:\sv | Out-Null }
foreach ($f in 'SessionVaultSetup', 'sessionvault', 'standin') {
    Copy-Item "$dist\$f.exe" -Destination C:\sv\ -ToSession $a
}

$helpers = @'
$pf = 'C:\Program Files\SessionVault'
$exe = "$pf\sessionvault.exe"
$v = 'C:\ProgramData\SessionVault\vault\telegram'
function WaitFor($sb, $sec = 60) {
    $end = (Get-Date).AddSeconds($sec)
    while ((Get-Date) -lt $end) { if (& $sb) { return $true }; Start-Sleep 1 }
    return $false
}
function PromptUp() { [bool](Get-CimInstance Win32_Process -Filter "Name='sessionvault.exe'" | Where-Object { $_.CommandLine -like '* prompt *' }) }
function Files() { (Get-ChildItem $v -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'running.lock' } | ForEach-Object { $_.FullName.Substring($v.Length + 1) }) -join ',' }
function Tg() { Get-Process Telegram -IncludeUserName -ErrorAction SilentlyContinue | Select-Object -First 1 }
'@
function Vm($block, $ar = @()) {
    Invoke-Command $a -ScriptBlock { param($h, $b, $x) . ([scriptblock]::Create($h)); & ([scriptblock]::Create($b)) @x } -ArgumentList $helpers, $block.ToString(), $ar
}

Write-Host '--- 0. «Telegram» и его tdata у пользователя ---'
$hash = Invoke-Command $a {
    $d = 'C:\Users\tester\AppData\Roaming\Telegram Desktop'
    New-Item -ItemType Directory -Force "$d\tdata\emoji" | Out-Null
    Copy-Item C:\sv\standin.exe "$d\Telegram.exe"
    Set-Content "$d\tdata\key_datas" 'secret-session-data'
    Set-Content "$d\tdata\emoji\cache" 'cache'
    (Get-FileHash "$d\tdata\key_datas").Hash
}

Write-Host '--- 1. установка под учётку-администратора отклоняется ---'
$r = Vm { & C:\sv\sessionvault.exe install -user svadmin 2>&1 | Out-Null; @{ code = $LASTEXITCODE; svc = [bool](Get-Service SessionVault -ErrorAction SilentlyContinue); dir = (Test-Path C:\ProgramData\SessionVault) } }
Check ($r.code -eq 3 -and -not $r.svc -and -not $r.dir) "install для администратора: код $($r.code), ничего не создано"

Write-Host '--- 2. тихая установка Setup.exe ---'
$r = Vm {
    $p = Start-Process C:\sv\SessionVaultSetup.exe -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/LOG=C:\sv\setup.log' -Wait -PassThru
    Start-Sleep 3
    $cfg = Get-Content C:\ProgramData\SessionVault\config.json -Raw | ConvertFrom-Json
    $prof = Get-Content C:\ProgramData\SessionVault\profiles\telegram.json -Raw | ConvertFrom-Json
    @{
        code = $p.ExitCode; svc = (Get-Service SessionVault).Status.ToString(); exe = (Test-Path $exe)
        copy = (Test-Path "$pf\apps\telegram\Telegram.exe"); profExe = $prof.exe; user = $cfg.main_user
        run = [bool](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SessionVaultTray -ErrorAction SilentlyContinue)
        vault = [bool](Get-LocalUser vault -ErrorAction SilentlyContinue)
    }
}
Check ($r.code -eq 0 -and $r.svc -eq 'Running') "установщик завершился успешно, служба работает (код $($r.code), $($r.svc))"
Check ($r.user -eq 'tester') "основная учётка определена сама: $($r.user)"
Check ($r.copy -and $r.profExe -like '*apps\telegram\Telegram.exe') "Telegram из профиля пользователя скопирован туда, где его может запустить vault ($($r.profExe))"
Check ($r.run -and $r.vault) 'автозапуск трея и учётка vault созданы'

Write-Host '--- 3. import-tdata без пути: исходное место запоминается ---'
$r = Vm {
    param($pw)
    $pw | & $exe import-tdata -password-stdin | Out-Null
    $cfg = Get-Content C:\ProgramData\SessionVault\config.json -Raw | ConvertFrom-Json
    @{ files = (Files); old = (Test-Path 'C:\Users\tester\AppData\Roaming\Telegram Desktop\tdata'); origin = $cfg.origins.telegram }
} @($MasterPassword)
Check ($r.files -eq 'data.enc,vault.json') "в хранилище только шифр (есть: $($r.files))"
Check (-not $r.old) 'открытой tdata у пользователя не осталось'
Check ($r.origin -like '*Telegram Desktop\tdata') "исходный путь записан ($($r.origin))"

Write-Host '--- 4. запуск Telegram из трея ---'
Vm {
    $act = New-ScheduledTaskAction -Execute $exe -Argument 'tray'
    $pr = New-ScheduledTaskPrincipal -UserId 'SV-TEST\tester' -LogonType Interactive
    Register-ScheduledTask -TaskName 'svt-tray' -Action $act -Principal $pr -Force | Out-Null
    Start-ScheduledTask -TaskName 'svt-tray'
    Start-Sleep 5
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
    Register-ScheduledTask -TaskName 'svt-menu' -Action $act -Principal $pr -Force | Out-Null
    Start-ScheduledTask -TaskName 'svt-menu'
} | Out-Null
$prompted = Vm { WaitFor { PromptUp } 30 }
Check $prompted 'пункт меню трея вызвал окно мастер-пароля'
Start-Sleep 3
TypeInVm $MasterPassword
$r = Vm {
    $up = WaitFor { Tg } 40
    Start-Sleep 2
    $t = Tg
    @{ up = $up; user = $t.UserName; session = $t.SessionId; key = (Get-Content "$v\work\tdata\key_datas" -ErrorAction SilentlyContinue) }
}
Check ($r.up -and $r.user -like '*\vault' -and $r.session -ne 0) "Telegram запущен от vault в сессии пользователя ($($r.user))"
Check ($r.key -eq 'secret-session-data') 'сессия расшифрована и на месте'
$r = Vm { Stop-Process -Name Telegram -Force; @{ ok = (WaitFor { (Files) -eq 'data.enc,vault.json' } 60); files = (Files) } }
Check $r.ok "после закрытия на диске только шифр (есть: $($r.files))"

Write-Host '--- 5. удаление с неверным паролем: ничего не теряется ---'
$r = Vm {
    'Wrong-Pass-9' | & $exe uninstall -password-stdin 2>&1 | Out-Null
    $code = $LASTEXITCODE
    Start-Sleep 3
    @{ code = $code; svc = (Get-Service SessionVault -ErrorAction SilentlyContinue).Status.ToString(); files = (Files); user = [bool](Get-LocalUser vault -ErrorAction SilentlyContinue) }
}
Check ($r.code -ne 0) "uninstall с неверным паролем завершился ошибкой (код $($r.code))"
Check ($r.svc -eq 'Running' -and $r.user -and $r.files -eq 'data.enc,vault.json') "служба, учётка и зашифрованные данные на месте ($($r.svc); $($r.files))"

Write-Host '--- 6. удаление с возвратом данных ---'
Invoke-Command $a { Get-Process sessionvault -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -ne 0 } | Stop-Process -Force }
$r = Vm {
    param($pw)
    $pw | & $exe uninstall -password-stdin 2>&1 | Out-Null
    $code = $LASTEXITCODE
    Start-Sleep 2
    @{
        code = $code
        hash = (Get-FileHash 'C:\Users\tester\AppData\Roaming\Telegram Desktop\tdata\key_datas' -ErrorAction SilentlyContinue).Hash
        cache = (Test-Path 'C:\Users\tester\AppData\Roaming\Telegram Desktop\tdata\emoji\cache')
        svc = [bool](Get-Service SessionVault -ErrorAction SilentlyContinue)
        user = [bool](Get-LocalUser vault -ErrorAction SilentlyContinue)
        data = (Test-Path C:\ProgramData\SessionVault)
        run = [bool](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SessionVaultTray -ErrorAction SilentlyContinue)
        profile = (Test-Path C:\Users\vault)
        apps = (Test-Path "$pf\apps")
    }
} @($MasterPassword)
Check ($r.code -eq 0) "uninstall с верным паролем успешен (код $($r.code))"
Check ($r.hash -eq $hash -and $r.cache) 'tdata вернулась на прежнее место, содержимое то же'
Check (-not $r.svc -and -not $r.user -and -not $r.data -and -not $r.run) 'служба, учётка vault, ProgramData и автозапуск удалены'
Check (-not $r.profile -and -not $r.apps) 'профиль vault и копия Telegram убраны'
$r = Invoke-Command $a -ArgumentList $tester {
    param($cred)
    $key = 'C:\Users\tester\AppData\Roaming\Telegram Desktop\tdata\key_datas'
    $o = (Get-Acl $key).Owner
    @{ owner = $o; icacls = ((icacls $key) -join ' ') }
}
Check ($r.owner -like '*tester') "владелец вернувшихся данных — основная учётка ($($r.owner))"
Check ($r.icacls -notmatch 'vault' -and $r.icacls -match 'tester') 'права на данные — как у обычных файлов пользователя'

Write-Host '--- 7. деинсталлятор Inno после нашего удаления ---'
$r = Vm {
    $un = Get-ChildItem $pf -Filter 'unins*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $un) { return @{ found = $false } }
    $p = Start-Process $un.FullName -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait -PassThru
    Start-Sleep 4
    @{ found = $true; code = $p.ExitCode; dir = (Test-Path $pf) }
}
Check ($r.found -and $r.code -eq 0 -and -not $r.dir) "тихое удаление Inno завершено, каталог программы убран ($($r.found); $($r.code); осталось: $($r.dir))"

if ($fails.Count -eq 0) { Write-Host 'ТЕСТ УСТАНОВЩИКА ПРОЙДЕН'; exit 0 }
Write-Host "ТЕСТ УСТАНОВЩИКА ПРОВАЛЕН ($($fails.Count))"; exit 1
