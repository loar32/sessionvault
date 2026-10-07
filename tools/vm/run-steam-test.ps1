param(
    [string]$VmName = 'sv-test',
    [string]$Checkpoint = 'steam',   # чекпойнт с настоящим клиентом Steam в C:\Program Files (x86)\Steam (без игр и сессии)
    [string]$AdminPassword = 'Sv-Admin-1!',
    [string]$MasterPassword = 'Master-Pass-1'
)
# Автотест защиты Steam на настоящем клиенте. Входа в аккаунт нет (ВМ без сети и без аккаунта): сессия имитируется файлами с
# метками на тех местах, где её держит Steam (config, ssfn*, %LOCALAPPDATA%\Steam\htmlcache). Проверяется, что метки
# пропадают с диска (хранилище и приманка), возвращаются при запуске из SessionVault, обновления сохраняются, Steam вне
# SessionVault не вызывает тревогу, а чужое чтение приманки её вызывает.
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
Invoke-Command $a { New-Item -ItemType Directory -Force C:\sv | Out-Null }
foreach ($f in 'sessionvault.exe', 'standin.exe') { Copy-Item (Join-Path $dist $f) -Destination C:\sv\ -ToSession $a -Force }

$cs = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "Name='$((Get-VM $VmName).Id)'"
$kb = Get-CimAssociatedInstance $cs -ResultClassName Msvm_Keyboard | Select-Object -First 1
$mouse = Get-CimAssociatedInstance $cs -ResultClassName Msvm_SyntheticMouse | Select-Object -First 1
function ClickPrompt() {
    Invoke-CimMethod $mouse -MethodName SetAbsolutePosition -Arguments @{ HorizontalPosition = [int]32768; VerticalPosition = [int](272 * 65535 / 768) } | Out-Null
    Start-Sleep -Milliseconds 300
    Invoke-CimMethod $mouse -MethodName ClickButton -Arguments @{ ButtonIndex = [uint32]1 } | Out-Null
    Start-Sleep -Milliseconds 700
}
function PressEnter() {
    Invoke-CimMethod $kb -MethodName PressKey -Arguments @{ keyCode = 13 } | Out-Null
    Invoke-CimMethod $kb -MethodName ReleaseKey -Arguments @{ keyCode = 13 } | Out-Null
}
function LogCount($pat) { Invoke-Command $a { param($p) @(Get-Content C:\ProgramData\SessionVault\service.log -Encoding UTF8 -ErrorAction SilentlyContinue | Select-String $p).Count } -ArgumentList $pat }
function TypeInVm($text) {
    $before = LogCount 'неверный пароль|разблокировано'
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
            if ((LogCount 'неверный пароль|разблокировано') -gt $before) { return }
        }
        Write-Host "  (ввод не дошёл до окна, шаг '$step': повтор)"
    }
}

$helpers = @'
$exe = 'C:\Program Files\SessionVault\sessionvault.exe'
$sd = 'C:\Program Files (x86)\Steam'
$loc = 'C:\Users\tester\AppData\Local\Steam'
$vd = 'C:\ProgramData\SessionVault\vault\steam'
$marks = @('FAKE-SSFN-SECRET', 'FAKE-CONFIG-SECRET', 'FAKE-COOKIE-SECRET')
function AsTester($name, $cmd) {
    [IO.File]::Delete("C:\sv\$name.out")
    [IO.File]::WriteAllText("C:\sv\$name.cmd", "@echo off`r`n$cmd > C:\sv\$name.out 2>&1`r`n(echo EXIT=%ERRORLEVEL%) >> C:\sv\$name.out`r`n")
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
function PromptUp() { [bool](Get-CimInstance Win32_Process -Filter "Name='sessionvault.exe'" | Where-Object { $_.CommandLine -like '* prompt *' }) }
function SteamProcs() { @(Get-CimInstance Win32_Process -Filter "Name='steam.exe' or Name='steamwebhelper.exe'") }
function SteamOwner() { $p = SteamProcs | Where-Object { $_.Name -eq 'steam.exe' } | Select-Object -First 1; if ($p) { (Invoke-CimMethod $p -MethodName GetOwner).User } }
# Все файлы мест сессии как один текст: по нему ищутся метки.
# Приманку нельзя читать и перечислять (это и есть тревога): о ней судим по размерам файлов, не по содержимому.
function DecoyUp() { (Test-Path "$sd\config\config.vdf") -and ((Get-Item "$sd\config\config.vdf").Length -gt 1000) -and (Test-Path "$loc\htmlcache\Default\Network\Cookies") -and ((Get-Item "$loc\htmlcache\Default\Network\Cookies").Length -gt 10000) }
function PlacesText() {
    $paths = @("$sd\config", $loc) | Where-Object { Test-Path $_ }
    $t = ''
    foreach ($f in @(Get-ChildItem $paths -Recurse -File -Force -ErrorAction SilentlyContinue) + @(Get-ChildItem $sd -Filter 'ssfn*' -File -Force -ErrorAction SilentlyContinue)) {
        $t += [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($f.FullName))
    }
    $t
}
function HasMark($text, $m) { $text.Contains($m) }
function VaultHasMark() {
    foreach ($f in Get-ChildItem $vd -Recurse -File -Force -ErrorAction SilentlyContinue) {
        $t = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($f.FullName))
        foreach ($m in $marks) { if ($t.Contains($m)) { return $true } }
    }
    $false
}
function SvLog($pat) { @(Get-Content C:\ProgramData\SessionVault\service.log -Encoding UTF8 -ErrorAction SilentlyContinue | Select-String $pat).Count }
function PutSession() {
    New-Item -ItemType Directory -Force "$sd\config", "$loc\htmlcache\Default\Network" | Out-Null
    Set-Content "$sd\config\config.vdf" '"InstallConfigStore" { "ConnectCache" "FAKE-CONFIG-SECRET" }'
    Set-Content "$sd\config\loginusers.vdf" '"users" { "76561198000000000" { "AccountName" "fakeuser" } }'
    [IO.File]::WriteAllText("$sd\ssfn1234567890", 'FAKE-SSFN-SECRET')
    [IO.File]::WriteAllText("$loc\htmlcache\Default\Network\Cookies", 'FAKE-COOKIE-SECRET')
}
function KillSteam() { Get-Process steam, steamwebhelper, steamservice -ErrorAction SilentlyContinue | Stop-Process -Force }
'@
function Vm($block, $ar = @()) {
    Invoke-Command $a -ScriptBlock { param($h, $b, $x) . ([scriptblock]::Create($h)); & ([scriptblock]::Create($b)) @x } -ArgumentList $helpers, $block.ToString(), $ar
}
function RunSteam($name) {
    Vm { param($n) AsTester $n "`"$exe`" run steam" } @($name) | Out-Null
}

Write-Host '--- 1. установка и защита Steam ---'
$r = Vm {
    Get-Process steam*, steamwebhelper, sessionvault -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep 2
    Remove-Item 'C:\Program Files\SessionVault' -Recurse -Force -ErrorAction SilentlyContinue
    PutSession
    $env:SESSIONVAULT_SKIP_SIGNATURE = '1'   # подставной Telegram не подписан; подпись Steam проверяется по-настоящему
    $inst = & C:\sv\sessionvault.exe install -user tester -telegram-exe C:\sv\standin.exe 2>&1 | Out-String
    Remove-Item Env:\SESSIONVAULT_SKIP_SIGNATURE
    Start-Sleep 3
    $before = HasMark (PlacesText) 'FAKE-CONFIG-SECRET'
    $out = 'Master-Pass-1' | & $exe protect -password-stdin steam 2>&1 | Out-String
    $code = $LASTEXITCODE
    $decoy = WaitFor { DecoyUp } 90
    $t = ""
    @{ inst = ($inst -replace '\s+', ' '); before = $before; code = $code; out = ($out -replace '\s+', ' '); decoy = $decoy; marks = @($marks | Where-Object { HasMark $t $_ }); ssfn = [bool](Get-ChildItem $sd -Filter 'ssfn*' -File -ErrorAction SilentlyContinue)
       vault = ((Get-ChildItem $vd -File | Where-Object { $_.Name -notin 'running.lock', 'data.enc.bak' } | ForEach-Object Name) -join ','); vmark = (VaultHasMark)
       log = (SvLog 'приманка steam#') }
}
Check ([bool](Vm { Get-Service SessionVault -ErrorAction SilentlyContinue })) "служба установлена ($($r.inst))"
Check $r.before 'до защиты метки сессии лежат на местах Steam'
Check ($r.code -eq 0) "protect steam выполнен ($($r.out))"
Check ($r.marks.Count -eq 0 -and -not $r.ssfn) "после защиты меток сессии и ssfn на дисках Steam нет ($($r.marks -join ','))"
Check $r.decoy 'на местах config и htmlcache появилась приманка'
Check ($r.vault -eq 'data.enc,vault.json' -and -not $r.vmark) "в хранилище только шифр, меток открытым текстом нет ($($r.vault))"
Check ($r.log -ge 2) "служба создала приманки мест Steam ($($r.log))"

Write-Host '--- 2. запуск из SessionVault: файлы возвращаются, клиент от пользователя ---'
RunSteam 'rs1'
$prompted = Vm { WaitFor { PromptUp } 40 }
Check $prompted 'run steam: окно мастер-пароля'
if ($prompted) { Start-Sleep 3; TypeInVm $MasterPassword }
$r = Vm {
    $up = WaitFor { SteamOwner } 90
    Start-Sleep 12
    $t = PlacesText
    @{ up = $up; owner = SteamOwner; marks = @($marks | Where-Object { HasMark $t $_ }); open = (Test-Path "$vd\work"); decoyLeft = ($t -like '*InstallConfigStore"*{*"ConnectCache"*' -and -not (HasMark $t 'FAKE-CONFIG-SECRET')) }
}
Check ($r.up -and $r.owner -eq 'tester') "Steam запущен от основной учётки, а не от sv-учётки ($($r.owner))"
Check ($r.marks.Count -eq 3) "файлы сессии возвращены на места ($($r.marks -join ','))"
Check $r.open 'рабочая копия хранилища открыта, пока Steam запущен'
& "$PSScriptRoot\screenshot.ps1" -VmName $VmName -Path "$env:TEMP\sv-steam-run.png" | Out-Null
Write-Host "  снимок экрана: $env:TEMP\sv-steam-run.png"

Write-Host '--- 3. выход Steam: файлы убираются, изменения сохраняются ---'
$r = Vm {
    Add-Content "$sd\config\config.vdf" 'REFRESHED-TOKEN-2'
    KillSteam
    $closed = WaitFor { -not (Test-Path "$vd\work") } 90
    $decoy = WaitFor { DecoyUp } 90
    $t = ""
    @{ closed = $closed; decoy = $decoy; marks = @($marks | Where-Object { HasMark $t $_ }); refreshed = (HasMark $t 'REFRESHED-TOKEN-2'); vmark = (VaultHasMark)
       files = ((Get-ChildItem $vd -File | Where-Object { $_.Name -notin 'running.lock', 'data.enc.bak' } | ForEach-Object Name) -join ','); err = (SvLog 'шифрование после закрытия') }
}
Check $r.closed 'после выхода Steam рабочая копия удалена (данные зашифрованы)'
Check ($r.marks.Count -eq 0 -and -not $r.refreshed) "места снова без метки ($($r.marks -join ','))"
Check $r.decoy 'на местах снова приманка'
Check ($r.files -eq 'data.enc,vault.json' -and -not $r.vmark -and $r.err -eq 0) "в хранилище шифр, ошибок шифрования нет ($($r.files))"

Write-Host '--- 4. обновление сессии сохранилось ---'
Start-Sleep 12
RunSteam 'rs2'
$r = Vm {
    $up = WaitFor { SteamOwner } 90
    Start-Sleep 8
    $t = PlacesText
    $h = HasMark $t 'REFRESHED-TOKEN-2'
    KillSteam
    $closed = WaitFor { -not (Test-Path "$vd\work") } 90
    @{ up = $up; refreshed = $h; closed = $closed }
}
Check ($r.up -and $r.refreshed) 'при втором запуске вернулась сессия с изменением из прошлого запуска (без пароля)'
Check $r.closed 'второй выход тоже зашифровал данные'

Write-Host '--- 5. Steam вне SessionVault: не тревога, свои данные подхватываются ---'
$r = Vm {
    $alarms = SvLog 'ТРЕВОГА'
    AsTester 'so' "start `"`" `"$sd\steam.exe`""
    $up = WaitFor { SteamOwner } 60
    Start-Sleep 25
    @{ up = $up; alarms = ((SvLog 'ТРЕВОГА') - $alarms) }
}
Check ($r.up) 'Steam запущен напрямую, мимо SessionVault'
Check ($r.alarms -eq 0) "Steam от издателя Valve читает приманку без тревоги ($($r.alarms))"
# Steam, запущенный мимо SessionVault, оставил на месте приманки свою новую сессию (имитация: пишем файл поверх приманки).
# Запись поверх приманки обычным процессом тоже тревога: окно закрываем, службу перезапускаем, как сделал бы пользователь.
$r = Vm {
    KillSteam; Start-Sleep 5
    Set-Content "$sd\config\config.vdf" 'OUTSIDE-SESSION-MARK'
    Start-Sleep 6
    Get-Process sessionvault -ErrorAction SilentlyContinue | Where-Object { (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine -match ' alert ' } | Stop-Process -Force
    Restart-Service SessionVault; Start-Sleep 6
}
Start-Sleep 12
RunSteam 'rs3'
if (Vm { WaitFor { PromptUp } 40 }) { Start-Sleep 3; TypeInVm $MasterPassword }   # служба перезапущена: хранилище снова заперто
$r = Vm {
    $up = WaitFor { SteamOwner } 90
    Start-Sleep 5
    $b = SvLog 'использую их'
    KillSteam
    $closed = WaitFor { -not (Test-Path "$vd\work") } 90
    @{ up = $up; adopted = $b; closed = $closed }
}
Check ($r.up -and $r.closed) 'запуск из SessionVault после запуска мимо него работает'
Check ($r.adopted -ge 1) "служба взяла свежие файлы Steam с места, а не затёрла их из хранилища ($($r.adopted))"

Write-Host '--- 6. чужое чтение приманки: тревога ---'
$r = Vm {
    $alarms = SvLog 'ТРЕВОГА'
    WaitFor { DecoyUp } 90 | Out-Null
    AsTester 'rd' "type `"$sd\config\loginusers.vdf`""
    $got = WaitFor { (SvLog 'ТРЕВОГА') -gt $alarms } 60
    @{ alarm = $got }
}
Check $r.alarm 'чтение приманки Steam чужим процессом вызывает тревогу'
Vm { Get-Process sessionvault -ErrorAction SilentlyContinue | Where-Object { (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine -match ' alert ' } | Stop-Process -Force; Restart-Service SessionVault; Start-Sleep 5 } | Out-Null

Write-Host '--- 7. снятие защиты возвращает сессию ---'
$r = Vm {
    $out = 'Master-Pass-1' | & $exe unprotect -password-stdin steam 2>&1 | Out-String
    $code = $LASTEXITCODE
    $t = PlacesText
    @{ code = $code; out = ($out -replace '\s+', ' '); cfg = (HasMark $t 'OUTSIDE-SESSION-MARK'); ssfn = (HasMark $t 'FAKE-SSFN-SECRET'); cookie = (HasMark $t 'FAKE-COOKIE-SECRET'); vault = (Test-Path $vd)
       profile = (Test-Path C:\ProgramData\SessionVault\profiles\steam.json); decoys = (Get-Content C:\ProgramData\SessionVault\decoys.json -Raw -ErrorAction SilentlyContinue) -match 'steam#' }
}
Check ($r.code -eq 0) "unprotect steam выполнен ($($r.out))"
Check ($r.cfg -and $r.ssfn -and $r.cookie) 'настоящие файлы сессии (config, ssfn, cookies) вернулись на места'
Check (-not $r.vault -and -not $r.profile -and -not $r.decoys) 'хранилище, профиль и записи приманки убраны'

Write-Host '--- 8. удаление программы при защищённом Steam ---'
$r = Vm {
    'Master-Pass-1' | & $exe protect -password-stdin steam 2>&1 | Out-Null
    Start-Sleep 5
    $out = 'Master-Pass-1' | & $exe uninstall -password-stdin 2>&1 | Out-String
    $t = PlacesText
    @{ code = $LASTEXITCODE; cfg = (HasMark $t 'OUTSIDE-SESSION-MARK'); ssfn = (HasMark $t 'FAKE-SSFN-SECRET'); svc = [bool](Get-Service SessionVault -ErrorAction SilentlyContinue) }
}
Check ($r.code -eq 0 -and $r.cfg -and $r.ssfn -and -not $r.svc) 'uninstall вернул сессию Steam и удалил службу'

if ($fails.Count) { Write-Host "ПРОВАЛОВ: $($fails.Count)"; $fails | ForEach-Object { Write-Host "  - $_" }; exit 1 }
Write-Host 'Тест Steam пройден'
