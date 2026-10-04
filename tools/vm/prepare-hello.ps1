param(
    [string]$VmName = 'sv-test',
    [string]$AdminPassword = 'Sv-Admin-1!',
    [string]$UserPassword = 'Sv-Tester-1!',
    [string]$Pin = '135790'
)
# Чекпойнт hello = browsers + PIN Windows Hello у tester. В ВМ есть vTPM; PIN настраивается через «Параметры»
# UI Automation раскрывает пункт и жмёт «Set up» (hello-pin.ps1), пароль и PIN вводит клавиатура Hyper-V.
$ErrorActionPreference = 'Stop'
$admin = New-Object pscredential('svadmin', (ConvertTo-SecureString $AdminPassword -AsPlainText -Force))

Restore-VMCheckpoint -VMName $VmName -Name browsers -Confirm:$false
Start-VM $VmName 3>$null
while ((Get-VM $VmName).Heartbeat -notmatch 'Ok') { Start-Sleep 3 }
Start-Sleep 15
$a = New-PSSession -VMName $VmName -Credential $admin
while (-not (Invoke-Command $a { (Get-Process explorer -IncludeUserName -ErrorAction SilentlyContinue).UserName -like '*tester' })) { Start-Sleep 2 }
$vmId = (Get-VM $VmName).Id
$kb = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "Name='$vmId'" | Get-CimAssociatedInstance -ResultClassName Msvm_Keyboard

function Key($code) {
    Invoke-CimMethod $kb -MethodName PressKey -Arguments @{ keyCode = [int]$code } | Out-Null
    Invoke-CimMethod $kb -MethodName ReleaseKey -Arguments @{ keyCode = [int]$code } | Out-Null
    Start-Sleep -Milliseconds 400
}
$mouse = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "Name='$vmId'" | Get-CimAssociatedInstance -ResultClassName Msvm_SyntheticMouse | Select-Object -First 1
# Координаты в пикселях экрана 1024x768.
function Click($x, $y) {
    Invoke-CimMethod $mouse -MethodName SetAbsolutePosition -Arguments @{ HorizontalPosition = [int]($x * 65535 / 1024); VerticalPosition = [int]($y * 65535 / 768) } | Out-Null
    Start-Sleep -Milliseconds 400
    Invoke-CimMethod $mouse -MethodName ClickButton -Arguments @{ ButtonIndex = [uint32]1 } | Out-Null
    Start-Sleep -Milliseconds 800
}
function Typ($t) { Invoke-CimMethod $kb -MethodName TypeText -Arguments @{ asciiText = $t } | Out-Null; Start-Sleep -Milliseconds 1000 }

function AsTester($name, $cmd) {
    Invoke-Command $a -ScriptBlock {
        param($name, $cmd)
        New-Item -ItemType Directory -Force C:\sv | Out-Null
        [IO.File]::Delete("C:\sv\$name.out")
        [IO.File]::WriteAllText("C:\sv\$name.cmd", "@echo off`r`n$cmd > C:\sv\$name.out 2>&1`r`n(echo EXIT=%ERRORLEVEL%) >> C:\sv\$name.out`r`n")
        $act = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument "--headless cmd.exe /c C:\sv\$name.cmd"
        $pr = New-ScheduledTaskPrincipal -UserId 'SV-TEST\tester' -LogonType Interactive
        Register-ScheduledTask -TaskName "svt-$name" -Action $act -Principal $pr -Force | Out-Null
        Start-ScheduledTask -TaskName "svt-$name"
    } -ArgumentList $name, $cmd
}

Copy-Item (Join-Path $PSScriptRoot 'hello-pin.ps1') -Destination C:\sv\ -ToSession $a
Start-Sleep 30   # оболочка после входа ещё открывает окна (первый запуск Edge и т. п.)
Invoke-Command $a { Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force }
AsTester 'settings' 'start ms-settings:signinoptions'
Start-Sleep 12
Key 27; Start-Sleep 2   # поверх «Параметров» открывается меню «Пуск» и забирает фокус
Click 500 400; Start-Sleep 1   # клик по содержимому делает «Параметры» активным окном, иначе Enter уйдёт в никуда
AsTester 'pin' 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\sv\hello-pin.ps1'
$end = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $end -and -not ((Invoke-Command $a { Get-Content C:\sv\pin.out -Raw -ErrorAction SilentlyContinue }) -match 'EXIT=')) { Start-Sleep 2 }
$pinOut = Invoke-Command $a { Get-Content C:\sv\pin.out -Raw -ErrorAction SilentlyContinue }
Write-Host $pinOut
if ($pinOut -notmatch 'EXIT=0') { throw 'не удалось открыть настройку PIN: см. tools/vm/screenshot.ps1' }
Key 13; Start-Sleep 8                          # «Set up» -> окно проверки пароля
Typ $UserPassword; Key 13; Start-Sleep 8       # пароль учётки
Typ $Pin; Key 9; Typ $Pin; Key 13; Start-Sleep 8   # PIN и подтверждение

# Закрыть «Параметры» и проверить результат.
Invoke-Command $a { Get-Process SystemSettings, powershell -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -like '*tester' } | Stop-Process -Force }
Copy-Item (Join-Path $PSScriptRoot '..\..\dist\hello-spike.exe') -Destination C:\sv\ -ToSession $a
AsTester 'sup' 'C:\sv\hello-spike.exe'
Start-Sleep 6
$out = Invoke-Command $a { Get-Content C:\sv\sup.out -Raw -ErrorAction SilentlyContinue }
Write-Host $out
if ($out -notmatch 'supported: true') { throw 'Windows Hello не настроился: см. снимок экрана ВМ (tools/vm/screenshot.ps1)' }
Invoke-Command $a { Get-Process hello-spike, CredentialUIBroker -ErrorAction SilentlyContinue | Stop-Process -Force }
Remove-PSSession $a
Get-VMSnapshot $VmName -Name hello -ErrorAction SilentlyContinue | Remove-VMSnapshot
Checkpoint-VM $VmName -SnapshotName hello
Write-Host 'чекпойнт hello создан'
