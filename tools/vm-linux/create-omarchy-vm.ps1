param(
    [string]$VmName = 'sv-omarchy',
    [string]$Iso = "$env:USERPROFILE\Downloads\omarchy-4.0.4.iso",
    [string]$Dir = 'C:\VM',
    [string]$User = 'tester',
    [string]$Password = 'svtest1234',
    [string]$Shots = "$env:TEMP"
)
# Ставит Omarchy в Hyper-V без участия человека: ввод в установщик идёт клавиатурой Hyper-V (по клавише, текст целиком
# установщик не принимает). Диск без шифрования, чтобы перезагрузки не спрашивали пароль LUKS.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\vmkeys.ps1"

if (Get-VM $VmName -ErrorAction SilentlyContinue) {
    Stop-VM $VmName -TurnOff -Force -ErrorAction SilentlyContinue
    Remove-VM $VmName -Force
}
Remove-Item "$Dir\$VmName.vhdx" -Force -ErrorAction SilentlyContinue
New-VM -Name $VmName -Generation 2 -MemoryStartupBytes 8GB -NewVHDPath "$Dir\$VmName.vhdx" -NewVHDSizeBytes 64GB -SwitchName 'Default Switch' | Out-Null
Set-VMProcessor $VmName -Count 4
Set-VMMemory $VmName -DynamicMemoryEnabled $false
Set-VMFirmware $VmName -EnableSecureBoot Off
# Иначе экран 1024x768 с масштабом 2: плавающие окна Omarchy (875x600) в него не помещаются.
Set-VMVideo $VmName -HorizontalResolution 1920 -VerticalResolution 1080 -ResolutionType Single
Add-VMDvdDrive $VmName -Path $Iso
Set-VMFirmware $VmName -FirstBootDevice (Get-VMDvdDrive $VmName)
Set-VM $VmName -AutomaticCheckpointsEnabled $false
Start-VM $VmName

function Step([string]$Text, [int[]]$Keys, [int]$Wait = 2) {
    if ($Text) { Send-VmText $VmName $Text }
    foreach ($k in $Keys) { Send-VmKey $VmName $k }
    Start-Sleep $Wait
}

Start-Sleep 40
Step -Keys 13                      # Press Return to Start Install
Step -Keys 13                      # раскладка English (US)
Step $User @(13)
Step $Password @(13)
Step $Password @(13)
Step -Keys 13                      # полное имя
Step -Keys 13                      # почта
Step -Keys 13                      # имя компьютера omarchy
Step 'Moscow' @(13) 3              # часовой пояс
Step -Keys 13                      # сводка: Yes
Step -Keys 13 3                    # диск
Send-VmCombo $VmName 0x11 0x43     # Ctrl+C: установка без шифрования
Start-Sleep 2
Step -Keys 13                      # Yes, install without encryption
Save-VmShot $VmName "$Shots\omarchy-installing.png"
Start-Sleep 150
Save-VmShot $VmName "$Shots\omarchy-installed.png"
Set-VMFirmware $VmName -FirstBootDevice (Get-VMHardDiskDrive $VmName)
Step -Keys 13 5                    # Reboot Now
Set-VMDvdDrive -VMName $VmName -Path $null
Start-Sleep 50
Step $Password @(13) 30            # вход в SDDM
Save-VmShot $VmName "$Shots\omarchy-desktop.png"
Write-Host "Omarchy установлена в $VmName; дальше tools\vm-linux\prepare-omarchy.ps1"
