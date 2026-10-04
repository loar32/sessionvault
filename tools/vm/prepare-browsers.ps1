param(
    [Parameter(Mandatory)][string]$InstallersDir,   # chrome.msi и brave.exe (в ВМ нет интернета, качаем на хосте)
    [string]$VmName = 'sv-test',
    [string]$AdminPassword = 'Sv-Admin-1!'
)
# Чекпойнт browsers = clean + Chrome и Brave, установленные для всех пользователей (Edge уже есть в Windows 11).
$ErrorActionPreference = 'Stop'
$admin = New-Object pscredential('svadmin', (ConvertTo-SecureString $AdminPassword -AsPlainText -Force))

Restore-VMCheckpoint -VMName $VmName -Name clean -Confirm:$false
Start-VM $VmName 3>$null
while ((Get-VM $VmName).Heartbeat -notmatch 'Ok') { Start-Sleep 3 }
Start-Sleep 15
$a = New-PSSession -VMName $VmName -Credential $admin
while (-not (Invoke-Command $a { (Get-Process explorer -IncludeUserName -ErrorAction SilentlyContinue).UserName -like '*tester' })) { Start-Sleep 2 }

Invoke-Command $a { New-Item -ItemType Directory -Force C:\sv | Out-Null }
foreach ($f in 'chrome.msi', 'brave.exe') { Copy-Item (Join-Path $InstallersDir $f) -Destination C:\sv\ -ToSession $a }
Invoke-Command $a {
    $p = Start-Process msiexec.exe -ArgumentList '/i', 'C:\sv\chrome.msi', '/qn', '/norestart' -Wait -PassThru
    "chrome msi: $($p.ExitCode)"
    $p = Start-Process C:\sv\brave.exe -ArgumentList '--system-level', '--do-not-launch-chrome' -Wait -PassThru
    "brave: $($p.ExitCode)"
    # Установщики запускают браузеры и службы обновления; для чекпойнта нужны только файлы.
    Start-Sleep 20
    Get-Process chrome, brave -ErrorAction SilentlyContinue | Stop-Process -Force
    Remove-Item C:\sv\chrome.msi, C:\sv\brave.exe -Force
    foreach ($e in 'C:\Program Files\Google\Chrome\Application\chrome.exe', 'C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe', 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe') {
        "$e : $(Test-Path $e)"
    }
}
Remove-PSSession $a
Get-VMSnapshot $VmName -Name browsers -ErrorAction SilentlyContinue | Remove-VMSnapshot
Checkpoint-VM $VmName -SnapshotName browsers
Write-Host 'чекпойнт browsers создан'
