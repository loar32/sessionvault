param(
    [string]$VmName = 'sv-omarchy',
    [string]$Password = 'svtest1234',
    [string]$Key = "$env:USERPROFILE\.ssh\sv_omarchy",
    [string]$Apps = 'C:\VM\omarchy-apps',
    [string]$Checkpoint = 'clean'
)
# Готовит свежую Omarchy к тестам: SSH через Hyper-V socket (vsock, порт 22; сеть Default Switch на хосте с VPN не
# работает), sudo без пароля, тестовые приложения (Telegram, Discord, Brave, Chrome из архивов в $Apps) и чекпойнт.
# На хосте нужны: ключ $Key, ssh-конфиг «Host sv-omarchy» с ProxyCommand hvssh.exe и регистрация службы vsock
# 00000016-facb-11e6-bd58-64006a7986d3 в GuestCommunicationServices.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\vmkeys.ps1"

function Test-Ssh {
    # Предупреждения ssh в stderr при Stop стали бы исключением PowerShell 5.1.
    $ErrorActionPreference = 'Continue'
    ssh sv-omarchy true 2>$null | Out-Null
    $LASTEXITCODE -eq 0
}

$pub = (Get-Content "$Key.pub").Trim()
if (-not (Test-Ssh)) {
Send-VmCombo $VmName 0x5B 13      # Super+Enter: терминал
Start-Sleep 4
Send-VmText $VmName "mkdir -p ~/.ssh && echo '$pub' >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"
Send-VmKey $VmName 13
$boot = "echo 'tester ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-svtest; echo hv_sock > /etc/modules-load.d/hv_sock.conf; modprobe hv_sock; ssh-keygen -A; " +
    "printf '[Socket]\nListenStream=vsock::22\nAccept=yes\n[Install]\nWantedBy=sockets.target\n' > /etc/systemd/system/sshd-vsock.socket; " +
    "printf '[Service]\nExecStart=-/usr/bin/sshd -i\nStandardInput=socket\n' > /etc/systemd/system/sshd-vsock@.service; " +
    "systemctl daemon-reload; systemctl enable --now sshd-vsock.socket"
Send-VmText $VmName "sudo sh -c `"$boot`""
Send-VmKey $VmName 13
Start-Sleep 2
Send-VmText $VmName $Password
Send-VmKey $VmName 13
Start-Sleep 5

}
$ok = $false
foreach ($i in 1..10) {
    if (Test-Ssh) { $ok = $true; break }
    Start-Sleep 3
}
if (-not $ok) { throw 'ssh в ВМ не поднялся' }

$ErrorActionPreference = 'Continue'
scp -q "$Apps\telegram.tar.xz" "$Apps\discord.tar.gz" "$Apps\brave.zip" "$Apps\chrome.deb" "$PSScriptRoot\guest-setup.sh" sv-omarchy:/tmp/
ssh sv-omarchy 'bash /tmp/guest-setup.sh'
if ($LASTEXITCODE -ne 0) { throw 'guest-setup.sh не прошёл' }
$ErrorActionPreference = 'Stop'

# Стандартный чекпойнт хранит память: после отката ВМ продолжает с открытого рабочего стола, без входа в SDDM.
Set-VM $VmName -CheckpointType Standard
Checkpoint-VM $VmName -SnapshotName $Checkpoint
Write-Host "Готово: чекпойнт $Checkpoint"
