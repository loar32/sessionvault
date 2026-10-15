param(
    [string]$VmName = 'sv-omarchy',
    [string]$Checkpoint = 'clean',
    [switch]$NoRestore
)
# Полный тест Linux-версии в ВМ Omarchy: сборка, откат к чекпойнту, test-guest.sh в ВМ. Код выхода — число провалов.
$ErrorActionPreference = 'Stop'
$root = Resolve-Path "$PSScriptRoot\..\.."
Push-Location $root
$env:GOOS = 'linux'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
go build -trimpath -o dist\sessionvault-linux-amd64 .\cmd\sessionvault
$code = $LASTEXITCODE
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED
Pop-Location
if ($code -ne 0) { throw 'сборка не прошла' }

if (-not $NoRestore) {
    Restore-VMSnapshot -VMName $VmName -Name $Checkpoint -Confirm:$false
    Start-VM $VmName
}
# Дальше нативные команды: их stderr при Stop стал бы исключением PowerShell 5.1.
$ErrorActionPreference = 'Continue'
foreach ($i in 1..20) {
    ssh sv-omarchy true 2>$null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep 3
}
scp -q "$root\dist\sessionvault-linux-amd64" sv-omarchy:/tmp/sessionvault
scp -q "$PSScriptRoot\test-guest.sh" sv-omarchy:/tmp/test-guest.sh
ssh sv-omarchy 'chmod +x /tmp/sessionvault; bash /tmp/test-guest.sh'
exit $LASTEXITCODE
