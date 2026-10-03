# Сборка в dist\. Основной бинарник — GUI-подсистема: трей и окно пароля не должны показывать консоль.
$ErrorActionPreference = 'Stop'
$root = Resolve-Path "$PSScriptRoot\.."
$env:Path += ';C:\Program Files\Go\bin'
New-Item -ItemType Directory -Force "$root\dist" | Out-Null
Push-Location $root
go build -ldflags '-H=windowsgui' -o dist\sessionvault.exe .\cmd\sessionvault
go build -o dist\access-check.exe .\tools\access-check
go build -o dist\standin.exe .\tools\standin
Pop-Location
