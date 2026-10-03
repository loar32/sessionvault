param(
    [string]$VmName = 'sv-test',
    [string]$Path = "$env:TEMP\sv-screen.png",
    [int]$Width = 1024,
    [int]$Height = 768
)
# Снимок экрана ВМ через Hyper-V WMI (миниатюра RGB565): видно, что реально происходит на рабочем столе tester.
$ErrorActionPreference = 'Stop'
$ns = 'root\virtualization\v2'
$svc = Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemManagementService
$vm = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "Name='$((Get-VM $VmName).Id)'"
$sd = Get-CimAssociatedInstance $vm -ResultClassName Msvm_VirtualSystemSettingData | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' } | Select-Object -First 1
$r = Invoke-CimMethod $svc -MethodName GetVirtualSystemThumbnailImage -Arguments @{ TargetSystem = $sd; WidthPixels = [uint16]$Width; HeightPixels = [uint16]$Height }
$data = $r.ImageData
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap $Width, $Height, ([System.Drawing.Imaging.PixelFormat]::Format16bppRgb565)
$bd = $bmp.LockBits((New-Object System.Drawing.Rectangle 0, 0, $Width, $Height), 'WriteOnly', $bmp.PixelFormat)
[System.Runtime.InteropServices.Marshal]::Copy($data, 0, $bd.Scan0, [Math]::Min($data.Length, $bd.Stride * $Height))
$bmp.UnlockBits($bd)
$bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Host $Path
