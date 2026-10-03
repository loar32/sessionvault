param(
    [string]$VmName = 'sv-test',
    [string]$Iso = 'C:\VM\win11-eval.iso',
    [string]$Dir = 'C:\VM',
    [string]$ImageName = 'Windows 11 Enterprise Evaluation',
    [string]$AdminPassword = 'Sv-Admin-1!',
    [string]$UserPassword = 'Sv-Tester-1!'
)
$ErrorActionPreference = 'Stop'

$xml = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DiskConfiguration>
        <Disk wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>100</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>EFI</Label></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>3</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall><OSImage>
        <InstallFrom><MetaData wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"><Key>/IMAGE/NAME</Key><Value>$ImageName</Value></MetaData></InstallFrom>
        <InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>
      </OSImage></ImageInstall>
      <UserData><AcceptEula>true</AcceptEula></UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>$VmName</ComputerName>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC><SkipMachineOOBE>true</SkipMachineOOBE><SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
            <Name>svadmin</Name><Group>Administrators</Group>
            <Password><Value>$AdminPassword</Value><PlainText>true</PlainText></Password>
          </LocalAccount>
          <LocalAccount wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
            <Name>tester</Name><Group>Users</Group>
            <Password><Value>$UserPassword</Value><PlainText>true</PlainText></Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon><Enabled>true</Enabled><Username>tester</Username><Password><Value>$UserPassword</Value><PlainText>true</PlainText></Password><LogonCount>1</LogonCount></AutoLogon>
    </component>
  </settings>
</unattend>
"@

$tmp = Join-Path $Dir 'unattend'
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $tmp | Out-Null
[IO.File]::WriteAllText("$tmp\autounattend.xml", $xml, (New-Object Text.UTF8Encoding $false))

# Образ с ответным файлом: Setup ищет autounattend.xml на любом подключённом диске
$answerIso = Join-Path $Dir 'answer.iso'
Remove-Item $answerIso -Force -ErrorAction SilentlyContinue
$fs = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$fs.FileSystemsToCreate = 3
$fs.VolumeName = 'ANSWER'
$fs.Root.AddTree($tmp, $false)
$stream = $fs.CreateResultImage().ImageStream
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices.ComTypes;
public class IsoWriter { public static void Write(object s, string path) {
  var st = (IStream)s; STATSTG stat; st.Stat(out stat, 1); long left = stat.cbSize;
  using (var f = System.IO.File.Create(path)) { var buf = new byte[1048576];
    while (left > 0) { int n = (int)System.Math.Min(buf.Length, left); System.IntPtr p = System.Runtime.InteropServices.Marshal.AllocHGlobal(4);
      st.Read(buf, n, p); int r = System.Runtime.InteropServices.Marshal.ReadInt32(p); System.Runtime.InteropServices.Marshal.FreeHGlobal(p);
      if (r == 0) break; f.Write(buf, 0, r); left -= r; } } } }
'@
[IsoWriter]::Write($stream, $answerIso)

$vhd = Join-Path $Dir "$VmName.vhdx"
New-VM -Name $VmName -Generation 2 -MemoryStartupBytes 4GB -NewVHDPath $vhd -NewVHDSizeBytes 64GB -SwitchName 'Default Switch' | Out-Null
Set-VMProcessor $VmName -Count 2
Set-VMMemory $VmName -DynamicMemoryEnabled $false
Set-VMKeyProtector -VMName $VmName -NewLocalKeyProtector
Enable-VMTPM $VmName
Add-VMDvdDrive $VmName -Path $Iso
Add-VMDvdDrive $VmName -Path $answerIso
Set-VMFirmware $VmName -FirstBootDevice (Get-VMDvdDrive $VmName)[0]
Start-VM $VmName

# «Press any key to boot from CD»: шлём пробел, пока ВМ не начнёт грузиться с диска
$kb = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_Keyboard -Filter "ElementName='$((Get-VM $VmName).Id)'" -ErrorAction SilentlyContinue
if (-not $kb) { $kb = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='$VmName'" | Get-CimAssociatedInstance -ResultClassName Msvm_Keyboard }
1..15 | ForEach-Object { Invoke-CimMethod $kb -MethodName TypeText -Arguments @{ asciiText = ' ' } | Out-Null; Start-Sleep 1 }
Write-Host "ВМ $VmName запущена, идёт установка Windows (~15-20 минут)"
