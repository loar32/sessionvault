# Клавиатура и экран Linux-ВМ Hyper-V. TypeText установщик Omarchy и Hyprland не принимают, поэтому текст
# отправляется по клавише (коды виртуальных клавиш, Shift для заглавных и знаков).

function Get-VmKeyboard([string]$VmName) {
    $vm = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='$VmName'"
    $vm | Get-CimAssociatedInstance -ResultClassName Msvm_Keyboard
}

function Send-VmKey([string]$VmName, [int]$Key) {
    $kb = Get-VmKeyboard $VmName
    Invoke-CimMethod $kb -MethodName TypeKey -Arguments @{ keyCode = [uint32]$Key } | Out-Null
    Start-Sleep -Milliseconds 300
}

# Send-VmCombo ВМ 0x5B 13 — Super+Enter; модификатор зажимается на время нажатия клавиши.
function Send-VmCombo([string]$VmName, [int]$Mod, [int]$Key) {
    $kb = Get-VmKeyboard $VmName
    Invoke-CimMethod $kb -MethodName PressKey -Arguments @{ keyCode = [uint32]$Mod } | Out-Null
    Invoke-CimMethod $kb -MethodName TypeKey -Arguments @{ keyCode = [uint32]$Key } | Out-Null
    Invoke-CimMethod $kb -MethodName ReleaseKey -Arguments @{ keyCode = [uint32]$Mod } | Out-Null
    Start-Sleep -Milliseconds 300
}

$script:plainKeys = @{ ' ' = 0x20; '-' = 0xBD; '=' = 0xBB; '[' = 0xDB; ']' = 0xDD; '\' = 0xDC; ';' = 0xBA; "'" = 0xDE; ',' = 0xBC; '.' = 0xBE; '/' = 0xBF; '`' = 0xC0 }
$script:shiftKeys = @{ '_' = 0xBD; '+' = 0xBB; '{' = 0xDB; '}' = 0xDD; '|' = 0xDC; ':' = 0xBA; '"' = 0xDE; '<' = 0xBC; '>' = 0xBE; '?' = 0xBF; '~' = 0xC0;
    '!' = 0x31; '@' = 0x32; '#' = 0x33; '$' = 0x34; '%' = 0x35; '^' = 0x36; '&' = 0x37; '*' = 0x38; '(' = 0x39; ')' = 0x30 }

function Send-VmText([string]$VmName, [string]$Text) {
    $kb = Get-VmKeyboard $VmName
    foreach ($c in $Text.ToCharArray()) {
        $s = [string]$c
        $shift = $false
        if ($c -cmatch '[a-z]') { $k = [int][char]$s.ToUpper() }
        elseif ($c -cmatch '[A-Z]') { $k = [int]$c; $shift = $true }
        elseif ($c -match '[0-9]') { $k = [int]$c }
        elseif ($script:plainKeys.ContainsKey($s)) { $k = $script:plainKeys[$s] }
        elseif ($script:shiftKeys.ContainsKey($s)) { $k = $script:shiftKeys[$s]; $shift = $true }
        else { throw "нет кода клавиши для '$s'" }
        if ($shift) { Invoke-CimMethod $kb -MethodName PressKey -Arguments @{ keyCode = [uint32]0x10 } | Out-Null }
        Invoke-CimMethod $kb -MethodName TypeKey -Arguments @{ keyCode = [uint32]$k } | Out-Null
        if ($shift) { Invoke-CimMethod $kb -MethodName ReleaseKey -Arguments @{ keyCode = [uint32]0x10 } | Out-Null }
        Start-Sleep -Milliseconds 40
    }
}

function Save-VmShot([string]$VmName, [string]$Path) {
    & "$PSScriptRoot\..\vm\screenshot.ps1" -VmName $VmName -Path $Path | Out-Null
}
