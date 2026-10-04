# Запускается в сеансе tester внутри ВМ (prepare-hello.ps1): раскрывает пункт PIN в «Параметрах» и ставит фокус на «Set up».
# Диалоги «Windows Security» (пароль, PIN) принадлежат процессу с повышенной целостностью: UI Automation их не видит,
# их заполняет клавиатура Hyper-V из prepare-hello.ps1.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$UIA = [System.Windows.Automation.AutomationElement]
$root = $UIA::RootElement
function Log($m) { Write-Output "$(Get-Date -Format HH:mm:ss) $m" }

function Find($scope, $name, $type, $sec = 30) {
    $end = (Get-Date).AddSeconds($sec)
    while ((Get-Date) -lt $end) {
        foreach ($e in $scope.FindAll('Descendants', [System.Windows.Automation.Condition]::TrueCondition)) {
            if ($e.Current.Name -eq $name -and ($type -eq '' -or $e.Current.ControlType.ProgrammaticName -eq "ControlType.$type")) { return $e }
        }
        Start-Sleep -Milliseconds 500
    }
    return $null
}
function Dump($scope) {
    foreach ($e in $scope.FindAll('Descendants', [System.Windows.Automation.Condition]::TrueCondition)) {
        Log ("  {0} | {1} | {2}" -f $e.Current.ControlType.ProgrammaticName, $e.Current.Name, $e.Current.AutomationId)
    }
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type @'
using System; using System.Runtime.InteropServices;
public class M {
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint x, uint y, uint d, UIntPtr e);
  public static void Click(int x, int y) { SetCursorPos(x, y); System.Threading.Thread.Sleep(150); mouse_event(2, 0, 0, 0, UIntPtr.Zero); mouse_event(4, 0, 0, 0, UIntPtr.Zero); }
}
'@
# Кнопки «Параметров» не поддерживают Invoke: тогда настоящий клик мышью по центру элемента.
function Invoke($e) {
    $p = $null
    if ($e.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$p)) { $p.Invoke(); return }
    $r = $e.Current.BoundingRectangle
    [M]::Click([int]($r.X + $r.Width / 2), [int]($r.Y + $r.Height / 2))
}
function SetText($e, $text) {
    $p = $null
    if ($e.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$p) -and -not $e.Current.IsPassword) { $p.SetValue($text); return }
    Invoke $e
    Start-Sleep -Milliseconds 500
    [System.Windows.Forms.SendKeys]::SendWait($text)
}
function Dialog($sec = 30) {
    $c = New-Object System.Windows.Automation.PropertyCondition($UIA::ClassNameProperty, 'Credential Dialog Xaml Host')
    $end = (Get-Date).AddSeconds($sec)
    while ((Get-Date) -lt $end) {
        $d = $root.FindFirst('Children', $c)
        if ($d) { return $d }
        Start-Sleep -Milliseconds 500
    }
    return $null
}

$settings = $root.FindFirst('Children', (New-Object System.Windows.Automation.PropertyCondition($UIA::NameProperty, 'Settings')))
if (-not $settings) { Log 'нет окна Settings'; exit 1 }
$pinItem = Find $settings 'PIN (Windows Hello)' 'ListItem'
if (-not $pinItem) { Log 'нет пункта PIN'; exit 1 }
$setup = Find $settings 'Set up' 'Button' 3
if (-not $setup) {
    # Шевроны всех пунктов называются одинаково: нужен тот, что лежит в строке PIN. Раскрывается через ExpandCollapse.
    $pr = $pinItem.Current.BoundingRectangle
    $chev = $null
    foreach ($e in $settings.FindAll('Descendants', [System.Windows.Automation.Condition]::TrueCondition)) {
        if ($e.Current.Name -eq 'Show more settings' -and $e.Current.ControlType.ProgrammaticName -eq 'ControlType.Button') {
            $r = $e.Current.BoundingRectangle
            if (-not $e.Current.IsOffscreen -and $r.Y -ge $pr.Y -and ($r.Y + $r.Height) -le ($pr.Y + $pr.Height)) { $chev = $e; break }
        }
    }
    if (-not $chev) { Log 'шеврон PIN не найден'; exit 1 }
    ($chev.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern)).Expand()
    $setup = Find $settings 'Set up' 'Button' 10
}
if (-not $setup) { Log 'кнопка Set up не найдена:'; Dump $settings; exit 1 }
Start-Sleep 3   # пункт раскрывается с анимацией
# Нажатие делает Enter с клавиатуры ВМ: только настоящий ввод даёт окну «Windows Security» фокус клавиатуры.
$setup = Find $settings 'Set up' 'Button' 5
$setup.SetFocus()
Log 'фокус на Set up'
