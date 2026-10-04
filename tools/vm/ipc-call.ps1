param([Parameter(Mandatory)][string]$Cmd)
# Одна команда по pipe службы (как трей): печатает ответ. Запускается в сеансе tester.
$p = New-Object IO.Pipes.NamedPipeClientStream('.', 'SessionVault', 'InOut')
$p.Connect(5000)
$w = New-Object IO.StreamWriter($p); $w.AutoFlush = $true
$r = New-Object IO.StreamReader($p)
$w.WriteLine($Cmd)
$r.ReadLine()
