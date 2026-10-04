Add-Type @'
using System; using System.Text; using System.Runtime.InteropServices; using System.Collections.Generic;
public class E {
  public delegate bool P(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] static extern bool EnumWindows(P p, IntPtr l);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  public static List<string> All() {
    var r = new List<string>();
    EnumWindows((h, l) => {
      if (!IsWindowVisible(h)) return true;
      var c = new StringBuilder(256); var t = new StringBuilder(256); uint pid;
      GetClassName(h, c, 256); GetWindowText(h, t, 256); GetWindowThreadProcessId(h, out pid);
      r.Add(h.ToInt64().ToString("x") + " | " + c + " | " + t + " | pid=" + pid);
      return true;
    }, IntPtr.Zero);
    return r;
  }
}
'@
[E]::All()
"foreground: " + [E]::GetForegroundWindow().ToInt64().ToString('x')
