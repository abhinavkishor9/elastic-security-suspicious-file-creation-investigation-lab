# Investigation Timeline 

| Time | Event | User | Process | PID | Evidence |
|---|---|---|---|---:|---|
| Oct 2, 2026 06:04:16.501 | PowerShell-related temporary file activity observed | SYSTEM | `powershell.exe` | 13688 | `__PSScriptPolicyTest_*` |
| Oct 2, 2026 06:04:17.024 | PowerShell policy-test file observed | SYSTEM | `powershell.exe` | 13688 | `__PSScriptPolicyTest_*` |
| Oct 2, 2026 06:04:17.027 | PowerShell policy-test file observed | SYSTEM | `powershell.exe` | 13688 | `__PSScriptPolicyTest_*` |
| Oct 2, 2026 06:05:21.243 | Controlled test file created | Dell | `pwsh.exe` | 21540 | `Lab13_Test.txt` |
| Oct 2, 2026 06:06:04.712 | Controlled PowerShell-named file created | Dell | `pwsh.exe` | 21540 | `Lab13_Suspicious.ps1` |
| After 06:06 | Execution search performed | - | - | - | No matching command-line event |

