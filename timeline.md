# Investigation Timeline — Lab 13

## Timeline Overview

The timeline documents the controlled file-creation activity and subsequent Elastic investigation.

| Time | Event | User | Process | PID | Evidence |
|---|---|---|---|---:|---|
| Oct 2, 2026 06:04:16.501 | PowerShell-related temporary file activity observed | SYSTEM | `powershell.exe` | 13688 | `__PSScriptPolicyTest_*` |
| Oct 2, 2026 06:04:17.024 | PowerShell policy-test file observed | SYSTEM | `powershell.exe` | 13688 | `__PSScriptPolicyTest_*` |
| Oct 2, 2026 06:04:17.027 | PowerShell policy-test file observed | SYSTEM | `powershell.exe` | 13688 | `__PSScriptPolicyTest_*` |
| Oct 2, 2026 06:05:21.243 | Controlled test file created | Dell | `pwsh.exe` | 21540 | `Lab13_Test.txt` |
| Oct 2, 2026 06:06:04.712 | Controlled PowerShell-named file created | Dell | `pwsh.exe` | 21540 | `Lab13_Suspicious.ps1` |
| After 06:06 | Execution search performed | - | - | - | No matching command-line event |

## File Creation Details

### Lab13_Test.txt

```text
Timestamp: Oct 2, 2026 @ 06:05:21.243
Host:      desktop-9mmm37v
User:      Dell
Process:   pwsh.exe
PID:       21540
Path:      C:\Users\Public\Lab13_Test.txt
```

### Lab13_Suspicious.ps1

```text
Timestamp: Oct 2, 2026 @ 06:06:04.712
Host:      desktop-9mmm37v
User:      Dell
Process:   pwsh.exe
PID:       21540
Path:      C:\Users\Public\Lab13_Suspicious.ps1
```

## Execution Check

The following search was performed:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*Lab13_Suspicious.ps1*"
| KEEP @timestamp, process.name, process.pid, process.parent.name, process.command_line
| SORT @timestamp DESC
```

Result:

```text
0 documents processed
```

No matching execution event was identified.

## Investigation Sequence

```text
Baseline file telemetry
        ↓
Controlled file creation
        ↓
Search for Lab13 files
        ↓
Process/user correlation
        ↓
Execution search
        ↓
Evidence-based assessment
```

## Final Timeline Assessment

The available telemetry confirms the creation of two controlled files and associates both with `pwsh.exe`, PID `21540`, under the `Dell` user.

No matching execution event for `Lab13_Suspicious.ps1` was identified.

The timeline therefore supports **file creation and attribution**, but does not support a conclusion of malicious execution or compromise.
