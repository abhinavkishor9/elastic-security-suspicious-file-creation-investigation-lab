# Investigation Notes 

## 1. Endpoint Verification

The Elastic Agent was confirmed as healthy.

| Field | Value |
|---|---|
| Host | `DESKTOP-9MMM37V` |
| Agent Policy | `Windows-SOC-Lab rev. 2` |
| Agent Version | `9.5.4+build2026` |
| Status | Healthy |

This confirmed that endpoint telemetry was actively being collected during the investigation.

## 2. File Creation Baseline

The following query was used to identify recent file activity:

```esql
FROM logs-*
| WHERE file.name IS NOT NULL
| KEEP @timestamp, host.name, user.name, process.name, process.pid, file.name, file.path
| SORT @timestamp DESC
```

The query processed approximately 1.3K documents.

Recent results included:

- PowerShell temporary policy-test files under `C:\WINDOWS\SystemTemp\`
- `wazuh-agent.state` created by `wazuh-agent.exe`

This established that the endpoint was generating legitimate file activity before the controlled test.

## 3. Controlled File Creation

A benign test file was created:

```powershell
New-Item -Path "C:\Users\Public\Lab13_Test.txt" -ItemType File -Force
```

The file was subsequently verified using:

```powershell
Get-Item "C:\Users\Public\Lab13_Test.txt"
```

The file existed at:

`C:\Users\Public\Lab13_Test.txt`

The file size was `0` bytes.

## 4. Suspicious-Looking Test File

A harmless PowerShell script file was created:

```powershell
Set-Content -Path "C:\Users\Public\Lab13_Suspicious.ps1" -Value "# Elastic Lab 13 - benign test file"
```

The file was intentionally not executed.

The purpose was to determine whether Elastic could identify its creation and whether a subsequent execution event could be observed.

## 5. Search for Lab13 Files

The following query was used:

```esql
FROM logs-*
| WHERE file.name LIKE "*Lab13*"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, file.name, file.path
| SORT @timestamp DESC
```

Two documents were returned.

### Event 1

```text
Timestamp:    Oct 2, 2026 @ 06:06:04.712
Host:         desktop-9mmm37v
User:         Dell
Process:      pwsh.exe
PID:          21540
File:         Lab13_Suspicious.ps1
Path:         C:\Users\Public\Lab13_Suspicious.ps1
```

### Event 2

```text
Timestamp:    Oct 2, 2026 @ 06:05:21.243
Host:         desktop-9mmm37v
User:         Dell
Process:      pwsh.exe
PID:          21540
File:         Lab13_Test.txt
Path:         C:\Users\Public\Lab13_Test.txt
```

## 6. Process Attribution

Both file creation events were associated with:

```text
Process: pwsh.exe
PID:     21540
User:    Dell
```

This provides useful attribution for the controlled activity.

However, the telemetry did not provide a populated parent process name or command line in these particular file events.

Therefore, the investigation should not invent a parent-child relationship that was not present in the telemetry.

## 7. Execution Investigation

A follow-up search was performed:

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

No matching process command-line event was identified.

This is consistent with the fact that the test `.ps1` file was created but deliberately not executed.

## 8. Investigation Timeline

```text
06:05:21
    Lab13_Test.txt created
        ↓
06:06:04
    Lab13_Suspicious.ps1 created
        ↓
Elastic search
    Both files identified
        ↓
Process correlation
    pwsh.exe / PID 21540 / Dell
        ↓
Execution search
    No matching command-line event
```

## 9. Evidence Classification

### Confirmed

- Two `Lab13` files were created.
- Both files were located in `C:\Users\Public\`.
- Both were associated with `pwsh.exe`.
- Both were associated with PID `21540`.
- The user was `Dell`.

### Not Demonstrated

- Script execution
- Malicious code execution
- Persistence
- Network communication
- Command-and-control
- Data exfiltration

### Analyst Note

The correct conclusion is not:

> "A malicious PowerShell script was executed."

The supported conclusion is:

> "A PowerShell-named test file was created and associated with `pwsh.exe`; no matching execution event was observed in the searched telemetry."

This distinction is important for accurate SOC reporting.
