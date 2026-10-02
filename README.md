# Elastic Security — Suspicious File Creation Investigation Lab

## Overview

This lab investigates suspicious file creation activity on a Windows endpoint using Elastic Security endpoint telemetry.

The investigation uses controlled file creation to simulate activity that a SOC analyst might encounter during an endpoint investigation. The objective is not to create or execute malware, but to determine how file creation events can be investigated and correlated with the responsible process, user, file path, and potential follow-on execution.

The lab demonstrates an evidence-driven approach where a suspicious filename or file extension is treated as an investigation lead rather than automatic proof of malicious activity.

## Lab Environment

| Component | Details |
|---|---|
| Platform | Windows 11 |
| Host | `DESKTOP-9MMM37V` |
| User | `Dell` |
| SIEM / XDR | Elastic Security |
| Agent Policy | `Windows-SOC-Lab rev. 2` |
| Elastic Agent | `9.5.4+build2026` |
| Process | `pwsh.exe` |
| Test Location | `C:\Users\Public\` |

## Scenario

A SOC analyst observes file creation activity on a Windows endpoint and wants to determine whether the activity represents normal administrative or application behavior or something requiring further investigation.

Two controlled files are created in `C:\Users\Public\`:

- `Lab13_Test.txt`
- `Lab13_Suspicious.ps1`

The analyst then searches Elastic telemetry for these files and examines the associated timestamp, hostname, username, process, PID, filename, and file path.

The investigation also checks whether the `.ps1` file was subsequently executed. No matching process command-line event was identified, allowing the investigation to distinguish file creation from file execution.

## Investigation Focus

The investigation focuses on:

- File creation telemetry
- File names and extensions
- File paths
- Creating process
- Process ID
- User attribution
- Follow-on execution
- Endpoint telemetry availability
- Evidence-based assessment

## Key Findings

Elastic returned two file events matching `Lab13`:

| Time | User | Process | PID | File |
|---|---|---|---:|---|
| Oct 2, 2026 06:05:21 | `Dell` | `pwsh.exe` | `21540` | `Lab13_Test.txt` |
| Oct 2, 2026 06:06:04 | `Dell` | `pwsh.exe` | `21540` | `Lab13_Suspicious.ps1` |

Both files were created under:

`C:\Users\Public\`

The endpoint telemetry associated both events with `pwsh.exe`, PID `21540`, running under the `Dell` user.

A separate search for execution of `Lab13_Suspicious.ps1` returned:

`0 documents processed`

Therefore, the investigation confirmed file creation but did not identify evidence that the test PowerShell file was executed.

## Baseline Observation

A broader file telemetry query returned approximately 1.3K documents.

The results also showed legitimate system activity such as:

- `powershell.exe` creating temporary PowerShell policy-test files under `C:\WINDOWS\SystemTemp\`
- `wazuh-agent.exe` writing its state file

This demonstrates why file creation should be evaluated in context rather than treated as inherently malicious.

## Conclusion

The investigation confirmed controlled creation of two files in `C:\Users\Public\` and successfully correlated both events with the `Dell` user and `pwsh.exe` process. The `.ps1` filename represented a useful hunting lead, but no subsequent execution of the file was observed in the available telemetry. The activity therefore demonstrates suspicious-file investigation methodology rather than confirmed malicious behavior.

The main lesson is that a file name, extension, or location alone is insufficient to establish compromise. Stronger conclusions require correlation with process execution, parent-child relationships, file contents or hashes, persistence mechanisms, network activity, and other supporting evidence.

## Evidence-Based Assessment

### Confirmed

- `Lab13_Test.txt` was created.
- `Lab13_Suspicious.ps1` was created.
- Both files were created in `C:\Users\Public\`.
- Both events were associated with `pwsh.exe`.
- The associated user was `Dell`.
- The process ID was `21540`.

### Not Observed

- Execution of `Lab13_Suspicious.ps1`
- Malicious payload execution
- Persistence
- Command-and-control activity
- Data exfiltration

### Investigation Limitation

The available telemetry establishes file creation and process attribution, but the absence of an execution event should not be interpreted as proof that execution is impossible. It only means that execution was not demonstrated by the searched telemetry.
