# Troubleshooting Notes — Lab 13

## Issue 1 — Confirming File Telemetry

Before creating the test files, the investigation first checked whether file telemetry was available.

Query:

```esql
FROM logs-*
| WHERE file.name IS NOT NULL
| KEEP @timestamp, host.name, user.name, process.name, process.pid, file.name, file.path
| SORT @timestamp DESC
```

The query returned approximately 1.3K documents.

This confirmed that file telemetry was available and populated in the current Elastic environment.

## Issue 2 — Identifying the Test Files

The controlled files were searched using:

```esql
FROM logs-*
| WHERE file.name LIKE "*Lab13*"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, file.name, file.path
| SORT @timestamp DESC
```

The query returned two documents.

This confirmed that the Elastic Agent successfully captured the controlled file activity.

## Issue 3 — Process Attribution

The returned events showed:

```text
Process: pwsh.exe
PID:     21540
User:    Dell
```

However, the parent process and command-line fields were not populated in the returned file events.

Therefore, those fields should not be inferred from the PowerShell console used during the test.

## Issue 4 — No Execution Event

The following query was used to determine whether the suspicious-looking file was subsequently executed:

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

This was expected because the file was intentionally not executed.

The result should therefore be documented as:

> No matching execution telemetry was observed.

It should not be interpreted as:

> The file could never have executed.

## Issue 5 — Legitimate Background File Activity

The baseline query returned legitimate file creation activity, including:

```text
powershell.exe
__PSScriptPolicyTest_*.psm1
__PSScriptPolicyTest_*.ps1
C:\WINDOWS\SystemTemp\
```

It also showed:

```text
wazuh-agent.exe
wazuh-agent.state
```

These observations demonstrate that file creation occurs routinely on the endpoint.

Therefore, a file creation alert requires contextual investigation.

## Investigation Lessons

### Do not treat the filename as proof

`Lab13_Suspicious.ps1` is intentionally suspicious-looking, but the contents were benign.

### Do not treat the extension as proof

A `.ps1` extension does not automatically indicate malicious PowerShell activity.

### Do not assume execution

File creation and process execution are separate investigative events.

### Do not invent missing telemetry

If the parent process or command line is missing, document it as unavailable rather than assuming its value.

### Do not overstate zero-result searches

A zero-result query means the searched telemetry did not contain a matching event. It does not prove that the activity was impossible.

## Recommended Follow-up

For a real investigation, additional enrichment could include:

- File hash
- File size
- File creation and modification timestamps
- Digital signature
- File contents
- Parent process
- Process command line
- Process tree
- Network connections
- Persistence locations
- Antivirus or EDR detections
- User context
- Related events before and after file creation
