# elastic-security-suspicious-file-creation-investigation-lab
## Overview
File creation is a useful endpoint investigation signal because attackers may create:

Temporary payloads
Scripts
Configuration files
Dropped executables
Persistence-related files
Staged data
Files in unusual directories

However, file creation alone does not indicate malicious activity. Windows, browsers, installers, security tools, and normal applications constantly create files.

The investigation should therefore focus on:

File Creation
      ↓
Timestamp
      ↓
File Path / Name
      ↓
Creating Process
      ↓
User
      ↓
Parent Process
      ↓
File Extension
      ↓
Follow-on Execution
      ↓
SOC Assessment

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

## Lab Objectives

The objectives of this lab are to:

- Understand how file creation telemetry can be used for endpoint threat hunting.
- Identify newly created files and examine their filenames, extensions, and paths.
- Correlate file creation events with the associated user and process.
- Identify the process ID associated with a file creation event.
- Investigate files created in locations that may warrant additional scrutiny, such as `C:\Users\Public\`.
- Distinguish suspicious-looking file characteristics from evidence of actual malicious behavior.
- Investigate whether a newly created PowerShell script is subsequently executed.
- Correlate file creation activity with process execution telemetry where available.
- Establish a timeline connecting file creation and potential follow-on activity.
- Recognize legitimate background file creation performed by Windows and security software.
- Document situations where parent-process or command-line telemetry is unavailable.
- Correctly interpret zero-result searches without treating them as absolute proof that an activity never occurred.
- Apply an evidence-driven approach when assessing potentially suspicious file activity.
- Clearly separate confirmed observations from assumptions, investigative leads, and unknowns.
- Reinforce that file creation alone is insufficient to establish malware execution or endpoint compromise.

## Lab Scenario

A SOC analyst is investigating file creation activity on a Windows endpoint after identifying files that could potentially warrant further investigation. The objective is to determine whether the activity represents normal administrative or application behavior or whether there is evidence of malicious file creation or follow-on execution.

The investigation uses controlled files to simulate a suspicious-file scenario without executing any malicious payload. The analyst creates:

- `Lab13_Test.txt`
- `Lab13_Suspicious.ps1`

Both files are created under `C:\Users\Public\`, allowing the analyst to investigate how Elastic Security records the activity.

The investigation focuses on:

- Identifying when the files were created.
- Determining the file paths and filenames.
- Identifying the associated user and process.
- Correlating the activity with the process ID.
- Checking whether the PowerShell-named file was subsequently executed.
- Comparing the activity with other legitimate file creation events on the endpoint.
- Documenting any missing or unavailable telemetry.

Elastic telemetry identifies both test files as being associated with `pwsh.exe`, PID `21540`, under the `Dell` user. A separate execution search is then performed for `Lab13_Suspicious.ps1`, but no matching process command-line event is returned.

The investigation therefore requires careful interpretation. A `.ps1` extension, a location such as `C:\Users\Public\`, or association with PowerShell may make an event interesting for hunting, but none of these characteristics alone proves malicious activity.

The scenario emphasizes the importance of correlating **file creation, process attribution, execution activity, and surrounding endpoint telemetry** before reaching a security conclusion.


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
