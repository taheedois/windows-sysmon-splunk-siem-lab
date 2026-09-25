# Lab 3 — SOC investigation report

## Case summary

| Item | Observation |
| --- | --- |
| Lab endpoint | `SOC-LAB-01` (Windows 11 in Oracle VirtualBox) |
| Data source | `Microsoft-Windows-Sysmon/Operational` via Splunk Universal Forwarder to Splunk Cloud |
| Detection | `LAB3 - PowerShell Encoded Command Detection` |
| Primary event type | Sysmon Event ID 1 (process creation) |
| Additional investigation | Sysmon Event ID 3 (network connection) |
| Disposition | Authorized lab simulation; no compromise established by this activity |

## Investigation objective

Collect and search Sysmon telemetry, review process ancestry and outbound network activity, identify an encoded PowerShell execution, decode the test payload, and verify detection scheduling under the timestamp differences observed in the lab.

## Investigation timeline

Times below are **as displayed in the provided Splunk screenshots**; they are not independently reconciled with the VM clock or a common timezone.

| Activity | Evidence |
| --- | --- |
| Process creation | A child PowerShell process executed `Get-Process notepad`, recorded as process ID `6040`, with parent PowerShell process ID `6668`. |
| Network activity | Original PowerShell process ID `6668` connected to `1.1.1.1` destination port `443` from local IP `10.0.2.15`, in a separate controlled `Test-NetConnection` exercise. |
| Initial encoded-command event | Splunk showed an Event ID 1 execution at `07:17:35` with `-EncodedCommand`. |
| Other controlled encoded-command events | Results also showed matching events at `07:24:31` and `07:33:05`. |
| Initial alert records | Triggered Alerts showed scheduled medium-severity records at `07:31:27`, `07:36:27`, `07:41:27`, and `07:46:27` UTC. The older search window repeatedly included earlier events. |
| Event/index-time comparison | One final controlled event showed `_time` `08:21:01.607` and index time `08:28:27` — approximately 7 minutes 25 seconds apart at the displayed precision. |
| Index-time-aware search | A scheduled-search results page returned one matching PowerShell event under the `_indextime` filter. A **new separate triggered-alert record after the tuning** was not independently verified. |

## Detection and triage

The search matched Sysmon Event ID 1 events on `SOC-LAB-01` where `CommandLine` contained `-EncodedCommand`. In the controlled exercises, the executable was `powershell.exe` and the user was the lab administrator account. Review of the executable, command-line flag, parent process, timestamps, and command content provided the context for interpretation.

The network connection to `1.1.1.1:443` and the `Get-Process notepad` child process were generated during separate tests. The evidence supports correlation through the original PowerShell process but **not** a claim that the child command initiated the outbound connection.

## Payload examination

The latest controlled payload was created with:

```powershell
$test = "Write-Output 'LAB3-INDEX-TIME-VALIDATION'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($test))
powershell.exe -NoProfile -EncodedCommand $encoded
```

The test variable was decoded with:

```powershell
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
```

Decoded text:

```powershell
Write-Output 'LAB3-INDEX-TIME-VALIDATION'
```

Because the command only printed a test marker in an authorized exercise, this finding was classified as **benign lab activity**. Encoded PowerShell is a useful detection signal, but the encoding itself does not establish malicious intent.

## Troubleshooting

### 1. Sysmon channel permissions

The Splunk forwarder initially logged `errorCode=5` (access denied) when subscribing to `Microsoft-Windows-Sysmon/Operational`. The forwarder service ran as `NT SERVICE\SplunkForwarder`; after correcting/verifying its Event Log Readers membership and restarting the service, event collection was verified in Splunk Cloud.

### 2. Event-time vs. index-time window

The original five-minute **event-time** alert window could miss entries that became searchable more than five minutes after the time recorded in the event. The lab's later event/indexing differences were around seven and a half minutes. Potential explanations include ingestion delay and clock skew; they were not isolated experimentally.

The revised query searches events from the last 24 hours and then filters `_indextime` to the previous five minutes. This approach returned a matching event during scheduled-search validation. Future improvements would include inspecting VM and Splunk time synchronization, reviewing actual forwarding latency, and handling scheduled-search overlap or jitter safely.

## Outcome

Demonstrated Sysmon telemetry collection, event forwarding, SPL analysis, process/network investigation, decoding of a controlled PowerShell payload, initial alert triggering, and index-time-aware scheduled-search testing. The case does not claim a real intrusion or a fully production-hardened rule.

## Evidence references

All images are uploaded in the [20-image evidence gallery](screenshots/README.md). Key files:

- [Sysmon Event ID 1 — process creation](screenshots/03-sysmon-powershell-process.png) and [Event ID 3 — network connection](screenshots/05-sysmon-network-connection.png).
- [Splunk process investigation](screenshots/11-splunk-powershell-investigation.png), [network connection](screenshots/12-splunk-network-connection.png), and [correlation](screenshots/13-splunk-process-correlation.png).
- [Initial triggered alerts](screenshots/17-splunk-alert-triggered.png) and [alert investigation results](screenshots/18-splunk-triggered-alert-investigation.png).
- [Index-time-aware search result](screenshots/19-splunk-index-time-detection.png).
- [Decoded PowerShell test](screenshots/20-powershell-payload-decoded.png).

[Reusable SPL detection query](detections/encoded-powershell.spl) · [Detection configuration notes](detections/encoded-powershell.md).
