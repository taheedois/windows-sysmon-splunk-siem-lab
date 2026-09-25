# Windows Sysmon & Splunk SIEM Lab

Hands-on cybersecurity lab using Windows 11, Sysmon, and Splunk Cloud to investigate endpoint activity, analyze PowerShell execution, correlate network connections, and develop a scheduled SIEM detection.

## Overview

I built a Windows endpoint monitoring environment in Oracle VirtualBox and used it to practice collecting, searching, and investigating security telemetry. I configured Microsoft Sysmon to record process creation and network connections, forwarded the Sysmon Operational log to Splunk Cloud, and used Splunk Search Processing Language (SPL) to investigate controlled activity.

I also created a scheduled detection for PowerShell executions using the `-EncodedCommand` argument. The exercise included troubleshooting Windows event-log permissions and examining differences between event timestamps and Splunk indexing timestamps.

**All activity in this project was generated for learning and testing in my Windows 11 lab.** Finding an encoded command is a reason to investigate, not proof that an endpoint is compromised.

## Lab environment

| Component | Purpose |
| --- | --- |
| Oracle VirtualBox | Host the Windows lab virtual machine |
| Windows 11 (`SOC-LAB-01`) | Monitored endpoint |
| Microsoft Sysmon | Record process creation (Event ID 1) and network connections (Event ID 3) |
| Windows Event Viewer / Sysmon Operational log | Confirm source events on the endpoint |
| Splunk Universal Forwarder | Send Windows events to Splunk Cloud |
| Splunk Cloud | Centralize, search, and alert on telemetry |
| PowerShell | Generate safe, repeatable test activity |

### Data flow

```text
Windows 11 VM (SOC-LAB-01)
         |
       Sysmon
         |
Microsoft-Windows-Sysmon/Operational
         |
Splunk Universal Forwarder
         |
     Splunk Cloud
         |
SPL searches -> investigation -> scheduled alert
```

## Objectives

- Install Sysmon and verify event collection locally.
- Forward endpoint telemetry to Splunk Cloud.
- Investigate Sysmon Event ID 1 and Event ID 3.
- Use process IDs, parent process IDs, and timestamps to reconstruct controlled activity.
- Write an SPL detection for encoded PowerShell execution.
- Schedule an alert and investigate results.
- Troubleshoot collection permissions and detection time windows.

## 1. Collect and forward Sysmon events

I installed Sysmon on the Windows 11 VM, verified the `Microsoft-Windows-Sysmon/Operational` log in Event Viewer, and generated test process and network activity.

After installing Splunk Universal Forwarder and configuring the event-log input, Splunk reported that it could not subscribe to the Sysmon Operational channel with Windows error code 5 (**Access denied**).

I identified the forwarder's service account as `NT SERVICE\SplunkForwarder`, added or verified its membership in the local **Event Log Readers** group, and restarted the forwarder. I then confirmed that Sysmon events were searchable in Splunk Cloud under host `SOC-LAB-01`. One verification search returned **4,825 events** at that point in the lab; this is a point-in-time count, not a fixed ongoing total.

## 2. Investigate process creation

Sysmon **Event ID 1** records process creation details, including the executable, command line, user, and parent-process information.

I generated a child PowerShell process with a harmless command:

```powershell
powershell.exe -NoProfile -Command "Get-Process notepad"
```

Then I searched for its execution in Splunk:

```spl
index=main host="SOC-LAB-01" EventCode=1
| search CommandLine="*Get-Process notepad*"
| table _time ComputerName User Image CommandLine ParentImage ProcessId ParentProcessId ProcessGuid
```

The result identified child PowerShell **PID 6044**, with original PowerShell **parent PID 6668**.

## 3. Investigate network connections and correlate activity

Sysmon **Event ID 3** showed the original PowerShell process making outbound TCP connections from `10.0.2.15` to `1.1.1.1:443` during controlled `Test-NetConnection` exercises.

```spl
index=main host="SOC-LAB-01" EventCode=3 DestinationIp="1.1.1.1"
| table _time ComputerName User Image ProcessId ProcessGuid SourceIp SourcePort DestinationIp DestinationPort Protocol Initiated
```

To review process and network events associated with the original PowerShell session, I used:

```spl
index=main host="SOC-LAB-01" (EventCode=1 OR EventCode=3) (ProcessId=6668 OR ParentProcessId=6668)
| table _time EventCode User Image CommandLine ProcessId ParentImage ParentProcessId SourceIp DestinationIp DestinationPort ProcessGuid ParentProcessGuid
| sort _time
```

The child process and network connections were related to the original PowerShell session, but **the child command did not cause the network connections**. These test activities occurred at separate times.

## 4. Detect encoded PowerShell execution

I generated a safe encoded PowerShell command using UTF-16LE (PowerShell's Unicode encoding for `-EncodedCommand`):

```powershell
$test = "Write-Output 'LAB3-INDEX-TIME-VALIDATION'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($test))
powershell.exe -NoProfile -EncodedCommand $encoded
```

Sysmon recorded a new process creation event with `-EncodedCommand` in its command line. I created the scheduled Splunk alert **LAB3 - PowerShell Encoded Command Detection**. The initial alert configuration successfully produced triggered-alert records.

During later validation, I found that several event timestamps were approximately **7 minutes 26 seconds** earlier than their Splunk indexing timestamps. A five-minute *event-time* window could therefore miss recently indexed events. This observed difference could involve forwarding latency, clock skew, or both; the lab did not establish a single underlying cause.

### Index-time-aware SPL

I updated the detection to use a **24-hour event-time search window** while selecting events whose `_indextime` was within the previous five minutes:

```spl
index=main host="SOC-LAB-01" EventCode=1
| search CommandLine="*-EncodedCommand*"
| where _indextime >= relative_time(now(), "-5m")
    AND _indextime < now()
| eval IndexedTime=strftime(_indextime,"%Y-%m-%d %H:%M:%S")
| sort - _indextime
| table _time IndexedTime ComputerName User Image CommandLine ParentImage ProcessId ParentProcessId ProcessGuid
```

The alert's cron schedule was `*/5 * * * *`, with the trigger condition **number of results > 0**, trigger frequency **Once**, and action **Add to Triggered Alerts**.

**Validation status:** A scheduled-search results page showed one matching event for the updated index-time-aware query. A separate new *Triggered Alerts* record after this final tuning was not yet independently verified in the lab screenshots. The earlier, original scheduled alert did produce triggered-alert records.

## 5. Decode and assess the test payload

I decoded the controlled payload in PowerShell:

```powershell
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
```

It resolved to:

```powershell
Write-Output 'LAB3-INDEX-TIME-VALIDATION'
```

**Finding:** This was an authorized, harmless lab test that printed a string. The command-line flag alone would not justify treating the activity as malicious.

## Skills practiced

Windows endpoint monitoring · Sysmon · Windows Event Logs · Splunk Universal Forwarder · Splunk Cloud · SPL · Process and parent-process investigation · Network connection analysis · Scheduled detections · Event time vs. index time · PowerShell decoding · Troubleshooting · Investigation documentation

## Supporting materials

- [Encoded PowerShell detection query and validation notes](detections/encoded-powershell.md)
- [SOC investigation report](investigation-report.md)
- Screenshots: pending upload to `screenshots/`. Only one copy of the index-time result will be retained (screenshot 19), followed by the decoded payload (screenshot 20).
