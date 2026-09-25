# Lab 3 — Encoded PowerShell detection (Splunk SPL)

[Download the standalone SPL query](encoded-powershell.spl) for copying into Splunk Search & Reporting.

## Scheduled detection query

Run with the alert's event-time range set to **Last 24 hours**, cron schedule `*/5 * * * *`, trigger condition **number of results > 0**, trigger frequency **Once**, and the **Add to Triggered Alerts** action.

```spl
index=main host="SOC-LAB-01" EventCode=1
| search CommandLine="*-EncodedCommand*"
| where _indextime >= relative_time(now(), "-5m")
    AND _indextime < now()
| eval IndexedTime=strftime(_indextime,"%Y-%m-%d %H:%M:%S")
| sort - _indextime
| table _time IndexedTime ComputerName User Image CommandLine ParentImage ProcessId ParentProcessId ProcessGuid
```

## Why the two time filters?

- **Last 24 hours**: broader event-time window to include events whose timestamps precede indexing by several minutes.
- **`_indextime` last 5 minutes**: only surface matching events newly indexed during the current five-minute interval.
- The broader event-time range still imposes a maximum lookback; this is a lab-tuned query, not a universal production rule.
- An event/indexing timestamp difference can result from transport delays, clock differences, or a combination. Root cause was not conclusively established.
- A scheduled search may execute late or events may be indexed at a window boundary; production alerting would need monitoring, margin/overlap, and deduplication.

## What it detects

Sysmon process-creation events (Event ID 1) with the string `-EncodedCommand` in the command line on `SOC-LAB-01`. This is an **investigation lead**, not proof of malicious activity.

## Lab test

```powershell
$test = "Write-Output 'LAB3-INDEX-TIME-VALIDATION'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($test))
powershell.exe -NoProfile -EncodedCommand $encoded
```

### Validation status

The original scheduled alert generated triggered-alert records. The later index-time-aware scheduled search returned one matching event; a separate new Triggered Alerts record after tuning was not independently confirmed in the screenshots.
