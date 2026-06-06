## Tools
- SoftPerfect NetScan
- Advanced IP Scanner
- Advanced Port Scanner

## KQL (Microsoft Defender for Endpoint)

### Process events

> **Catches:** any of the three tools by vendor, product, description, or flag pair.

> **Tune:** time window (default 30d). Otherwise leave alone.

```kusto
let CompanyKeywords = dynamic(["Famatech", "SoftPerfect"]);
let ProductKeywords = dynamic(["Advanced IP Scanner", "Advanced Port Scanner", "Network Scanner"]);
let DescKeywords    = dynamic(["Advanced IP Scanner", "Advanced Port Scanner", "Application for scanning networks"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessVersionInfoCompanyName has_any (CompanyKeywords)
    or ProcessVersionInfoProductName has_any (ProductKeywords)
    or ProcessVersionInfoFileDescription has_any (DescKeywords)
    or ProcessCommandLine has_all ("/portable", "/lng")
    or ProcessCommandLine has_all ("/hide", "/auto")
| project
    Timestamp, DeviceName, AccountName, FileName,
    ProcessCommandLine, ProcessVersionInfoCompanyName,
    ProcessVersionInfoProductName, ProcessVersionInfoFileDescription,
    SHA256, InitiatingProcessFileName,
    InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

### Network events

> **Catches:** any process making rapid connections to many private IPs across multiple ports. Tool-agnostic, so it survives binary renames AND metadata stripping.

> **Tune:** `ipThreshold` and `portThreshold` for your environment. Default 50 IPs / 3 ports per 5-minute bucket.


```kusto
let startTime = datetime(2026-04-02T03:00:00);
let endTime   = datetime(2026-05-06T10:00:00);
let ipThreshold   = 50;
let portThreshold = 3;
let bucket = 5m;
DeviceNetworkEvents
| where Timestamp between (startTime .. endTime)
| where RemoteIPType == "Private"
| where ActionType startswith "Connection"  
| summarize
    DistinctIPs   = dcount(RemoteIP),
    DistinctPorts = dcount(RemotePort),
    SampleIPs     = make_set(RemoteIP, 10),
    SamplePorts   = make_set(RemotePort, 10),
    FirstSeen     = min(Timestamp),
    LastSeen      = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, bin(Timestamp, bucket)
| where DistinctIPs >= ipThreshold and DistinctPorts >= portThreshold
| sort by DistinctIPs desc
```
### File events

> **Catches:** AIPS and APS install artifacts in their default folders. NetScan is already covered by the process query.

> **Tune:** folder path patterns if attackers stage to non-default locations.


```kusto
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any (@"\Advanced IP Scanner 2", @"\Advanced Port Scanner 2")
| summarize FilesDropped = make_set(FileName, 20), FileCount = dcount(FileName), FirstDrop = min(Timestamp)
    by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
       InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by FirstDrop asc
```
## ESQL (Elastic)
Same logic, Elastic field names. 

### Process events

> **Catches:** same surface as the KQL process query.

> **Tune:** time window. 

```sql
FROM logs-windows.sysmon_operational-default
| WHERE @timestamp > NOW() - 30 days
  AND event.code == "1"
| EVAL cmd_l = TO_LOWER(process.command_line)
| WHERE process.pe.company     RLIKE ".*(Famatech|SoftPerfect).*"
     OR process.pe.product     RLIKE ".*(Advanced IP Scanner|Advanced Port Scanner|Network Scanner).*"
     OR process.pe.description RLIKE ".*(Advanced IP Scanner|Advanced Port Scanner|Application for scanning networks).*"
     OR (cmd_l LIKE "*/portable*" AND cmd_l LIKE "*/lng*")
     OR (cmd_l LIKE "*/hide*"     AND cmd_l LIKE "*/auto*")
| KEEP @timestamp, host.name, user.name, process.name, process.command_line,
       process.pe.company, process.pe.product, process.pe.description,
       process.hash.sha256, process.parent.name, process.parent.command_line
| SORT @timestamp ASC
| LIMIT 1000
```

### Network events

> **Catches:** sweep behavior across all three tools via Sysmon event 3.

> **Tune:** thresholds (default 3 IPs / 2 ports per 5-min bucket for Sysmon).

```sql
FROM logs-windows.sysmon_operational-default
| WHERE @timestamp >= "2026-04-02T03:00:00Z" AND @timestamp <= "2026-05-06T10:00:00Z"
    AND event.code == "3"
    AND process.name IS NOT NULL
    AND destination.ip IS NOT NULL
    AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS DistinctIPs   = COUNT_DISTINCT(destination.ip),
        DistinctPorts = COUNT_DISTINCT(destination.port),
        TotalConns    = COUNT(*),
        SampleIPs     = TOP(destination.ip, 10, "asc"),
        SamplePorts   = TOP(destination.port, 10, "asc"),
        FirstSeen     = MIN(@timestamp),
        LastSeen      = MAX(@timestamp)
    BY host.name,
       process.executable,
       time_bucket = BUCKET(@timestamp, 5 minutes)
| WHERE DistinctIPs >= 3 AND DistinctPorts >= 2
| SORT DistinctIPs DESC
```

### File events

> **Catches:** AIPS and APS install footprints via Sysmon event 11.

> **Tune:** path patterns.

```sql
FROM logs-windows.sysmon_operational-default
| WHERE @timestamp >= "2026-04-02T03:00:00Z" AND @timestamp <= "2026-05-06T10:00:00Z"
    AND event.code == "11" AND file.path IS NOT NULL
| EVAL path_lc = TO_LOWER(file.path)
| WHERE path_lc LIKE "*advanced ip scanner 2*" OR path_lc LIKE "*advanced port scanner 2*"
| EVAL Tool = CASE(
    path_lc LIKE "*advanced ip scanner 2*","Advanced IP Scanner", "Advanced Port Scanner")
| STATS FilesDropped = TOP(file.name, 20, "asc"),
        FileCount    = COUNT_DISTINCT(file.name),
        FirstDrop    = MIN(@timestamp),
        LastDrop     = MAX(@timestamp)
    BY host.name, Tool, user.name, process.executable
| SORT FirstDrop ASC
| LIMIT 500
```
