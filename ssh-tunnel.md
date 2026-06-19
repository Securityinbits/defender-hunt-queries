Read this article for more background on the hunt KQL and ES|QL queries below:
https://securityinbits.substack.com/p/detecting-reverse-ssh-socks-tunnels

# From Sigma Logic
## KQL (MDE, DeviceProcessEvents)

```kusto
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ "ssh.exe"
| where ProcessCommandLine matches regex @"\s-\w*R" 
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
    InitiatingProcessVersionInfoProductVersion, InitiatingProcessIntegrityLevel
| order by Timestamp asc
```
## ES|QL (Elastic, Sysmon EID 1 / ECS)

```sql
FROM logs-windows.sysmon_operational-default
| WHERE @timestamp > NOW() - 1 hours
| WHERE event.code == "1"
| WHERE process.name == "ssh.exe"
| WHERE process.command_line RLIKE """.*\s-[A-Za-z]*R.*"""
| KEEP @timestamp, host.name, process.name, process.command_line,
       process.parent.name, process.parent.command_line,
       user.name, winlog.event_data.IntegrityLevel
| SORT @timestamp ASC
| LIMIT 1000
```

# Proving the Pivot in Network Telemetry

## KQL (MDE, DeviceNetworkEvents)

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName =~ "ssh.exe"
| where InitiatingProcessCommandLine matches regex @"\s-\w*R" 
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
    LocalIP, LocalPort, Protocol,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
    InitiatingProcessVersionInfoProductVersion, InitiatingProcessIntegrityLevel
| order by Timestamp asc
```
## ES|QL (Elastic, Sysmon EID 3)

```sql
// EID 3 has no CommandLine field — filter by image only, pivot via process.entity_id
FROM logs-windows.sysmon_operational-default
| WHERE @timestamp > NOW() - 1 hour
| WHERE event.code == "3"
  AND process.name == "ssh.exe"
| KEEP @timestamp, host.name, destination.ip, destination.port, destination.domain,
       source.ip, source.port, network.transport,
       process.name, process.entity_id, user.name
| SORT @timestamp ASC
| LIMIT 1000
```
## The aggregation: the cardinality and churn tell

>Now collapse the session into one row and read its shape. This is the query that pulls benign apart from malicious.

### KQL (MDE, DeviceNetworkEvents)

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName =~ "ssh.exe"
| where InitiatingProcessCommandLine matches regex @"\s-\w*R"
| summarize
    DistinctRemoteIPs = dcount(RemoteIP),
    DistinctRemotePorts = dcount(RemotePort),
    Successes = countif(ActionType == "ConnectionSuccess"),
    Failures = countif(ActionType == "ConnectionFailed"),
    Window = max(Timestamp) - min(Timestamp)
    by DeviceName, InitiatingProcessCommandLine
```
### ES|QL (Elastic, Sysmon EID 1 + EID 3 correlated by ProcessGuid)

```sql
// SSH reverse-tunnel detection (Sysmon EID 1 + EID 3 correlated by ProcessGuid)
FROM logs-windows.sysmon_operational-default
| WHERE @timestamp > NOW() - 1 hour
| WHERE event.code IN ("1", "3")
| WHERE process.name == "ssh.exe"
| EVAL is_tunnel_start = event.code == "1"
    // hyphen flag-cluster containing the -R (remote forward) flag: -R, -NR, -fNR, -fNTR ...
    AND process.command_line RLIKE """.*\s-[A-Za-z]*R.*"""
| STATS tunnel_starts        = COUNT(*) WHERE is_tunnel_start,
        DistinctRemoteIPs    = COUNT_DISTINCT(destination.ip),
        DistinctRemotePorts  = COUNT_DISTINCT(destination.port),
        NetworkConnections   = COUNT(*) WHERE event.code == "3",
        InitiatingProcessCommandLine = VALUES(process.command_line),
        first_seen = MIN(@timestamp),
        last_seen  = MAX(@timestamp)
        BY DeviceName = host.name, process.entity_id
| WHERE tunnel_starts > 0
| EVAL Window = DATE_DIFF("minutes", first_seen, last_seen)
| KEEP DeviceName, InitiatingProcessCommandLine, DistinctRemoteIPs, DistinctRemotePorts,
       NetworkConnections, Window, first_seen, last_seen
| SORT DeviceName ASC
| LIMIT 1000
```
