Detection idea:
- Version info: SoftPerfect / Network Scanner / scanning networks
- cmdline: /hide + /auto

/hide = no GUI

/auto: = scan + XML output

## KQL (MDE, DeviceProcessEvents)

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessVersionInfoCompanyName has "SoftPerfect"
    or ProcessVersionInfoProductName has "Network Scanner"
    or ProcessVersionInfoFileDescription has "scanning networks"
    or ProcessCommandLine has_all ("/hide", "/auto")
| project
    Timestamp,
    FileName,
    SHA256,
    ProcessVersionInfoProductName,
    ProcessVersionInfoFileDescription,
    ProcessVersionInfoCompanyName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| sort by Timestamp asc
```
