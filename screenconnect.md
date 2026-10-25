# ScreenConnect (ConnectWise Control) - hunt a vendor-signed implant

Query reference for the newsletter issue **"ScreenConnect RMM Abuse: The Cloud Client Gets In,
The Self-Hosted One Stays"**. The reasoning, lab evidence and caveats are in the issue:
[newsletter.securityinbits.com](https://newsletter.securityinbits.com)

Lab-validated on two real ConnectWise-signed samples detonated on a live host and back-filled
against MDE + Elastic. Every query is a 30-day hunt via `let lookback = 30d`; drop it to `1d` for
a scheduled rule, and add `DeviceId` + `ReportId` to `project` to save one as a custom detection.

## 1. Download origin (MDE)

`FileOriginUrl` captures the download URL at write time, and held on both samples even with no
`Zone.Identifier` MoTW stream on disk. Blind to an implant that never touched a browser.

### KQL (MDE) - 30-day hunt, installer download origin

```kusto
// ScreenConnect installer arriving from the internet, with its download origin
let lookback = 30d;                                                           
DeviceFileEvents
| where Timestamp > ago(lookback)
| where FileName has "ScreenConnect" or FileOriginUrl has "screenconnect.com" 
| where isnotempty(FileOriginUrl)                                             
| project Timestamp, DeviceName, FileName, FolderPath, FileOriginUrl, FileOriginReferrerUrl, SHA256
```

## 2. Vendor identity (Elastic)

Match the RMM vendor's signer, not the trust status. Both samples were validly signed, so a
`code_signature.trusted == false` filter drops them.

### ES|QL (Elastic) - 30-day hunt, RMM-vendor signature

```sql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 30 days
| WHERE event.action : "start"
| WHERE STARTS_WITH(process.code_signature.subject_name, "ConnectWise")   
| STATS firstseen = MIN(@timestamp), events = COUNT(*), paths = TOP(process.executable, 5, "asc")
    BY host.name, process.name, process.code_signature.subject_name, process.code_signature.trusted
```

## 3. Relay classifier (MDE)

Cloud/trial is `instance-<id>-relay.screenconnect.com` on 443, self-hosted is a bare IP or
foreign domain, typically on 8041. The only query here that tells two implants apart.

### KQL (MDE) - 30-day hunt, relay callback classifier

```kusto
// ScreenConnect relay callback: cloud (443, *.screenconnect.com) vs self-hosted (8041 or a foreign host)
let lookback = 30d;                                                       
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName =~ "ScreenConnect.ClientService.exe"
| where ActionType == "ConnectionSuccess"
| extend RelayModel = case(RemoteUrl matches regex @"(?i)instance-[a-z0-9]+-relay\.screenconnect\.com", "cloud/trial",
                           isnotempty(RemoteUrl) and RemoteUrl !endswith "screenconnect.com", "self-hosted",
                           RemotePort == 8041, "self-hosted",
                           "review")
| project Timestamp, DeviceName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, RelayModel
```

## 4. Unattended-access role (MDE)

`e=Access&y=Guest` on the client command line means persistence rather than a one-off support
session, and the same string carries the `h=` relay host.

### KQL (MDE) - 30-day hunt, client launch string

```kusto
// The e=Access&y=Guest role and the h= relay host live on the client process cmdline
let lookback = 30d;                                              
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName =~ "ScreenConnect.ClientService.exe"
| where ProcessCommandLine has "y=Guest"                         
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

## 5. Count the services (MDE)

Each ScreenConnect client installs its own `ScreenConnect Client (<thumbprint>)` service, one per
server that owns the host. More than one on a host you did not deploy = more than one server owns
it, or one client was upgraded from a support session to unattended access (that shape is published,
not lab-observed). Section 4's launch string tells them apart: two different `h=` relays = two servers.
In the lab, sample 2 alone left two on one host, nine minutes apart: the cloud client, then the
self-hosted one its operator pushed. (A third row in the lab data is sample 1, an earlier run on
the same host that was rolled back before sample 2.)

### KQL (MDE) - 30-day hunt, hosts with more than one ScreenConnect client service

```kusto
// More than one ScreenConnect service on one host = more than one server owns it (or a support-to-access upgrade)
let lookback = 30d;
DeviceEvents
| where Timestamp > ago(lookback)
| where ActionType == "ServiceInstalled"
| extend Svc = tostring(parse_json(AdditionalFields).ServiceName)
| where Svc startswith "ScreenConnect Client"
| summarize Services = dcount(Svc), ServiceNames = make_set(Svc, 10),
            FirstInstall = min(Timestamp), LastInstall = max(Timestamp) by DeviceId, DeviceName
| where Services > 1
```

## 6. The operator's shell (MDE)

`ScreenConnect.WindowsBackstageShell.exe` is the hidden session an operator opens behind the
user's desktop, spawned by the client service as SYSTEM. In the lab it started once per live
operator session: in sample 2 from the cloud client, 4 minutes after it landed and before the operator
pushed the self-hosted one; in sample 4 from the self-hosted client, under 2 minutes after install.

### KQL (MDE) - 30-day hunt, Backstage shell launch

```kusto
// The operator's hidden shell, spawned by the ScreenConnect service
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName =~ "ScreenConnect.WindowsBackstageShell.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, AccountName, ProcessCommandLine
```

## 7. SigmaHQ rules that fired

Confirmed with [Hayabusa](https://github.com/Yamato-Security/hayabusa) against the sample-2 evtx,
offline rather than in the live SIEM.

| SigmaHQ rule | Level | Log / EID | Fires on |
| ------------ | ----- | --------- | -------- |
| [Remote Access Tool - ScreenConnect Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect.yml) (`57bff678`) | medium | Sysmon 1 | The client running, keyed on the binary's own identity |
| [Remote Access Tool - ScreenConnect Remote Command Execution - Hunting](https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_child_proc.yml) (`d1a401ab`) | medium | Sysmon 1 / Security 4688 | Child processes of the ScreenConnect client |
| [DNS Query To Remote Access Software Domain From Non-Browser App](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/dns_query/dns_query_win_remote_access_software_domains_non_browsers.yml) (`4d07b1f4`) | medium | Sysmon 22 | The client service resolving its relay, browser lookups excluded |

The Hunting rule is hunting-grade and high-volume (roughly 210 hits on one host). Tune it before
it goes near an alert queue.
