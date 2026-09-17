# ScreenConnect (ConnectWise Control) - hunt a vendor-signed implant

Hunt queries from the newsletter issue **"The ScreenConnect Installer Was Validly Signed. It
Was Still the Attack."** https://newsletter.securityinbits.com

Lab-validated on **two real samples** (ANY.RUN-sourced, ConnectWise-signed cloud-built clients,
lure-delivered), detonated on a live workstation and back-filled against both stacks (MDE +
Elastic). Egress to the real C2.

The core idea: the installer is **validly signed by ConnectWise** (DigiCert), served from a
`*.screenconnect.com` cloud instance the attacker rents. A signature-status or SmartScreen
filter passes it. So do not ask "is this untrusted." Match on **vendor identity, provenance,
the relay model, and the unattended-access role**.

Two collection notes that decide whether a hunt reaches the whole infrastructure:

- **The download host and the relay host wear different DNS names.** The file arrives from one
  `*.screenconnect.com` instance (or the lure host) and the client dials a
  `instance-<id>-relay.screenconnect.com` relay. Same tenant, unrelated-looking names. Pivot on
  one and you miss the other. Collect both.
- **Read cloud vs self-hosted off the launch string.** `h=instance-<id>-relay.screenconnect.com`
  + `p=443` is the official cloud/trial. A bare IP or a foreign domain, typically on `p=8041`,
  is a self-hosted rogue relay. One sample dropped **both** at once.

MDE queries keep `DeviceId` + `ReportId` so they save as custom detections.

## Delivery provenance (MDE) - where it came from, before it ran

`FileOriginUrl` records the download source at write time. It survived on both samples **even
though neither left a `Zone.Identifier` mark-of-the-web stream on disk**, so this holds where a
MoTW-presence hunt goes blind. MDE-only: Elastic recorded the file event but has no provenance
equivalent.

### KQL (MDE) - 30-day hunt

```kusto
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".msi" or FileName endswith ".exe"
| where isnotempty(FileOriginUrl)
| where InitiatingProcessVersionInfoCompanyName has "ScreenConnect"
     or InitiatingProcessVersionInfoCompanyName has "ConnectWise"
     or FileName has "ScreenConnect" or FileName has "ConnectWise"
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath,
          FileOriginUrl, FileOriginIP, SHA256, InitiatingProcessFileName
| order by Timestamp desc
```

## Identity - match the vendor signature, not the trust status

The counter-intuitive one. Both samples were validly ConnectWise-signed, so
`InitiatingProcessSignatureStatus != "Valid"` / `code_signature.trusted == false` filter them
**out**. The valid signature that defeats the trust filter is the exact field that catches the
tool when you read it the other way: match `code_signature.subject_name` (Elastic) or the PE
company name (MDE) against known RMM vendors. Treat trust status as an enrichment field, never
the discriminator.

### KQL (MDE) - 1-day detection

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
// rename-proof identity; ProcessVersionInfoOriginalFileName is unreliable here, use company/product
| where ProcessVersionInfoCompanyName has "ScreenConnect" or ProcessVersionInfoCompanyName has "ConnectWise"
     or ProcessVersionInfoProductName has "ScreenConnect" or ProcessVersionInfoProductName has "ConnectWise"
| project Timestamp, DeviceId, ReportId, DeviceName, AccountName, FileName, FolderPath,
          ProcessVersionInfoCompanyName, ProcessVersionInfoProductName,
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### ES|QL (Elastic) - 30-day, RMM-vendor signature

```sql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 30 days
| WHERE process.code_signature.subject_name LIKE "*ConnectWise*"
    OR process.pe.company LIKE "*ScreenConnect*"
    OR process.pe.company LIKE "*ConnectWise*"
| KEEP @timestamp, host.name, process.name, process.executable, process.command_line,
       process.parent.name, process.code_signature.subject_name, process.code_signature.trusted
| SORT @timestamp DESC
```

## Relay classifier - cloud/trial vs self-hosted

`instance-<id>-relay.screenconnect.com` + port 443 + a `*.screenconnect.com` DNS name + a valid
ConnectWise signature means cloud/trial. A bare IP or a foreign domain on 8041 means
self-hosted. Read it two ways: off the network destination, and off the client's own launch
string on the process command line (which also carries the `e=Access&y=Guest` role).

### KQL (MDE) - 1-day, network destination

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl matches regex @"(?i)instance-[a-z0-9]+-relay\.screenconnect\.com"
    or (InitiatingProcessFileName =~ "ScreenConnect.ClientService.exe" and RemotePort in (443, 8040, 8041))
| extend RelayModel = iff(RemoteUrl matches regex @"(?i)instance-[a-z0-9]+-relay\.screenconnect\.com",
                         "cloud/trial", "self-hosted?")
| project Timestamp, DeviceId, ReportId, DeviceName, RemoteUrl, RemoteIP, RemotePort,
          RelayModel, InitiatingProcessFileName
```

### KQL (MDE) - 1-day, the launch string on the client process (the `e=Access&y=Guest` role + relay)

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "ScreenConnect.ClientService.exe"
| where ProcessCommandLine has "y=Guest"
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, InitiatingProcessFileName,
          ProcessCommandLine
```

### ES|QL (Elastic) - 1-day, network destination

```sql
FROM logs-endpoint.events.network-*
| WHERE @timestamp > NOW() - 1 DAY
| WHERE TO_LOWER(destination.domain) RLIKE "instance-[a-z0-9]+-relay\\.screenconnect\\.com"
    OR (process.name == "ScreenConnect.ClientService.exe" AND destination.port IN (443, 8040, 8041))
| KEEP @timestamp, host.name, destination.domain, destination.ip, destination.port, process.name
```

> **ES|QL `RLIKE` trap:** it is Lucene regex with no inline flags, so `(?i)` does not fold case,
> it silently matches nothing. Lower-case the field with `TO_LOWER()` instead. KQL `matches regex`
> (RE2) does honour `(?i)`, so the KQL blocks keep it.

## Persistence - EID 7045 service install

Both samples registered an EID 7045 service `ScreenConnect Client (<thumbprint>)`, LocalSystem,
auto-start. In MDE that lands in `DeviceEvents` as `ActionType == "ServiceInstalled"`, with the
service name in `AdditionalFields`.

### KQL (MDE) - 30-day hunt

```kusto
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "ServiceInstalled"
| where AdditionalFields has "ScreenConnect Client"
| project Timestamp, DeviceId, ReportId, DeviceName, ActionType, AdditionalFields
```

> **Lab correction (or you ship a dead rule):** the `e=Access&y=Guest` role and the `h=` relay
> are **not** in the service event's `AdditionalFields` (it carries only ServiceName, ServiceType,
> ServiceStartType, ServiceAccount). Filter the service event on `e=Access` and you get zero.
> The launch string lives on the `ScreenConnect.ClientService.exe` process command line, use the
> relay-classifier process query above for it.

### ES|QL (Elastic) - 30-day, service install via Sysmon EID 7045 / event.code 7045

```sql
FROM logs-windows.sysmon_operational-*, logs-endpoint.events.*
| WHERE @timestamp > NOW() - 30 days
| WHERE event.code == "7045"
| WHERE TO_LOWER(message) LIKE "*screenconnect client*"
| KEEP @timestamp, host.name, event.code, service.name, message
| SORT @timestamp DESC
```

## Operator control - the hidden Backstage shell + SystemTemp RunFile

When an operator takes the session, the client spawns a shell. **Lab-verified on sample 2 (this is the
correction that matters):** the operator joined at 17:05:12 via `ScreenConnect.WindowsBackstageShell.exe`,
ScreenConnect's **hidden** shell (a child of `ClientService.exe`), NOT `cmd.exe`/`powershell.exe`. Then they
used `RunFile` to stage a payload under `C:\Windows\SystemTemp\ScreenConnect\<ver>\Temp\` and executed it,
handing off to a self-hosted relay. A cmd/powershell child rule would have missed the operator entirely.

> **Two anchors, both stronger than a cmd/powershell child.** `WindowsBackstageShell.exe` as a child of
> `ClientService.exe` is the hidden operator shell. A file written under
> `C:\Windows\SystemTemp\ScreenConnect\*\Temp\` and then executed means a human pushed something. Neither has
> a benign explanation on an endpoint.

### KQL (MDE) - operator join (Backstage) or operator-staged payload (SystemTemp RunFile)

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName =~ "ScreenConnect.WindowsBackstageShell.exe" and InitiatingProcessFileName =~ "ScreenConnect.ClientService.exe")
     or (ProcessCommandLine has @"\SystemTemp\ScreenConnect\" and (ProcessCommandLine has "RunFile"
          or FileName in~ ("msiexec.exe","cmd.exe","powershell.exe","rundll32.exe")))
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

### ES|QL (Elastic)

```sql
FROM logs-endpoint.events.process-*, logs-windows.sysmon_operational-*
| WHERE @timestamp > NOW() - 1 DAY
| WHERE (process.name == "ScreenConnect.WindowsBackstageShell.exe" AND process.parent.name == "ScreenConnect.ClientService.exe")
    OR TO_LOWER(process.command_line) LIKE "*\\systemtemp\\screenconnect\\*"
| KEEP @timestamp, host.name, process.name, process.command_line, process.parent.name
```

### Secondary - the classic cmd/powershell child (corroboration)

Keep this too - some operators do drop a `cmd`/`powershell` child - but it is NOT the primary anchor, because
the Backstage shell above is what an operator gets by default and it is not `cmd`/`powershell`.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("ScreenConnect.ClientService.exe","ScreenConnect.WindowsClient.exe","ScreenConnect.WindowsBackstageShell.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","net.exe","whoami.exe","nltest.exe")
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```
> Watch the parent: in the case-10 window the `powershell.exe -EncodedCommand` processes were OURS
> (`qemu-ga.exe` -> `gspawn-win64-helper.exe`, the lab guest-exec path), not the operator. Check the parent
> before attributing any PowerShell to the adversary.

## SmartScreen companion (MDE) - and why it stayed silent

### KQL (MDE)

```kusto
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("SmartScreenUrlWarning","SmartScreenAppWarning","ExploitGuardSmartScreenBlocked")
| project Timestamp, DeviceId, ReportId, DeviceName, ActionType, FileName, RemoteUrl, InitiatingProcessFileName
```

> **Lab result: 0 rows, both samples.** A ConnectWise-signed, cloud-built client served from
> `*.screenconnect.com` is neither low-reputation nor low-prevalence, so SmartScreen had no reason
> to warn. Scope this companion to the **repacked / on-prem** variant only, not the cloud-delivery
> case. (Confirm the `ActionType` strings on your tenant, they drift.)

## Elastic rules that fired (the fast first pass)

Built-in Elastic Defend rules that caught the two samples in the lab. The behavioural catch is
the RMM-vendor / newly-observed-host shape, not a signature-status filter.

| Elastic rule | Fires on | Note |
| ------------ | -------- | ---- |
| First Time Seen DNS Query to RMM Domain | Non-browser process resolving an RMM domain | First to fire; browser exclusion is what makes it work |
| First Time Seen Remote Monitoring and Management Tool | Process signed by a known RMM vendor | **Fires because the binary is validly signed** - the counter to trust-status filters |
| Multiple Remote Management Tool Vendors on Same Host | Two distinct RMM vendors starting within minutes | Fired when the second implant landed |
| Newly Observed ScreenConnect Host Server | ScreenConnect client dialing a server that is not the official cloud | **Fired HIGH on the self-hosted relay** - the one rule that caught the rogue-relay stage |
| Remote Management Access Launch After MSI Install | `msiexec` (parent `explorer.exe`/`sihost.exe`) then the ScreenConnect client with `?e=Access&y=Guest...&k=` | Caught the MSI sample. **Missed the EXE-wrapped sample** - its `msiexec` parent was `ScreenConnect.ClientSetup.exe`, so the parent constraint has a gap worth widening |

## SigmaHQ rules that fired (offline, via Hayabusa)

SigmaHQ rules that fire on the case-10 telemetry, confirmed by running
[Hayabusa](https://github.com/Yamato-Security/hayabusa) against the collected evtx (Sysmon +
Security) from the sample-2 detonation. Every first-fire time lands inside the detonation window
(first client launch 17:00:50, service install 17:01:00, relay DNS 17:01:03 UTC).

| SigmaHQ rule | Level | Log / EID | Fires on |
| ------------ | ----- | --------- | -------- |
| [Remote Access Tool - ScreenConnect Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect.yml) (`57bff678`) | medium | Sysmon 1 | The ScreenConnect client launching (`ScreenConnect.ClientService.exe` / `.WindowsClient.exe`) |
| [Remote Access Tool - ScreenConnect Remote Command Execution - Hunting](https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_child_proc.yml) (`d1a401ab`) | medium | Sysmon 1 / Security 4688 | Child processes of the ScreenConnect client |
| [DNS Query To Remote Access Software Domain From Non-Browser App](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/dns_query/dns_query_win_remote_access_software_domains_non_browsers.yml) (`4d07b1f4`) | medium | Sysmon 22 | The client service resolving the relay domain (browser resolutions excluded) |

Corroborating built-in events (not ScreenConnect-specific Sigma rules): EID 7045 / 4697 service
installs for `ScreenConnect Client (<thumbprint>)` under `C:\Program Files (x86)\`, one per
sample-2 implant (17:01:00 and 17:09:43 UTC).

> **Provenance and a tuning caveat, stated honestly.** These fired via Hayabusa against the evtx
> after the fact, not in the live SIEM during the run (the live catches were Elastic's own rules
> above). Same telemetry, offline Sigma engine. The child-proc "Hunting" rule is hunting-grade and matched
> the client's helper-process tree, so it is high-volume (210 hits over the implants' life), not one clean
> alert - tune before operationalising. Note it does NOT specifically flag the operator's hidden
> `WindowsBackstageShell.exe` join or the SystemTemp `RunFile` staging (both observed on sample 2); those need
> the operator-control queries above, which are the higher-fidelity signal.

## MDE alerts (context)

With Defender AV live, MDE prevented the sample first (`'Sonbokli' malware was prevented`, the
Microsoft detection name for this abused-ScreenConnect family) and its EDR fired `Uncommon
remote access software` (CommandAndControl) independently of AV. With real-time protection off,
MDE recorded the full telemetry chain and raised no alert, so it ships no default "RMM tool
installed" analytic comparable to Elastic's. Fill that gap with the identity / relay / service
queries above as custom detections.
