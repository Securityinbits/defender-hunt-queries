# AnyDesk - hunt it by behavior

KQL queries from the newsletter issue **"32 Ransomware Groups Abuse AnyDesk. Your EDR Sees a
Legit Tool"** https://newsletter.securityinbits.com

All lab-validated on real MDE telemetry against both AnyDesk delivery paths: the **attended
portable** run (renamed binary in `%TEMP%`, victim clicks Accept) and the **unattended
service** install (`--install --silent` + piped `--set-password`, the Fog sequence).


Four angles, none of which trust the filename: **identity, rarity, behavior, destination** 

## Identity - rename-proof AnyDesk from user-writable paths

Presence check. Catches the renamed portable (`Invoice_Viewer.exe` in the lab) and the
untouched service binary side by side, keyed on PE version-info, restricted to paths where
a portable RMM tool has no business running. 

### KQL (MDE) - 1-day detection

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
// rename-proof AnyDesk identity (OriginalFileName is EMPTY for AnyDesk - do NOT use it)
| where ProcessVersionInfoCompanyName == "AnyDesk Software GmbH"
    or ProcessVersionInfoProductName == "AnyDesk"
    or ProcessVersionInfoFileDescription == "AnyDesk"
| where FolderPath contains @"\Users\" or FolderPath contains @"\Downloads\"
    or FolderPath contains @"\AppData\" or FolderPath contains @"\Temp\"
    or FolderPath contains @"\ProgramData\" or FolderPath contains @"\Public\"
| where FolderPath !startswith @"C:\Program Files"
| project Timestamp, DeviceId, ReportId, DeviceName, AccountName, FileName, FolderPath,
          ProcessVersionInfoCompanyName, ProcessVersionInfoFileDescription, ProcessVersionInfoProductName,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Rarity - 30-day prevalence hunt

A sanctioned RMM is everywhere or nowhere; a planted one lands on one or two machines.
Rank AnyDesk-fingerprinted binaries by host count - the renamed copy on a single endpoint
is the row that should stop you. Surfaces the lure filenames.

### KQL (MDE) - 30-day hunt

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessVersionInfoCompanyName == "AnyDesk Software GmbH" or ProcessVersionInfoProductName == "AnyDesk"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hosts=dcount(DeviceId),
            HostList=make_set(DeviceName,10), Users=make_set(AccountName,10)
    by FileName
| where Hosts <= 3
| order by Hosts asc, LastSeen desc
```

## Behavior - piped `--set-password` (highest fidelity)

The unattended-access setup: `cmd /c "echo <password> | AnyDesk.exe --set-password"`.
Command-line based, so the rename never mattered.

A person never produces this. Setting the unattended password by hand is Settings > Access >
Set password, which never touches the command line, so a piped `--set-password` is always
scripted. Baseline before alerting: AnyDesk documents this same command for
[mass deployment](https://support.anydesk.com/docs/command-line-interface-for-windows), so a
sanctioned rollout fires on many hosts inside one change window, parented by your deployment
agent. An operator fires on one or two hosts, parented by `powershell.exe` into `cmd.exe`.
If you do not deploy AnyDesk at all, there is nothing to baseline.

### KQL (MDE) - 1-day detection

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine contains "--set-password"
    or (InitiatingProcessCommandLine contains "set-password" and InitiatingProcessCommandLine has "echo")
| project Timestamp, DeviceId, ReportId, DeviceName, AccountName, FileName,
          FolderPath, ProcessVersionInfoCompanyName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

## Destination - relay callback, network only

AnyDesk cannot rename its infrastructure. Every client bootstraps to `boot.net.anydesk.com`
then a `relay-*.net.anydesk.com` server - a fact about AnyDesk's network, not the binary the
attacker controls. If version info is stripped and the filename renamed, this still fires.
Baseline once; any unsanctioned host reaching it is a lead. Relays rotate per session.

### KQL (MDE) - 1-day detection, relay-only

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl contains "net.anydesk.com"
| project Timestamp, DeviceId, ReportId, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          RemoteUrl, RemoteIP, RemotePort
```

### KQL (MDE) - 10-day wide variant (also catches the `download.anydesk.com` staging pull)

```kusto
DeviceNetworkEvents
| where Timestamp > ago(10d)
| where RemoteUrl endswith ".anydesk.com" // or net.anydesk.com
| project Timestamp, DeviceId, ReportId, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          RemoteUrl, RemoteIP, RemotePort
| order by Timestamp asc
```

## Operator IP from failed P2P hole-punch (opportunistic)

AnyDesk prefers a direct peer-to-peer link (TCP 7070) and tries to punch straight to the
operator's public IP before falling back to the relay. When the firewall blocks the punch,
the attempt logs as `ConnectionFailed` **to the operator's true egress IP**. The successful
session only ever shows the relay - so hunt the failures.

Caveats (lab-verified): opportunistic only - an operator who unchecks "Allow direct
connections" forces relay-only and the IP never appears; strict egress can skip the direct
attempt entirely. In this lab **MDE caught it; Sysmon did not**. The IP is operator
infra/egress (VPS/VPN/NAT) - a pivot and block IOC, not attribution. The reliable source
for the same IP is `ad.trace`'s `Logged in from` line on the host.

### KQL (MDE) 

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessVersionInfoCompanyName == "AnyDesk Software GmbH" or InitiatingProcessVersionInfoProductName == "AnyDesk"
| where ActionType == "ConnectionFailed"
| where not(ipv4_is_private(RemoteIP))   // public only
| where isempty(RemoteUrl) or RemoteUrl !endswith ".anydesk.com"   // not an AnyDesk relay FQDN
| summarize Attempts=count(), Ports=make_set(RemotePort), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, RemoteIP, InitiatingProcessFileName, Protocol
```

## SigmaHQ rules that fired (the fast first pass)

The community ruleset already survives the rename trick - it keys on the same three PE
fields. These seven fired in the lab across both scenarios; each rule name links to the exact yml.

| SigmaHQ rule | Fires on |
| ------------ | -------- |
| [Remote Access Tool - AnyDesk Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk.yml) | Any launch, incl. renamed binary (PE-metadata arm catches the rename) |
| [Anydesk Temporary Artefact](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_anydesk_artefact.yml) | Portable working files under the user profile |
| [Remote Access Tool - Anydesk Execution From Suspicious Folder](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_susp_exec.yml) | Launch outside `%AppData%` / Program Files |
| [Remote Access Tool - AnyDesk Silent Installation](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_silent_install.yml) | `--install --start-with-win --silent` |
| [Remote Access Tool - AnyDesk Piped Password Via CLI](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_piped_password_via_cli.yml) | `echo ... \| --set-password` - operationalize |
| [Suspicious Binary Writes Via AnyDesk](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_anydesk_writing_susp_binaries.yml) | e.g. binary landing in `C:\ProgramData\AnyDesk` |
| [Anydesk Remote Access Software Service Installation](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/service_control_manager/win_system_service_install_anydesk.yml) | Service registration (Event ID 7045) |
