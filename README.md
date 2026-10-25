# defender-hunt-queries

Hunt and detection queries for the tools and techniques I write up on
[newsletter.securityinbits.com](https://newsletter.securityinbits.com/). Each markdown file is
one detection **topic** and carries the query in **both** stacks where relevant:

- **KQL** for Microsoft Defender for Endpoint (Advanced Hunting / custom detections)
- **ES|QL** for Elastic (Sysmon / ECS)

Keeping both stacks in one topic file is deliberate: same detection idea, two stacks, side by
side, with the prose and tuning notes that explain it. The repo is topic-first, not
language-first, on purpose.

## Files

| File | Topic |
| ---- | ----- |
| `anydesk.md` | AnyDesk RMM abuse: rename-proof identity, prevalence, `--set-password`, relay FQDNs, operator-IP failed P2P + the 7 SigmaHQ rules that fired. Issue: [32 Ransomware Groups Abuse AnyDesk](https://newsletter.securityinbits.com/p/32-ransomware-groups-abuse-anydesk) |
| `discovery-tools.md` | SoftPerfect NetScan, Advanced IP/Port Scanner (process / network / file events) |
| `softperfect-netscan.md` | SoftPerfect NetScan, focused process detection |
| `ssh-tunnel.md` | Reverse SSH SOCKS tunnel (`ssh -R`) detection + the aggregation tell |
| `screenconnect.md` | ScreenConnect RMM abuse: download origin (`FileOriginUrl`), vendor-signed client (match identity not trust), relay classifier (cloud 443 vs self-hosted 8041), the `e=Access` unattended-access launch string, service count per host, the Backstage operator shell + the 3 SigmaHQ rules that fired. Issue: [ScreenConnect RMM Abuse](https://newsletter.securityinbits.com/p/screenconnect-rmm-abuse-the-cloud) |

## Convention (keeps the dual-stack files machine-extractable)

The HEADING names the real language; the FENCE uses the closest GitHub-highlightable
identifier. 
- KQL  -> ` ```kusto ` fence (GitHub's Kusto grammar), under a `## KQL ...` / `### KQL ...` heading
- ES|QL -> ` ```sql ` fence (generic SQL, the closest available match), under a `## ES|QL ...` / `### ES|QL ...` heading


## How this was made

Every query was run against real telemetry from emulations I ran by hand in my home lab, and I
validated the results myself. AI-assisted development helped draft and refine the queries; I
reviewed and lab-tested each one before publishing. Always verify a query in your own environment
before you rely on it. Provided as-is under the [MIT License](LICENSE).
