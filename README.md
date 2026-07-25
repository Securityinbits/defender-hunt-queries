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
| `anydesk.md` | AnyDesk RMM abuse: rename-proof identity, prevalence, `--set-password`, relay FQDNs, operator-IP failed P2P + the 7 SigmaHQ rules that fired |
| `discovery-tools.md` | SoftPerfect NetScan, Advanced IP/Port Scanner (process / network / file events) |
| `softperfect-netscan.md` | SoftPerfect NetScan, focused process detection |
| `ssh-tunnel.md` | Reverse SSH SOCKS tunnel (`ssh -R`) detection + the aggregation tell |

## Convention (keeps the dual-stack files machine-extractable)

The HEADING names the real language; the FENCE uses the closest GitHub-highlightable
identifier. 
- KQL  -> ` ```kusto ` fence (GitHub's Kusto grammar), under a `## KQL ...` / `### KQL ...` heading
- ES|QL -> ` ```sql ` fence (generic SQL, the closest available match), under a `## ES|QL ...` / `### ES|QL ...` heading

