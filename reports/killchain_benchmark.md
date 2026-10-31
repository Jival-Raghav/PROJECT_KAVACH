# Kill Chain & Attack Path — Benchmark

Dataset: `firex-10G.log` — 9,125,382 events. Ground truth: `data/ground_truth/firex_planted.yaml` (20 scenarios, 28 steps; recovered by our own hunt — the dataset shipped without labels).

| What we measure | Result | Good / Great | Rating |
|---|---|---|---|
| Detection | **100.0%** | > 70% / > 90% | 🟢 Great |
| Correct labels (strict) | **100.0%** | > 60% / > 85% | 🟢 Great |
| Attack path | **100%** | half / all | 🟢 Great |
| False alarms | **0.0%** | < 30% / < 10% | 🟢 Great |
| Processing time | **3.0 min** | < 3 h / < 1 h | 🟢 Great |
| Peak memory | **3.19 GB** | < 16 GB / < 8 GB | 🟢 Great |
| Investigation speed (p95 open) | **0.01 ms** | < 2 s / < 500 ms | 🟢 Great |

Attack paths: 20/20 scenarios rebuilt, of which 4/4 are multi-step chains where step order is actually tested. A scenario only counts as rebuilt when its incident contains no other scenario. Incidents spanning more than one scenario: 0. Incident purity (share of an incident's events that are planted): 100.0%.

Steps found 28/28; lenient label accuracy 100.0%; 20 incidents, 0 false alarms; 11,078 raw alerts merged into 20 incidents (B-3). Cold load of all incidents: 3.39 ms.

Stage timings (s): ingest 177.21, detect 4.72, correlate 0.0, enrich 0.3

## Per scenario

| Scenario | Steps | Path rebuilt | Incident |
|---|---|---|---|
| GT-01 XSS probing of the DMZ web portal | 1 | yes | 1 |
| GT-02 Mirai botnet C2 fan-in from the IoT segment | 1 | yes | 3 |
| GT-03 Malware download burst (invoice_2026.pdf.exe) | 1 | yes | 5 |
| GT-04 Firewall admin login from an unusual country (parul.sinha) | 1 | yes | 7 |
| GT-05 DNS tunnelling to doqotobitum.com | 1 | yes | 6 |
| GT-06 SQL injection against the DMZ web server | 1 | yes | 9 |
| GT-07 Nemucod dropper gets through, beacons to its C2, then exfiltrates | 3 | yes | 10 |
| GT-08 Low-and-slow exfiltration to one external host | 1 | yes | 11 |
| GT-09 Command injection against the DMZ web server | 1 | yes | 12 |
| GT-10 Webshell access on the DMZ web server | 1 | yes | 13 |
| GT-11 SMB fan-out from a LAN host to DMZ servers | 1 | yes | 14 |
| GT-12 External port scan of the DMZ | 1 | yes | 15 |
| GT-13 Firewall admin login from Russia (Deepika.Khan) | 1 | yes | 17 |
| GT-14 VPN impossible travel (keerat.ghughal) | 1 | yes | 16 |
| GT-15 Path traversal against the DMZ web server | 1 | yes | 18 |
| GT-16 Scan, SQL injection, webshell and exfiltration by one attacker | 4 | yes | 19 |
| GT-17 Rogue firewall admin svc_backup30 created, used, deleted | 3 | yes | 20 |
| GT-18 Logging and firewall policy tampering (Tejas.Roy) | 2 | yes | 2 |
| GT-19 SMB/RDP lateral sweep from a LAN host across DMZ servers | 1 | yes | 8 |
| GT-20 Five-day HTTPS beacon from a LAN host (every 300 s) | 1 | yes | 4 |

## Per step

| Step | Found | Expected | Labelled | OK |
|---|---|---|---|---|
| GT-01-1 | yes | T1190 | T1190 | yes |
| GT-02-1 | yes | T1071 | T1071 | yes |
| GT-03-1 | yes | T1105 | T1105 | yes |
| GT-04-1 | yes | T1078 | T1078 | yes |
| GT-05-1 | yes | T1071.004 | T1071.004 | yes |
| GT-06-1 | yes | T1190 | T1190 | yes |
| GT-07-1 | yes | T1204.002 | T1204.002 | yes |
| GT-07-2 | yes | T1071.001 | T1071.001 | yes |
| GT-07-3 | yes | T1041 | T1041 | yes |
| GT-08-1 | yes | T1041 | T1041 | yes |
| GT-09-1 | yes | T1190 | T1190 | yes |
| GT-10-1 | yes | T1505.003 | T1505.003 | yes |
| GT-11-1 | yes | T1021.002 | T1021.002 | yes |
| GT-12-1 | yes | T1595 | T1595 | yes |
| GT-13-1 | yes | T1078 | T1078 | yes |
| GT-14-1 | yes | T1133 | T1133 | yes |
| GT-15-1 | yes | T1190 | T1190 | yes |
| GT-16-1 | yes | T1595 | T1595 | yes |
| GT-16-2 | yes | T1190 | T1190 | yes |
| GT-16-3 | yes | T1505.003 | T1505.003 | yes |
| GT-16-4 | yes | T1041 | T1041 | yes |
| GT-17-1 | yes | T1136.001 | T1136.001 | yes |
| GT-17-2 | yes | T1078 | T1078 | yes |
| GT-17-3 | yes | T1070 | T1070 | yes |
| GT-18-1 | yes | T1562.001 | T1562.001 | yes |
| GT-18-2 | yes | T1562.004 | T1562.004 | yes |
| GT-19-1 | yes | T1021.002 | T1021.001, T1021.002 | yes |
| GT-20-1 | yes | T1071.001 | T1071.001 | yes |

## Honest limits

- The ground truth was reconstructed by us from the logs (rare events, the `crscore` field planted lines carry, periodicity and repeated-pair analysis). Rules are tested to contain none of its IPs, users or domains.
- The ground truth was widened once during tuning: the first rule run produced 4 detections outside the then-ground-truth (a false-alarm rate of 4/20 at that point). On inspection they were planted activity without the `crscore` marker (periodic 300 s beacons; repeated ~20 KB transfers to the same attacker IPs), so 5 steps were added (GT-07 beacon + exfil, GT-16 scan + exfil, GT-20). The 0% false-alarm figure is measured against that widened ground truth.
- The supplied file was truncated: its last 1.7 GB was random bytes and was removed; 9.1M clean lines remain.
- Timestamps are the firewall's local clock (+05:30).
