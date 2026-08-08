# Home Labs

Cybersecurity home lab projects: environment setup, attack simulation, and detection engineering, documented so the process is reproducible by others. Each lab lives in its own folder with a full write-up and screenshots.

| Lab | Category | Summary |
|---|---|---|
| [lab01_simulate_detect](lab01_simulate_detect/README.md) | Simulate & Detect | Built a Sysmon + Elastic Stack SIEM, simulated MITRE ATT&CK T1136.001 with Atomic Red Team, and built a detection query and dashboard for it. |
| [lab02_credential_access](lab02_credential_access/README.md) | Simulate & Detect | Attempted MITRE ATT&CK T1003.001 (LSASS credential dumping) with Atomic Red Team; Windows Defender blocked both attempts, so detection was built around Defender's own alert log instead. |
| [lab03_powershell_lolbin](lab03_powershell_lolbin/README.md) | Simulate & Detect | Ran an obfuscated PowerShell command (T1059.001) with Atomic Red Team and found it in Script Block Logging, then narrowed a high-volume log down to a usable detection query. |

New labs follow the template in [`_template/`](_template/README.md).

## Planned labs

Each lab builds on the environment and skills from the previous one, escalating in complexity.

| Lab | Technique / Focus | What's new |
|---|---|---|
| 01 | T1136.001 - local account creation | Sysmon, Elastic Stack, Atomic Red Team, KQL detection, dashboard |
| 02 | T1003.001 - credential dumping (LSASS access) | Both attempts blocked by Windows Defender; detection built around Defender's own alert log instead of raw process telemetry |
| 03 | T1059.001 - PowerShell / living-off-the-land | Script Block Logging; detection required content filtering on a high-volume log instead of matching a specific event ID |
| 04 | T1053 / T1547 - persistence (scheduled tasks, run keys) | Chaining multiple techniques into one attack sequence |
| 05 | Network security monitoring | Zeek/Suricata, correlating host and network detections |
| 06 | Lateral movement in a small AD environment (T1021) | Second VM as a domain controller, domain-joined detections |
| 07 | Detection response / automation | Elastic Watcher or a script that auto-responds to a detection |
