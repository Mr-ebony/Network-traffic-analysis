 ## ⛓ Network Traffic Analysis (Kali + Windows)
 ### Objective
Capture and analyze network traffic for common attacker behaviors (scan, beacon/HTTP exfil, ICMP sweep, SMB touch) and document detections.

### Lab Topology
- Kali (attacker/analyst): `<KALI_IP>`
- Windows 10 VM (victim): `<WIN_IP>`
- Same Host-Only/Internal network.

### Tools
- tcpdump / Wireshark (packet capture)
- Zeek (pcap → structured logs)
- (Optional) Splunk (search/visualize Zeek logs)

### Scenarios
1. Port scan → `scan_windows.pcap` (MITRE T1046)
2. HTTP beacon/exfil → `http_exfil.pcap` (T1071.001, T1041)
3. ICMP sweep → `icmp_sweep.pcap` (T1018)
4. SMB touch → `smb_touch.pcap` (T1135)

### How to Reproduce
See `reports/NTA_Methodology.md` for exact commands and Wireshark filters.

### Findings
- `reports/Findings_scan.md`
- `reports/Findings_http.md`
- `reports/Findings_icmp.md`
- `reports/Findings_smb.md`

### Evidence
- `pcaps/` (captured traffic)
- `zeek/` (parsed logs)
- `screenshots/` (Wireshark/Splunk)
