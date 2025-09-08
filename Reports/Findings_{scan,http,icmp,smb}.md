# Findings – HTTP Beacon/Exfil

## Summary
Windows sent HTTP POST/GET to Kali web server (benign lab exfil).

## Key Evidence
- Wireshark filter: `http.request.method == "POST"`
- Zeek: `zeek/http/http.log`

## Notable Fields
- `method`: POST
- `host`: <KALI_IP>:8000
- `uri`: /upload, /beat
- `user_agent`: Windows PowerShell

## MITRE ATT&CK
- T1071.001 (Web protocols)
- T1041 (Exfiltration over C2 channel)

## Screenshots
- `../screenshots/wireshark/http_post.png`
- `../screenshots/wireshark/flow_graph_http.png`
