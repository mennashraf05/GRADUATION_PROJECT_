# TODO: Implement Threat Level Classification

## Information Gathered
- Analyzed unique labels from RT_IOT2022 and LYCOS datasets.
- RT_IOT2022 labels: MQTT_Publish, Thing_Speak, Wipro_bulb, ARP_poisioning, DDOS_Slowloris, DOS_SYN_Hping, Metasploit_Brute_Force_SSH, NMAP_FIN_SCAN, NMAP_OS_DETECTION, NMAP_TCP_scan, NMAP_UDP_SCAN, NMAP_XMAS_TREE_SCAN.
- LYCOS train/test labels: dos_hulk, benign, ddos, portscan, dos_slowhttptest, dos_slowloris, dos_goldeneye, ftp_patator, bot, ssh_patator, webattack_bruteforce, webattack_xss, heartbleed, webattack_sql_injection.
- Proposed threat levels based on user's examples:
  - Low: Benign activities (MQTT_Publish, Thing_Speak, Wipro_bulb, benign).
  - Medium: Scanning (NMAP_FIN_SCAN, NMAP_OS_DETECTION, NMAP_TCP_scan, NMAP_UDP_SCAN, NMAP_XMAS_TREE_SCAN, portscan, ARP_poisioning).
  - High: DoS/DDoS and brute force (DDOS_Slowloris, DOS_SYN_Hping, dos_hulk, ddos, dos_slowhttptest, dos_slowloris, dos_goldeneye, heartbleed, Metasploit_Brute_Force_SSH, ftp_patator, ssh_patator, webattack_bruteforce).
  - Critical: Web attacks and Botnet (webattack_xss, webattack_sql_injection, bot).

## Plan
- [x] Backend/app.py:
  - [x] Add a dictionary `threat_levels` mapping each label to its threat level.
  - [x] Modify the `/predict` endpoint to include the threat level in the response.

## Dependent Files to be edited
- [x] Backend/app.py

## Followup steps
- [x] Test the updated /predict endpoint with sample data.
- [x] Verify that threat levels are returned correctly.
