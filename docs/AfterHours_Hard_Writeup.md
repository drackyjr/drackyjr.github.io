---
title: After Hours
tags: [ctf, Tryhackme]
description:  forensics
date: 2026-08-10
---


# After Hours — Hard Windows DFIR Lab Write-up

## Overview

This lab simulates a stealthy Windows persistence investigation. The attacker-like activity is
represented only through synthetic forensic artifacts. There is no live malware.

The intended chain is:

`anomalous logon -> WMI permanent event subscription -> WmiPrvSE child PowerShell ->
custom WMI class -> registry seed -> Base64/XOR/GZip decode -> final flag`

---

## Answer Key

1. **First anomalous successful logon:** `2026-08-07 03:14:22`
2. **Account:** `svc_pool`
3. **Parent process:** `C:\Windows\System32\wbem\WmiPrvSE.exe`
4. **WMI consumer:** `TelemetryHealthConsumer`
5. **Custom WMI class:** `Win32_PerfFormattedData_CacheManager_UpdateTelemetry`
6. **Hex registry seed:** `6f72636869642d30333137`
7. **Decoded XOR key:** `orchid-0317`
8. **Final flag:** `THM{quiet_hours_are_never_quiet}`

---

## Step-by-Step Investigation

### 1. Identify the first suspicious login

Open:

`evidence/eventlogs/Security.evtx.txt`

The important event is Event ID 4624 at:

`2026-08-07T03:14:22Z`

It shows:

- User: `svc_pool`
- Logon Type: `3`
- Source IP: `10.23.4.19`
- Workstation: `POOL-KIOSK02`

The earlier `nighttech` login is an interactive local login and is a decoy.

### 2. Build the execution timeline

Review:

- `evidence/filesystem/timeline.csv`
- `evidence/eventlogs/Sysmon.evtx.txt`
- `evidence/prefetch/POWERSHELL.EXE-A1B2C3D4.pf.txt`

The key pattern repeats at 03:17, 04:17 and 05:17 UTC.

The process chain is:

`svchost.exe -> WmiPrvSE.exe -> powershell.exe`

This strongly points to WMI-backed execution rather than a normal scheduled task.

### 3. Confirm WMI permanent event persistence

Open:

`evidence/eventlogs/Microsoft-Windows-WMI-Activity-Operational.evtx.txt`

Event 5861 shows a permanent subscription binding:

- Filter: `TelemetryHealthFilter`
- Consumer: `TelemetryHealthConsumer`
- Namespace: `root\subscription`

Then inspect:

`evidence/wmi/repository_objects.json`

You can confirm the binding and find the suspicious
`CommandLineEventConsumer`.

### 4. Find the custom class

The PowerShell operational artifact and WMI query both reference:

`Win32_PerfFormattedData_CacheManager_UpdateTelemetry`

Inside `repository_objects.json`, this class contains:

- `PackedBlob`
- `Checksum`

There is also a printer-health custom class. That is a decoy.

### 5. Recover the decoding key

`evidence/memory/strings.txt` gives the pipeline hint:

`codec_hint=b64->xor->gzip`

It also points to the registry seed location:

`HKLM\SOFTWARE\Asteria\Telemetry`

Open:

`evidence/registry/SOFTWARE.reg.txt`

The `Seed` value is:

`6f72636869642d30333137`

Decode that hex as ASCII:

```python
bytes.fromhex("6f72636869642d30333137").decode()
```

Result:

`orchid-0317`

### 6. Decode the embedded blob

Extract `PackedBlob` from the suspicious WMI class and run:

```python
import json, base64, gzip

key = b"orchid-0317"

with open("evidence/wmi/repository_objects.json", "r", encoding="utf-8") as f:
    repo = json.load(f)

blob = None
for c in repo["CustomClasses"]:
    if c["ClassName"] == "Win32_PerfFormattedData_CacheManager_UpdateTelemetry":
        blob = c["Properties"]["PackedBlob"]
        break

raw = base64.b64decode(blob)
de_xor = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
plain = gzip.decompress(de_xor)

print(plain.decode())
```

The decoded JSON is inert training content and contains:

`THM{quiet_hours_are_never_quiet}`

---


