---
title: THM Block 
tags: [Blue Team]
description: Encryption? What encryption?
date: 2025-05-06
 

---
**Difficulty:** Medium  
**Room Link:** https://tryhackme.com/r/room/block 
![Extract and download files - showing terminal with unzip command and file listing](/images/logo.png)
## Introduction

Block is a digital forensics challenge on TryHackMe that teaches memory dump analysis and network traffic decryption. Two fired employees used old credentials to access the company server. Your task is to analyze the forensic evidence and recover the flags.

**Evidence Files:**
- `Elsa.DMP` - LSASS memory dump
- `traffic.pcapng` - Network packet capture

---

## Question 1: First User Username

**Answer:** `M_real_man`

### Step 1: Download and Extract Files

Start by downloading the evidence files from the TryHackMe Block room. Extract the ZIP archive:

```bash
unzip evidence.zip
```

You should see:
- `Elsa.DMP` (memory dump file)
- `traffic.pcapng` (network capture file)

### Step 2: Open Wireshark

Open the network capture file with Wireshark:

```bash
wireshark traffic.pcapng
```

*Wireshark main window with traffic.pcapng file loaded. Packet list shows multiple encrypted SMB packets.*

### Step 3: Inspect SMB Packets for Username

Look through the SMB packets in Wireshark. The username is visible in plaintext in the packet details even though the file transfer data is encrypted.


![Wireshark packet details showing username - expand SMB tree to show mrealman in the packet](/images/wireshark.png)

*Packet details panel (bottom of Wireshark) showing the username field: `mrealman` in plaintext within the SMB packets.*

**Answer: `mrealman`**

---



### Step 1: Run Pypykatz on LSASS Dump

Open a terminal and extract credentials from the LSASS memory dump:

```bash
pypykatz lsa minidump Elsa.DMP
```

*Terminal window with the command: `pypykatz lsa minidump Elsa.DMP` being typed/executed.*

### Step 2: View Pypykatz Output

The output will show NTLM hashes for all users on the system. You'll see both M_real_man and eShellStrop.



*Terminal output showing:*
```
[*] MSV LOGON_SESSIONS
[*] Username: mrealman
    Domain: WORKGROUP
    NTLM: aad3b435b51404eeaad3b435b51404ee:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

[*] Username: eShellStrop
    Domain: WORKGROUP
    NTLM: aad3b435b51404eeaad3b435b51404ee:YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
```

### Step 3: Copy M_real_man's NTLM Hash

From the output, copy the NTLM hash for M_real_man (the long hex string after "NTLM:").


*Terminal showing the NTLM hash for M_real_man clearly visible and selected.*

### Step 4: Crack the Hash with Hashcat

Create a file with the hash and crack it using Hashcat:

```bash
echo "aad3b435b51404eeaad3b435b51404ee:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" > m_real_man_hash.txt
hashcat -m 1000 -a 0 m_real_man_hash.txt /usr/share/wordlists/rockyou.txt
```

*Terminal showing:*
```bash
hashcat -m 1000 -a 0 m_real_man_hash.txt /usr/share/wordlists/rockyou.txt
```
*With progress bar visible.*

### Step 5: View Cracked Password

Hashcat will find the plaintext password quickly.
*Terminal output showing the result:*
```
aad3b435b51404eeaad3b435b51404ee:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:Blockbuster1
```

**Answer: `Blockbuster1`**

---
From the Pypykatz output in Question 2, you already have the second username.

*Terminal showing the eShellStrop entry from Pypykatz output highlighted.*

**Answer: `eShellStrop`**

---
`

From the same Pypykatz output, copy the NTLM hash for eShellStrop.

*Terminal showing:*
```
[*] Username: eShellStrop
    Domain: WORKGROUP
    NTLM: aad3b435b51404eeaad3b435b51404ee:YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
```

Note: This hash is strong and won't crack easily. We'll use it directly for SMB decryption instead.

**Answer: `[Your copied hash]`**

---

This section is the most complex. We need to decrypt SMB3 traffic using keys derived from both the password (memory dump) and authentication packets (network traffic).

### Step 1: Find Session ID in Wireshark

In Wireshark, click on an SMB2 packet and expand the packet details to find the Session ID.

![Wireshark packet details showing SMB2 header with Session ID fieldn](/images/1.png)

*Wireshark packet details (bottom panel) showing:*
- SMB2 header expanded
- Session ID field visible
- Right-click menu showing "Copy as Hex Stream" option
- *Important: Use "Copy as Hex Stream", not regular copy*

Right-click on Session ID and select **"Copy as Hex Stream"**. Save this value (should be 8 bytes in hex format: `01 02 03 04 05 06 07 08`).

### Step 2: Find NT Proof String

In the same or similar NTLMSSP packet, find the NT Proof String.

**Screenshot 5.2 - Extracting NT Proof String (Timestamp: 9:20 - 10:00)**

![Wireshark packet details showing NTLM Response section with NTProofStr field expanded, showing hex value](./images/5_2_nt_proof_str.png)

*Packet details showing:*
- SMB2 → Session Setup Request
- NTLM Security Service Provider
- NTLMv2 Response
- NTProofStr field with hex value

Right-click on NTProofStr and select **"Copy Value"**. Save this hex string.

### Step 3: Find Encrypted Session Key

Find the Encrypted Session Key (also called Key Exchange Key).
*Packet details showing:*
- Encrypted Session Key field
- Hex value visible
- Right-click menu with "Copy as Hex Stream" option

Right-click and select **"Copy as Hex Stream"**. Save this value.

### Step 4: Create Python Script for Key Derivation

Create a Python script to derive the session key. Save it as `get_session_key.py`:


```python
#!/usr/bin/env python3
import hashlib
import hmac
from Crypto.Cipher import AES

# Fill in these values from Wireshark and Pypykatz
username = "M_real_man"
domain = "WORKGROUP"
password = "Blockbuster1"

# Replace with your copied values (remove spaces from hex strings)
nt_proof_str = bytes.fromhex("PASTE_YOUR_NT_PROOF_STR_HERE")
key_exchange_key = bytes.fromhex("PASTE_YOUR_ENCRYPTED_SESSION_KEY_HERE")

print("[*] Starting SMB Session Key Derivation")
print(f"[+] Username: {username}")
print(f"[+] Domain: {domain}")

def ntlm_hash(password):
    password_bytes = password.encode('utf-16-le')
    return hashlib.new('md4', password_bytes).digest()

ntlm = ntlm_hash(password)
hmac_obj = hmac.new(ntlm, nt_proof_str, hashlib.md5)
session_key = hmac_obj.digest()

cipher = AES.new(session_key, AES.MODE_ECB)
random_session_key = cipher.decrypt(key_exchange_key)

print(f"[+] Random Session Key (for Wireshark): {random_session_key.hex().upper()}")
```

### Step 5: Run Python Script

Execute the script to get the session key:

```bash
python3 get_session_key.py
```

*Terminal output showing:*
```
[*] Starting SMB Session Key Derivation
[+] Username: M_real_man
[+] Domain: WORKGROUP
[+] Random Session Key (for Wireshark): XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Copy the Random Session Key value.

### Step 6: Configure Wireshark SMB2 Preferences

In Wireshark, go to: **Edit** → **Preferences** → **Protocols** → **SMB2**

*Wireshark Preferences window showing:*
- Navigation: Edit → Preferences
- Left panel: Protocols → SMB2 selected
- SMB2 settings visible

### Step 7: Add Session Key Configuration

In the SMB2 preferences, find the section for decryption keys. Add a new entry with:
- **Session ID:** (your copied hex stream, e.g., `01 02 03 04 05 06 07 08`)
- **Session Key:** (the Random Session Key from the Python script)

*Dialog showing:*
```
Session ID: 01 02 03 04 05 06 07 08
Session Key: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Click **OK** to save.

### Step 8: Reload PCAP and View Decrypted Traffic

Close and reopen the PCAP file in Wireshark:

```bash
wireshark traffic.pcapng
```

Now when you look at SMB2 packets, they should be decrypted (showing readable plaintext instead of encrypted data).

*Wireshark showing:*
- SMB2 packets in the packet list
- Packet details showing readable plaintext (file operations, directory names, etc.)
- NOT encrypted binary data

### Step 9: Export SMB Objects

Go to: **File** → **Export Objects** → **SMB**

**Screenshot 5.9 - Export Objects Dialog (Timestamp: 13:50 - 14:15)**

![Wireshark "Export Objects - SMB" dialog showing a list of files accessed, including client156, client978, etc., with Save options](/images/2.png)

*Export Objects dialog showing:*
- List of files accessed over SMB
- Files like: client156, client978, etc.
- Save options at the bottom

Select and save the files. The first user's flag should be in `client156` or similar.

### Step 10: Read the First Flag

Open the exported file:

```bash
cat client156
```


---

### Step 1: Find eShellStrop's NTLMSSP Packets

Scroll down in Wireshark to find eShellStrop's authentication packets (different Session ID than first user).
*Wireshark packet list showing:*
- NTLMSSP packets for eShellStrop
- Lower in the packet list (later timestamps)
- Different Session ID

### Step 2: Extract eShellStrop's Authentication Values

Extract the same three values from eShellStrop's packets:

**Screenshot 6.2 - Extracting Authentication Values (Timestamp: 15:30 - 16:20)**

![Wireshark packet details showing eShellStrop's NTLM Response with NTProofStr and Encrypted Session Key fields expanded](./images/6_2_eshellstrop_values.png)

*Packet details showing:*
- eShellStrop's NTLMSSP packet
- NTProofStr field with hex value
- Encrypted Session Key field

Copy:
1. NT Proof String (right-click → Copy Value)
2. Encrypted Session Key (right-click → Copy as Hex Stream)
3. Session ID (from SMB2 header, right-click → Copy as Hex Stream)

### Step 3: Create Modified Python Script (Using NTLM Hash)

Since we don't have eShellStrop's plaintext password, we'll use the NTLM hash directly. Create `get_session_key_hash.py`:


```python
#!/usr/bin/env python3
import hashlib
import hmac
from Crypto.Cipher import AES

username = "eShellStrop"
domain = "WORKGROUP"

# Use NTLM hash directly - no password needed!
ntlm_hash = bytes.fromhex("PASTE_ESHELLSTROP_NTLM_HASH_HERE")

nt_proof_str = bytes.fromhex("PASTE_YOUR_NT_PROOF_STR_HERE")
key_exchange_key = bytes.fromhex("PASTE_YOUR_ENCRYPTED_SESSION_KEY_HERE")

print("[*] Starting SMB Session Key Derivation (Using NTLM Hash)")
print(f"[+] Username: {username}")
print(f"[+] Using NTLM hash directly (password not needed!)")

# Skip password hashing - use hash directly
ntlm_val = ntlm_hash

hmac_obj = hmac.new(ntlm_val, nt_proof_str, hashlib.md5)
session_key = hmac_obj.digest()

cipher = AES.new(session_key, AES.MODE_ECB)
random_session_key = cipher.decrypt(key_exchange_key)

print(f"[+] Random Session Key (for Wireshark): {random_session_key.hex().upper()}")
```

### Step 4: Run Modified Script

```bash
python3 get_session_key_hash.py
```


*Terminal output showing:*
```
[*] Starting SMB Session Key Derivation (Using NTLM Hash)
[+] Username: eShellStrop
[+] Using NTLM hash directly (password not needed!)
[+] Random Session Key (for Wireshark): YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
```

Copy the Random Session Key.

### Step 5: Add Second Session Key to Wireshark

In Wireshark Preferences (SMB2), add another entry:
- **Session ID:** eShellStrop's Session ID
- **Session Key:** The Random Session Key from the script

*SMB2 Preferences showing:*
- First entry: M_real_man's Session ID and Key
- Second entry: eShellStrop's Session ID and Key

### Step 6: Reload and Export All Objects

Close and reopen the PCAP file. Now both users' traffic is decrypted.

Go to: **File** → **Export Objects** → **SMB**


*Export Objects dialog showing:*
- More files than before
- Files from both M_real_man and eShellStrop
- Including client978 (eShellStrop's file)

### Step 7: Read the Second Flag

Save the eShellStrop file (usually `client978`). Open it:

```bash
cat client978
```

*Terminal showing:*
```bash
$ cat client978
```


---


---

## Resources

- **Pypykatz GitHub:** https://github.com/skelsec/pypykatz
- **Wireshark:** https://www.wireshark.org/
- **Hashcat:** https://hashcat.net/
- **SMB3 Decryption Blog:** https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2

---


---

