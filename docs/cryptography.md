---
title: Cryptography
tags: [cryptography, Security Tools, notes]
description:  encoding and decoding
date: 2025-10-02
---

## PART 1: DETAILED REFERENCE NOTES

---

## 1. CORE CONCEPTS & DEFINITIONS

### 1.1 Fundamental Principles

**Cryptography** is the science of protecting information through encoding and encryption. In penetration testing, the goal is to identify weaknesses in cryptographic implementations.

**Key Terms:**
- **Plaintext**: Unencrypted readable message
- **Ciphertext**: Encrypted unreadable message
- **Encryption**: Converting plaintext to ciphertext using a key
- **Decryption**: Converting ciphertext back to plaintext
- **Key**: Secret parameter required for encryption/decryption
- **Hash**: Fixed-length fingerprint of data (one-way, deterministic)
- **Salt**: Random data added to hashes to prevent rainbow table attacks
- **Nonce**: “Number used once” – prevents replay attacks

### 1.2 Cryptographic Categories

**Symmetric Encryption (Same key for encryption & decryption):**
- Caesar Cipher, Vigenère, ROT13 (classical, weak)
- AES (Advanced Encryption Standard) – modern, 128/192/256-bit keys
- DES/3DES (deprecated)
- Blowfish, Twofish

**Asymmetric Encryption (Public/Private key pair):**
- RSA – most common, key sizes 1024/2048/4096 bits
- Elliptic Curve Cryptography (ECC)
- Diffie-Hellman (key exchange)

**Hashing (One-way, no decryption possible):**
- MD5 (128-bit, BROKEN – collisions found)
- SHA-1 (160-bit, WEAK – collision vulnerabilities)
- SHA-256, SHA-512 (SHA-2 family, secure)
- bcrypt, scrypt, Argon2 (password hashing with salt/iterations)

**Encoding (NOT encryption, reversible):**
- Base64 – standard for data transmission
- Hex – hexadecimal representation
- URL encoding – spaces as %20, etc.
- ASCII/Unicode

---

## 2. ATTACK METHODOLOGY & KILL-CHAIN STAGES

### Stage 1: Reconnaissance & Identification

**Objective:** Determine what cipher/hash is in use

1. **Identify cipher type:**
    - Check ciphertext properties (length, character set, patterns)
    - Look for known signatures (Base64 padding `=`, hex pairs)
    - Use cipher identifier tools (dCode, CyberChef)
2. **Identify hash type:**
    - Match hash length: MD5=32 chars, SHA-1=40, SHA-256=64, bcrypt=2*y*
    - Test against hash databases (hashidentifier.com, hash-identifier tool)
3. **Check for encoding:**
    - Base64: Contains A-Z, a-z, 0-9, +, /, = (padding)
    - Hex: Contains only 0-9, a-f (case-insensitive)
    - URL-encoded: Contains % followed by hex pairs

### Stage 2: Enumeration

**Objective:** Gather intelligence on cryptographic implementations

1. **Weak cipher detection:**
    - Check for hardcoded keys in source code (git history, config files)
    - Identify use of MD5 or SHA-1 (cryptographically broken)
    - Detect ECB mode (deterministic, weak)
    - Check for predictable IV (initialization vector)
2. **Key extraction:**
    - Search for keys in environment variables, config files, databases
    - Check for key reuse across multiple systems
    - Look for keys in compiled binaries (strings command)
3. **Implementation flaws:**
    - No salt used for hashes
    - Weak random number generator for key generation
    - Missing authentication (encryption without integrity checking)

### Stage 3: Exploitation

**Objective:** Recover plaintext, forge authentication, or bypass protection

1. **Brute-force attacks:**
    - Dictionary attacks (wordlists for common passwords)
    - Mask attacks (pattern-based, e.g., `?u?l?l?l?l?d?d` = letter+letter+letter+letter+digit+digit)
    - Hybrid attacks (combine dictionary with mask)
2. **Cryptanalysis:**
    - Frequency analysis (weak ciphers like Caesar, simple substitution)
    - Known-plaintext attacks (recover key if plaintext/ciphertext pair known)
    - Chosen-plaintext attacks (encrypt chosen data to leak information)
    - Padding oracle attacks (exploit CBC mode padding validation)
3. **Mathematical attacks:**
    - RSA factorization (if modulus is weak, < 2048 bits, or factors known)
    - RSA common modulus (if two ciphertexts encrypted with same n but different e)
    - Weak random number generators
    - Side-channel attacks (timing, power consumption – advanced)

### Stage 4: Post-Exploitation

**Objective:** Maintain access and extract sensitive data

1. **Decrypt stored data:**
    - Use recovered keys/passwords to decrypt databases, files
    - Extract authentication tokens, session data
    - Access encrypted communication logs
2. **Forge authentication:**
    - Create valid JWT tokens (if algorithm=none or weak signature)
    - Generate valid session cookies
    - Bypass signature verification if key is recovered
3. **Lateral movement:**
    - Use recovered credentials for other systems
    - Extract plaintext credentials from decrypted configs

---

## 3. TOOL SETUP & CONFIGURATION

### 3.1 Essential Cryptography Tools

### CyberChef (Web-based, all-in-one)

- **URL:** gchq.github.io/CyberChef/
- **Setup:** No installation, runs in browser
- **Best for:** Quick encoding/decoding, chaining operations
- **Usage:** Drag recipes (Base64 → Hex → Caesar) in sequence

### OpenSSL (Command-line, encryption/decryption)

- **Installation:** `apt-get install openssl` (pre-installed most systems)
- **Encrypt file:** `openssl enc -aes-256-cbc -salt -in file.txt -out file.enc`
- **Decrypt file:** `openssl enc -aes-256-cbc -d -in file.enc -out file.txt`
- **Hash:** `openssl dgst -sha256 file.txt`
- **Generate RSA key:** `openssl genrsa -out key.pem 2048`

### Hashcat (GPU-accelerated password cracking)

- **Installation:** `apt-get install hashcat`
- **Identify hash:** `hashcat --example-hashes | grep -i md5`
- **Crack MD5:** `hashcat -m 0 hashes.txt wordlist.txt`
- **Mask attack:** `hashcat -m 0 hashes.txt -a 3 ?u?l?l?l?l?d?d`
- **Resume session:** `hashcat --session=mysession -m 0 hashes.txt wordlist.txt`

### John the Ripper (Traditional password cracker)

- **Installation:** `apt-get install john`
- **Basic usage:** `john hashes.txt`
- **Wordlist:** `john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt`
- **Format auto-detect:** `john --format=dynamic_0 hashes.txt`
- **GPU support:** `john --format=bcrypt hashes.txt --device=gpu`

### Ciphey (Automated cipher solver)

- **Installation:** `pip install ciphey`
- **Usage:** `ciphey -t "encrypted_text_here"`
- **Best for:** Unknown cipher quick identification

### dCode (Online)

- **URL:** dcode.fr
- **Tools:** Caesar decoder, Vigenère solver, cipher identifier
- **No setup needed, browser-based**

---

## 4. IN-DEPTH EXPLOITATION STEPS

### 4.1 Caesar Cipher (Shift Cipher)

**Definition:** Each letter shifted by fixed number of positions (e.g., shift=3: A→D, B→E)

**Weakness:** Only 26 possible keys, brute-forceable in seconds

**Manual Breaking:**
1. Try all 26 shifts
2. Look for readable plaintext
3. Example: “KHOOR” with shift=3 → “HELLO”

**Tool-based Breaking:**

```bash
# CyberChef: Add "Caesar/ROT13 Brute Force" recipe# Output shows all 26 possibilities# dCode: dcode.fr/caesar-cipher (auto-decode)# Python one-liner:python3 -c "ct='KHOOR'; print([chr((ord(c)-65-i)%26+65) for i in range(26) for c in ct])"
```

**Detection:** Look for letter-only ciphertext (26 chars if English)

---

### 4.2 Vigenère Cipher (Polyalphabetic Substitution)

**Definition:** Uses repeating keyword to shift letters (e.g., keyword=“KEY”, shifts repeat)

**Example:**

```
Plaintext:  HELLOWORLD
Key:        KEYKEYKEYK (repeated)
Shift:      3 4 24 10 10 3 4 24 10 10
Ciphertext: KHZLRXVNHD
```

**Attacks:**

**1. Kasiski Examination (Find key length):**
- Identify repeated sequences in ciphertext
- Distance between repetitions likely multiple of key length
- Test key lengths: 3, 6, 9 (factors of repetition distances)

**2. Index of Coincidence (IC):**
- Calculate IC for different assumed key lengths
- IC ≈ 0.065 for English plaintext
- Correct key length shows IC closest to 0.065

**3. Frequency Analysis (Once key length known):**
- Break into Caesar ciphers (chunks of length = key length)
- Apply frequency analysis to each chunk separately
- Recover individual key characters

**Tool-based Breaking:**

```bash
# CyberChef: Vigenère Brute Force (if key length known)# dCode: dcode.fr/vigenere-cipher (auto-solve)# Online: quipqiup.com (for substitution variants)
```

**Detection:** Multiple repeated patterns suggest polyalphabetic cipher

---

### 4.3 ROT13 (Simple Rotation)

**Definition:** Special case of Caesar (shift always 13)

**Breaking:** ROT13 is reversible (apply twice = original)

```bash
# Command line:echo "HELLO" | rot13# CyberChef: ROT13 recipe# Python: "HELLO".encode('rot13')# Online: Many single-click decoders
```

---

### 4.4 XOR Cipher

**Definition:** Bitwise XOR operation: plaintext ⊕ key = ciphertext

**Properties:**
- Single-byte key: vulnerable to frequency analysis
- Repeating key: frequency patterns emerge
- Same key used: ciphertext1 ⊕ ciphertext2 = plaintext1 ⊕ plaintext2 (key cancels)

**Single-byte XOR Attack:**
1. Try all 256 possible key values
2. Decode each result
3. Check for readable text (ASCII printable characters)

```python
# Python brute-force:
for key in range(256):    
     decoded = bytes([byte ^ key for byte in ciphertext])  
       try:        
       if decoded.decode('ascii', errors='ignore').isprintable():           
       print(f"Key: {key}, Text: {decoded}")   
        except:       
         pass
```

**Known-Plaintext XOR:**
- If you know plaintext & ciphertext: key = plaintext ⊕ ciphertext
- Example: ciphertext=“JGNNQ”, suspected plaintext=“HELLO”
- key = 0x4A ^ 0x48 = 0x02 (or similar for each byte)

**Repeating-Key XOR (Vigenère-like):**
- Use Kasiski or IC to find key length
- Solve as single-byte XOR for each position

---

### 4.5 Hash Cracking

**MD5 / SHA-1 / SHA-256 (Weak Hashes):**

**Attack 1: Dictionary Attack**

```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
# -m 0 = MD5, -m 100 = SHA1, -m 1400 = SHA256
```

**Attack 2: Rainbow Tables**
- Pre-computed hash → plaintext mappings
- Instant lookup if hash found
- Ineffective vs salted hashes
- Tools: Online hash lookups (md5.com, etc.)

**Attack 3: Mask Attack (Pattern-based)**

```bash
# Pattern: 4 lowercase + 2 digits (e.g., "test42")hashcat -m 0 hashes.txt -a 3 ?l?l?l?l?d?d
# Mask characters:# ?l = lowercase, ?u = uppercase, ?d = digit, ?s = special# ?a = all printable characters
```

**Attack 4: Hybrid (Dictionary + Mask)**

```bash
# Dictionary words + digits appended (e.g., "password123")hashcat -m 0 hashes.txt -a 6 wordlist.txt ?d?d?d
# -a 6 = wordlist + mask, -a 7 = mask + wordlist
```

**bcrypt / scrypt / Argon2 (Strong Hashes):**
- Intentionally slow (high iteration count)
- Salt is stored in hash itself
- Resistant to GPU cracking
- Crack same way, but much slower:

```bash
hashcat -m 3200 bcrypt_hashes.txt wordlist.txt
# May take hours/days even with GPU
```

**No-Salt Hash Detection:**
- Same plaintext = same hash (identical entries in hash list)
- Weak implementation, prioritize cracking

---

### 4.6 Encoding Attacks

**Base64 Decoding:**

```bash
echo "SGVsbG8gV29ybGQ=" | base64 -d# Output: Hello World# Python:import base64
base64.b64decode("SGVsbG8gV29ybGQ=").decode()# CyberChef: Base64 Decode recipe
```

**Hex Decoding:**

```bash
echo "48656c6c6f" | xxd -r -p# Output: Hello# Python:bytes.fromhex("48656c6c6f").decode()# CyberChef: From Hex recipe
```

**URL Decoding:**

```bash
echo "Hello%20World%21" | python3 -c "import urllib.parse, sys; print(urllib.parse.unquote(sys.stdin.read()))"# CyberChef: URL Decode recipe
```

**Chained Encoding (Multi-layer):**

```bash
# CyberChef: Add multiple recipes in sequence# Base64 Decode → Hex Decode → Caesar Brute Force
```

---

### 4.7 RSA Attacks

**RSA Basics:**
- Public key: (n, e) | Private key: (d, p, q)
- Encryption: ciphertext = plaintext^e mod n
- Decryption: plaintext = ciphertext^d mod n
- n = p × q (product of two large primes)

**Attack 1: Small e with No Padding**
- If e=3 and plaintext small: plaintext^3 may not wrap around n
- Recover plaintext by taking e-th root

```bash
# Check: ct < n? Then plaintext = ct^(1/e)python3 -c "from gmpy2 import cbrt; print(int(cbrt(ciphertext)))"
```

**Attack 2: Common Modulus (Same n, different e/d)**
- If you have (n, e1, c1) and (n, e2, c2), recover plaintext without private key
- Use extended Euclidean algorithm: c1^x × c2^y ≡ plaintext (mod n)

```bash
# Tool: RSA Common Modulus Attack (GitHub)# Input: e1, c1, e2, c2, n# Output: plaintext
```

**Attack 3: Weak Key (Small n or Weak Primes)**
- Factor n if small (< 2048 bits)
- Once p, q factored: d = e^-1 mod (p-1)(q-1)
- Then decrypt: plaintext = ciphertext^d mod n

```bash
# Factorization tools:# Online: factordb.com# Command: factor (for small numbers)# Tool: yafu (Yet Another Factorization Utility)yafu "factor(12345678901234567890)"
```

**Attack 4: Padding Oracle (in TLS/encryption systems)**
- Send ciphertext, check if padding valid
- Valid padding = ciphertext is valid
- Invalid padding = adjust guess
- Eventually recover plaintext byte-by-byte

```bash
# Tool: PaddingOracle (Burp extension)# Auto-exploit padding oracle vulnerabilities
```

---

### 4.8 JWT (JSON Web Token) Attacks

**JWT Structure:** `header.payload.signature`
- All three parts Base64-encoded
- Signature = HMAC(header.payload, secret_key)

**Attack 1: Weak Secret**

```bash
# Crack HMAC secret:hashcat -m 16500 jwt_file.txt wordlist.txt
# or use online JWT crackers with common secrets
```

**Attack 2: Algorithm=None**
- Some implementations accept algorithm: “none”
- No signature verification needed
- Simply modify payload, set algorithm to “none”

```bash
# Create valid token:# header: {"alg": "none"}# payload: {"user": "admin"}# signature: (empty or delete)# Result: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

**Attack 3: Key Confusion (HS256 vs RS256)**
- Algorithm says RS256 (asymmetric)
- But system checks with HS256 (symmetric) using public key as secret
- Forge token using public key as HMAC secret

```bash
# Extract public key, use as HMAC secret to forge token
```

**Attack 4: Token Expiration Bypass**
- Modify exp (expiration) claim
- Set to future date
- Resign with weak secret or none

---

### 4.9 Steganography

**Definition:** Hiding data within other media (image, audio, file)

**Common Tools:**
- **Strings:** Extract text from files
`bash   strings file.jpg | grep -i flag`

- **ExifTool:** Extract metadata
    
    ```bash
    exiftool file.jpg
    ```
    
- **Stegsolve:** Visualize hidden layers in images
    
    ```bash
    java -jar Stegsolve.jar
    # Cycle through color planes (R, G, B, LSB, etc.)
    ```
    
- **SteganoNow:** Steganography solver
- **Foremost:** Carve files from data
    
    ```bash
    foremost -i file.bin -o output/
    ```
    
- **Binwalk:** Analyze binary files
    
    ```bash
    binwalk file.bin
    binwalk -e file.bin  # Extract embedded files
    ```
    

**Attack Process:**
1. Run `strings` to check for plaintext
2. Check file metadata (exiftool)
3. Visualize image (Stegsolve)
4. Extract embedded files (binwalk, foremost)
5. Check for nested steganography (recursive)

---

## 5. DEFENSIVE INDICATORS & RED FLAGS

### 5.1 Weak Implementations (Red Flags)

- **MD5 or SHA-1 in use:** Cryptographically broken, vulnerable to collision attacks
- **No salt in hashes:** Rainbow table attacks possible, identical plaintext = identical hash
- **Hardcoded keys:** Keys in source code, config files, or git history
- **ECB mode:** Deterministic encryption (same plaintext block = same ciphertext block, patterns visible)
- **Predictable IV/Nonce:** Enables replay or IV collision attacks
- **Small key sizes:** < 128 bits symmetric, < 2048 bits RSA
- **Weak random number generator:** Keys/IVs may be predictable
- **No integrity checking:** Encryption without MAC/HMAC (doesn’t detect tampering)
- **Algorithm=none in JWT:** No signature verification
- **Reused keys:** Same key across multiple systems/purposes

### 5.2 Secure Implementations (Defensive Indicators)

- **AES-256 with authenticated encryption (AES-GCM):** Provides confidentiality + integrity
- **bcrypt/scrypt/Argon2 for passwords:** Slow, salted, resistant to cracking
- **SHA-256 or better for data integrity:** Cryptographically strong
- **2048+ bit RSA keys:** Current standard
- **Random, unique IVs per message:** Prevents IV collision attacks
- **Proper key management:** Separate keys for different purposes, rotation policies
- **HMAC for message authentication:** Detects tampering
- **TLS 1.2+ for transport:** Secure communication
- **Proper JWT validation:** Algorithm whitelist, signature verification, expiration checks

---

## 6. COMMON HURDLES & MITIGATION BYPASSES

### Hurdle 1: Unknown Cipher Type

**Bypass:** Use automated tools
- **dCode:** Cipher identifier (dcode.fr)
- **Ciphey:** `ciphey -t "ciphertext"`
- **CyberChef:** Try multiple recipes

### Hurdle 2: Long Key in Brute-Force

**Bypass:** Use mask attacks + dictionary
- Limit key space (known patterns: passwords, common words)
- Use hybrid: dictionary + mask
- GPU acceleration (hashcat, hashcat with NVIDIA CUDA)

### Hurdle 3: High Iteration Count (bcrypt)

**Bypass:** Accept slow cracking
- bcrypt intentionally slow by design
- Use GPU/ASIC for marginal speedup
- Target weak passwords (dictionary attacks faster than brute-force)

### Hurdle 4: Missing Plaintext in Hash List

**Bypass:** Check multiple sources
- Check if hash appears in known breaches (hashidentifier.com, dehashed)
- Combine wordlists
- Rule-based generation (common substitutions: a→@, o→0)

### Hurdle 5: Chained Encoding/Encryption

**Bypass:** Apply tools iteratively
- Decode Base64 → Decode Hex → Caesar shift → Frequency analysis
- CyberChef: Chain multiple recipes
- Test each intermediate output for readability

### Hurdle 6: Algorithm Pinning (JWT)

**Bypass:** Check for edge cases
- Try algorithm=none
- Check if public key is accessible (use as HMAC secret)
- Brute-force secret if weak
- Check for CVE-specific bypasses

---

## 7. QUICK TROUBLESHOOTING

| Issue | Diagnosis | Solution |
| --- | --- | --- |
| Hash not cracking | Wrong format detected | Use hashidentifier, try different mode in hashcat (-m flag) |
| Cipher seems random | Correct cipher/key used | Verify plaintext is actually readable (not false negative) |
| Base64 decode fails | Invalid Base64 | Add/remove padding (=), check for URL-safe Base64 |
| RSA decryption fails | Wrong algorithm assumed | Check if small e, no padding, or common modulus attack possible |
| JWT token invalid | Signature verification fails | Check algorithm (none?), weak secret, key confusion |
| Steganography not found | Wrong tool/layer | Try multiple: strings, exiftool, stegsolve, binwalk, foremost |

---

# PART 2: RAPID-REFERENCE CHEATSHEET

---

## ENCODING QUICK REFERENCE

```bash
# ==========================
# 🔐 Base64 Encoding / Decoding
# ==========================
# Encode
echo "text" | base64
# Decode
echo "dGV4dA==" | base64 -d
# Python
# Encode: base64.b64encode(b"text")
# Decode: base64.b64decode("dGV4dA==")

# ==========================
# ⚙️ Hex Encoding / Decoding
# ==========================
# Encode
echo -n "text" | xxd -p
# Decode
echo "74657874" | xxd -r -p
# Python
# Encode: "text".encode().hex()
# Decode: bytes.fromhex("74657874").decode()

# ==========================
# 🌐 URL Encoding / Decoding
# ==========================
# Encode
python3 -c "import urllib.parse; print(urllib.parse.quote('text with spaces'))"
# Decode
echo "text%20with%20spaces" | python3 -c "import urllib.parse, sys; print(urllib.parse.unquote(sys.stdin.read()))"

# ==========================
# 🔁 ROT13 Encoding / Decoding
# ==========================
# Encode
echo "hello" | rot13
# Decode
echo "uryyb" | rot13

```

---

## CIPHER IDENTIFICATION DECISION TREE

```
IF ciphertext looks like: ?
  ├─ ONLY letters, short & repeated patterns
  │  └─ Caesar/ROT13 (Brute force all 26 shifts)
  │
  ├─ Letters only, long, many repeated sequences
  │  └─ Vigenère (Kasiski + IC + frequency analysis)
  │
  ├─ Mixed letters/numbers/symbols, no clear pattern
  │  └─ XOR or substitution cipher (Frequency analysis, known-plaintext)
  │
  ├─ 32 hex chars OR "===" ending
  │  └─ Likely Base64/Hex encoded (Try decode first)
  │
  ├─ Random binary-looking
  │  └─ AES/RSA encrypted (Need key/password or cryptanalysis)
  │
  └─ Use dCode, Ciphey, or CyberChef if unsure
```

---

## HASH IDENTIFICATION BY LENGTH

```
Length → Algorithm
32 hex         → MD5 (WEAK, easily cracked)
40 hex         → SHA-1 (WEAK, avoid)
64 hex         → SHA-256 (Good)
128 hex        → SHA-512 (Good)
$2a$/$2b$/...  → bcrypt (Strong, slow)
$5$/$6$...     → Linux crypt (Medium)
$argon2...     → Argon2 (Strong, modern)
```

---

## HASH CRACKING COMMAND CHEATSHEET

```bash
# ==========================
# Identify hash format (example output filtering)
# ==========================
# Show example hashes / formats and filter for format names (adjust grep pattern as needed)
hashcat --example-hashes | grep -i "format name" | head -20

# ==========================
# Dictionary attack (using rockyou)
# ==========================
# Replace <MODE> with appropriate -m value for the hash type
hashcat -m <MODE> hashes.txt /usr/share/wordlists/rockyou.txt -o cracked.txt

# ==========================
# Mask attack (example: 4 lowercase letters + 2 digits)
# ==========================
hashcat -m <MODE> hashes.txt -a 3 ?l?l?l?l?d?d

# ==========================
# Hybrid attack (wordlist + 3-digit numeric suffix)
# ==========================
# -a 6: wordlist + mask
hashcat -m <MODE> hashes.txt -a 6 wordlist.txt ?d?d?d

# ==========================
# Rules-based attack (common substitutions)
# ==========================
# Use a rules file such as best64.rule (a → @, o → 0, l → 1, etc.)
hashcat -m <MODE> hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# ==========================
# John the Ripper (auto-detect + wordlist)
# ==========================
# John can attempt to auto-detect many formats
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# ==========================
# Common Hashcat -m mode mappings (examples)
# ==========================
# 0    = MD5
# 100  = SHA1
# 1400 = SHA256
# 1700 = SHA512
# 3200 = bcrypt
# 7400 = sha512crypt
# 9000 = Password protected PDF

# ==========================
# Notes & tips
# ==========================
# - Always confirm the correct -m mode for your target hash before running a large attack.
# - Use --show after a session to display cracked hashes from a potfile/session:
#     hashcat --show -m <MODE> hashes.txt
# - For large-scale cracking, use --session and --restore to resume interrupted runs.

```

---

## ENCRYPTION/DECRYPTION COMMANDS

```bash
# ==========================
# OpenSSL — AES-256-CBC (password-based)
# ==========================
# Encrypt (use PBKDF2 for stronger KDF and an iteration count)
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -in plaintext.txt -out encrypted.bin -k "password"

# Decrypt
openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter 100000 -in encrypted.bin -out plaintext.txt -k "password"

# ==========================
# OpenSSL — RSA keypair (modern recommended commands)
# ==========================
# Generate private key (2048 bits)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem

# Extract public key
openssl pkey -in private.pem -pubout -out public.pem

# If you still prefer the older genrsa/rsa commands:
# openssl genrsa -out private.pem 2048
# openssl rsa -in private.pem -pubout -out public.pem

# ==========================
# RSA encryption / decryption (small data only)
# ==========================
# Encrypt using public key (OAEP padding via pkeyutl)
openssl pkeyutl -encrypt -in plaintext.txt -pubin -inkey public.pem -pkeyopt rsa_padding_mode:oaep -out ciphertext.bin

# Decrypt using private key (OAEP)
openssl pkeyutl -decrypt -in ciphertext.bin -inkey private.pem -pkeyopt rsa_padding_mode:oaep -out plaintext.txt

# Note: RSA is for small data (keys or short secrets). For files use hybrid encryption:
# 1) Generate random symmetric key, encrypt file with AES, encrypt symmetric key with RSA.

# ==========================
# OpenSSL — Hybrid example (generate AES key, encrypt file, encrypt key with RSA)
# ==========================
# Generate a 32-byte AES key (256-bit)
openssl rand -out aes.key 32

# Encrypt file with AES-256-CBC using the raw key (key file)
openssl enc -aes-256-cbc -pbkdf2 -in plaintext.txt -out encrypted.bin -pass file:./aes.key

# Encrypt AES key with RSA public key
openssl pkeyutl -encrypt -inkey public.pem -pubin -in aes.key -out aes.key.enc -pkeyopt rsa_padding_mode:oaep

# To decrypt: use pkeyutl to decrypt aes.key.enc with private.pem, then use the recovered aes key to decrypt encrypted.bin.

# ==========================
# OpenSSL — Hash / Message Digests
# ==========================
# SHA-256
openssl dgst -sha256 file.txt

# MD5
openssl dgst -md5 file.txt

# HMAC-SHA256 (with key)
openssl dgst -sha256 -mac HMAC -macopt hexkey:deadbeef file.txt

# ==========================
# OpenSSL — Certificates
# ==========================
# View certificate details (PEM)
openssl x509 -in cert.pem -text -noout

# Convert DER -> PEM
openssl x509 -inform der -in cert.der -out cert.pem

# View certificate request (CSR)
openssl req -in request.csr -noout -text

# ==========================
# Useful tips
# ==========================
# - Prefer genpkey/pkey/pkeyutl over legacy genrsa/rsautl when possible.
# - Use -pbkdf2 and a high -iter value for password-based symmetric encryption.
# - Use OAEP padding for RSA encryption (rsa_padding_mode:oaep).
# - For large files, use hybrid encryption (symmetric file encryption + asymmetric key encryption).
# - Always protect and rotate private keys; keep backups in secure storage.

```

---

## CRYPTANALYSIS QUICK COMMANDS

```bash
# ==========================
# Brute-force Caesar cipher (try all 26 shifts) - Bash
# ==========================
CIPHERTEXT="CIPHERTEXT HERE"
for i in {0..25}; do
  echo "Shift $i:"
  # rotate uppercase
  echo "$CIPHERTEXT" | tr 'A-Z' "$(echo {A..Z} | tr -d ' ' | cut -c$((i+1))-26)$(echo {A..Z} | tr -d ' ' | cut -c1-$i)" \
                     | tr 'a-z' "$(echo {a..z} | tr -d ' ' | cut -c$((i+1))-26)$(echo {a..z} | tr -d ' ' | cut -c1-$i)"
done

# --------------------------
# Single-byte XOR brute-force - Python 3
# --------------------------
# Save this as xor_bruteforce.py and run: python3 xor_bruteforce.py
import sys

# Provide ciphertext as bytes (example: from hex)
# ciphertext = bytes.fromhex("your_hex_here")
ciphertext = b"YOUR_CIPHERTEXT_BYTES_HERE"

def score_plaintext(pt: bytes) -> float:
    # simple English scoring: letter frequency + printable count
    freq = b" etaoinshrdluETAOINSHRDLU"
    score = sum(byte in freq for byte in pt)
    score += sum(1 for b in pt if 32 <= b <= 126)  # printable
    return score

results = []
for key in range(256):
    plaintext = bytes([b ^ key for b in ciphertext])
    try:
        text = plaintext.decode('ascii')
    except Exception:
        text = plaintext.decode('ascii', errors='ignore')
    results.append((score_plaintext(plaintext), key, text))

# show top candidates
for s, k, t in sorted(results, reverse=True)[:20]:
    print(f"key={k} score={s}\n{t}\n{'-'*40}")

# --------------------------
# Frequency analysis - Python 3
# --------------------------
# Save as freq_analysis.py, run: python3 freq_analysis.py ciphertext_file
from collections import Counter
import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 freq_analysis.py ciphertext_file")
        sys.exit(1)
    data = open(sys.argv[1], "rb").read()
    freq = Counter(data)
    for byte, count in freq.most_common(50):
        print(f"{byte:02x} ({chr(byte) if 32<=byte<=126 else '.'}): {count}")

# --------------------------
# CyberChef multi-recipe (manual steps)
# --------------------------
# 1. Base64 Decode
# 2. Hex Decode
# 3. Caesar Brute Force (try all shifts and inspect readable outputs)
# 4. Inspect resulting plaintext for readable text
# (Implement these sequentially in CyberChef GUI using the listed operations)

# --------------------------
# Factor RSA modulus (utility)
# --------------------------
# If you want to attempt factoring an RSA modulus for research/learning, FactorDB (factordb.com) is a commonly-used public database where you can paste n.
# Note: only use on keys you own or have explicit permission to analyze.

# --------------------------
# Crack JWT secret with Hashcat (mode 16500)
# --------------------------
# Create a file (jwt_token.txt) containing the JWT hash line Hashcat expects (see Hashcat docs for format).
# Then run:
hashcat -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt --outfile=cracked.txt

# --------------------------
# Notes & legal reminder
# --------------------------
# - Replace placeholders (CIPHERTEXT, YOUR_CIPHERTEXT_BYTES_HERE, file names) before running.
# - Test and run these tools only against systems/data you own or have explicit authorization to analyze.
# - For large binary blobs, prefer saving to files and operating on files rather than embedding in source directly.

```

---

## TOOL SHORTCUTS & ALIASES

Add to `.bashrc` or `.zshrc`:

```bash
# ==========================
# Quick encoding / hashing aliases
# ==========================
alias b64enc="base64"
alias b64dec="base64 -d"
alias hexenc="xxd -p"
alias hexdec="xxd -r -p"

alias md5hash="md5sum"
alias sha256hash="sha256sum"

# ==========================
# Quick Caesar brute-force
# Usage: caesarbrute "CIPHERTEXT HERE"
# ==========================
caesarbrute() {
  local text="$*"
  if [ -z "$text" ]; then
    echo "Usage: caesarbrute \"CIPHERTEXT\""
    return 1
  fi

  for i in {0..25}; do
    echo "=== Shift $i ==="
    # Here-doc expands $i and reads the input from the heredoc
    python3 - <<PY
import sys
i = $i
text = sys.stdin.read()
def rot(ch, i):
    if 'A' <= ch <= 'Z':
        return chr((ord(ch) - 65 + i) % 26 + 65)
    if 'a' <= ch <= 'z':
        return chr((ord(ch) - 97 + i) % 26 + 97)
    return ch
print(''.join(rot(c, i) for c in text), end='')
PY
  done <<< "$text"
}

# ==========================
# Identify cipher heuristic
# Usage: identifycipher "SAMPLE_TEXT"
# ==========================
identifycipher() {
  local text="$*"
  if [ -z "$text" ]; then
    echo "Usage: identifycipher \"TEXT\""
    return 1
  fi

  echo "Checking: $text"
  python3 - <<PY
import sys, re
text = sys.stdin.read().strip()
print(f"Length: {len(text)}")
print(f"Alpha only: {text.isalpha()}")
print(f"Hex (0-9a-f only): {bool(re.fullmatch(r'[0-9a-fA-F]+', text))}")
print(f"Base64 compatible: {bool(re.fullmatch(r'[A-Za-z0-9+/]+=*', text))}")
# Basic entropy-ish check (rough): ratio of unique chars
uniq = len(set(text))
ratio = uniq / max(1, len(text))
print(f"Unique-char ratio: {ratio:.2f}")
# Heuristic suggestions
suggestions = []
if len(text) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]+', text):
    suggestions.append("Looks like HEX (byte-aligned).")
if re.fullmatch(r'[A-Za-z0-9+/]+=*', text):
    suggestions.append("Could be Base64.")
if text.isalpha() and len(text) < 200:
    suggestions.append("Alphabetic — try Caesar/ROT bruteforce.")
if not suggestions:
    suggestions.append("No strong guess — try common transforms (Base64, Hex, XOR, Caesar).")
print('Suggestions:')
for s in suggestions:
    print(' -', s)
PY
}

# ==========================
# Extract likely flags/strings from a file
# Usage: extracttext file.bin
# ==========================
extracttext() {
  if [ -z "$1" ]; then
    echo "Usage: extracttext <file>"
    return 1
  fi
  # prints strings and filters for common patterns: 'flag', braces like { ... }, or lines of alnum text
  strings "$1" | grep -Ei 'flag|{[^}]+}|^[A-Za-z0-9]+$'
}

```

---

## CRYPTOGRAPHY TOOL MATRIX

| Task | Tool | Command | Time |
| --- | --- | --- | --- |
| Identify cipher | dCode | dcode.fr/cipher-identifier | <1 min |
| Decode Base64 | CyberChef | CyberChef + recipe | <1 min |
| Brute-force Caesar | Python loop | for i in range(26): decode(shift=i) | <1 sec |
| Crack MD5 (weak password) | Hashcat | hashcat -m 0 hash.txt wordlist.txt | <5 min |
| Crack bcrypt | Hashcat | hashcat -m 3200 hash.txt wordlist.txt | 1-48 hours |
| Solve Vigenère | dCode | dcode.fr/vigenere-cipher (auto) | <1 min |
| Solve substitution cipher | QuipQiup | quipqiup.com | <1 min |
| Extract steganography | Binwalk | binwalk -e file.bin | <1 min |
| Factor RSA (small n) | FactorDB | factordb.com | <1 min |
| Crack JWT secret | Hashcat | hashcat -m 16500 jwt.txt wordlist.txt | <10 min |

---

## PYTHON ONE-LINERS FOR CRYPTANALYSIS

```python
# ==========================
# Caesar brute-force (prints all 26 shifts)
# ==========================
# Compact (list comprehension printing results)
[print(f"Shift {i}: {''.join(chr((ord(c)-65+i)%26+65) if 'A'<=c<='Z' else chr((ord(c)-97+i)%26+97) if 'a'<=c<='z' else c for c in ct)}")
 for i in range(26) for ct in ["KHOOR"]]

# Clearer version (loop, handles mixed-case)
ct = "KHOOR"
for i in range(26):
    out = []
    for c in ct:
        if 'A' <= c <= 'Z':
            out.append(chr((ord(c) - 65 + i) % 26 + 65))
        elif 'a' <= c <= 'z':
            out.append(chr((ord(c) - 97 + i) % 26 + 97))
        else:
            out.append(c)
    print(f"Shift {i}: {''.join(out)}")

# ==========================
# Frequency analysis
# ==========================
from collections import Counter
print(Counter("CIPHERTEXT").most_common())

# ==========================
# Base64 encode / decode
# ==========================
import base64
enc = base64.b64encode(b"text")        # bytes: b'dGV4dA=='
dec = base64.b64decode("dGV4dA==")     # bytes: b'text'
print(enc, dec)

# ==========================
# Hex encode / decode
# ==========================
hex_enc = "text".encode().hex()               # '74657874'
hex_dec = bytes.fromhex("74657874").decode()  # 'text'
print(hex_enc, hex_dec)

# ==========================
# XOR two values (example)
# ==========================
xor_result = 0x41 ^ 0x42   # -> 0x03
print(hex(xor_result))

# ==========================
# Brute-force single-byte XOR (returns decoded string for each key)
# ==========================
# ciphertext should be a bytes object, e.g. bytes.fromhex("...") or b"..."
ciphertext = b""  # set to actual bytes
results = [bytes([b ^ key for b in ciphertext]).decode('ascii', errors='ignore') for key in range(256)]
# print top few (or inspect manually)
for k, candidate in enumerate(results[:10]):
    print(f"key={k}: {candidate}")

# ==========================
# MD5 hash
# ==========================
import hashlib
print(hashlib.md5(b"password").hexdigest())

# ==========================
# Heuristic: check if a string looks like MD5/SHA1/SHA256
# ==========================
def looks_like_hash(s):
    s = s.lower()
    ishex = all(c in "0123456789abcdef" for c in s)
    return {
        "is_hex": ishex,
        "maybe_md5": len(s) == 32 and ishex,
        "maybe_sha1": len(s) == 40 and ishex,
        "maybe_sha256": len(s) == 64 and ishex
    }

print(looks_like_hash("5f4dcc3b5aa765d61d8327deb882cf99"))  # example MD5

```

---

## REAL-WORLD DECISION TREES

### Decision Tree 1: Unknown Encrypted Data

```
Unknown ciphertext discovered
↓
Is it Base64/Hex/URL-encoded? → YES → Decode first
↓ NO
Run dCode cipher identifier
↓
← Result: Caesar? → Brute-force all 26 shifts
← Result: Vigenère? → Kasiski examination → Frequency analysis
← Result: Substitution? → QuipQiup solver
← Result: Unknown/Random? → Try XOR brute-force (256 keys)
↓
No result? → Try CyberChef multi-recipe chain
↓
Still no result? → Check for RSA/AES (need key or context)
```

### Decision Tree 2: Hash Cracking Priority

```
Hash discovered
↓
Length check:
├─ 32 chars → MD5 (WEAK, crack with dictionary/mask)
├─ 40 chars → SHA-1 (WEAK, crack with dictionary)
├─ 64 chars → SHA-256 (Crack if weak password)
├─ $2y$... → bcrypt (STRONG, accept slow or weak password target)
└─ Unknown → hashidentifier tool
↓
Check: No salt used? (identical plaintext = identical hash)
├─ YES → Rainbow table likely works, try online lookup first
└─ NO → Dictionary/mask attack required
↓
Apply attack:
├─ Weak password expected → Dictionary: wordlist.txt + rules
├─ Pattern-based password → Mask: ?u?l?l?l?d?d
└─ Unknown pattern → Hybrid: wordlist.txt -a 6 ?d?d?d
```

### Decision Tree 3: CTF Cryptography Challenge

```
CTF challenge given
↓
Read description for hints (cipher type? encoding? key-related?)
↓
Check for encoded data:
├─ Base64? → Decode → Check for new cipher
├─ Hex? → Decode → Check for new cipher
├─ URL-encoded? → Decode → Check for new cipher
└─ Unknown? → Proceed to cipher identification
↓
Identify cipher type (dCode/Ciphey)
↓
├─ Caesar → Brute-force
├─ Vigenère → Kasiski + IC + frequency
├─ XOR → Brute-force key (256 possibilities)
├─ Substitution → QuipQiup
├─ Hash → Identify type → Crack
├─ RSA → Check for weak key, small e, common modulus
├─ JWT → Check secret, algorithm=none, key confusion
└─ Steganography → strings, exiftool, stegsolve, binwalk
↓
Combine results if multi-layer encoding/encryption
↓
Extract flag format (usually "flag{...}" or "CTF{...}")
```

---

## UNDER-PRESSURE WORKFLOW

**Time-limited engagement (CTF or quick pentest)?**

1. **First 30 seconds:** Identify data type (encoding vs cipher vs hash)
    - Use: dCode cipher identifier, hash length check
    - Command: `file`, `strings`, `hexdump -C | head`
2. **Next 2 minutes:** Try quick wins
    - All 26 Caesar shifts
    - Online Base64/Hex decoders
    - Dictionary attack on weak hashes
3. **If stuck (5+ minutes):** Use automation
    - Ciphey: `ciphey -t "ciphertext"`
    - CyberChef: Load data, try recipe chains
    - Hashcat: Dictionary + rules
4. **Last resort:** Contextual analysis
    - Re-read challenge description for hints
    - Check for multiple encoding layers
    - Look for key in description or previous CTF challenges

---

# PART 3: REAL-WORLD EXAMPLES & LAB SCENARIOS

---

## SCENARIO 1: Discovered Base64 Ciphertext

**Context:** Found in web application cookie/parameter

```
Ciphertext discovered:
SGVsbG8gV29ybGQ=SGVsbG8gV29ybGQ=U0VDUkVU
```

**Step 1: Identify encoding**

```bash
# Observation: Contains A-Z, a-z, 0-9, +/=, and padding (=)# Diagnosis: Base64 encoded
```

**Step 2: Decode**

```bash
echo "SGVsbG8gV29ybGQ=" | base64 -d# Output: Hello World# Continue with rest:echo "SGVsbG8gV29ybGQ=U0VDUkVU" | base64 -d# Output: Hello WorldSECRET
```

**Step 3: Check if encrypted or just encoded**
- Decoded text is readable → Just Base64 encoding, no encryption
- If decoded text is garbage → May be encrypted before Base64

**Lab Walkthrough (TryHackMe):**

```bash
# Download provided ciphertextcat ciphertext.txt | base64 -d > decoded.bin
# If binary garbage, try:file decoded.bin  # Check file type# If image: Open in viewer or exiftoolexiftool decoded.bin
# If text: Already readable (the flag)cat decoded.bin
# Flag: THM{base64_is_not_encryption}
```

---

## SCENARIO 2: Caesar Cipher in Web Parameter

**Context:** Web login bypass via encrypted cookie

```
Cookie value:
KHOOR_ZRUOG_IURP_FDHVDU_FLSKHU

Hypothesis: Caesar cipher (found in description hint)
```

**Step 1: Identify shift value**

```bash
# Brute-force all 26 shifts:for i in {0..25}; do
  echo "Shift $i: $(echo 'KHOOR_ZRUOG_IURP_FDHVDU_FLSKHU' | tr 'A-Z' $(echo {A..Z} | cut -c$((i+1))-))"done# Output (partial):# Shift 0: KHOOR_ZRUOG_IURP_FDHVDU_FLSKHU# Shift 1: JGNNQ_YQTNF_HTSQ_ECGUCT_EKTJGV# ...# Shift 3: HELLO_WORLD_FROM_CAESAR_CIPHER  ← READABLE!
```

**Step 2: Extract plaintext**

```bash
# Shift = 3plaintext="HELLO_WORLD_FROM_CAESAR_CIPHER"echo $plaintext | tr 'A-Z_' 'a-z '
# Output: hello world from caesar cipher
```

**Step 3: Use recovered value**
- Replace cookie value with plaintext or shifted version
- Bypass authentication if cookie was access control check

**Lab Walkthrough (Hack The Box):**

```bash
# Challenge: ROT13 challengeecho "uryyb_jbeyq" | rot13# Output: hello_world# Or use dCode:# Navigate to: dcode.fr/caesar-cipher# Paste: uryyb_jbeyq# Auto-returns: hello_world (shift 13)# Flag: HTB{rot13_is_caesar_shift_13}
```

---

## SCENARIO 3: Multi-Layer Encoding

**Context:** CTF challenge with nested encoding

```
Given data:
SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBGbGFnOiBGTEFHe2VuY29kaW5nX2xheWVyc19hcmVfZnVufQ==
```

**Step 1: First decode (Base64)**

```bash
echo "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBGbGFnOiBGTEFHe2VuY29kaW5nX2xheWVyc19hcmVfZnVufQ==" | base64 -d# Output: Hello World! This is a Flag: FLAG{encoding_layers_are_fun}
```

**Step 2: Check for additional encoding**

```bash
# Output is readable ASCII - no further decoding needed# Flag extracted: FLAG{encoding_layers_are_fun}
```

**More Complex Example (3 layers):**

```
Layer 1 (Base64):
V0NUQkFURXs0MzJkZTUxMjExYjBjMzQwYjAxYTcxODU=

Layer 2 (Hex):
Result of Base64 decode: WCUBATEx{432de51211b0c340b01a71895...}

Layer 3 (Caesar):
Result of Hex decode: ICTBATEX...
Apply shift: ?
```

**Lab Workflow (CyberChef):**

```
1. Open: gchq.github.io/CyberChef/
2. Drag recipes in sequence:
   - Base64 Decode
   - Hex Decode
   - Caesar Brute Force (or add manually with shift=13)
3. Input: original Base64 string
4. Output: Flag revealed
```

---

## SCENARIO 4: Hash Cracking (Weak MD5)

**Context:** Database dump with MD5 hashes

```
Discovered hashes:
admin:5f4dcc3b5aa765d61d8327deb882cf99
user1:202cb962ac59075b964b07152d234b70
user2:c20ad4d76fe97759aa27a0c99bff6710

Objective: Recover passwords
```

**Step 1: Identify hash type**

```bash
# All hashes are 32 characters (hex)# Diagnosis: MD5 (cryptographically broken, easily cracked)
```

**Step 2: Check online databases**

```bash
# Visit: md5.com, hashidentifier.com, or dehashed.com# Search: 5f4dcc3b5aa765d61d8327deb882cf99# Result: admin (if hash known in database)
```

**Step 3: Offline cracking (if not in database)**

```bash
# Save hashes to file (format: hash:salt or just hash)# admin:5f4dcc3b5aa765d61d8327deb882cf99hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt --outfile=cracked.txt
# Wait for resultscat cracked.txt
# Output:# 5f4dcc3b5aa765d61d8327deb882cf99:admin# 202cb962ac59075b964b07152d234b70:123456# c20ad4d76fe97759aa27a0c99bff6710:1234567
```

**Step 4: Extract credentials**

```bash
admin:adminuser1:123456user2:1234567
```

**Lab Example (TryHackMe):**

```bash
# Challenge: Crack These Hashes# Given: 5d41402abc4b2a76b9719d911017c592hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
# Output: hello# Flag: THM{MD5_hash_cracked_hello}
```

---

## SCENARIO 5: Vigenère Cipher Decryption

**Context:** Historical cipher in CTF

```
Ciphertext:
LXFOPVEFRNHR

Hint: "Key is 3 letters, related to cryptography"
```

**Step 1: Identify cipher**

```bash
# Observation:# - Letters only# - Multiple repeated sequences possible# - Challenge mentions "key related"# Diagnosis: Polyalphabetic cipher (Vigenère likely)
```

**Step 2: Determine key length**

```bash
# Hint says key is 3 letters# Or use Kasiski examination if no hint
```

**Step 3: Frequency analysis per chunk**

```
Key length = 3, so break into 3 Caesar ciphers:
Position 0: L, O, V, R, R (shift unknown)
Position 1: X, P, E, N, H (shift unknown)
Position 2: F, V, F, H, (shift unknown)

Apply frequency analysis to each to find shift
```

**Step 4: Use online solver or manual approach**

**Easier: Use dCode**

```bash
# Navigate to: dcode.fr/vigenere-cipher# Paste ciphertext: LXFOPVEFRNHR# Auto-solve or specify key length: 3# Result: CRYPTOGRAPHY (key: "KEY" or similar)
```

**Manual Python (if key known):**

```python
def vigenere_decrypt(ciphertext, key):
    result = ""    key_index = 0    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            result += chr((ord(char) - shift - ord('A')) % 26 + ord('A'))
            key_index += 1        else:
            result += char
    return result
plaintext = vigenere_decrypt("LXFOPVEFRNHR", "KEY")
print(plaintext)  # Output: CRYPTOGRAPHY
```

**Lab Example (PicoCTF):**

```
Challenge: You've heard of Caesar Cipher, but what about Vigenere?

Given ciphertext: GXEQFXWWEXYVVF

Hint: Key is "CRYPTO" (6 letters)

Use CyberChef or dCode, input key "CRYPTO"
Result: MASTEROFCRYPTO

Flag: picoCTF{master_of_crypto}
```

---

## SCENARIO 6: XOR Single-Byte Brute-Force

**Context:** Suspicious binary file with XOR encryption

```
Hex dump of ciphertext:
3d 6b 7a 62 7d

Objective: Decrypt
```

**Step 1: Identify XOR cipher**

```bash
# Small file, suspicious pattern# Try XOR brute-force (256 keys possible)
```

**Step 2: Brute-force all keys**

```python
ciphertext = bytes.fromhex("3d 6b 7a 62 7d")
for key in range(256):
    decrypted = bytes([byte ^ key for byte in ciphertext])
    try:
        text = decrypted.decode('ascii')
        # Check if readable/printable        if all(c.isprintable() or c.isspace() for c in text):
            print(f"Key: {key:3d} (0x{key:02x}): {text}")
    except:
        pass# Output:# Key:  52 (0x34): hello# Key:  15 (0x0f): ?????# ... (other garbage)
```

**Step 3: Identify correct plaintext**

```bash
# Key 52 produces "hello" - readable English word# This is likely correct plaintext
```

**Lab Example (CTF):**

```bash
# Challenge: XOR Decryption# Given (base64): PWt6Yn0=echo "PWt6Yn0=" | base64 -d | xxd -p# Output: 3d6b7a627d (hex)# Brute-force XOR:python3 << 'EOF'ct = bytes.fromhex("3d6b7a627d")for k in range(256):    dec = bytes([b ^ k for b in ct]).decode('ascii', errors='ignore')    if dec.isprintable(): print(f"{k}: {dec}")EOF# Result: Key 52 produces "hello"# Flag: CTF{hello_xor_key_52}
```

---

## SCENARIO 7: RSA Weak Key Attack

**Context:** Small RSA modulus found in application

```
Public key (n, e):
n = 221 (very small, for demo; real: 2048+ bits)
e = 5

Ciphertext: 118
Objective: Recover plaintext
```

**Step 1: Factor modulus (if small)**

```bash
# n = 221# Try factorization:echo "221" | python3 -c "import sys; n=int(sys.stdin.read()); print(f'{n} = {n//13} x 13' if n%13==0 else 'Not divisible by 13')"# Output: 221 = 17 x 13# So: p = 13, q = 17
```

**Step 2: Calculate private exponent**

```python
p, q = 13, 17n = p * q
phi = (p - 1) * (q - 1)  # = 12 * 16 = 192e = 5# Find d: e*d ≡ 1 (mod phi)# Using extended Euclidean algorithm:def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y
gcd, x, y = extended_gcd(e, phi)
d = x % phi  # d = 77print(f"d = {d}")
```

**Step 3: Decrypt**

```python
ciphertext = 118plaintext = pow(ciphertext, d, n)
print(f"Plaintext: {plaintext}")
# Output: 4 (or some other small number depending on original encryption)
```

**Real-World Scenario (Online):**

```bash
# Challenge: Factor the modulus at factordb.com# Input: Your n value (e.g., 123456789012345678901234567890123456789)# Once factorized (p and q obtained):python3 << 'EOF'p = <factor1>q = <factor2>e = <public_exponent>ciphertext = <given_ciphertext>n = p * qphi = (p - 1) * (q - 1)# Calculate d (private exponent)def modinv(a, m):    def egcd(a, b):        if a == 0: return b, 0, 1        g, y, x = egcd(b % a, a)        return g, x - (b // a) * y, y    g, x, _ = egcd(a % m, m)    return x % md = modinv(e, phi)plaintext = pow(ciphertext, d, n)print(f"Plaintext: {plaintext}")EOF
```

---

## SCENARIO 8: JWT Secret Cracking

**Context:** JWT token found in HTTP header

```
Token:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

Objective: Crack the secret key
```

**Step 1: Decode JWT (no key needed for payload)**

```bash
# JWT format: header.payload.signature# Decode header (base64):echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d# Output: {"alg":"HS256","typ":"JWT"}# Decode payload (base64):echo "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" | base64 -d# Output: {"sub":"1234567890","name":"John Doe","iat":1516239022}
```

**Step 2: Save token and crack secret**

```bash
# Save token to fileecho "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" > jwt.txt
# Crack with hashcat (mode 16500 = JWT HMAC)hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --outfile=jwt_cracked.txt
# Output:# eyJhbGc...:your-256-bit-secret
```

**Step 3: Forge new token (with cracked secret)**

```python
import jwt
# Now you know secret: "your-256-bit-secret"secret = "your-256-bit-secret"# Create new payload (e.g., change name or add admin=true)payload = {
    "sub": "1234567890",
    "name": "Admin User",
    "iat": 1516239022,
    "admin": True}
# Generate new tokennew_token = jwt.encode(payload, secret, algorithm="HS256")
print(new_token)
# Use forged token in HTTP header:# Authorization: Bearer <new_token>
```

**Lab Example (PentesterLab):**

```bash
# Challenge: Weak JWT secrettoken="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.x_d2-Vr9TJ7X_D4Hs1MN3VZ_8X_O6Z_Y_A_B_C_D_E"hashcat -m 16500 <(echo $token) /usr/share/wordlists/rockyou.txt
# Secret cracked: "secret123"# Forge admin token with user_id=999# Flag: FLAG{jwt_secret_cracked_and_forged}
```

---

## SCENARIO 9: Steganography in Image

**Context:** CTF image file with hidden flag

```
File: challenge.png
Objective: Extract hidden data
```

**Step 1: Basic file inspection**

```bash
# Check file type and propertiesfile challenge.png
# Output: PNG image data, 800 x 600, 8-bit indexed, with color table# Look for plaintext stringsstrings challenge.png | grep -i "flag\|ctf\|{.*}"# If found: Great! Flag extracted# If not: Continue to next steps
```

**Step 2: Extract metadata**

```bash
# Check EXIF data or PNG metadataexiftool challenge.png
# Look for comment field or other text data
```

**Step 3: Visualize hidden layers (steganography)**

```bash
# Use Stegsolve (Java GUI tool)java -jar Stegsolve.jar
# Open image in Stegsolve# Cycle through color planes: Red, Green, Blue, Alpha# Check LSBs (Least Significant Bits) - Plane 0, 1, 2, etc.# Often flag is hidden in LSBs or specific color channel
```

**Step 4: Extract with binwalk (if file is embedded)**

```bash
# Check for embedded filesbinwalk challenge.png
# Extract filesbinwalk -e challenge.png
# Output: Extracted files in: _challenge.png.extracted/# Check extracted directoryls -la _challenge.png.extracted/
# May contain hidden .txt, .zip, or other files
```

**Step 5: Automated steganography detection**

```bash
# Tool: SteganoNow or other automated stego tools# Command: steganow -i challenge.png -o output/# Or use online: futureboy.us/stegano/decinput.html
```

**Lab Example (TryHackMe):**

```bash
# Challenge: Stego Extraction# File: secret.pngstrings secret.png | head -20# No luckexiftool secret.png | grep -i comment
# Comment: "Flag is in LSB"# Use Stegsolve, go to Plane 0 (LSB)# Flag appears pixel-by-pixel in image# Flag: THM{steganography_in_images}
```

---

## SCENARIO 10: Frequency Analysis on Substitution Cipher

**Context:** Substitution cipher with no known key

```
Ciphertext (100+ chars for reliability):
"KHOOR LV D WHVW RI IUHTXHQFB DQDOB..."

Objective: Recover plaintext without key
```

**Step 1: Count character frequencies**

```python
from collections import Counter
ct = "KHOOR LV D WHVW RI IUHTXHQFB DQDOB"freq = Counter(char for char in ct if char.isalpha())
print(freq.most_common())
# Output:# ('H', 5), ('R', 4), ('D', 3), ('W', 3), ...
```

**Step 2: Compare with English letter frequencies**

```
English (most common):
E, T, A, O, I, N, S, H, R

Our ciphertext (most common):
H, R, D, W, L, V, Q, B, K

Mapping hypothesis:
H→E (most common in both)
R→T or R→A
D→N or D→O
...
```

**Step 3: Test hypothesis iteratively**

```bash
# Replace H→E:"KEHOR LV D WEEW RI IUHTXHQFB DQDOB"# Still garbage, adjust# Try automated solver:# QuipQiup: quipqiup.com# Paste ciphertext# Auto-solves substitution cipher
```

**Step 4: Use online solver (QuipQiup)**

```
Paste: "KHOOR LV D WHVW RI IUHTXHQFB DQDOB"
Result: "HELLO IS A TEST OF FREQUENCY ANALYS[IS]"
Key recovered: H→E, K→H, O→L, etc.
```

---

## QUICK REFERENCE: COMMON CTF CIPHER PATTERNS

| Cipher | Ciphertext Pattern | Method | Tool | Time |
| --- | --- | --- | --- | --- |
| Caesar | Letters only, short | Brute-force 26 | dCode | <1 sec |
| ROT13 | Letters only | Reverse ROT13 | `rot13` | <1 sec |
| Base64 | A-Z,a-z,0-9,+/= | Decode | CyberChef | <1 sec |
| Hex | 0-9,a-f | Decode | `xxd -r -p` | <1 sec |
| Vigenère | Long letters, patterns | Kasiski+IC | dCode | <1 min |
| XOR single-byte | Random-looking | 256 key brute-force | Python loop | <1 sec |
| Substitution | Mixed, long text | Frequency analysis | QuipQiup | <1 min |
| Steganography | Image file | Stegsolve/binwalk | Various | <5 min |
| MD5 hash | 32 hex chars | Dictionary | Hashcat | <10 min |
| bcrypt hash | 2*y*/… | Dictionary (slow) | Hashcat | 1-48 hrs |
| RSA (weak key) | Ciphertext | Factor n | FactorDB | <1 min |
| JWT | header.payload.sig | Crack secret | Hashcat/jwt-cli | <10 min |

---

## FINAL TROUBLESHOOTING MATRIX

| Symptom | Likely Cause | Check | Fix |
| --- | --- | --- | --- |
| Tool hangs | Wrong hash format | `hashidentifier hash.txt` | Use correct `-m` mode |
| No cracking results after 1hr | Weak password not in wordlist | Try other wordlists | Custom wordlist or rules |
| Base64 decode fails | Incorrect Base64 | Check for URL-safe Base64 | Replace + with -, / with _ |
| Cipher identifier fails | Unknown/custom cipher | Check for multiple encoding layers | Decode step-by-step |
| RSA decryption fails | Large n (can’t factor) | Verify key size | Check for other RSA attacks (small e, common modulus) |
| Steganography tool fails | Wrong file type | `file challenge.*` | Try different tool (Stegsolve vs binwalk vs strings) |
| JWT secret crack stuck | Key not in wordlist | Check common secrets | Combine wordlists or brute-force with masks |

---

## APPENDIX: USEFUL RESOURCES

**Online Tools:**
- CyberChef: gchq.github.io/CyberChef/
- dCode: dcode.fr
- QuipQiup: quipqiup.com
- FactorDB: factordb.com
- JWT.io: jwt.io (decode only, manual verification)

**Wordlists:**
- RockYou: /usr/share/wordlists/rockyou.txt (SecList)
- Common: /usr/share/wordlists/common.txt
- Download: github.com/danielmiessler/SecLists

**Command References:**
- Hashcat: hashcat.net/wiki/
- John the Ripper: openwall.com/john/doc/
- OpenSSL: openssl.org/docs

---
