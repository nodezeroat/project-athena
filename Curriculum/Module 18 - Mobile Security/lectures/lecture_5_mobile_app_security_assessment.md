# Mobile App Security Assessment

This lecture covers the practical methodology for assessing mobile application security, including the OWASP framework, automated scanning tools, traffic interception, and manual testing techniques that form the foundation before moving into advanced reverse engineering and dynamic instrumentation.

## OWASP Mobile Application Security (MAS)

### MASVS - Mobile Application Security Verification Standard

The MASVS defines security requirements organized into categories:

#### MASVS-STORAGE: Data Storage

- No sensitive data in logs
- No sensitive data in backups
- No sensitive data in keyboard cache, clipboard, or screenshots
- Sensitive data encrypted or stored in platform-specific secure storage (Keychain/Keystore)

#### MASVS-CRYPTO: Cryptography

- No hardcoded cryptographic keys
- Use proven cryptographic implementations (no custom crypto)
- Appropriate key lengths and algorithms (AES-256, RSA-2048+)
- Proper random number generation (SecureRandom, not Math.random)

#### MASVS-AUTH: Authentication and Authorization

- Authentication is enforced server-side
- Session management follows best practices
- Biometric authentication is properly implemented
- Step-up authentication for sensitive operations

#### MASVS-NETWORK: Network Communication

- TLS for all network communication
- Certificate validation is not disabled
- App uses certificate pinning for critical connections
- No sensitive data in URL parameters

#### MASVS-PLATFORM: Platform Interaction

- Minimum necessary permissions requested
- IPC mechanisms are secured
- WebViews are properly configured
- No sensitive data exposed through URL schemes

#### MASVS-CODE: Code Quality

- App is signed with valid certificate
- Debug code and features removed in production
- Third-party libraries are up to date
- App handles errors and exceptions gracefully

#### MASVS-RESILIENCE: Anti-Tampering

- Root/jailbreak detection
- Anti-debugging mechanisms
- Code obfuscation
- Integrity verification

### MASTG - Mobile Application Security Testing Guide

The MASTG provides practical testing procedures for each MASVS requirement. It is the primary reference for mobile penetration testing.

## Testing Methodology

### Phase 1: Information Gathering

```text
┌─────────────────────────────────────────────┐
│             Information Gathering             │
├─────────────────────────────────────────────┤
│ 1. App Store Analysis                        │
│    - Permissions requested                   │
│    - Developer information                   │
│    - Update history                          │
│    - User reviews (security complaints)      │
│                                              │
│ 2. Network Reconnaissance                    │
│    - API endpoints                           │
│    - Backend technology stack                │
│    - CDN and third-party services            │
│    - DNS and subdomain enumeration           │
│                                              │
│ 3. Third-Party Analysis                      │
│    - SDK identification                      │
│    - Known vulnerabilities in dependencies   │
│    - Analytics and tracking libraries        │
│    - Ad networks                             │
└─────────────────────────────────────────────┘
```

### Phase 2: Static Analysis

Static analysis examines the application without executing it:

**Android Static Analysis:**

```bash
# 1. Obtain the APK
adb shell pm path com.target.app
adb pull /data/app/.../base.apk target.apk

# 2. Decompile with jadx (preferred for source code)
jadx target.apk -d output/
# Browse output/sources/ for Java/Kotlin code
# Browse output/resources/ for XML configs

# 3. Decompile with apktool (preferred for resources and repackaging)
apktool d target.apk -o output_apktool/
# Produces smali code and decoded resources

# 4. Check AndroidManifest.xml
# Look for: exported components, debug flags, permissions, backup settings

# 5. Search for hardcoded secrets
grep -rn "api_key\|secret\|password\|token" output/sources/
grep -rn "BEGIN RSA\|BEGIN CERTIFICATE" output/sources/
grep -rn "http://" output/sources/  # Cleartext traffic
```

**iOS Static Analysis:**

```bash
# 1. Obtain the IPA (from jailbroken device or iTunes backup)
# Use frida-ios-dump to decrypt App Store apps

# 2. Extract and examine
unzip target.ipa -d output/
cd output/Payload/AppName.app/

# 3. Analyze binary
otool -L AppName                # Linked libraries
class-dump AppName > classes.h  # Objective-C headers
strings AppName | grep -i "api\|key\|secret\|http"

# 4. Check Info.plist
plutil -p Info.plist

# 5. Analyze embedded frameworks
ls Frameworks/
```

### Phase 3: Dynamic Analysis

Dynamic analysis involves running the app and observing its behavior:

**Key Areas:**

- Network traffic analysis
- Runtime behavior monitoring
- Data storage inspection
- Authentication/authorization testing
- Business logic testing

### Phase 4: Reporting

Document findings with:

- Vulnerability description
- Affected MASVS requirement
- Steps to reproduce
- Impact assessment (CVSS)
- Remediation recommendations
- Proof-of-concept evidence

## Automated Scanning with MobSF

MobSF (Mobile Security Framework) is an open-source automated analysis platform:

### Setup

```bash
# Docker installation (recommended)
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Access web interface
# http://localhost:8000
```

### Static Analysis with MobSF

Upload an APK or IPA to the web interface. MobSF automatically analyzes:

**For Android APKs:**

- Manifest analysis (permissions, exported components, debug flags)
- Code analysis (hardcoded secrets, crypto issues, logging)
- Binary analysis (native libraries, protections)
- Network security configuration
- Certificate information
- CVSS-scored findings

**For iOS IPAs:**

- Info.plist analysis (ATS, URL schemes, permissions)
- Binary analysis (PIE, ARC, stack canaries, encryption)
- Linked frameworks and libraries
- Embedded provisioning profile

### Dynamic Analysis with MobSF

MobSF supports dynamic analysis with a connected device or emulator:

- API traffic monitoring
- Runtime instrumentation (Frida-based)
- Activity testing
- Exported component testing

### MobSF Findings to Investigate

Not all MobSF findings are critical. Focus on:

| **Priority** | **Finding Type** |
| --- | --- |
| Critical | Hardcoded credentials, disabled certificate validation |
| High | Exported components without permissions, debug enabled |
| Medium | Missing binary protections, weak crypto |
| Low | Informational findings, missing obfuscation |

## Traffic Interception

### Setting Up Burp Suite for Mobile Testing

**1. Configure Proxy:**

```text
Burp Suite → Proxy → Options → Add listener
- Bind to: All interfaces (0.0.0.0)
- Port: 8080
```

**2. Configure Device/Emulator:**

```text
Android:
- Settings → Wi-Fi → Long press network → Modify → Advanced
- Proxy: Manual
- Host: <your_ip>
- Port: 8080

iOS:
- Settings → Wi-Fi → (i) icon → HTTP Proxy → Manual
- Server: <your_ip>
- Port: 8080
```

**3. Install Burp CA Certificate:**

```text
Android (< 7.0 or rooted):
1. Browse to http://burpsuite on device
2. Download certificate
3. Settings → Security → Install from storage

Android (7.0+, non-rooted):
- Requires app repackaging with modified network_security_config
- Or use Frida to bypass certificate validation

iOS:
1. Browse to http://burpsuite on device
2. Install downloaded profile
3. Settings → General → About → Certificate Trust Settings → Enable
```

### Common Traffic Analysis Findings

**1. Cleartext HTTP Traffic:**

```http
POST http://api.example.com/login HTTP/1.1
Content-Type: application/json

{"username": "alice", "password": "secret123"}
```

**2. Sensitive Data in URLs:**

```http
GET /api/user?token=eyJhbGciOiJIUzI1NiJ9... HTTP/1.1
```

**3. Missing or Weak Authentication:**

```http
GET /api/admin/users HTTP/1.1
# No Authorization header required
# Or easily guessable API key
X-API-Key: 12345
```

**4. Verbose Error Messages:**

```json
{
  "error": "SQL error: SELECT * FROM users WHERE id='1' OR '1'='1'",
  "stack": "com.example.DatabaseHelper.query(DatabaseHelper.java:42)..."
}
```

**5. Insecure Direct Object Reference (IDOR):**

```http
# Change user_id to access other users' data
GET /api/users/123/profile HTTP/1.1
GET /api/users/124/profile HTTP/1.1  # Another user's data accessible
```

### Certificate Pinning Bypass for Traffic Interception

When an app implements certificate pinning, Burp Suite cannot intercept HTTPS traffic. Common bypass methods:

**1. objection (Frida-based):**

```bash
# Automatic SSL pinning bypass
objection -g com.target.app explore
> android sslpinning disable
# or
> ios sslpinning disable
```

**2. Frida Script:**

```bash
# Use a community SSL unpinning script
frida -U -l ssl_unpinning.js -f com.target.app
```

**3. Repackaging (Android):**

```bash
# Modify network_security_config to trust user CAs
# Rebuild and resign the APK
apktool d app.apk -o app_mod/
# Edit res/xml/network_security_config.xml
apktool b app_mod/ -o app_patched.apk
# Sign with a debug key
```

These techniques are covered in detail in Lecture 7 (Dynamic Instrumentation with Frida).

## Manual Testing Checklist

### Authentication Testing

- [ ] Test with invalid credentials (error message information leakage)
- [ ] Test account lockout after failed attempts
- [ ] Test password complexity requirements
- [ ] Test session token generation (randomness, length)
- [ ] Test session timeout and invalidation
- [ ] Test "Remember Me" functionality
- [ ] Test biometric authentication bypass
- [ ] Test authentication on all API endpoints (not just UI)

### Authorization Testing

- [ ] Test horizontal privilege escalation (access other users' data)
- [ ] Test vertical privilege escalation (access admin functions)
- [ ] Test IDOR on all parameterized endpoints
- [ ] Test API endpoint access without authentication
- [ ] Test role-based access control

### Data Storage Testing

**Android:**

```bash
# After using the app, examine stored data
adb shell run-as com.target.app ls shared_prefs/
adb shell run-as com.target.app cat shared_prefs/config.xml
adb shell run-as com.target.app ls databases/
# Pull database and examine with sqlite3
```

**iOS (jailbroken):**

```bash
# Examine app container
objection -g com.target.app explore
> env
> ios plist cat <path_to_plist>
> ios keychain dump
> sqlite connect <path_to_db>
> .tables
> SELECT * FROM sensitive_table;
```

- [ ] Check SharedPreferences/UserDefaults for sensitive data
- [ ] Check SQLite databases for unencrypted sensitive data
- [ ] Check log files for sensitive data
- [ ] Check cache files and temporary files
- [ ] Check clipboard data exposure
- [ ] Check backup files (adb backup / iTunes backup)
- [ ] Verify Keychain/Keystore usage for secrets

### Network Testing

- [ ] Verify TLS on all connections
- [ ] Check for certificate pinning
- [ ] Test API input validation (injection attacks)
- [ ] Check for sensitive data in request/response
- [ ] Test for rate limiting
- [ ] Verify proper error handling in API responses

### Platform Interaction Testing

- [ ] Test exported components (Activities, Services, Content Providers)
- [ ] Test deep links and URL schemes
- [ ] Test WebView security configuration
- [ ] Test for Intent/URL scheme hijacking
- [ ] Verify minimum permissions principle

## Reporting Example

### Finding: Hardcoded API Key in Source Code

**Severity**: High

**MASVS**: MASVS-CRYPTO-1

**Description**: The application contains a hardcoded API key in the source code that provides access to the backend payment processing service.

**Location**: `com/example/app/network/ApiClient.java:42`

```java
private static final String API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
```

**Impact**: An attacker can extract this key through reverse engineering and use it to make unauthorized API calls, potentially accessing payment data or performing transactions.

**Steps to Reproduce**:

1. Obtain APK: `adb pull $(adb shell pm path com.example.app | cut -d: -f2)`
2. Decompile: `jadx app.apk -d output/`
3. Search: `grep -rn "sk_live" output/sources/`

**Remediation**:

- Remove hardcoded API key from source code
- Use the Android Keystore to store keys securely
- Implement server-side API key management
- Rotate the compromised key immediately

## Key Takeaways

- Follow the OWASP MASVS/MASTG as your testing framework
- Combine automated tools (MobSF) with manual testing for comprehensive coverage
- Traffic interception is essential - be prepared to bypass certificate pinning
- Focus on high-impact findings: hardcoded secrets, authentication bypass, data exposure
- Document findings clearly with reproduction steps and impact assessment
- Static analysis reveals structural issues; dynamic analysis reveals runtime behavior
- Always test both the client (app) and the server (API) sides

## Resources

- OWASP MASTG: <https://mas.owasp.org/MASTG/>
- OWASP MASVS: <https://mas.owasp.org/MASVS/>
- MobSF: <https://github.com/MobSF/Mobile-Security-Framework-MobSF>
- jadx: <https://github.com/skylot/jadx>
- apktool: <https://apktool.org/>
- Burp Suite Mobile Testing: <https://portswigger.net/burp/documentation/desktop/mobile>
- mitmproxy: <https://mitmproxy.org/>
