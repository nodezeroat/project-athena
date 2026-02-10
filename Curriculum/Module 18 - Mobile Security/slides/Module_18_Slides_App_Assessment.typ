#import "../../../typst-athena-slides-template/1.0.1/src/lib.typ": *

#show: athena-theme.with(
  font: "Berkeley Mono",
  config-info(
    title: [Module 18: Mobile Security],
    subtitle: [Mobile App Security Assessment],
    authors: [*Marcel Schnideritsch*],
    extra: [],
    footer: [Module 18 - Mobile Security],
  ),
  config-common(
    handout: false,
  ),
)

#title-slide()

#section-slide(title: "OWASP Mobile Application Security")

#slide(title: "MASVS Categories")[
  *Mobile Application Security Verification Standard:*

  - *MASVS-STORAGE*: Secure data storage
  - *MASVS-CRYPTO*: Proper cryptography
  - *MASVS-AUTH*: Authentication and authorization
  - *MASVS-NETWORK*: Secure communication
  - *MASVS-PLATFORM*: Platform interaction security
  - *MASVS-CODE*: Code quality and build settings
  - *MASVS-RESILIENCE*: Anti-tampering and anti-RE

  MASTG (Testing Guide) provides procedures for each requirement.
]

#slide(title: "Key MASVS Requirements")[
  #table(
    columns: (auto, auto),
    inset: 6pt,
    stroke: 0.5pt,
    align: left,
    [*Category*], [*Critical Requirements*],
    [Storage], [No secrets in logs, backups, or clipboard],
    [Crypto], [No hardcoded keys, use proven algorithms],
    [Auth], [Server-side enforcement, proper session mgmt],
    [Network], [TLS everywhere, certificate pinning],
    [Platform], [Minimum permissions, secure IPC],
    [Code], [No debug flags, signed builds, updated libs],
    [Resilience], [Root detection, obfuscation, anti-debug],
  )
]

#section-slide(title: "Testing Methodology")

#slide(title: "Assessment Phases")[
  *Phase 1: Information Gathering*
  - App Store analysis (permissions, reviews, metadata)
  - Network reconnaissance (API endpoints, backends)
  - Third-party SDK identification

  *Phase 2: Static Analysis*
  - Decompile and review source code
  - Search for hardcoded secrets
  - Analyze manifest and configurations

  *Phase 3: Dynamic Analysis*
  - Monitor runtime behavior
  - Intercept network traffic
  - Hook functions with Frida
]

#slide(title: "Static Analysis Workflow")[
  *Android:*
  ```bash
  # Pull APK from device
  adb pull $(adb shell pm path com.app \
    | cut -d: -f2)

  # Decompile
  jadx target.apk -d output/

  # Search for secrets
  grep -rn "api_key\|secret\|password" output/
  grep -rn "http://" output/  # Cleartext traffic
  ```

  *iOS:*
  ```bash
  # Decrypt and extract
  frida-ios-dump com.app
  class-dump AppBinary > headers.h
  strings AppBinary | grep -i "api\|key"
  ```
]

#section-slide(title: "Automated Scanning: MobSF")

#slide(title: "MobSF (Mobile Security Framework)")[
  Open-source automated analysis platform:

  ```bash
  # Docker setup
  docker pull opensecurity/mobile-security-framework-mobsf
  docker run -it --rm -p 8000:8000 \
    opensecurity/mobile-security-framework-mobsf
  # Access: http://localhost:8000
  ```

  *Upload APK/IPA for automatic analysis:*
  - Manifest/Info.plist analysis
  - Hardcoded secrets detection
  - Binary protection checks
  - Network security analysis
  - CVSS-scored findings
]

#slide(title: "MobSF Findings Priority")[
  #table(
    columns: (auto, auto),
    inset: 6pt,
    stroke: 0.5pt,
    align: left,
    [*Priority*], [*Finding Type*],
    [Critical], [Hardcoded credentials, disabled cert validation],
    [High], [Exported components without perms, debug enabled],
    [Medium], [Missing binary protections, weak crypto],
    [Low], [Informational, missing obfuscation],
  )

  *Not all findings are critical!*
  MobSF is a starting point - always verify with manual testing.
]

#section-slide(title: "Traffic Interception")

#slide(title: "Burp Suite for Mobile Testing")[
  *1. Configure Proxy:*
  - Bind to all interfaces (0.0.0.0), port 8080

  *2. Configure Device:*
  - Wi-Fi proxy → your IP:8080

  *3. Install CA Certificate:*
  - Browse to `http://burpsuite` on device
  - Install and trust certificate

  *Challenge:*
  - Android 7+: User CAs not trusted by default
  - Certificate pinning blocks interception
  - Solution: Frida SSL pinning bypass
]

#slide(title: "Common Traffic Analysis Findings")[
  *1. Cleartext HTTP:*
  - Credentials sent over HTTP

  *2. Sensitive Data in URLs:*
  - Tokens in query parameters

  *3. Missing Authentication:*
  - API endpoints accessible without auth

  *4. Verbose Error Messages:*
  - SQL queries, stack traces in responses

  *5. IDOR (Insecure Direct Object Reference):*
  - Change `user_id=123` to `user_id=124`
  - Access another user's data
]

#slide(title: "Certificate Pinning Bypass")[
  When pinning blocks Burp Suite:

  *1. objection (easiest):*
  ```bash
  objection -g com.app explore
  > android sslpinning disable
  > ios sslpinning disable
  ```

  *2. Frida script:*
  ```bash
  frida -U -f com.app -l ssl_bypass.js
  ```

  *3. Repackaging (Android):*
  - Modify `network_security_config` to trust user CAs
  - Rebuild, resign, reinstall

  Covered in detail in the Frida lecture.
]

#section-slide(title: "Manual Testing Checklist")

#slide(title: "Authentication Testing")[
  - Test with invalid credentials (error message leakage?)
  - Test account lockout after failed attempts
  - Test session token generation (randomness, length)
  - Test session timeout and invalidation
  - Test biometric authentication bypass
  - Test authentication on ALL API endpoints
  - Test horizontal privilege escalation (other users' data)
  - Test vertical privilege escalation (admin functions)
]

#slide(title: "Data Storage Testing")[
  *Android:*
  ```bash
  # SharedPreferences
  adb shell run-as com.app cat shared_prefs/config.xml

  # SQLite databases
  adb shell run-as com.app ls databases/
  ```

  *iOS:*
  ```bash
  objection -g com.app explore
  > ios keychain dump
  > sqlite connect <path_to_db>
  > .tables
  > SELECT * FROM sensitive_table;
  ```

  Check: SharedPrefs, databases, logs, cache, clipboard, backups
]

#section-slide(title: "Reporting")

#slide(title: "Vulnerability Report Template")[
  *For each finding:*

  1. *Title*: Descriptive name
  2. *Severity*: Critical / High / Medium / Low / Info
  3. *MASVS Requirement*: Which standard is violated
  4. *Description*: What the vulnerability is
  5. *Location*: File, line number, or endpoint
  6. *Evidence*: Code snippet, screenshot, or traffic capture
  7. *Impact*: What an attacker can achieve
  8. *Steps to Reproduce*: Exact reproduction steps
  9. *Remediation*: How to fix it

  Always include an executive summary and prioritized remediation roadmap.
]

#section-slide(title: "Key Takeaways")

#slide(title: "Summary")[
  - Use OWASP MASVS/MASTG as your testing framework
  - Combine automated tools (MobSF) with manual testing
  - Traffic interception is essential - bypass pinning when needed
  - Focus on high-impact findings: hardcoded secrets, auth bypass, data exposure
  - Document findings clearly with reproduction steps
  - Static analysis reveals structural issues
  - Dynamic analysis reveals runtime behavior
  - Always test both client (app) and server (API) sides
]

#title-slide(
  author: [Marcel Schnideritsch],
  title: [Mobile App Security Assessment],
  subtitle: [Module 18 - Mobile Security],
)
