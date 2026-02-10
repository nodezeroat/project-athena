# iOS Security

Apple's iOS is widely regarded as one of the most secure mobile platforms, leveraging tight hardware-software integration, strict code signing, and a curated app distribution model. This lecture explores iOS-specific security mechanisms, their strengths and weaknesses, and techniques for security assessment.

## iOS Security Model

iOS security is built on several fundamental principles:

1. **Hardware Root of Trust**: Security anchored in silicon (Secure Enclave, Boot ROM)
2. **Mandatory Code Signing**: All executable code must be signed
3. **App Sandboxing**: Strict isolation between apps and the system
4. **Data Protection**: Hardware-accelerated encryption tied to user credentials
5. **Controlled Distribution**: App Store review process as a security gate

## Code Signing and Trust

### Code Signing Requirements

Every piece of executable code on iOS must be cryptographically signed:

- **Apple-signed**: System apps and frameworks
- **Developer-signed**: Third-party apps via Apple Developer Program
- **Enterprise-signed**: Internal enterprise distribution (requires enterprise certificate)
- **Ad-hoc**: Limited testing distribution (tied to specific device UDIDs)

```text
Code Signing Chain:
Apple Root CA
  └── Apple Intermediate CA
        └── Developer Certificate
              └── App Binary Signature
                    └── Embedded Provisioning Profile
                          ├── Allowed Device UDIDs (ad-hoc)
                          ├── Entitlements
                          └── Expiration Date
```

### Entitlements

Entitlements are key-value pairs that grant specific capabilities to an app:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>application-identifier</key>
    <string>TEAM_ID.com.example.app</string>
    <key>com.apple.developer.associated-domains</key>
    <array>
        <string>applinks:example.com</string>
    </array>
    <key>keychain-access-groups</key>
    <array>
        <string>TEAM_ID.com.example.shared</string>
    </array>
    <key>aps-environment</key>
    <string>production</string>
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.com.example.shared</string>
    </array>
</dict>
</plist>
```

**Security-Relevant Entitlements:**

| **Entitlement** | **Purpose** |
| --- | --- |
| `keychain-access-groups` | Keychain sharing between apps |
| `application-groups` | Shared container between apps |
| `aps-environment` | Push notification environment |
| `com.apple.developer.associated-domains` | Universal Links / App Clips |
| `com.apple.developer.networking.vpn.api` | VPN capabilities |

**Security Implications:**

- Entitlements define the security boundary of an app
- Overly broad entitlements increase attack surface
- Enterprise certificates can be abused for malware distribution

## App Sandboxing

### Sandbox Architecture

Each iOS app runs in its own sandboxed container:

```text
/var/mobile/Containers/
├── Bundle/
│   └── Application/
│       └── <UUID>/
│           └── AppName.app/       # Read-only app bundle
│               ├── AppName        # Mach-O binary
│               ├── Info.plist
│               └── Frameworks/
├── Data/
│   └── Application/
│       └── <UUID>/                # App's writable data container
│           ├── Documents/         # User-visible documents
│           ├── Library/
│           │   ├── Preferences/   # UserDefaults (plist files)
│           │   ├── Caches/        # Cache data
│           │   └── Cookies/       # HTTP cookies (Cookies.binarycookies)
│           └── tmp/               # Temporary files
└── Shared/
    └── AppGroup/
        └── <GROUP_UUID>/          # Shared between apps in same group
```

### Sandbox Restrictions

Apps are restricted from:

- Accessing other apps' containers
- Directly accessing system files
- Making arbitrary system calls (restricted by sandbox profile)
- Accessing hardware without entitlements
- Running background processes indefinitely (limited background modes)

**What Apps CAN Do:**

- Read/write within their own container
- Access shared Keychain groups (with matching entitlement)
- Communicate via URL schemes and Universal Links
- Use approved system frameworks and APIs
- Access specific resources with user permission (camera, photos, location)

## Data Protection

### Data Protection Classes

iOS uses hardware-accelerated encryption with multiple protection classes:

| **Protection Class** | **Key Available** | **Use Case** |
| --- | --- | --- |
| `NSFileProtectionComplete` | Only when device unlocked | Most sensitive data |
| `NSFileProtectionCompleteUnlessOpen` | Unlocked, or if file was open | Background file writes |
| `NSFileProtectionCompleteUntilFirstUserAuthentication` | After first unlock | Default for most apps |
| `NSFileProtectionNone` | Always available | Non-sensitive data |

**Encryption Key Hierarchy:**

```text
Hardware Key (UID - burned into Secure Enclave)
  └── Device Key (derived from UID)
        └── Passcode Key (derived from passcode + UID)
              └── Class Keys (one per protection class)
                    └── File Keys (unique per file)
```

**Security Implications:**

- Without user passcode, encrypted data cannot be decrypted (even by Apple)
- `NSFileProtectionComplete` provides the strongest protection
- Many apps use the default class (available after first unlock), which is weaker
- Forensic tools target the window after first unlock

### Keychain

The iOS Keychain is the recommended secure storage mechanism:

**Keychain Accessibility Constants:**

| **Constant** | **Access** |
| --- | --- |
| `kSecAttrAccessibleWhenUnlocked` | Only when unlocked |
| `kSecAttrAccessibleAfterFirstUnlock` | After first unlock (default) |
| `kSecAttrAccessibleAlways` | Always (deprecated, insecure) |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | Unlocked + passcode required |

**Keychain Items:**

- Passwords and tokens
- Cryptographic keys
- Certificates
- Generic secure data

```swift
// Storing a password in the Keychain
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "user@example.com",
    kSecValueData as String: "secret_token".data(using: .utf8)!,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
]
SecItemAdd(query as CFDictionary, nil)
```

**Security Implications:**

- Keychain data is encrypted with the data protection class key
- On a jailbroken device, Keychain items can be dumped (Keychain-Dumper, objection)
- Items with `kSecAttrAccessibleAlways` are accessible even when device is locked
- Items with `ThisDeviceOnly` suffix cannot be transferred via backup

## App Transport Security (ATS)

ATS enforces secure network connections by default (iOS 9+):

```xml
<!-- Info.plist - ATS Configuration -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- INSECURE: Disables ATS globally -->
    <key>NSAllowsArbitraryLoads</key>
    <false/>

    <!-- Exception for specific domain -->
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy-api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
        </dict>
    </dict>
</dict>
```

**ATS Requirements:**

- HTTPS with TLS 1.2 or later
- Forward secrecy cipher suites (ECDHE)
- SHA-256+ certificate signatures
- RSA 2048-bit+ or ECC 256-bit+ keys

**Security Implications:**

- Apps that disable ATS (`NSAllowsArbitraryLoads = true`) weaken transport security
- ATS exceptions for specific domains indicate potential weak points
- App Store review may reject apps with unjustified ATS exceptions

## Certificate Pinning on iOS

### Implementation Methods

**1. NSURLSession Delegate:**

```swift
func urlSession(_ session: URLSession,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                              URLCredential?) -> Void) {
    guard let serverTrust = challenge.protectionSpace.serverTrust,
          let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
        completionHandler(.cancelAuthenticationChallenge, nil)
        return
    }

    let serverCertData = SecCertificateCopyData(certificate) as Data
    let pinnedCertData = loadPinnedCertificate()

    if serverCertData == pinnedCertData {
        completionHandler(.useCredential,
                          URLCredential(trust: serverTrust))
    } else {
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
```

**2. TrustKit (Third-Party Library):**

```swift
let trustKitConfig: [String: Any] = [
    kTSKSwizzleNetworkDelegates: true,
    kTSKPinnedDomains: [
        "api.example.com": [
            kTSKEnforcePinning: true,
            kTSKPublicKeyHashes: [
                "base64EncodedSPKIHash1=",
                "base64EncodedSPKIHash2="
            ]
        ]
    ]
]
TrustKit.initSharedInstance(withConfiguration: trustKitConfig)
```

**Security Implications:**

- Certificate pinning prevents MITM attacks even with compromised CAs
- Must be bypassed for security testing (Frida, objection, SSL Kill Switch)
- Improper pinning implementation may cause app failures when certificates rotate

## Jailbreaking

### What is Jailbreaking?

Jailbreaking is the process of exploiting vulnerabilities in iOS to remove Apple's restrictions:

- **Removes code signing enforcement**: Run unsigned code
- **Gains root access**: Full filesystem access
- **Installs package manager**: Cydia, Sileo, or Zebra for unsigned apps
- **Enables tweaks**: Modify system and app behavior

### Types of Jailbreaks

| **Type** | **Persistence** | **Description** |
| --- | --- | --- |
| **Untethered** | Survives reboot | Rare, most valuable. Exploit runs at boot. |
| **Semi-Tethered** | Needs computer after reboot | Boots normally but loses jailbreak until re-jailbroken via computer. |
| **Semi-Untethered** | Needs app after reboot | Re-jailbreak using an on-device app after reboot. |
| **Tethered** | Requires computer every boot | Must be connected to computer to boot jailbroken. |

### Notable Jailbreaks

- **checkra1n**: Hardware-based (checkm8 BootROM exploit), unpatchable on A5-A11 chips
- **unc0ver**: Software-based, supports various iOS versions
- **Taurine**: Semi-untethered for iOS 14.x
- **Dopamine**: Modern jailbreak for iOS 15-16 (rootless)
- **palera1n**: checkm8-based for iOS 15-17 on A8-A11

### Rootless vs. Rootful Jailbreaks

Modern jailbreaks (iOS 15+) are often "rootless":

- **Rootful** (traditional): Full root filesystem access, system partition modified
- **Rootless**: System partition untouched, modifications in `/var/jb/` or similar

**Security Implications for Testing:**

- Jailbreaking is required for many iOS security testing techniques
- Rootless jailbreaks affect tool compatibility
- Apps may detect jailbroken devices and refuse to run

## Jailbreak Detection

Many apps implement jailbreak detection to protect against runtime manipulation:

### Common Detection Methods

**1. File-Based Checks:**

```swift
let jailbreakPaths = [
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/etc/apt",
    "/var/jb",
    "/private/var/lib/apt/",
    "/usr/lib/TweakInject",
    "/Library/MobileSubstrate/MobileSubstrate.dylib"
]

for path in jailbreakPaths {
    if FileManager.default.fileExists(atPath: path) {
        // Jailbreak detected
    }
}
```

**2. URL Scheme Checks:**

```swift
if UIApplication.shared.canOpenURL(URL(string: "cydia://")!) {
    // Jailbreak detected
}
```

**3. Sandbox Integrity:**

```swift
// Try to write outside sandbox
let testPath = "/private/jailbreak_test.txt"
do {
    try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
    try FileManager.default.removeItem(atPath: testPath)
    // Jailbreak detected (should not be writable)
} catch {
    // Normal - write failed as expected
}
```

**4. Dynamic Library Detection:**

```swift
// Check for injected libraries
let dyldCount = _dyld_image_count()
for i in 0..<dyldCount {
    let imageName = String(cString: _dyld_get_image_name(i))
    if imageName.contains("Substrate") || imageName.contains("TweakInject") {
        // Jailbreak detected
    }
}
```

**5. Fork Check:**

```c
// On non-jailbroken devices, fork() is restricted
pid_t pid = fork();
if (pid >= 0) {
    // Jailbreak detected (fork succeeded)
    if (pid > 0) kill(pid, SIGTERM);
}
```

### Bypassing Jailbreak Detection

All these checks can be bypassed using:

- **Frida**: Hook detection functions and return false
- **objection**: Built-in jailbreak bypass (`ios jailbreak disable`)
- **Liberty Lite / A-Bypass**: Tweaks that hide jailbreak from specific apps
- **Shadow**: Modern jailbreak concealment tweak

## iOS Binary Analysis

### Mach-O Format

iOS apps are compiled to Mach-O (Mach Object) format:

```bash
# Examine Mach-O binary info
otool -h AppBinary              # Header info
otool -L AppBinary              # Linked libraries
otool -l AppBinary              # Load commands
class-dump AppBinary            # Extract Objective-C class info

# Check for PIE (Position Independent Executable)
otool -hv AppBinary | grep PIE

# Check encryption status
otool -l AppBinary | grep -A4 LC_ENCRYPTION_INFO
```

**App Store Encryption (FairPlay DRM):**

- Apps downloaded from App Store are encrypted with FairPlay DRM
- Must be decrypted before analysis
- Tools: `frida-ios-dump`, `CrackerXI+`, `bfdecrypt`

```bash
# Decrypt using frida-ios-dump
python dump.py com.example.app

# Verify decryption (cryptid should be 0)
otool -l decrypted_binary | grep -A4 LC_ENCRYPTION_INFO
```

### Binary Protections

| **Protection** | **Purpose** | **Check** |
| --- | --- | --- |
| PIE | ASLR support | `otool -hv` should show PIE flag |
| ARC | Memory safety | Check for `objc_release`/`objc_retain` |
| Stack Canaries | Stack overflow protection | Check for `__stack_chk_fail` |
| Bitcode | Intermediate representation | Stripped in App Store builds |

## Practical: iOS Security Assessment Basics

### Extracting App Data (Jailbroken Device)

```bash
# Connect to jailbroken device
ssh root@<device_ip>  # Default password: alpine

# Find app container
find /var/mobile/Containers/Data/Application/ -name "com.example.app" 2>/dev/null

# Or use objection
objection -g com.example.app explore
> env   # Show app container paths

# Dump Keychain items
objection -g com.example.app explore
> ios keychain dump

# List property files
> ios plist cat /path/to/preferences.plist

# Check for binary cookies
> ios cookies get
```

### Analyzing Info.plist

```bash
# Extract and read Info.plist from IPA
unzip app.ipa -d extracted/
plutil -p extracted/Payload/AppName.app/Info.plist

# Key items to check:
# - NSAppTransportSecurity (ATS exceptions)
# - CFBundleURLTypes (URL schemes)
# - LSApplicationQueriesSchemes (queried URL schemes)
# - UIBackgroundModes (background capabilities)
# - NSCameraUsageDescription (permission reasons)
```

## Key Takeaways

- iOS security is deeply integrated with Apple hardware (Secure Enclave, Boot ROM)
- Mandatory code signing prevents execution of unsigned code (without jailbreak)
- App sandboxing provides strong isolation between apps
- Data Protection encryption classes determine when data is accessible
- The Keychain is the proper mechanism for storing secrets (not UserDefaults/plist)
- ATS enforces HTTPS by default; exceptions should be scrutinized
- Jailbreaking is often required for thorough iOS security testing
- Jailbreak detection is common but can be bypassed with Frida/objection
- FairPlay DRM must be removed before binary analysis of App Store apps

## Resources

- Apple Platform Security Guide: <https://support.apple.com/guide/security/>
- OWASP MASTG - iOS Testing: <https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/>
- iOS Security Research: <https://github.com/iOS-Repo-Updates/iOS-Security>
- TrustKit: <https://github.com/datatheorem/TrustKit>
- checkra1n: <https://checkra.in/>
- objection: <https://github.com/sensepost/objection>
