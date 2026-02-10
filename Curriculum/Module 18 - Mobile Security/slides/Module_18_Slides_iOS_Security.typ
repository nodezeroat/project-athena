#import "../../../typst-athena-slides-template/1.0.1/src/lib.typ": *

#show: athena-theme.with(
  font: "Berkeley Mono",
  config-info(
    title: [Module 18: Mobile Security],
    subtitle: [iOS Security],
    authors: [*Marcel Schnideritsch*],
    extra: [],
    footer: [Module 18 - Mobile Security],
  ),
  config-common(
    handout: false,
  ),
)

#title-slide()

#section-slide(title: "iOS Security Model")

#slide(title: "Core Security Principles")[
  1. *Hardware Root of Trust*: Security anchored in silicon
  2. *Mandatory Code Signing*: All code must be signed
  3. *App Sandboxing*: Strict per-app isolation
  4. *Data Protection*: Hardware encryption tied to credentials
  5. *Controlled Distribution*: App Store review as security gate

  Apple's tight hardware-software integration enables security features not possible on open platforms.
]

#slide(title: "Code Signing Chain")[
  ```text
  Apple Root CA
    └── Apple Intermediate CA
          └── Developer Certificate
                └── App Binary Signature
                      └── Provisioning Profile
                            ├── Allowed UDIDs
                            ├── Entitlements
                            └── Expiration Date
  ```

  *Every executable must be signed:*
  - Apple-signed: System apps
  - Developer-signed: App Store apps
  - Enterprise-signed: Internal distribution
  - Ad-hoc: Limited testing (specific devices)
]

#slide(title: "Entitlements")[
  Key-value pairs granting specific capabilities:

  #table(
    columns: (auto, auto),
    inset: 6pt,
    stroke: 0.5pt,
    align: left,
    [*Entitlement*], [*Purpose*],
    [`keychain-access-groups`], [Keychain sharing between apps],
    [`application-groups`], [Shared container between apps],
    [`aps-environment`], [Push notification environment],
    [`associated-domains`], [Universal Links / App Clips],
    [`networking.vpn.api`], [VPN capabilities],
  )

  Entitlements define the security boundary of an app.
]

#section-slide(title: "Sandboxing & Data Protection")

#slide(title: "App Sandbox")[
  ```text
  /var/mobile/Containers/
  ├── Bundle/Application/<UUID>/
  │   └── AppName.app/        # Read-only
  ├── Data/Application/<UUID>/
  │   ├── Documents/           # User data
  │   ├── Library/
  │   │   ├── Preferences/     # UserDefaults
  │   │   ├── Caches/
  │   │   └── Cookies/
  │   └── tmp/
  └── Shared/AppGroup/<UUID>/  # Shared data
  ```

  Apps cannot access other apps' containers, system files, or hardware without entitlements.
]

#slide(title: "Data Protection Classes")[
  #table(
    columns: (auto, auto, auto),
    inset: 6pt,
    stroke: 0.5pt,
    align: left,
    [*Class*], [*Key Available*], [*Use Case*],
    [Complete], [Only when unlocked], [Most sensitive data],
    [CompleteUnlessOpen], [Unlocked or file open], [Background writes],
    [UntilFirstUserAuth], [After first unlock], [Default for apps],
    [None], [Always], [Non-sensitive data],
  )

  *Key Hierarchy:*
  - Hardware Key (UID) → Device Key → Passcode Key → Class Keys → File Keys
  - Without passcode, encrypted data cannot be decrypted (even by Apple)
]

#slide(title: "iOS Keychain")[
  Recommended secure storage mechanism:

  #table(
    columns: (auto, auto),
    inset: 6pt,
    stroke: 0.5pt,
    align: left,
    [*Accessibility*], [*Access*],
    [`WhenUnlocked`], [Only when device unlocked],
    [`AfterFirstUnlock`], [After first unlock (default)],
    [`WhenPasscodeSetThisDeviceOnly`], [Unlocked + passcode required],
  )

  *On jailbroken devices, Keychain items can be dumped:*
  ```bash
  objection -g com.app explore
  > ios keychain dump
  ```
]

#section-slide(title: "App Transport Security")

#slide(title: "ATS (App Transport Security)")[
  Enforces secure network connections (iOS 9+):

  *Requirements:*
  - HTTPS with TLS 1.2+
  - Forward secrecy cipher suites (ECDHE)
  - SHA-256+ certificate signatures
  - RSA 2048-bit+ or ECC 256-bit+ keys

  *Info.plist Exception (INSECURE):*
  ```xml
  <key>NSAllowsArbitraryLoads</key>
  <true/>  <!-- Disables ATS globally -->
  ```

  Look for ATS exceptions during assessment - they indicate weak points.
]

#section-slide(title: "Jailbreaking")

#slide(title: "What is Jailbreaking?")[
  Exploiting iOS vulnerabilities to remove Apple's restrictions:
  - Removes code signing enforcement
  - Gains root filesystem access
  - Enables package managers (Cydia, Sileo)
  - Allows system and app modification

  #table(
    columns: (auto, auto),
    inset: 6pt,
    stroke: 0.5pt,
    align: left,
    [*Type*], [*Persistence*],
    [Untethered], [Survives reboot (rare)],
    [Semi-Untethered], [Re-jailbreak via on-device app],
    [Semi-Tethered], [Re-jailbreak via computer],
    [Tethered], [Requires computer every boot],
  )
]

#slide(title: "Jailbreak Detection Methods")[
  *1. File-Based Checks:*
  - `/Applications/Cydia.app`, `/usr/sbin/sshd`, `/var/jb`

  *2. URL Scheme Checks:*
  - `canOpenURL("cydia://")`

  *3. Sandbox Integrity:*
  - Try writing outside sandbox

  *4. Dynamic Library Detection:*
  - Check for `MobileSubstrate`, `TweakInject`

  *5. Fork Check:*
  - `fork()` restricted on non-jailbroken devices

  *All of these can be bypassed with Frida or objection!*
]

#section-slide(title: "iOS Binary Analysis")

#slide(title: "Mach-O Analysis")[
  ```bash
  # Binary info
  otool -h AppBinary
  otool -L AppBinary        # Linked libraries
  class-dump AppBinary      # Objective-C headers

  # Check protections
  otool -hv AppBinary | grep PIE  # ASLR
  otool -l AppBinary | grep -A4 LC_ENCRYPTION_INFO

  # Strings
  strings AppBinary | grep -i "api\|key\|secret"
  ```

  *FairPlay DRM:* App Store apps are encrypted. Use `frida-ios-dump` to decrypt before analysis.
]

#slide(title: "class-dump Output")[
  Reveals the entire Objective-C API surface:

  ```objc
  @interface LoginViewController : UIViewController
  @property (nonatomic, strong) NSString *authToken;
  - (void)validateCredentials;
  - (BOOL)isJailbroken;
  - (void)sendLoginRequest:(NSString *)user
                  password:(NSString *)pass;
  - (NSString *)encryptData:(NSString *)data
                    withKey:(NSString *)key;
  @end
  ```

  Immediately reveals targets for Frida hooking:
  - `isJailbroken` → bypass
  - `encryptData:withKey:` → intercept
  - `authToken` → extract at runtime
]

#section-slide(title: "Practical Assessment")

#slide(title: "iOS Assessment Basics")[
  ```bash
  # Connect to jailbroken device
  ssh root@<device_ip>  # Default: alpine

  # Use objection for exploration
  objection -g com.app explore

  > env                    # App container paths
  > ios keychain dump      # Keychain contents
  > ios plist cat <path>   # Read plist files
  > ios cookies get        # HTTP cookies
  ```

  *Key files to check:*
  - `Info.plist` → ATS exceptions, URL schemes, permissions
  - `embedded.mobileprovision` → entitlements
  - Keychain → stored credentials
  - SQLite databases → sensitive data
]

#section-slide(title: "Key Takeaways")

#slide(title: "Summary")[
  - iOS security is deeply integrated with Apple hardware
  - Mandatory code signing prevents unsigned code execution
  - App sandboxing provides strong inter-app isolation
  - Data Protection classes determine when data is accessible
  - Keychain is the proper mechanism for secrets (not UserDefaults)
  - ATS enforces HTTPS by default; exceptions are red flags
  - Jailbreaking is often required for thorough iOS testing
  - Jailbreak detection is common but always bypassable
  - FairPlay DRM must be removed before binary analysis
]

#title-slide(
  author: [Marcel Schnideritsch],
  title: [iOS Security],
  subtitle: [Module 18 - Mobile Security],
)
