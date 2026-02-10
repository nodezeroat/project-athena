#import "../../../typst-athena-slides-template/1.0.1/src/lib.typ": *

#show: athena-theme.with(
  font: "Berkeley Mono",
  config-info(
    title: [Module 18: Mobile Security],
    subtitle: [Android Security],
    authors: [*Marcel Schnideritsch*],
    extra: [],
    footer: [Module 18 - Mobile Security],
  ),
  config-common(
    handout: false,
  ),
)

#title-slide()

#section-slide(title: "Android Security Model")

#slide(title: "Core Security Principles")[
  1. *Defense in Depth*: Multiple overlapping security layers
  2. *Least Privilege*: Apps only get permissions they need
  3. *Isolation by Default*: Apps sandboxed from each other
  4. *Open Platform*: Security through transparency

  *Layers:*
  - Linux kernel process isolation
  - SELinux mandatory access control
  - Seccomp-BPF system call filtering
  - App permission model
  - Google Play Protect scanning
]

#slide(title: "Application Sandboxing")[
  Each app gets a unique Linux UID at install time:

  ```text
  App A (UID 10001) → /data/data/com.app.a/
  App B (UID 10002) → /data/data/com.app.b/
  App C (UID 10003) → /data/data/com.app.c/
  ```

  - Apps cannot access each other's files (permissions `0700`)
  - Separate process per app
  - SELinux enforces security contexts on all processes
  - Even root is restricted by SELinux policies
]

#section-slide(title: "Permission Model")

#slide(title: "Permission Types")[
  *Normal* (auto-granted):
  - `INTERNET`, `BLUETOOTH`, `SET_WALLPAPER`

  *Dangerous* (user approval required):
  - Camera, Location, Microphone, Contacts, SMS, Storage

  *Signature* (same signing key only):
  - Inter-app communication within developer's suite

  *Special* (require settings screen):
  - `SYSTEM_ALERT_WINDOW`, `REQUEST_INSTALL_PACKAGES`
]

#slide(title: "Runtime Permissions (Android 6.0+)")[
  1. App declares permission in manifest
  2. At runtime: `checkSelfPermission(CAMERA)`
  3. If not granted → `requestPermissions(CAMERA)`
  4. System shows dialog to user
  5. User grants or denies
  6. App receives callback with result

  *Security Implications:*
  - Apps targeting SDK < 23 get all permissions at install
  - Users can revoke permissions anytime in Settings
  - Apps should handle denial gracefully (but often don't)
]

#section-slide(title: "AndroidManifest.xml")

#slide(title: "Security-Critical Manifest Flags")[
  #table(
    columns: (auto, auto, auto),
    inset: 6pt,
    stroke: 0.5pt,
    align: left,
    [*Flag*], [*Secure Value*], [*Risk if Wrong*],
    [`debuggable`], [`false`], [Allows debugging, bypass security],
    [`allowBackup`], [`false`], [Data extractable via adb backup],
    [`exported`], [`false`], [Component accessible to all apps],
    [`usesCleartextTraffic`], [`false`], [Allows HTTP traffic],
    [`networkSecurityConfig`], [Custom], [Controls certificate trust],
  )

  *The manifest is the FIRST file to analyze in any assessment.*
]

#slide(title: "Exported Components")[
  Components accessible to other apps:

  ```xml
  <!-- Exported activity - any app can launch -->
  <activity android:name=".AdminActivity"
            android:exported="true" />

  <!-- Exported provider - any app can query -->
  <provider android:name=".UserProvider"
            android:authorities="com.app.provider"
            android:exported="true" />
  ```

  *Test with ADB:*
  ```bash
  adb shell am start -n com.app/.AdminActivity
  adb shell content query \
    --uri content://com.app.provider/users
  ```
]

#section-slide(title: "Data Storage")

#slide(title: "Storage Locations")[
  *Internal Storage* (`/data/data/<pkg>/`):
  - `shared_prefs/` - SharedPreferences (XML key-value)
  - `databases/` - SQLite databases
  - `files/` - General files
  - Protected by Linux permissions (app-only access)

  *External Storage* (`/sdcard/`):
  - Readable by all apps (with permission)
  - *Never store sensitive data here*

  *Android Keystore*:
  - Hardware-backed key storage (TEE/StrongBox)
  - Keys bound to user authentication
]

#slide(title: "Common Data Storage Vulnerabilities")[
  *Plaintext SharedPreferences:*
  ```xml
  <map>
    <string name="password">P@ssw0rd123</string>
    <string name="api_key">sk-abc123</string>
  </map>
  ```

  *Extract with root:*
  ```bash
  adb shell su -c "cat /data/data/com.app/ \
    shared_prefs/settings.xml"
  ```

  *Fix:* Use `EncryptedSharedPreferences` or Android Keystore
]

#section-slide(title: "Network Security")

#slide(title: "Network Security Configuration")[
  Android 7.0+ declarative network security:

  ```xml
  <network-security-config>
    <!-- Block cleartext globally -->
    <base-config cleartextTrafficPermitted="false">
      <trust-anchors>
        <certificates src="system" />
      </trust-anchors>
    </base-config>

    <!-- Certificate pinning -->
    <domain-config>
      <domain>secure.example.com</domain>
      <pin-set>
        <pin digest="SHA-256">base64Hash=</pin>
      </pin-set>
    </domain-config>
  </network-security-config>
  ```
]

#slide(title: "Traffic Interception Challenges")[
  *Android 7+:*
  - User-installed CA certificates NOT trusted by default
  - Burp Suite / mitmproxy certs rejected by apps

  *Bypass methods:*
  1. Modify `network_security_config` (repackaging)
  2. Install CA as system cert (requires root)
  3. Frida SSL pinning bypass (Lecture 7)

  *Android 9+:*
  - Cleartext traffic blocked by default
  - Apps must explicitly opt-in to HTTP
]

#section-slide(title: "Component Vulnerabilities")

#slide(title: "Activity Vulnerabilities")[
  *Exported Activities:*
  ```bash
  # Launch without authentication
  adb shell am start -n com.app/.AdminActivity

  # Send crafted data
  adb shell am start -n com.app/.TransferActivity \
    --es "recipient" "attacker" \
    --ei "amount" 10000
  ```

  *Risks:*
  - Bypass authentication (launch admin screens directly)
  - Task hijacking (inject into another app's task stack)
  - Intent redirection (forward without validation)
]

#slide(title: "Content Provider Vulnerabilities")[
  *SQL Injection:*
  ```bash
  adb shell content query \
    --uri "content://com.app.provider/users" \
    --where "1=1) OR 1=1--"
  ```

  *Path Traversal:*
  ```bash
  adb shell content read \
    --uri "content://com.app.provider/../../../etc/hosts"
  ```

  *Fix:*
  - Set `exported="false"` when not needed
  - Use parameterized queries
  - Validate all URI paths
]

#section-slide(title: "Practical: ADB")

#slide(title: "Essential ADB Commands")[
  ```bash
  # List devices
  adb devices

  # Package management
  adb shell pm list packages -3   # Third-party
  adb shell pm path com.example   # APK location
  adb pull /data/app/.../base.apk # Extract APK

  # App data (debug or root)
  adb shell run-as com.app ls shared_prefs/
  adb backup -f backup.ab com.app

  # Logging (look for data leaks)
  adb logcat | grep -i "password\|token\|key"

  # Port forwarding (for Burp/Frida)
  adb forward tcp:8080 tcp:8080
  ```
]

#slide(title: "Common Logging Vulnerabilities")[
  *Sensitive data often leaked in logs:*
  ```bash
  adb logcat --pid=$(adb shell pidof com.app)
  ```

  Commonly found:
  - Authentication tokens
  - API keys and secrets
  - User credentials
  - Personal data (PII)
  - SQL queries with user data

  *Fix:* Remove all `Log.d()` / `Log.i()` calls with sensitive data in production builds. Use ProGuard to strip log calls.
]

#section-slide(title: "Key Takeaways")

#slide(title: "Summary")[
  - Android security combines Linux isolation, SELinux, and permissions
  - `AndroidManifest.xml` is the first analysis target
  - Exported components expand the attack surface
  - Insecure data storage (plaintext SharedPreferences) is extremely common
  - Network security config controls CA trust and pinning
  - ADB is essential for Android security testing
  - Understanding Android internals enables effective Frida instrumentation
]

#title-slide(
  author: [Marcel Schnideritsch],
  title: [Android Security],
  subtitle: [Module 18 - Mobile Security],
)
