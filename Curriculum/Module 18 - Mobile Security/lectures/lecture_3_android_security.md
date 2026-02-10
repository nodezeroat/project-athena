# Android Security

Android's security model is built on multiple layers of defense, from the Linux kernel up through the application framework. This lecture examines Android-specific security mechanisms, common vulnerabilities, and practical techniques for security assessment.

## Android Security Model

Android's security relies on several core principles:

1. **Defense in Depth**: Multiple overlapping security layers
2. **Least Privilege**: Apps only get permissions they need
3. **Isolation by Default**: Apps are sandboxed from each other
4. **Open Platform**: Security through transparency and community review

## Application Sandboxing

Every Android app runs in its own sandbox, enforced at multiple levels:

### UID-Based Isolation

Each app is assigned a unique Linux UID at install time:

```text
App A (UID 10001) ──► Own process, own files in /data/data/com.app.a/
App B (UID 10002) ──► Own process, own files in /data/data/com.app.b/
App C (UID 10003) ──► Own process, own files in /data/data/com.app.c/
```

- Apps cannot access each other's files by default
- File permissions are set to `0700` (owner-only)
- Apps sharing the same signing key can request `sharedUserId` to share data

### SELinux Enforcement

Android uses SELinux in enforcing mode since Android 5.0:

- **Type Enforcement**: Every process and file has a security context
- **Policy Rules**: Explicitly define what each context can access
- **Denial by Default**: Anything not explicitly allowed is denied

```text
# Example SELinux context for an app
u:r:untrusted_app:s0:c512,c768

# System service context
u:r:system_server:s0
```

**Security Implications:**

- Even root processes are restricted by SELinux policies
- Rooting a device may not bypass SELinux (requires policy modification)
- Custom ROMs may have weaker SELinux policies

### Seccomp-BPF

System call filtering restricts which kernel APIs apps can invoke:

- Blocks dangerous syscalls (e.g., `mount`, `reboot`, `kexec_load`)
- Applied to the Zygote process (parent of all app processes)
- Violations result in process termination (SIGKILL)

## Android Permission Model

### Permission Types

**1. Normal Permissions** (granted automatically):

- Low-risk access (e.g., `INTERNET`, `BLUETOOTH`, `SET_WALLPAPER`)
- No user prompt required
- Declared in manifest, granted at install

**2. Dangerous Permissions** (require user approval):

- Access to sensitive data or device features
- Grouped into permission groups:

| **Permission Group** | **Permissions** |
| --- | --- |
| Calendar | READ_CALENDAR, WRITE_CALENDAR |
| Camera | CAMERA |
| Contacts | READ_CONTACTS, WRITE_CONTACTS, GET_ACCOUNTS |
| Location | ACCESS_FINE_LOCATION, ACCESS_COARSE_LOCATION |
| Microphone | RECORD_AUDIO |
| Phone | READ_PHONE_STATE, CALL_PHONE, READ_CALL_LOG |
| SMS | SEND_SMS, RECEIVE_SMS, READ_SMS |
| Storage | READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE |

**3. Signature Permissions:**

- Granted only to apps signed with the same key as the declaring app
- Used for inter-app communication within a developer's app suite

**4. Special Permissions:**

- Require special grant procedures (settings screen)
- Examples: `SYSTEM_ALERT_WINDOW`, `WRITE_SETTINGS`, `REQUEST_INSTALL_PACKAGES`

### Runtime Permissions (Android 6.0+)

Starting with Android 6.0 (Marshmallow), dangerous permissions are requested at runtime:

```text
App declares: <uses-permission android:name="android.permission.CAMERA" />

At runtime:
1. App calls checkSelfPermission(CAMERA)
2. If not granted → requestPermissions(CAMERA)
3. System shows dialog to user
4. User grants or denies
5. App receives callback with result
```

**Security Implications:**

- Apps on older target SDK versions (< 23) get all permissions at install
- Users can revoke permissions at any time in Settings
- Apps should handle permission denial gracefully (but often don't)

## AndroidManifest.xml

The manifest is the most important file for security assessment. It declares:

### Components

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">

    <!-- Permissions requested -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />

    <application
        android:allowBackup="true"
        android:debuggable="false"
        android:networkSecurityConfig="@xml/network_security_config"
        android:usesCleartextTraffic="false">

        <!-- Activities (UI screens) -->
        <activity android:name=".MainActivity"
                  android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity android:name=".AdminActivity"
                  android:exported="false" />

        <!-- Services (background tasks) -->
        <service android:name=".SyncService"
                 android:exported="false" />

        <!-- Broadcast Receivers -->
        <receiver android:name=".BootReceiver"
                  android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>

        <!-- Content Providers -->
        <provider android:name=".UserProvider"
                  android:authorities="com.example.app.provider"
                  android:exported="true"
                  android:readPermission="com.example.app.READ_DATA" />
    </application>
</manifest>
```

### Security-Critical Manifest Flags

| **Flag** | **Secure Value** | **Risk if Misconfigured** |
| --- | --- | --- |
| `android:debuggable` | `false` | Allows debugging, bypassing security |
| `android:allowBackup` | `false` | Data extractable via `adb backup` |
| `android:exported` | `false` (default for no intent-filter) | Component accessible to other apps |
| `android:usesCleartextTraffic` | `false` | Allows HTTP (unencrypted) traffic |
| `android:networkSecurityConfig` | Custom config | Controls certificate trust |

## Data Storage on Android

### Storage Locations and Security

**1. Internal Storage** (`/data/data/<package>/`):

```text
/data/data/com.example.app/
├── shared_prefs/          # SharedPreferences (XML key-value)
│   └── settings.xml
├── databases/             # SQLite databases
│   └── app.db
├── files/                 # General files
├── cache/                 # Cache files
└── no_backup/             # Excluded from backups
```

- Protected by Linux permissions (accessible only to the app)
- Root access or device backup can extract this data
- **Common vulnerability**: Storing sensitive data in plaintext SharedPreferences

**2. External Storage** (`/sdcard/` or `/storage/emulated/0/`):

- Readable by all apps with `READ_EXTERNAL_STORAGE`
- No per-app isolation (scoped storage changes this in Android 10+)
- **Never store sensitive data here**

**3. SharedPreferences:**

```xml
<!-- /data/data/com.example.app/shared_prefs/credentials.xml -->
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="username">admin</string>
    <string name="password">P@ssw0rd123</string>  <!-- INSECURE! -->
    <string name="api_key">sk-abc123def456</string>  <!-- INSECURE! -->
</map>
```

**Secure Alternative**: Use Android Keystore or EncryptedSharedPreferences:

```kotlin
// EncryptedSharedPreferences (Jetpack Security library)
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val sharedPreferences = EncryptedSharedPreferences.create(
    context, "secret_prefs", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
```

**4. SQLite Databases:**

- Stored in `/data/data/<package>/databases/`
- Unencrypted by default
- Can be extracted via backup or root access
- Use SQLCipher for database encryption

**5. Android Keystore:**

- Hardware-backed key storage (if TEE/StrongBox available)
- Keys can be bound to user authentication (biometric/PIN)
- Supports key attestation to verify hardware backing
- Best practice for storing cryptographic keys

## Network Security Configuration

Android 7.0+ supports declarative network security configuration:

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <!-- Block cleartext (HTTP) traffic globally -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>

    <!-- Allow user-installed CA certificates for specific domain (testing) -->
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </domain-config>

    <!-- Certificate pinning -->
    <domain-config>
        <domain includeSubdomains="true">secure.example.com</domain>
        <pin-set expiration="2025-12-31">
            <pin digest="SHA-256">base64EncodedPublicKeyHash=</pin>
            <pin digest="SHA-256">backupKeyHash=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**Security Implications:**

- Apps targeting Android 9+ block cleartext traffic by default
- Apps targeting Android 7+ do NOT trust user-installed CA certificates by default
- This means Burp Suite/mitmproxy certificates are not trusted without modification
- Certificate pinning must be bypassed for traffic interception during testing

## Android App Components and Attack Surface

### Activities

Activities represent UI screens. Security concerns:

- **Exported Activities**: Can be launched by other apps
- **Task Hijacking**: Malicious app can insert itself into another app's task stack
- **Intent Redirection**: Forwarding Intents without validation

```bash
# Launch an exported activity via ADB
adb shell am start -n com.example.app/.AdminActivity
adb shell am start -n com.example.app/.DeepLinkActivity \
    -d "https://example.com/reset?token=leaked"
```

### Services

Services run background operations. Security concerns:

- **Exported Services**: Can be bound/started by other apps
- **Messenger-based IPC**: Message handling vulnerabilities
- **Pending Intents**: Can be hijacked if mutable

### Broadcast Receivers

Handle system-wide broadcasts. Security concerns:

- **Ordered Broadcasts**: Higher-priority receiver can abort broadcast
- **Sticky Broadcasts** (deprecated): Data persists and is accessible to all
- **Exported Receivers**: Any app can send broadcasts to them

### Content Providers

Share structured data. Security concerns:

- **SQL Injection**: Through `query()`, `update()`, `delete()` methods
- **Path Traversal**: Through `openFile()` method
- **Permission Bypass**: Misconfigured `grantUriPermissions`

```bash
# Query an exported content provider
adb shell content query --uri content://com.example.app.provider/users
```

## Common Android Vulnerabilities

### 1. Insecure Data Storage

```bash
# Extract SharedPreferences from a rooted device
adb shell su -c "cat /data/data/com.example.app/shared_prefs/settings.xml"

# Extract SQLite database
adb shell su -c "cp /data/data/com.example.app/databases/app.db /sdcard/"
adb pull /sdcard/app.db
sqlite3 app.db "SELECT * FROM users;"
```

### 2. Insecure Logging

```bash
# Monitor app logs for sensitive data leakage
adb logcat | grep -i "password\|token\|key\|secret"

# Filter by specific app
adb logcat --pid=$(adb shell pidof com.example.app)
```

Common leaks in logs:

- Authentication tokens
- API keys
- User credentials
- Personal data (PII)

### 3. Insecure WebView Configuration

```java
// INSECURE WebView configuration
WebView webView = new WebView(this);
webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowFileAccess(true);      // Can read local files
webView.getSettings().setAllowUniversalAccessFromFileURLs(true); // File:// can access any origin
webView.addJavascriptInterface(new JsBridge(), "Android"); // JS can call Java methods
webView.loadUrl(untrustedUrl); // Loading untrusted content
```

**Attacks:**

- **JavaScript Interface Abuse**: Call Java methods from injected JavaScript
- **File Scheme Access**: Read local files through WebView
- **Cross-origin Access**: Bypass same-origin policy via file:// URLs

### 4. Intent Vulnerabilities

```bash
# Send a crafted Intent to an exported component
adb shell am broadcast -a com.example.app.ACTION_RESET \
    --es "email" "attacker@evil.com"

# Start an exported activity with crafted data
adb shell am start -n com.example.app/.TransferActivity \
    --es "recipient" "attacker" --ei "amount" 10000
```

### 5. Clipboard Data Leakage

- Sensitive data copied to clipboard is accessible to all apps
- Clipboard history may persist across app switches
- Android 12+ shows a toast when clipboard is accessed

## Practical: ADB for Security Testing

### Essential ADB Commands

```bash
# Device connection
adb devices                    # List connected devices
adb connect <ip>:<port>        # Connect to device over network
adb shell                      # Open shell on device

# Package management
adb shell pm list packages              # List all packages
adb shell pm list packages -3           # Third-party apps only
adb shell pm path com.example.app       # Find APK path
adb shell dumpsys package com.example.app  # Package details

# APK extraction
adb shell pm path com.example.app       # Get APK path
adb pull /data/app/.../base.apk         # Pull APK to host

# App data
adb shell run-as com.example.app ls files/  # Access app files (debug apps)
adb backup -f backup.ab com.example.app     # Backup app data
adb shell su -c "ls /data/data/com.example.app/"  # Root access

# Activity Manager
adb shell am start -n com.example.app/.MainActivity
adb shell am startservice -n com.example.app/.MyService
adb shell am broadcast -a com.example.CUSTOM_ACTION

# Logging
adb logcat -c                  # Clear logs
adb logcat -s "TAG_NAME"       # Filter by tag
adb logcat *:E                 # Errors only

# Network
adb forward tcp:8080 tcp:8080  # Port forwarding
adb reverse tcp:8080 tcp:8080  # Reverse port forwarding
```

### Installing Burp CA on Android

For intercepting HTTPS traffic on Android 7+:

```bash
# Method 1: Network Security Config modification (repackaging)
# Add user certificates to trust anchors in the app

# Method 2: System CA installation (requires root)
# Convert Burp certificate to Android format
openssl x509 -inform DER -in burp-cert.der -out burp-cert.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp-cert.pem | head -1)
cp burp-cert.pem "$HASH.0"

# Push to system certificate store
adb root
adb remount
adb push "$HASH.0" /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/"$HASH.0"
adb reboot

# Method 3: Frida SSL pinning bypass (covered in Lecture 7)
```

## Key Takeaways

- Android's security model combines Linux process isolation, SELinux, and a permission framework
- The AndroidManifest.xml is the first file to analyze in any security assessment
- Exported components (Activities, Services, Receivers, Providers) expand the attack surface
- Insecure data storage (plaintext SharedPreferences, unencrypted databases) is extremely common
- Network security configuration controls CA trust and certificate pinning
- ADB is an essential tool for Android security testing
- Understanding Android internals is prerequisite for effective dynamic instrumentation with Frida

## Resources

- Android Security Best Practices: <https://developer.android.com/topic/security/best-practices>
- OWASP MASTG - Android Testing: <https://mas.owasp.org/MASTG/Android/0x05a-Platform-Overview/>
- Android KeyStore System: <https://developer.android.com/training/articles/keystore>
- Network Security Configuration: <https://developer.android.com/training/articles/security-config>
- ADB Documentation: <https://developer.android.com/tools/adb>
- Android App Components: <https://developer.android.com/guide/components/fundamentals>
