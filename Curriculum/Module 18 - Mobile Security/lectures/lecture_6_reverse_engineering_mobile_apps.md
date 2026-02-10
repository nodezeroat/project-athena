# Reverse Engineering Mobile Apps

Reverse engineering is a core skill in mobile security assessment. It allows analysts to understand how an app works internally, identify security mechanisms, discover vulnerabilities, and find hidden functionality. This lecture covers practical techniques for reversing both Android and iOS applications.

## Why Reverse Engineer Mobile Apps?

- **Discover hardcoded secrets**: API keys, credentials, encryption keys
- **Understand security mechanisms**: How authentication, encryption, and anti-tampering work
- **Find hidden functionality**: Debug endpoints, admin features, feature flags
- **Identify vulnerabilities**: Insecure logic, weak cryptography, improper validation
- **Prepare for dynamic analysis**: Know which functions to hook with Frida
- **Assess third-party code**: Understand what SDKs and libraries actually do

## Android Reverse Engineering

### APK Decompilation Workflow

```text
                    ┌─────────┐
                    │  APK    │
                    │ (ZIP)   │
                    └────┬────┘
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
        ┌──────────┐ ┌────────┐ ┌──────────┐
        │ jadx     │ │apktool │ │ dex2jar  │
        │(Java src)│ │(smali) │ │ (JAR)    │
        └──────────┘ └────────┘ └──────────┘
              │          │          │
              ▼          ▼          ▼
        Human-readable  Modifiable  JD-GUI /
        Java/Kotlin     assembly    Procyon
```

### Tool 1: jadx (Preferred for Analysis)

jadx decompiles DEX bytecode directly to Java source code:

```bash
# Command-line decompilation
jadx target.apk -d output/

# Output structure:
output/
├── sources/            # Decompiled Java source
│   └── com/
│       └── example/
│           └── app/
│               ├── MainActivity.java
│               ├── network/
│               │   └── ApiClient.java
│               └── utils/
│                   └── CryptoHelper.java
└── resources/          # Decoded resources
    ├── AndroidManifest.xml
    ├── res/
    └── assets/

# GUI mode (interactive browsing)
jadx-gui target.apk
```

**jadx Features:**

- Decompiles to readable Java code (even from Kotlin sources)
- Decodes resources and manifest
- GUI supports searching, cross-references, and navigation
- Handles ProGuard-obfuscated code (with renamed symbols)

### Tool 2: apktool (Preferred for Modification)

apktool decodes resources and produces smali (Dalvik assembly):

```bash
# Decompile
apktool d target.apk -o output_dir/

# Output structure:
output_dir/
├── AndroidManifest.xml     # Decoded XML
├── smali/                  # Dalvik assembly
│   └── com/example/app/
│       └── MainActivity.smali
├── smali_classes2/         # Additional DEX files
├── res/                    # Decoded resources
├── assets/                 # Raw assets
├── lib/                    # Native libraries
└── original/               # Original signing info

# Rebuild after modification
apktool b output_dir/ -o modified.apk

# Sign the modified APK
keytool -genkey -v -keystore debug.keystore -alias debug \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass password -keypass password \
    -dname "CN=Debug"

apksigner sign --ks debug.keystore --ks-pass pass:password modified.apk

# Or use jarsigner
jarsigner -verbose -keystore debug.keystore \
    -storepass password modified.apk debug

# Zipalign for optimization
zipalign -v 4 modified.apk aligned.apk
```

### Understanding Smali

Smali is the human-readable representation of Dalvik bytecode:

```smali
# Method signature
.method public checkPin(Ljava/lang/String;)Z
    .locals 2
    .param p1, "inputPin"    # p0 = this, p1 = first param

    # Load hardcoded PIN
    const-string v0, "1234"

    # Compare input with hardcoded PIN
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v1

    # Return result
    return v1
.end method
```

**Smali Quick Reference:**

| **Instruction** | **Meaning** |
| --- | --- |
| `const-string vX, "str"` | Load string constant |
| `const/4 vX, 0x0` | Load integer constant |
| `invoke-virtual {args}` | Call virtual method |
| `invoke-static {args}` | Call static method |
| `invoke-direct {args}` | Call constructor or private method |
| `move-result vX` | Store method return value |
| `iget-object vX, vY, Field` | Read instance field |
| `iput-object vX, vY, Field` | Write instance field |
| `if-eqz vX, :label` | Branch if zero/null |
| `if-nez vX, :label` | Branch if not zero/null |
| `return vX` | Return value |
| `return-void` | Return void |

**Smali Types:**

| **Type** | **Java Equivalent** |
| --- | --- |
| `V` | void |
| `Z` | boolean |
| `I` | int |
| `J` | long |
| `F` | float |
| `D` | double |
| `Ljava/lang/String;` | String |
| `[I` | int[] |
| `[Ljava/lang/Object;` | Object[] |

### Practical: Smali Patching

Modify app behavior by editing smali code:

#### Example: Bypass Root Detection

Original smali:

```smali
.method public isDeviceRooted()Z
    .locals 2

    const-string v0, "/system/app/Superuser.apk"
    invoke-static {v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    # ... checks for root indicators ...

    const/4 v1, 0x1    # return true (rooted)
    return v1
.end method
```

Patched smali (always returns false):

```smali
.method public isDeviceRooted()Z
    .locals 1

    const/4 v0, 0x0    # Always return false (not rooted)
    return v0
.end method
```

#### Example: Enable Debug Logging

```smali
# Change: const/4 v0, 0x0  (debug = false)
# To:     const/4 v0, 0x1  (debug = true)
```

### Native Library Analysis

Android apps may include native libraries (C/C++) via JNI:

```bash
# List native libraries in APK
unzip -l target.apk | grep "\.so$"
# lib/arm64-v8a/libnative.so
# lib/armeabi-v7a/libnative.so

# Extract native library
unzip target.apk "lib/arm64-v8a/libnative.so" -d extracted/

# Analyze with Ghidra
ghidraRun  # Import libnative.so, select ARM64 architecture

# Find JNI functions
# They follow naming convention: Java_com_example_app_ClassName_methodName
strings libnative.so | grep "Java_"
```

**Tools for Native Analysis:**

- **Ghidra** (NSA, free): Full decompiler with ARM support
- **IDA Pro** (Hex-Rays, commercial): Industry standard disassembler
- **Binary Ninja**: Modern binary analysis platform
- **radare2/rizin** (free): Command-line reverse engineering framework

### Identifying Obfuscation

**ProGuard/R8 (Default Android Obfuscator):**

- Renames classes, methods, and fields to short names (a, b, c)
- Removes unused code (tree shaking)
- Optimizes bytecode
- Does NOT encrypt strings or hide control flow

```java
// Before ProGuard
public class AuthenticationManager {
    private String encryptPassword(String password) { ... }
}

// After ProGuard
public class a {
    private String a(String str) { ... }
}
```

**DexGuard / DexProtector (Commercial):**

- String encryption
- Class encryption
- Control flow obfuscation
- Native code protection
- Anti-debugging
- Tamper detection

**Identifying Obfuscated Code:**

```bash
# Check for ProGuard mapping file
unzip -l target.apk | grep "mapping"

# Look for characteristic short names in jadx output
# Single-letter class names: a.java, b.java
# Methods like: a(), b(String), c(int, int)

# Check for string encryption (encrypted strings loaded at runtime)
grep -rn "decrypt\|deobfuscate\|decode" output/sources/
```

## iOS Reverse Engineering

### Decrypting App Store Apps

App Store binaries are encrypted with FairPlay DRM:

```bash
# Check encryption status
otool -l AppBinary | grep -A4 LC_ENCRYPTION_INFO
# cryptid 1 = encrypted
# cryptid 0 = decrypted

# Method 1: frida-ios-dump (recommended)
pip install frida-tools
python dump.py com.target.app

# Method 2: CrackerXI+ (on-device, requires jailbreak)
# Install from Cydia/Sileo

# Method 3: bfdecrypt (on-device tweak)
# Install from jailbreak repository
```

### Analyzing Mach-O Binaries

```bash
# Basic binary information
file AppBinary
# AppBinary: Mach-O 64-bit executable arm64

# List linked libraries
otool -L AppBinary
# /usr/lib/libobjc.A.dylib
# /System/Library/Frameworks/UIKit.framework/UIKit
# /System/Library/Frameworks/Security.framework/Security
# @rpath/Alamofire.framework/Alamofire

# Load commands (segments, encryption info, code signature)
otool -l AppBinary

# Symbol table
nm AppBinary | head -50

# String references
strings AppBinary | grep -i "api\|key\|secret\|password\|http"
```

### class-dump (Objective-C)

Extract Objective-C class headers:

```bash
class-dump AppBinary > headers.h

# Output reveals:
# - Class names and hierarchy
# - Method signatures
# - Property declarations
# - Protocol conformance
```

**Example class-dump Output:**

```objc
@interface LoginViewController : UIViewController

@property (nonatomic, strong) UITextField *usernameField;
@property (nonatomic, strong) UITextField *passwordField;
@property (nonatomic, strong) NSString *authToken;

- (void)validateCredentials;
- (BOOL)isJailbroken;
- (void)sendLoginRequest:(NSString *)username password:(NSString *)password;
- (NSString *)encryptData:(NSString *)data withKey:(NSString *)key;

@end
```

This immediately reveals interesting targets for Frida hooking:

- `isJailbroken` - jailbreak detection to bypass
- `encryptData:withKey:` - understand encryption implementation
- `validateCredentials` - authentication logic
- `authToken` - runtime value to extract

### Swift Reverse Engineering

Swift binaries are harder to reverse engineer than Objective-C:

- Swift name mangling makes symbols less readable
- Swift structures are not revealed by class-dump
- Less runtime reflection compared to Objective-C

```bash
# Swift demangling
swift demangle '_$s10TargetApp14LoginViewModelC8validateyyF'
# Output: TargetApp.LoginViewModel.validate() -> ()

# Find Swift symbols
nm AppBinary | grep "_$s" | swift demangle

# Use Ghidra or IDA for Swift binary analysis
```

### Ghidra for iOS Analysis

```text
1. Create new project in Ghidra
2. Import decrypted Mach-O binary
3. Select architecture: AARCH64 (arm64)
4. Auto-analyze
5. Key analysis windows:
   - Symbol Tree: Browse functions and classes
   - Decompiler: View pseudo-C code
   - Defined Strings: Search for interesting strings
   - Cross References: Find who calls a function
```

**Ghidra Analysis Tips:**

- Start with string references to find interesting functions
- Look for `NSLog`, `print`, `debugPrint` calls (information leakage)
- Search for crypto-related functions (`CCCrypt`, `SecKey`, `AES`)
- Identify certificate pinning code (`SecTrust`, `URLSession` delegates)
- Find jailbreak detection (`fileExistsAtPath`, `canOpenURL`)

## Cross-Platform Analysis Techniques

### String Analysis

Strings often reveal the most about an app's functionality:

```bash
# Android
jadx target.apk -d output/
grep -rn "https://\|http://" output/sources/          # API endpoints
grep -rn "password\|secret\|key\|token" output/sources/ # Secrets
grep -rn "debug\|test\|staging" output/sources/         # Debug configs
grep -rn "firebase\|aws\|azure" output/sources/         # Cloud services

# iOS
strings decrypted_binary | sort -u > all_strings.txt
grep -i "api\|endpoint" all_strings.txt
grep -i "key\|secret\|password" all_strings.txt
grep "http" all_strings.txt
```

**Common Findings in Strings:**

- API base URLs (production, staging, development)
- API keys and authentication tokens
- Firebase/AWS/Azure configuration
- Debug flags and feature flags
- Database names and SQL queries
- Error messages revealing internal logic
- Encryption keys or initialization vectors
- Third-party SDK identifiers

### Identifying Security Mechanisms

**Certificate Pinning Indicators:**

```text
Android:
- OkHttp CertificatePinner class
- network_security_config.xml with <pin-set>
- TrustManagerFactory custom implementation
- Custom X509TrustManager

iOS:
- TrustKit library
- URLSession delegate methods
- SecTrustEvaluate calls
- AFSecurityPolicy (AFNetworking)
- AlamofireExtended ServerTrustManager
```

**Root/Jailbreak Detection Indicators:**

```text
Android:
- Checks for su binary
- Checks for Superuser.apk, Magisk
- SafetyNet/Play Integrity API calls
- RootBeer library

iOS:
- FileManager.fileExistsAtPath checks
- canOpenURL for cydia://
- Fork/sandbox escape tests
- IOSSecuritySuite library
```

**Anti-Debugging Indicators:**

```text
Android:
- android.os.Debug.isDebuggerConnected()
- /proc/self/status TracerPid check
- ptrace(PTRACE_TRACEME)

iOS:
- sysctl() P_TRACED flag check
- ptrace(PT_DENY_ATTACH)
- getppid() check
- Exception port monitoring
```

### Identifying Cryptographic Usage

```text
Look for:
- AES/DES/3DES constants and S-boxes
- RSA key generation
- HMAC computation
- Base64 encoding/decoding near crypto operations
- Key derivation (PBKDF2, scrypt, Argon2)
- Random number generation (SecureRandom vs insecure)

Common Issues:
- ECB mode usage (patterns visible in ciphertext)
- Hardcoded IVs (initialization vectors)
- Hardcoded encryption keys
- Insufficient key derivation iterations
- Custom crypto implementations
```

## Practical Walkthrough: Reversing an Android App

### Step-by-Step Analysis

```bash
# 1. Pull APK from device
adb shell pm path com.target.app
# package:/data/app/com.target.app-xxxx/base.apk
adb pull /data/app/com.target.app-xxxx/base.apk target.apk

# 2. Quick overview with aapt
aapt dump badging target.apk | grep -E "package|permission|activity"

# 3. Decompile with jadx
jadx target.apk -d target_output/

# 4. Analyze AndroidManifest.xml
cat target_output/resources/AndroidManifest.xml
# Look for:
# - android:debuggable="true"
# - android:allowBackup="true"
# - exported components
# - custom permissions
# - network security config

# 5. Map the application
find target_output/sources/ -name "*.java" | head -30
# Identify packages:
# - com.target.app.ui/         -> UI layer
# - com.target.app.network/    -> API communication
# - com.target.app.model/      -> Data models
# - com.target.app.security/   -> Security mechanisms
# - com.target.app.utils/      -> Utility functions

# 6. Search for interesting code
grep -rn "SharedPreferences" target_output/sources/    # Data storage
grep -rn "WebView" target_output/sources/              # WebView usage
grep -rn "SQLiteDatabase" target_output/sources/       # Database usage
grep -rn "Log\." target_output/sources/                # Logging
grep -rn "getExternalStorage" target_output/sources/   # External storage
grep -rn "MODE_WORLD_" target_output/sources/          # Insecure file modes

# 7. Identify targets for dynamic instrumentation
grep -rn "isRooted\|rootDetect" target_output/sources/
grep -rn "sslPinning\|certificatePinner" target_output/sources/
grep -rn "encrypt\|decrypt\|cipher" target_output/sources/
```

## Key Takeaways

- Reverse engineering is a prerequisite for effective dynamic analysis
- jadx provides the best readability for Android apps; apktool enables modification
- iOS apps require decryption (FairPlay removal) before analysis
- String analysis is often the fastest path to discovering secrets and endpoints
- Obfuscation slows down analysis but does not prevent it
- Identify security mechanisms (pinning, root detection, anti-debug) during static analysis to prepare targeted Frida hooks
- Native code (JNI libraries, iOS frameworks) requires binary analysis tools like Ghidra
- Understanding smali enables patching Android apps without source code
- class-dump reveals the entire Objective-C API surface of iOS apps

## Resources

- jadx: <https://github.com/skylot/jadx>
- apktool: <https://apktool.org/>
- Ghidra: <https://ghidra-sre.org/>
- class-dump: <https://github.com/nygard/class-dump>
- OWASP MASTG - Reverse Engineering: <https://mas.owasp.org/MASTG/techniques/>
- Android RE 101: <https://www.ragingrock.com/AndroidAppRE/>
- iOS App Reverse Engineering: <https://github.com/iosre/iOSAppReverseEngineering>
- Frida iOS Dump: <https://github.com/AloneMonkey/frida-ios-dump>
