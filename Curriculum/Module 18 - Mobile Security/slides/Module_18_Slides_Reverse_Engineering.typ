#import "../../../typst-athena-slides-template/1.0.1/src/lib.typ": *

#show: athena-theme.with(
  font: "Berkeley Mono",
  config-info(
    title: [Module 18: Mobile Security],
    subtitle: [Reverse Engineering Mobile Apps],
    authors: [*Marcel Schnideritsch*],
    extra: [],
    footer: [Module 18 - Mobile Security],
  ),
  config-common(
    handout: false,
  ),
)

#title-slide()

#section-slide(title: "Why Reverse Engineer?")

#slide(title: "Goals of Mobile Reverse Engineering")[
  - *Discover hardcoded secrets*: API keys, credentials, encryption keys
  - *Understand security mechanisms*: How auth, encryption, anti-tamper work
  - *Find hidden functionality*: Debug endpoints, admin features, flags
  - *Identify vulnerabilities*: Insecure logic, weak crypto, bad validation
  - *Prepare for dynamic analysis*: Know which functions to hook with Frida
  - *Assess third-party code*: Understand what SDKs actually do
]

#section-slide(title: "Android Reverse Engineering")

#slide(title: "Decompilation Workflow")[
  ```text
               ┌─────────┐
               │  APK     │
               │ (ZIP)    │
               └────┬─────┘
                    │
         ┌──────────┼──────────┐
         ▼          ▼          ▼
    ┌─────────┐ ┌────────┐ ┌─────────┐
    │  jadx   │ │apktool │ │ dex2jar │
    │(Java)   │ │(smali) │ │ (JAR)   │
    └─────────┘ └────────┘ └─────────┘
         │          │          │
         ▼          ▼          ▼
    Readable    Modifiable   JD-GUI /
    source      assembly     Procyon
  ```

  - *jadx*: Best for reading/analyzing code
  - *apktool*: Best for modifying and repackaging
]

#slide(title: "jadx: Decompile to Java")[
  ```bash
  # Decompile APK to Java source
  jadx target.apk -d output/

  # Output structure:
  output/
  ├── sources/        # Decompiled Java
  │   └── com/example/app/
  │       ├── MainActivity.java
  │       └── network/ApiClient.java
  └── resources/      # Decoded XML
      ├── AndroidManifest.xml
      └── res/

  # Interactive GUI
  jadx-gui target.apk
  ```

  Decompiles DEX bytecode to readable Java, even from Kotlin sources.
]

#slide(title: "apktool: Decode & Rebuild")[
  ```bash
  # Decompile to smali + resources
  apktool d target.apk -o output/

  # Edit smali code or resources...

  # Rebuild modified APK
  apktool b output/ -o modified.apk

  # Sign the APK
  apksigner sign --ks debug.keystore \
    --ks-pass pass:password modified.apk
  ```

  Produces *smali* (Dalvik assembly) which can be edited and repackaged.
]

#slide(title: "Understanding Smali")[
  ```smali
  .method public checkPin(Ljava/lang/String;)Z
      .locals 2
      .param p1, "inputPin"

      # Load hardcoded PIN
      const-string v0, "1234"

      # Compare input with hardcoded PIN
      invoke-virtual {p1, v0},
        Ljava/lang/String;->equals(
          Ljava/lang/Object;)Z
      move-result v1

      return v1
  .end method
  ```

  *Key types:* `Z`=boolean, `I`=int, `Ljava/lang/String;`=String
]

#slide(title: "Smali Patching Example")[
  *Bypass root detection by patching smali:*

  Original:
  ```smali
  .method public isDeviceRooted()Z
      # ... checks for root indicators ...
      const/4 v1, 0x1    # return true
      return v1
  .end method
  ```

  Patched:
  ```smali
  .method public isDeviceRooted()Z
      .locals 1
      const/4 v0, 0x0    # Always return false
      return v0
  .end method
  ```
]

#section-slide(title: "iOS Reverse Engineering")

#slide(title: "Decrypting App Store Apps")[
  App Store binaries are FairPlay-encrypted:

  ```bash
  # Check encryption status
  otool -l AppBinary | grep -A4 LC_ENCRYPTION_INFO
  # cryptid 1 = encrypted
  # cryptid 0 = decrypted

  # Decrypt with frida-ios-dump
  python dump.py com.target.app

  # Verify decryption
  otool -l decrypted | grep -A4 LC_ENCRYPTION_INFO
  # cryptid should now be 0
  ```

  *Must decrypt before any meaningful analysis!*
]

#slide(title: "Analyzing iOS Binaries")[
  ```bash
  # Linked libraries
  otool -L AppBinary

  # Objective-C class headers
  class-dump AppBinary > headers.h

  # String references
  strings AppBinary | grep -i "api\|key\|secret"

  # Binary protections
  otool -hv AppBinary | grep PIE    # ASLR
  ```

  *class-dump* reveals:
  - All class names and hierarchy
  - Method signatures
  - Property declarations
  - Protocol conformance
]

#slide(title: "Ghidra for Binary Analysis")[
  *Free decompiler (NSA) with ARM support:*

  1. Import decrypted Mach-O or `.so` native library
  2. Select architecture (AARCH64 for modern devices)
  3. Auto-analyze

  *Analysis approach:*
  - Start with string references → find interesting functions
  - Look for `NSLog` / `print` calls (information leakage)
  - Search for crypto functions (`CCCrypt`, `SecKey`, `AES`)
  - Identify certificate pinning (`SecTrust`, delegate methods)
  - Find root/jailbreak detection methods
]

#section-slide(title: "Identifying Security Mechanisms")

#slide(title: "What to Look For")[
  *Certificate Pinning:*
  - OkHttp `CertificatePinner`, `network_security_config` pin-set
  - TrustKit, custom `URLSession` delegates, `SecTrustEvaluate`

  *Root/Jailbreak Detection:*
  - File existence checks (`su`, `Cydia.app`, `/var/jb`)
  - SafetyNet/Play Integrity API calls
  - RootBeer / IOSSecuritySuite libraries

  *Anti-Debugging:*
  - `Debug.isDebuggerConnected()`, TracerPid checks
  - `ptrace(PT_DENY_ATTACH)`, `sysctl` P_TRACED

  *All identified statically → bypassed dynamically with Frida*
]

#slide(title: "Identifying Cryptographic Usage")[
  *Look for:*
  - AES/DES/3DES constants and S-boxes
  - RSA key generation / HMAC computation
  - Base64 near crypto operations
  - Key derivation (PBKDF2, scrypt, Argon2)

  *Common Issues:*
  - ECB mode (patterns visible in ciphertext)
  - Hardcoded IVs and encryption keys
  - Insufficient key derivation iterations
  - Custom crypto implementations
  - `Math.random()` instead of `SecureRandom`
]

#section-slide(title: "Practical Walkthrough")

#slide(title: "Android RE Walkthrough")[
  ```bash
  # 1. Pull APK
  adb pull $(adb shell pm path com.app \
    | cut -d: -f2) target.apk

  # 2. Decompile
  jadx target.apk -d output/

  # 3. Map the application
  find output/sources/ -name "*.java" | head -20

  # 4. Search for secrets
  grep -rn "api_key\|secret\|password" output/
  grep -rn "http://" output/  # Cleartext

  # 5. Identify RE targets
  grep -rn "isRooted\|sslPinning" output/
  grep -rn "encrypt\|decrypt\|cipher" output/
  ```
]

#slide(title: "String Analysis (Quick Wins)")[
  Strings often reveal the most about an app:

  - *API base URLs*: production, staging, development
  - *API keys and tokens*: hardcoded secrets
  - *Cloud config*: Firebase, AWS, Azure endpoints
  - *Debug/feature flags*: hidden functionality
  - *Database names*: data structure hints
  - *Error messages*: internal logic leaks

  ```bash
  # Android
  grep -rn "https://\|http://" output/sources/

  # iOS
  strings decrypted_binary | grep "http"
  ```
]

#section-slide(title: "Obfuscation")

#slide(title: "Identifying Obfuscation")[
  *ProGuard/R8 (default Android):*
  - Renames classes/methods to short names (a, b, c)
  - Removes unused code
  - Does NOT encrypt strings

  *DexGuard/DexProtector (commercial):*
  - String encryption
  - Control flow obfuscation
  - Native code protection
  - Anti-debugging

  *Key insight:* Obfuscation slows analysis but *never prevents it*. Runtime values can always be observed with Frida.
]

#section-slide(title: "Key Takeaways")

#slide(title: "Summary")[
  - RE is a prerequisite for effective dynamic analysis
  - jadx gives readability; apktool enables modification
  - iOS apps require FairPlay decryption before analysis
  - String analysis is the fastest path to secrets and endpoints
  - Obfuscation slows analysis but doesn't prevent it
  - Identify security mechanisms statically → bypass with Frida
  - Native code requires Ghidra / IDA / Binary Ninja
  - class-dump reveals the entire Objective-C API surface
  - Smali editing enables patching without source code
]

#title-slide(
  author: [Marcel Schnideritsch],
  title: [Reverse Engineering Mobile Apps],
  subtitle: [Module 18 - Mobile Security],
)
