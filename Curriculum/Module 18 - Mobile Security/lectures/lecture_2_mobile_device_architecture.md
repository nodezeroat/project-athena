# Mobile Device Architecture

Understanding the underlying architecture of mobile platforms is essential for security testing. The design decisions made at the OS level directly impact application security, the attack surface, and the techniques available to both attackers and defenders.

## Android Architecture

Android is an open-source, Linux-based mobile operating system developed by Google. Its architecture is organized in a layered stack where each layer provides services to the layer above it.

### Android Platform Stack

```text
┌─────────────────────────────────────────────┐
│              System Apps                     │
│   (Dialer, SMS, Browser, Calendar, ...)      │
├─────────────────────────────────────────────┤
│           Java API Framework                 │
│  (Activity Manager, Content Providers,       │
│   Window Manager, View System, ...)          │
├──────────────────┬──────────────────────────┤
│  Native C/C++    │   Android Runtime (ART)   │
│   Libraries      │   - Core Libraries        │
│  (OpenGL, Media, │   - DEX bytecode          │
│   SQLite, SSL)   │   - AOT/JIT compilation   │
├──────────────────┴──────────────────────────┤
│       Hardware Abstraction Layer (HAL)       │
│  (Audio, Bluetooth, Camera, Sensors, ...)    │
├─────────────────────────────────────────────┤
│              Linux Kernel                    │
│  (Drivers, Binder IPC, Power Management,     │
│   Memory Management, SELinux)                │
└─────────────────────────────────────────────┘
```

### Layer 1: Linux Kernel

Android is built on top of the Linux kernel, which provides:

- **Process Management**: Each app runs as a separate Linux process
- **Memory Management**: Virtual memory, memory protection between processes
- **Binder IPC**: Android's custom Inter-Process Communication mechanism
- **File System**: ext4/f2fs with Linux permission model
- **Device Drivers**: Hardware abstraction through kernel drivers
- **SELinux**: Mandatory Access Control for system-wide security policies
- **Seccomp-BPF**: System call filtering for additional sandboxing

**Security Implications:**

- Linux process isolation forms the foundation of Android's app sandboxing
- Kernel vulnerabilities can lead to full device compromise (privilege escalation)
- SELinux policies restrict what even root processes can do

### Layer 2: Hardware Abstraction Layer (HAL)

The HAL provides standard interfaces between hardware capabilities and the higher-level Java API framework:

- **Camera HAL**: Standardized camera access
- **Audio HAL**: Audio input/output abstraction
- **Sensors HAL**: Accelerometer, gyroscope, etc.
- **Bluetooth HAL**: Bluetooth communication
- **Graphics HAL**: GPU access and rendering

**Security Implications:**

- HAL modules run with elevated privileges
- Vulnerabilities in HAL implementations can bypass sandboxing
- Vendor-specific HAL code is often less audited than core AOSP code

### Layer 3: Native Libraries and Android Runtime

**Native Libraries (C/C++):**

- **libc (Bionic)**: Android's custom C standard library
- **OpenSSL/BoringSSL**: Cryptographic operations
- **SQLite**: Local database storage
- **libmedia**: Audio/video codec support
- **Webkit/Chromium**: Web rendering engine

**Android Runtime (ART):**

- Replaced Dalvik VM from Android 5.0 onwards
- Executes DEX (Dalvik Executable) bytecode
- **Ahead-of-Time (AOT) Compilation**: Compiles DEX to native code at install time
- **Just-in-Time (JIT) Compilation**: Optimizes frequently executed code at runtime
- **Garbage Collection**: Automatic memory management
- Each app runs in its own ART instance

**Security Implications:**

- DEX bytecode is relatively easy to decompile (unlike native code)
- Native libraries (JNI) are harder to reverse engineer but may contain vulnerabilities
- ART provides memory safety features (bounds checking, null pointer handling)

### Layer 4: Java API Framework

The framework provides high-level APIs for app development:

- **Activity Manager**: Manages app lifecycle and navigation
- **Content Providers**: Structured data sharing between apps
- **Window Manager**: Display and UI management
- **Notification Manager**: System notification handling
- **Package Manager**: App installation, permissions, package info
- **Telephony Manager**: Cellular network access
- **Location Manager**: GPS and network-based location

**Security Implications:**

- Content Providers can leak data if improperly configured (exported without permissions)
- Activity Managers handle Intent resolution, which can be manipulated
- Framework APIs enforce the permission model

### Layer 5: System and User Apps

- **System Apps**: Pre-installed apps (dialer, settings, browser)
- **User Apps**: Third-party apps installed from Play Store or sideloaded

**Security Implications:**

- System apps have elevated privileges compared to user apps
- Pre-installed bloatware may contain vulnerabilities
- Sideloaded apps bypass Play Store vetting

## iOS Architecture

iOS is Apple's proprietary mobile operating system, built on Darwin (a BSD-derived UNIX system) with the XNU hybrid kernel.

### iOS Platform Stack

```text
┌─────────────────────────────────────────────┐
│              Cocoa Touch Layer                │
│  (UIKit, MapKit, GameKit, PushKit, ...)      │
├─────────────────────────────────────────────┤
│              Media Layer                     │
│  (AVFoundation, Core Audio, Core Graphics,   │
│   Metal, Core Animation)                     │
├─────────────────────────────────────────────┤
│            Core Services Layer               │
│  (Foundation, Core Data, Core Location,      │
│   CloudKit, HealthKit, Security Framework)   │
├─────────────────────────────────────────────┤
│              Core OS Layer                   │
│  (Darwin/XNU Kernel, Mach, BSD, IOKit,       │
│   Security, Keychain, CommonCrypto)          │
├─────────────────────────────────────────────┤
│            Secure Enclave / SEP              │
│  (Hardware Security, Biometrics, Keys)       │
└─────────────────────────────────────────────┘
```

### Layer 1: Core OS and XNU Kernel

**XNU Kernel** (X is Not Unix):

- **Mach Microkernel**: Low-level process/thread management, IPC (Mach ports), memory management
- **BSD Layer**: POSIX APIs, file system (APFS), networking, user/group model
- **IOKit**: Device driver framework (C++ based)
- **libkern**: Kernel-level C++ runtime

**Key Features:**

- **ASLR (Address Space Layout Randomization)**: Randomizes memory layout to prevent exploits
- **XPC (Cross-Process Communication)**: Structured IPC for privilege separation
- **Mandatory Code Signing**: All code must be signed by Apple or a trusted developer
- **Sandboxing (Seatbelt)**: TrustedBSD-based mandatory access control

**Security Implications:**

- XNU kernel exploits are rare but extremely valuable (used in jailbreaks and spyware)
- Mach ports can be a vector for privilege escalation
- APFS provides hardware-level encryption support

### Layer 2: Core Services

- **Foundation Framework**: Basic data types, collections, networking
- **Core Data**: Persistent data storage (ORM for SQLite)
- **Core Location**: Location services
- **Security Framework**: Keychain access, certificate management, cryptographic operations
- **CommonCrypto**: Low-level cryptographic functions

**Security Implications:**

- The Keychain provides secure credential storage (hardware-backed on devices with Secure Enclave)
- Core Data databases can contain sensitive information
- Security Framework provides proper APIs, but developers sometimes misuse them

### Layer 3: Media Layer

- **AVFoundation**: Audio/video capture and playback
- **Core Graphics/Quartz**: 2D rendering
- **Metal**: GPU-accelerated graphics (replaced OpenGL ES)
- **Core Animation**: UI animation framework

### Layer 4: Cocoa Touch

- **UIKit**: User interface framework (views, controls, navigation)
- **WebKit**: Web content rendering
- **MapKit**: Map display and location services
- **PushKit**: Push notification handling
- **HealthKit**: Health data access
- **HomeKit**: Smart home device control

**Security Implications:**

- WebKit vulnerabilities are common jailbreak vectors
- Push notification systems can be abused for phishing
- HealthKit data requires special privacy protections

### Secure Enclave Processor (SEP)

The Secure Enclave is a dedicated security coprocessor:

- **Isolated from main processor**: Separate boot process, firmware, and memory
- **Hardware key storage**: Device-unique keys never leave the enclave
- **Biometric processing**: Touch ID/Face ID data processed within SEP
- **Cryptographic operations**: AES encryption engine, true random number generator
- **Anti-replay counter**: Prevents rollback attacks on data protection

**Security Implications:**

- Even a fully compromised iOS kernel cannot extract Secure Enclave keys
- Biometric data is never accessible to the main OS or apps
- Provides hardware root of trust for device encryption

## Android vs. iOS Architecture Comparison

| **Aspect** | **Android** | **iOS** |
| --- | --- | --- |
| **Kernel** | Linux (monolithic) | XNU (hybrid Mach + BSD) |
| **Source** | Open source (AOSP) | Closed source (proprietary) |
| **App Runtime** | ART (DEX bytecode) | Native (compiled ARM) |
| **IPC** | Binder + Intents | Mach ports + XPC |
| **App Format** | APK (ZIP archive) | IPA (ZIP archive) |
| **Code Signing** | Developer self-signs | Apple must sign/notarize |
| **App Distribution** | Play Store + sideloading | App Store (sideloading restricted) |
| **File System** | ext4/f2fs | APFS (encrypted) |
| **Hardware Security** | TEE (TrustZone, varies) | Secure Enclave (standardized) |
| **MAC** | SELinux | TrustedBSD (Seatbelt) |
| **Updates** | Fragmented (vendor-dependent) | Centralized (Apple controls) |

## Inter-Process Communication (IPC) Mechanisms

### Android IPC

Android uses several IPC mechanisms, all of which have security implications:

**1. Binder:**

- Primary IPC mechanism in Android
- Client-server model with kernel driver
- Used for all system service communication
- Enforces caller identity (UID/PID) for security checks

```text
App Process A ──► Binder Driver (Kernel) ──► System Service
                  (validates UID/PID)
```

**2. Intents:**

- High-level messaging objects for requesting actions
- **Explicit Intents**: Target a specific component (secure)
- **Implicit Intents**: System resolves the target (can be intercepted)
- **Broadcast Intents**: Sent to all registered receivers

```text
# Explicit Intent (secure - targets specific component)
Intent intent = new Intent(this, TargetActivity.class);

# Implicit Intent (potentially insecure - any app can handle)
Intent intent = new Intent(Intent.ACTION_VIEW, uri);
```

**Security Risks:**

- Implicit Intents can be intercepted by malicious apps
- Broadcast Intents may leak sensitive data
- Exported components without permission checks are accessible to any app

**3. Content Providers:**

- Structured data sharing between apps
- URI-based access model
- Can enforce read/write permissions separately

**Security Risks:**

- SQL injection through content provider queries
- Path traversal via content provider file access
- Exported providers without permissions expose data to all apps

### iOS IPC

**1. Mach Ports:**

- Low-level IPC mechanism from the Mach microkernel
- Used internally for system services
- Not directly accessible to third-party apps (sandboxed)

**2. XPC (Cross-Process Communication):**

- Modern, structured IPC framework
- Used for privilege separation within apps
- System enforces entitlements and sandboxing

**3. URL Schemes:**

- Apps register custom URL schemes (e.g., `myapp://action`)
- Any app can invoke another app's URL scheme

**Security Risks:**

- URL scheme hijacking (multiple apps register the same scheme)
- No sender verification (app cannot verify who sent the URL)
- Sensitive data in URL parameters can be leaked

**4. Universal Links / App Links:**

- Domain-verified deep linking (more secure than URL schemes)
- Requires server-side verification file
- Cannot be hijacked by other apps

## Application Packaging

### Android APK Structure

An APK (Android Package Kit) is a ZIP archive:

```text
app.apk
├── AndroidManifest.xml        # App metadata, permissions, components
├── classes.dex                # Compiled Dalvik bytecode
├── classes2.dex               # Additional DEX files (multidex)
├── resources.arsc             # Compiled resources
├── res/                       # Resource files (layouts, images, strings)
│   ├── layout/
│   ├── drawable/
│   └── values/
├── assets/                    # Raw asset files
├── lib/                       # Native libraries per architecture
│   ├── armeabi-v7a/
│   ├── arm64-v8a/
│   ├── x86/
│   └── x86_64/
├── META-INF/                  # Signing information
│   ├── MANIFEST.MF
│   ├── CERT.SF
│   └── CERT.RSA
└── kotlin/                    # Kotlin metadata (if applicable)
```

**Security-Relevant Files:**

- `AndroidManifest.xml`: Declares permissions, exported components, debug flags
- `classes.dex`: Can be decompiled to near-original Java/Kotlin source
- `lib/*.so`: Native libraries (harder to reverse engineer)
- `res/values/strings.xml`: May contain hardcoded strings, API endpoints
- `assets/`: May contain configuration files, certificates, databases

### iOS IPA Structure

An IPA (iOS App Store Package) is also a ZIP archive:

```text
app.ipa
└── Payload/
    └── AppName.app/           # App bundle
        ├── AppName             # Compiled Mach-O binary (ARM)
        ├── Info.plist          # App metadata and configuration
        ├── embedded.mobileprovision  # Provisioning profile
        ├── _CodeSignature/     # Code signature
        │   └── CodeResources
        ├── Frameworks/         # Embedded frameworks
        │   └── SomeLib.framework/
        ├── Assets.car          # Compiled asset catalog
        ├── Base.lproj/         # Localized resources
        │   └── Main.storyboardc
        └── *.nib               # Compiled interface files
```

**Security-Relevant Files:**

- **Mach-O Binary**: Compiled native code (harder to decompile than DEX)
- **Info.plist**: App transport security settings, URL schemes, permissions
- **embedded.mobileprovision**: Provisioning profile with entitlements
- **Frameworks/**: Third-party libraries (potential vulnerabilities)

## Boot Process and Chain of Trust

### Android Verified Boot

```text
┌──────────────┐
│  Hardware     │  ROM bootloader (burned into SoC)
│  Root of Trust│  Verifies next stage
├──────────────┤
│  Bootloader   │  Verifies boot partition
│  (locked)     │  Shows warning if unlocked
├──────────────┤
│  Kernel       │  Verified by bootloader
│  + initramfs  │  dm-verity protects system partition
├──────────────┤
│  System       │  Verified at block level
│  Partition    │  Read-only mount
├──────────────┤
│  User Space   │  SELinux enforces policies
│  (ART + Apps) │  App sandboxing active
└──────────────┘
```

- **dm-verity**: Cryptographically verifies system partition integrity at block level
- **AVB (Android Verified Boot)**: Verifies all partitions, supports rollback protection
- **Unlocking bootloader**: Wipes user data, shows persistent warning

### iOS Secure Boot Chain

```text
┌──────────────┐
│  Boot ROM     │  Immutable, burned into silicon
│  (hardware)   │  Contains Apple root CA
├──────────────┤
│  iBoot        │  Low-level bootloader
│  (signed)     │  Verified by Boot ROM
├──────────────┤
│  Kernel       │  XNU kernel
│  (signed)     │  Verified by iBoot
├──────────────┤
│  System       │  Signed System Volume (SSV)
│  Volume       │  Sealed with cryptographic hash tree
├──────────────┤
│  User Space   │  All code must be signed
│  (Apps)       │  Sandbox enforced
├──────────────┤
│  Secure       │  Independent boot chain
│  Enclave      │  Own firmware verification
└──────────────┘
```

- **Every stage verifies the next**: Unbroken chain from hardware to user space
- **No unsigned code**: Even kernel extensions must be signed (on Apple Silicon)
- **Secure Enclave boots independently**: Separate from main processor chain

## Key Takeaways

- Android's open architecture makes it more accessible for security research but also for attackers
- iOS's closed ecosystem provides strong default security but limits testing capabilities
- IPC mechanisms (Intents, URL Schemes) are common attack vectors on both platforms
- Understanding app packaging formats (APK/IPA) is essential for reverse engineering
- The boot chain of trust protects system integrity but can be bypassed (rooting/jailbreaking)
- Hardware security features (Secure Enclave, TrustZone) provide a final line of defense
- Both platforms use mandatory access control (SELinux / TrustedBSD) beyond traditional UNIX permissions

## Resources

- Android Architecture Overview: <https://developer.android.com/guide/platform>
- Android Security Architecture: <https://source.android.com/docs/security>
- Apple Platform Security Guide: <https://support.apple.com/guide/security/>
- Android Verified Boot: <https://source.android.com/docs/security/features/verifiedboot>
- XNU Kernel Source: <https://github.com/apple-oss-distributions/xnu>
- Android Binder IPC: <https://developer.android.com/reference/android/os/Binder>
