#import "../../../typst-athena-slides-template/1.0.1/src/lib.typ": *

#show: athena-theme.with(
  font: "Berkeley Mono",
  config-info(
    title: [Module 18: Mobile Security],
    subtitle: [Mobile Device Architecture],
    authors: [*Marcel Schnideritsch*],
    extra: [],
    footer: [Module 18 - Mobile Security],
  ),
  config-common(
    handout: false,
  ),
)

#title-slide()

#section-slide(title: "Android Architecture")

#slide(title: "Android Platform Stack")[
  ```text
  ┌───────────────────────────────────┐
  │         System & User Apps        │
  ├───────────────────────────────────┤
  │       Java API Framework          │
  │  (Activity Manager, Providers...) │
  ├────────────────┬──────────────────┤
  │ Native C/C++   │ Android Runtime  │
  │ Libraries      │ (ART, DEX)      │
  ├────────────────┴──────────────────┤
  │  Hardware Abstraction Layer (HAL) │
  ├───────────────────────────────────┤
  │         Linux Kernel              │
  │  (Binder, SELinux, Drivers)       │
  └───────────────────────────────────┘
  ```
]

#slide(title: "Linux Kernel Layer")[
  *Foundation of Android Security:*
  - *Process Management*: Each app runs as separate Linux process
  - *Memory Management*: Virtual memory, inter-process protection
  - *Binder IPC*: Custom Inter-Process Communication mechanism
  - *SELinux*: Mandatory Access Control policies
  - *Seccomp-BPF*: System call filtering

  *Security Implication:* Linux process isolation forms the basis of app sandboxing. Kernel vulnerabilities lead to full device compromise.
]

#slide(title: "Android Runtime (ART)")[
  - Replaced Dalvik VM from Android 5.0
  - Executes DEX (Dalvik Executable) bytecode
  - *AOT Compilation*: DEX → native code at install time
  - *JIT Compilation*: Runtime optimization of hot paths
  - Each app runs in its own ART instance

  *Security Implications:*
  - DEX bytecode is *easy to decompile* (unlike native code)
  - Native libraries (JNI) are harder to reverse engineer
  - ART provides bounds checking and null pointer handling
]

#slide(title: "Java API Framework")[
  High-level APIs for app development:
  - *Activity Manager*: App lifecycle, navigation
  - *Content Providers*: Structured data sharing between apps
  - *Package Manager*: Installation, permissions, metadata
  - *Telephony/Location Manager*: Network and GPS access

  *Security Implications:*
  - Content Providers can leak data if improperly exported
  - Activity Manager handles Intent resolution (manipulable)
  - Framework enforces the permission model
]

#section-slide(title: "iOS Architecture")

#slide(title: "iOS Platform Stack")[
  ```text
  ┌───────────────────────────────────┐
  │      Cocoa Touch Layer            │
  │  (UIKit, WebKit, MapKit, ...)     │
  ├───────────────────────────────────┤
  │      Media Layer                  │
  │  (AVFoundation, Metal, ...)       │
  ├───────────────────────────────────┤
  │      Core Services Layer          │
  │  (Foundation, Core Data, ...)     │
  ├───────────────────────────────────┤
  │      Core OS (Darwin / XNU)       │
  │  (Mach + BSD, IOKit, Security)    │
  ├───────────────────────────────────┤
  │    Secure Enclave Processor       │
  │  (Hardware keys, biometrics)      │
  └───────────────────────────────────┘
  ```
]

#slide(title: "XNU Kernel")[
  *X is Not Unix* - hybrid kernel:
  - *Mach Microkernel*: Process/thread management, IPC via Mach ports
  - *BSD Layer*: POSIX APIs, file system (APFS), networking
  - *IOKit*: Device driver framework

  *Security Features:*
  - ASLR (Address Space Layout Randomization)
  - XPC (structured IPC for privilege separation)
  - Mandatory code signing for all executables
  - TrustedBSD-based sandboxing (Seatbelt)
]

#slide(title: "Secure Enclave Processor (SEP)")[
  Dedicated security coprocessor, isolated from main CPU:

  - *Separate boot process*, firmware, and memory
  - *Hardware key storage*: Device-unique keys never leave enclave
  - *Biometric processing*: Touch ID / Face ID within SEP
  - *Crypto engine*: AES encryption, true random number generator
  - *Anti-replay counter*: Prevents rollback attacks

  *Even a fully compromised iOS kernel cannot extract Secure Enclave keys*
]

#section-slide(title: "Platform Comparison")

#slide(title: "Android vs. iOS")[
  #table(
    columns: (auto, auto, auto),
    inset: 6pt,
    stroke: 0.5pt,
    align: left,
    [*Aspect*], [*Android*], [*iOS*],
    [Kernel], [Linux (monolithic)], [XNU (hybrid)],
    [Source], [Open (AOSP)], [Closed (proprietary)],
    [Runtime], [ART (DEX bytecode)], [Native ARM],
    [IPC], [Binder + Intents], [Mach ports + XPC],
    [Code Signing], [Developer self-signs], [Apple must sign],
    [Distribution], [Play Store + sideloading], [App Store only],
    [HW Security], [TrustZone (varies)], [Secure Enclave],
    [Updates], [Fragmented], [Centralized],
  )
]

#section-slide(title: "IPC Mechanisms")

#slide(title: "Android IPC: Intents")[
  *Explicit Intents* (secure - specific target):
  ```java
  Intent intent = new Intent(this, TargetActivity.class);
  ```

  *Implicit Intents* (risk - any app can handle):
  ```java
  Intent intent = new Intent(Intent.ACTION_VIEW, uri);
  ```

  *Security Risks:*
  - Implicit Intents can be intercepted by malicious apps
  - Broadcast Intents may leak sensitive data
  - Exported components without permissions are open to all apps
]

#slide(title: "iOS IPC: URL Schemes")[
  Apps register custom URL schemes:

  ```text
  myapp://action?param=value
  ```

  *Security Risks:*
  - *URL Scheme Hijacking*: Multiple apps can register same scheme
  - *No sender verification*: App cannot verify who sent the URL
  - *Data leakage*: Sensitive parameters visible in URL

  *Mitigation:* Use Universal Links (domain-verified deep links) instead of URL schemes for sensitive operations.
]

#section-slide(title: "Application Packaging")

#slide(title: "Android APK Structure")[
  APK = ZIP archive containing:

  ```text
  app.apk
  ├── AndroidManifest.xml    # Permissions, components
  ├── classes.dex            # Compiled bytecode
  ├── resources.arsc         # Compiled resources
  ├── res/                   # Layouts, images, strings
  ├── assets/                # Raw asset files
  ├── lib/                   # Native libraries (.so)
  │   ├── arm64-v8a/
  │   └── armeabi-v7a/
  └── META-INF/              # Signing info
  ```

  *Key insight:* `classes.dex` can be decompiled to near-original source
]

#slide(title: "iOS IPA Structure")[
  IPA = ZIP archive containing:

  ```text
  app.ipa
  └── Payload/AppName.app/
      ├── AppName              # Mach-O binary (ARM)
      ├── Info.plist           # App configuration
      ├── embedded.mobileprovision
      ├── _CodeSignature/      # Code signature
      ├── Frameworks/          # Embedded frameworks
      └── Assets.car           # Compiled assets
  ```

  *Key insight:* Compiled native binary is harder to decompile than DEX.
  App Store apps are FairPlay-encrypted (must decrypt before analysis).
]

#section-slide(title: "Boot Chain of Trust")

#slide(title: "Verified Boot")[
  #grid(
    columns: (1fr, 1fr),
    gutter: 5mm,
  )[
    *Android:*
    1. Hardware Root of Trust
    2. Bootloader (locked)
    3. Kernel + dm-verity
    4. System partition
    5. User space (SELinux)

    Unlocking bootloader wipes data and shows warning.
  ][
    *iOS:*
    1. Boot ROM (immutable)
    2. iBoot (Apple-signed)
    3. XNU Kernel (signed)
    4. System Volume (SSV)
    5. User space (sandbox)
    6. Secure Enclave (independent chain)

    Every stage verifies the next.
  ]
]

#section-slide(title: "Key Takeaways")

#slide(title: "Summary")[
  - Android: open architecture, easier to research and to attack
  - iOS: closed ecosystem, strong defaults but limited testing
  - IPC mechanisms (Intents, URL Schemes) are common attack vectors
  - APK/IPA packaging formats are essential to understand for RE
  - Boot chain of trust protects system integrity
  - Hardware security (Secure Enclave, TrustZone) is the last line of defense
  - Both platforms use mandatory access control beyond UNIX permissions
]

#title-slide(
  author: [Marcel Schnideritsch],
  title: [Mobile Device Architecture],
  subtitle: [Module 18 - Mobile Security],
)
