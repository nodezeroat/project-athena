#import "../../../typst-athena-slides-template/1.0.1/src/lib.typ": *

#show: athena-theme.with(
  font: "Berkeley Mono",
  config-info(
    title: [Module 18: Mobile Security],
    subtitle: [Introduction to Mobile Security],
    authors: [*Marcel Schnideritsch*],
    extra: [],
    footer: [Module 18 - Mobile Security],
  ),
  config-common(
    handout: false,
  ),
)

#title-slide()

#section-slide(title: "The Mobile Landscape")

#slide(title: "Why Mobile Security Matters")[
  - Over 6.8 billion smartphone users worldwide
  - Average person: 4+ hours daily on mobile
  - Devices handle: banking, healthcare, communication, enterprise
  - BYOD blurs personal and corporate security boundaries

  *Mobile devices are the primary computing platform*
  - Unique attack surface compared to desktops
  - Always-on connectivity, rich sensors, physical exposure
]

#slide(title: "Unique Mobile Challenges")[
  *1. Always-On Connectivity*
  - Wi-Fi: Rogue access points, evil twin attacks
  - Cellular: IMSI catchers, SS7 vulnerabilities
  - Bluetooth: BlueBorne, BLE tracking
  - NFC: Relay attacks, contactless payment interception

  *2. Rich Sensor Data*
  - GPS, Camera, Microphone, Accelerometer
  - Biometric sensors (fingerprint, face)
  - All potential targets for unauthorized access
]

#slide(title: "Mobile vs. Traditional Security")[
  #table(
    columns: (auto, auto, auto),
    inset: 6pt,
    stroke: 0.5pt,
    align: left,
    [*Aspect*], [*Desktop*], [*Mobile*],
    [OS Updates], [User-controlled], [Vendor-dependent],
    [App Distribution], [Open (any source)], [App stores (curated)],
    [Sandboxing], [Limited (per-user)], [Strong (per-app)],
    [Permissions], [Coarse (admin/user)], [Fine-grained (per-resource)],
    [Physical Security], [Stationary], [Portable, theft risk],
    [Network], [Mostly wired], [Multiple dynamic connections],
  )
]

#section-slide(title: "OWASP Mobile Top 10")

#slide(title: "OWASP Mobile Top 10 (2024)")[
  #table(
    columns: (auto, auto),
    inset: 6pt,
    stroke: 0.5pt,
    align: left,
    [*#*], [*Risk*],
    [M1], [Improper Credential Usage],
    [M2], [Inadequate Supply Chain Security],
    [M3], [Insecure Authentication/Authorization],
    [M4], [Insufficient Input/Output Validation],
    [M5], [Insecure Communication],
    [M6], [Inadequate Privacy Controls],
    [M7], [Insufficient Binary Protections],
    [M8], [Security Misconfiguration],
    [M9], [Insecure Data Storage],
    [M10], [Insufficient Cryptography],
  )
]

#slide(title: "Threat Actors")[
  - *Opportunistic Attackers*: Lost/stolen devices, freely available tools
  - *Organized Cybercriminals*: Banking trojans, ransomware, credential harvesting
  - *Nation-State Actors*: Sophisticated spyware (Pegasus), zero-day exploits
  - *Malicious Insiders*: Data exfiltration via personal devices
  - *Competitors*: Corporate espionage through mobile surveillance
]

#slide(title: "Common Attack Vectors")[
  #grid(
    columns: (1fr, 1fr),
    gutter: 5mm,
  )[
    *Application Layer*
    - Reverse engineering
    - App repackaging
    - Insecure data storage
    - MITM on API calls
    - Runtime manipulation
  ][
    *OS / Platform Layer*
    - Privilege escalation
    - Jailbreaking/rooting
    - IPC exploitation
    - System service abuse
  ]
]

#section-slide(title: "Testing Methodology")

#slide(title: "Mobile Security Assessment Phases")[
  1. *Reconnaissance*
     - Map functionality, API endpoints, third-party SDKs

  2. *Static Analysis*
     - Decompile, search for secrets, review configurations

  3. *Dynamic Analysis*
     - Runtime monitoring, traffic interception, Frida hooks

  4. *Reverse Engineering*
     - Understand logic, identify security mechanisms

  5. *Exploitation*
     - Bypass controls, demonstrate impact, chain findings
]

#slide(title: "Testing Tools Overview")[
  #table(
    columns: (auto, auto, auto),
    inset: 6pt,
    stroke: 0.5pt,
    align: left,
    [*Category*], [*Android*], [*iOS*],
    [Decompilation], [jadx, apktool], [Hopper, Ghidra, class-dump],
    [Dynamic Analysis], [Frida, objection], [Frida, objection],
    [Traffic Interception], [Burp Suite, mitmproxy], [Burp Suite, Charles],
    [Automated Scanning], [MobSF, QARK], [MobSF],
    [Environment], [Android Emulator], [Corellium, device],
  )
]

#slide(title: "Lab Environment Setup")[
  *Android Testing:*
  - Android Studio + emulator (API 30+, rooted)
  - ADB (Android Debug Bridge)
  - Frida server on device

  *Common Tools:*
  - Burp Suite for traffic interception
  - jadx for decompilation
  - MobSF for automated analysis
  - Python 3 with frida-tools

  ```bash
  pip install frida-tools objection
  frida --version
  ```
]

#section-slide(title: "Key Takeaways")

#slide(title: "Summary")[
  - Mobile security is distinct from traditional security
  - OWASP Mobile Top 10 provides the vulnerability framework
  - Testing combines static, dynamic, and reverse engineering approaches
  - Frida (dynamic instrumentation) is a critical modern skill
  - Both Android and iOS have strong security models
  - Implementation flaws in apps remain the primary attack surface
  - Always test in authorized environments only
]

#title-slide(
  author: [Marcel Schnideritsch],
  title: [Introduction to Mobile Security],
  subtitle: [Module 18 - Mobile Security],
)
