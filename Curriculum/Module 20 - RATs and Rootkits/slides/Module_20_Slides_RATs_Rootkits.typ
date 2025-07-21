#import "../../../athena-typst-theme/athena-polylux.typ": *
#import "@preview/pinit:0.1.4": *
#show: athena-theme.with(
  footer: [Reapie],
  progress-bar: true,
)

#set text(font: "Noto Sans Mono", weight: "regular", size: 20pt)
#show math.equation: set text(font: "Fira Math")
#set strong(delta: 100)
#set par(justify: true)

#title-slide(
  title: [Module 20: RATs and Rootkits],
  subtitle: [Introduction],
)

#slide(title: "Outline")[
  #metropolis-outline
]

#new-section-slide("Introduction")

#slide(title: "RATs and Rootkits")[
  #side-by-side[
    - Remote Access
    - Backdoors
  ][
    #image("../figures/fartware.gif", width: 90%)
  ]
]

#new-section-slide("RATs")

#slide(title: "RATs")[
  - Remote Access Trojans
  - Infostealers
  - Operationally similar to legitimate tools
]

#slide(title: "Infostealers")[
  - *x* got ratted -> Usually just an infostealer
  - Basic social engineering
  - Steals tokens, passwords, cookies, etc.
  - VERY poplar in communities with lots of *young people*
  - No infra, relies heavily on webhooks or similar
]

#slide(title: "Real RATs")[
  #side-by-side(gutter: 3mm, columns: (2fr, 1fr))[
    - More complex, requires C2 infra
    - Not worth for individual targets
    - Can pivot into Ransomware or related
  ][
    #image("../figures/xmrig.gif")
  ]
]

#slide(title: "RAT Operation")[
  1) Entry via social engineering

  2) *current cve* or *0day* to escalate

  3) Install and start beaconing

  4) Profit
]

#new-section-slide("Command and Control (C2")

#slide(title: "Command and Control (C2)")[
  - Recieve and execute commands
  - Exfiltrate data
  - Commercial or custom frameworks
]

#slide(title: "Command and Control (C2)")[
  #set align(center)
  #image("../figures/cobalt-strike.jpg")
]

#slide(title: "C2 Communication")[
  - Beaconing
    - host -> C2
  - Crawling
    - C2 -> known hosts
  - Traffic obfuscation
    - Redirection
    - C2 over DNS
    - Encryption
    - Mallealbe traffic
]

#slide(title: "More traffic obfuscation")[
  #side-by-side(gutter: 3mm, columns: (1.2fr, 1fr))[
    - Domain Fronting
    - Fast Flux
    - DNS Tunneling
    - Other generic traffic obfuscation
  ][
    #image("../figures/domain-fronting-scheme.png")
  ]
]

#slide(title: "Persistence")[
  #side-by-side(gutter: 3mm, columns: (1fr, 1fr))[
    - Registry
    - Startup
    - Scheduled Tasks
    - DLLs
  ][
    #image("../figures/DLL-load-order.png", height: 120%)
  ]
]

#slide(title: "Protection")[
  #side-by-side[
    === Prevent infection
    - User training
    - Patching
    - Minimal permissions

  ][
    === Detect
    - Monitor traffic
    - EDR monitoring
  ]
]



#slide(title: "Examples")[
  - Discord Bot Infostealer
  https://www.trellix.com/blogs/research/java-based-sophisticated-stealer-using-discord-bot-as-eventlistener/)


  - RAT builder RAT
  https://cyberpress.org/weaponized-xworm-rat-builder-targeting-script-kiddies/)
]

#new-section-slide("Rootkits")

#slide(title: "Rootkits")[
  - Backdoor with typically elevated privileges


  - Traditionally requires permissions and/or exploit to install

]

#slide(title: "Types of Rootkits")[
    === Userland
    - First type of rootkits
    - Replace glibc, etc.

    === Kernel
    - Permissions or exploit required
    - Nowadays more protections

    === Firmware/BIOS/Hypervisor
    - Very rare and complex
]



#slide(title: "Mobile Rootkits")[
  - State spyware may fall into this category
  - Root/jailbreak usually included
  - Very rare due to cost of required vulns
]

#slide(title: "Why Ring0")[
  - Normally invisible from userspace
  - Manipulate structures and install hooks
  - Can be detected by earlier/deeper code
]

#slide(title: "Kernel Protections")[
  - Non-exposed symbols
  - KASLR & SMAP
  - Write protection
  - Exploit protections
  - Integrity checks
  - Still not perfect
  #set align(center)
  #image("../figures/kernel-protection.png")

]

#slide(title: "Firmware/BIOS/ Hypervisor")[
  - Functionally similar to enterprise management software
  - Requires high severity vuln to install
  - Might start to become more common
]

#title-slide(
  title: [Module 20: RATs and Rootkits],
  subtitle: [Introduction],
)