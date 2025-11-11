#import "../../../typst-athena-slides-template/1.0.1/src/lib.typ": *

#show: athena-theme.with(
  font: "Berkeley Mono",
  config-info(
    title: [Module 02: Reconnaissance],
    subtitle: [Introduction to Reconnaissance],
    authors: [*Marcel Schnideritsch*],
    extra: [],
    footer: [Module 02 - Reconnaissance],
  ),
  config-common(
    handout: false,
  ),
)

#title-slide()

#slide(title: "What is Reconnaissance?")[
  The critical initial phase where information about a target is systematically collected and analyzed.

  *Key Points:*
  - First stage of cyber attack lifecycle
  - Identifies vulnerabilities and entry points
  - Determines success of subsequent attack stages
  - Foundation for both offensive and defensive security
]

#slide(title: "Why Reconnaissance Matters")[
  *In cybersecurity, information is power!*

  - *Attack Surface Mapping*: Identify all potential entry points
  - *Vulnerability Discovery*: Find weaknesses before exploitation
  - *Risk Assessment*: Understand target's security posture
  - *Attack Planning*: Develop targeted strategies
  - *Stealth Operations*: Minimize detection by understanding defenses

  #text(fill: red)[*Part of the Cyber Kill Chain*]
]

#section-slide(title: "Types of Reconnaissance")

#slide(title: "Passive Reconnaissance")[
  #color-block(
    title: [ *Definition:* ],
    [Gathering information WITHOUT directly interacting with the target system.],
  )


  *Key Characteristics:*
  - Non-intrusive - no packets sent to target
  - Difficult to detect - leaves no logs
  - Legal gray area - uses public information
  - Time-intensive but lower risk
  - Minimal chance of triggering security alerts
]

#slide(title: "Passive Reconnaissance: Methods")[
  *Common Techniques:*

  - Search engine research (Google, Bing, DuckDuckGo)
  - Public records analysis
  - Social media investigation (LinkedIn, Twitter, Facebook)
  - Job postings revealing technologies
  - Financial reports and company filings
  - Archive services (Wayback Machine)
  - DNS enumeration (without querying target directly)
  - Cached content analysis
]

#slide(title: "Passive Reconnaissance: Tools")[
  *Essential Tools:*

  - *WHOIS*: Domain registration information
  - *nslookup/dig*: DNS records
  - *theHarvester*: Email and subdomain gathering
  - *Maltego*: Visual link analysis and OSINT
  - *Recon-ng*: Web reconnaissance framework
  - *WHOIS History*: Track historical data
]

#slide(title: "Passive Reconnaissance: Example")[
  *Scenario:* Ethical hacker researching `example-corp.com`

  1. Run WHOIS → Registration date (2015), registrar info
  2. LinkedIn search → 250+ employees, 15 in IT/Security
  3. Job posting → "AWS Cloud Engineer with Terraform experience"
  4. theHarvester → 47 emails: `firstname.lastname@example-corp.com`
  5. Certificate transparency → Subdomain: `dev.example-corp.com`
  6. Google Dorks → Exposed API documentation on staging server

  *Result:* Comprehensive profile, ZERO packets sent to target!
]

#slide(title: "Active Reconnaissance")[
  *Definition:* Direct interaction with target systems to gather information.

  *Key Characteristics:*
  - Intrusive - directly probes target systems
  - Easily detected - leaves clear trails in logs
  - Requires explicit authorization
  - Faster results - real-time, accurate information
  - Higher risk - triggers IDS/IPS, firewalls
]

#slide(title: "Active Reconnaissance: Methods")[
  *Common Techniques:*

  - Network scanning (IP range probing)
  - Port scanning (identify open ports/services)
  - Service enumeration (fingerprint applications)
  - OS fingerprinting (TCP/IP stack analysis)
  - Vulnerability scanning (automated detection)
  - Network mapping (topology creation)
  - Banner grabbing (capture service versions)
]

#slide(title: "Active Reconnaissance: Tools")[
  *Essential Tools:*

  - *NMAP*: Industry-standard network mapping and port scanning
  - *Masscan*: High-speed port scanner (millions of ports/second)
  - *Netcat (nc)*: Swiss Army knife for network connections
  - *hping3*: Packet crafting and advanced TCP/IP analysis
  - *Nessus/OpenVAS*: Comprehensive vulnerability scanners
  - *Nikto*: Web server vulnerability scanner
]

#slide(title: "Active Reconnaissance: Example")[
  *Authorized penetration test on 192.168.1.0/24:*

  1. *Host Discovery*: `nmap -sn 192.168.1.0/24` → 45 active hosts
  2. *Port Scan*: `nmap -p- -T4 192.168.1.10` → Ports: 22, 80, 443, 3306
  3. *Service Detection*: `nmap -sV` → OpenSSH 7.4, Apache 2.4.29, MySQL 5.7.22
  4. *OS Detection*: `nmap -O` → Ubuntu Linux 18.04
  5. *Vulnerability Scan*: Nessus → Outdated Apache, exposed MySQL

  *Result:* Detailed technical profile for targeted exploitation
]

#slide(title: "Passive vs. Active Comparison")[
  #table(
    columns: (auto, 1fr, 1fr),
    align: (left, left, left),
    table.header([*Aspect*], [*Passive*], [*Active*]),
    [Detection Risk], [Very Low], [High],
    [Information Quality], [Historical, outdated], [Current, accurate],
    [Speed], [Slower], [Faster],
    [Authorization], [Often not required], [Always required],
    [Footprint], [Minimal to none], [Significant logs],
    [Use Case], [Initial research], [Pentest, audits],
  )
]

#section-slide(title: "Phases of Reconnaissance")

#slide(title: "Phase 1: Information Gathering")[
  *Objective:* Establish baseline understanding of target

  *Activities:*
  - Domain name and subdomain discovery
  - IP address ranges (CIDR notation)
  - Email address formats
  - Organizational structure
  - Technologies in use

  *Tools:* WHOIS, nslookup, dig, theHarvester, Sublist3r, Amass

  *Output:* Comprehensive asset inventory and organizational profile
]

#slide(title: "Phase 2: Scanning and Identification")[
  *Objective:* Identify active systems and enumerate services

  *Activities:*
  - Live host detection across IP ranges
  - Port scanning to find open services
  - Service version identification
  - Operating system fingerprinting
  - Network topology mapping

  *Tools:* NMAP, Masscan, Unicornscan

  *Output:* Network diagram with active hosts, services, versions
]

#slide(title: "Phase 3: Enumeration")[
  *Objective:* Extract detailed information from services

  *Activities:*
  - User account enumeration
  - Network share discovery
  - SNMP community strings
  - DNS zone transfers
  - Email server enumeration

  *Tools:* enum4linux, SNMPwalk, ldapsearch, smtp-user-enum

  *Output:* Detailed service configurations and entry points
]

#slide(title: "Phase 4: Vulnerability Mapping")[
  *Objective:* Identify security weaknesses

  *Activities:*
  - Known vulnerability scanning (CVE matching)
  - Misconfiguration detection
  - Default credential identification
  - Outdated software analysis
  - SSL/TLS configuration testing

  *Tools:* Nessus, OpenVAS, Nikto, Nuclei, SSLScan

  *Output:* Prioritized vulnerability list with exploitability ratings
]

#slide(title: "Phase 5: Analysis and Reporting")[
  *Objective:* Synthesize findings into actionable intelligence

  *Activities:*
  - Correlate information from multiple sources
  - Identify attack paths and kill chains
  - Prioritize targets by value and accessibility
  - Document findings in structured format
  - Prepare attack plan or remediation recommendations

  *Output:* Reconnaissance report with executive summary and technical details
]

#section-slide(title: "Real-World Case Studies")

#slide(title: "Case Study: Target Corporation (2013)")[
  *Background:* 40M credit cards, 70M customer records stolen

  *Reconnaissance Role:*
  1. Identified Fazio Mechanical (HVAC vendor) as Target vendor
  2. Phishing attack yielded vendor network credentials
  3. Used vendor access to map Target's internal network (weeks)
  4. Identified POS systems and payment processing infrastructure
  5. Mapped data flows to identify extraction points

  *Key Lesson:* Supply chain reconnaissance reveals weaknesses direct attacks miss

  *Impact:* 162M costs, CEO resignation, reputational damage
]

#slide(title: "Case Study: SolarWinds (2020)")[
  *Background:* Nation-state attack affecting 18,000+ organizations

  *Reconnaissance Role:*
  1. Studied SolarWinds Orion platform architecture and update mechanisms
  2. Researched high-value customers (government, Fortune 500)
  3. Reconnaissance of SolarWinds' build infrastructure
  4. Understood software signing and distribution mechanisms
  5. Methodically mapped victim networks post-compromise

  *Key Lesson:* Patient, long-term reconnaissance of supply chains = massive impact

  *Impact:* Classified data accessed, 100+ billion global damages
]

#slide(title: "Case Study: Equifax (2017)")[
  *Background:* 147M people's data exposed via Apache Struts vulnerability

  *Reconnaissance Role:*
  1. Monitored CVE databases for high-impact vulnerabilities
  2. Fingerprinted Equifax web apps using vulnerable Apache Struts
  3. Enumerated public-facing applications and endpoints
  4. Found critical system missing CVE-2017-5638 patch
  5. After access, mapped internal database systems

  *Key Lesson:* Vulnerability disclosure + version fingerprinting = rapid exploitation

  *Impact:* 1.4B costs, executive resignations, ongoing legal issues
]

#section-slide(title: "Ethical and Legal Considerations")

#slide(title: "Authorization is Non-Negotiable")[
  #color-block(
    title: [Critical Rule:],
    [

    ]
  )

  *Legal Frameworks:*
  - Computer Fraud and Abuse Act (CFAA) - U.S.
  - Computer Misuse Act - U.K.
  - EU Directives - Europe
  - Even passive reconnaissance can cross legal lines

  *Scope Limitations:*
  - Stay within authorized IP ranges and domains
  - Respect time windows in engagement agreements
  - Document all activities with timestamps
]

#slide(title: "Defensive Reconnaissance")[
  *Organizations should perform reconnaissance on themselves:*

  - Identify exposed assets and information leakage
  - Understand attacker perspective
  - Discover shadow IT and forgotten systems
  - Validate security controls effectiveness

  *Benefits:*
  - Proactive security posture
  - Find issues before attackers do
  - Understand attack surface
  - Improve security controls
]

#section-slide(title: "Defensive Measures")

#slide(title: "Defending Against Reconnaissance")[
  *Technical Controls:*
  - Rate limiting to prevent automated scanning
  - Honeypots to detect and mislead attackers
  - WHOIS privacy protection
  - CDNs to hide true infrastructure
  - Port filtering and service minimization
  - Banner suppression (remove version info)

  *Administrative Controls:*
  - Security awareness training
  - Information classification policies
  - Vendor security assessment
  - Review job postings for excessive technical details
]

#slide(title: "Monitoring and Detection")[
  *Detection Strategies:*

  - *Log Analysis*: Monitor for reconnaissance patterns
  - *IDS/IPS Signatures*: Detect known scanning tools
  - *Behavioral Analytics*: Identify unusual query patterns
  - *Threat Intelligence*: Track known reconnaissance infrastructure

  *Example NMAP Detection:*
  - Rapid sequential port connections from single IP
  - SYN packets without completion
  - Scans of commonly targeted ports (22, 80, 443, 3389)
]

#section-slide(title: "Key Takeaways")

#slide(title: "Summary")[
  *Critical Points:*

  - Reconnaissance is the foundation of both offensive and defensive security
  - Passive techniques provide stealth; active techniques provide accuracy
  - Proper authorization is legally and ethically essential
  - Reconnaissance is continuous, not one-time
  - Defenders must understand reconnaissance to implement countermeasures
  - Modern reconnaissance leverages automation and multiple data sources
  - Supply chain and third-party relationships expand reconnaissance targets
]

#slide(title: "Practical Next Steps")[
  *For Students:*
  1. Practice passive reconnaissance on yourself (self-OSINT)
  2. Set up lab environment for active scanning practice
  3. Learn NMAP thoroughly - it's the foundation
  4. Understand legal boundaries in your jurisdiction
  5. Practice defensive reconnaissance on authorized targets

  *For Organizations:*
  1. Perform regular self-reconnaissance audits
  2. Implement detection for reconnaissance activities
  3. Train employees on information security
  4. Monitor for exposed assets and data leakage
  5. Develop incident response for detected reconnaissance
]

#slide(title: "Resources")[
  *Books:*
  - "Penetration Testing" by Georgia Weidman
  - "The Hacker Playbook 3" by Peter Kim
  - "RTFM: Red Team Field Manual" by Ben Clark

  *Online Resources:*
  - NMAP Documentation: nmap.org/book
  - OSINT Framework: osintframework.com
  - MITRE ATT&CK Framework: attack.mitre.org

  *Practice Platforms:*
  - HackTheBox
  - TryHackMe
  - PentesterLab
]

#title-slide()
