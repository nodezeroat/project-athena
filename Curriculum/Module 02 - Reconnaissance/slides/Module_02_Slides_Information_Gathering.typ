#import "../../../typst-athena-slides-template/1.0.1/src/lib.typ": *

#show: athena-theme.with(
  font: "Berkeley Mono",
  config-info(
    title: [Module 02: Reconnaissance],
    subtitle: [Information Gathering & NMAP],
    authors: [*Project Athena*],
    extra: [],
    footer: [Module 02 - Information Gathering],
  ),
  config-common(
    handout: false,
  ),
)

#title-slide()

#slide(title: "Information Gathering")[
  #color-block(
    title: [Definition:],
    [Systematic process of collecting, analyzing, and cataloging data about a target to produce actionable intelligence.],
  )
]

#slide(title: "The Process of Information Gathering")[
  *Phases:*

  1. *Planning and Preparation*
    - Define scope, objectives, rules of engagement
    - Gather tools and resources

  2. *Data Collection*
    - Passive methods: OSINT, public records
    - Active methods: Network scanning, service enumeration

  3. *Data Analysis*
    - Correlate findings
    - Identify patterns and anomalies

  4. *Reporting*
    - Document findings
    - Provide recommendations for next steps
]

#slide(title: "What Information to Gather")[
  *Network Infrastructure:*
  - IP ranges, domains, subdomains
  - DNS configurations, network topology

  *Systems and Services:*
  - Operating systems, running services
  - Application versions, patch levels

  *Organizational Information:*
  - Company structure, employees
  - Email formats, office locations

  *Security Posture:*
  - Security products, authentication methods
  - Compliance requirements
]

#section-slide(title: "NMAP: Network Mapper")

#slide(title: "What is NMAP?")[
  Industry-standard open-source tool for network discovery and security auditing

  *Created by:* Gordon "Fyodor" Lyon (1997)

  *Why NMAP?*
  - Most comprehensive network scanning tool
  - Flexible and scriptable (NSE)
  - Cross-platform compatibility
  - Used by security professionals worldwide
  - Free and open source
]

#slide(title: "NMAP Core Capabilities")[
  *Four Main Functions:*

  1. *Host Discovery* - Which systems are online?
  2. *Port Scanning* - Which ports are open?
  3. *Version Detection* - What services/versions running?
  4. *OS Detection* - What operating systems?

  Plus: Vulnerability detection, network mapping, and more via NSE scripts
]

#slide(title: "Host Discovery")[
  #grid(
    columns: (1fr, 1fr),
    gutter: 6mm,
    align: (top),
  )[
    *Find hosts without full scan*

    ```bash
    # Basic ping scan (ICMP)
    nmap -sn 192.168.1.0/24

    # Skip ping, assume all up
    nmap -Pn 192.168.1.10

    # ARP scan (local network, most reliable)
    nmap -PR 192.168.1.0/24
    ```
  ][
    *Discovery Methods:*
    - ICMP echo requests (ping)
    - TCP SYN to common ports
    - TCP ACK (bypass simple firewalls)
    - ARP for local networks
  ]
]

#slide(title: "Port Scanning")[
  #grid(
    columns: (1fr, 1fr),
    gutter: 6mm,
    align: (top),
  )[
    *Scan Types:*

    - *TCP SYN* (`-sS`): Stealth, doesn't complete handshake (requires root)
    - *TCP Connect* (`-sT`): Full connection (no root needed)
    - *UDP* (`-sU`): Scan UDP ports (slower)
  ][
    ```bash
    # Specific ports
    nmap -p 22,80,443 192.168.1.10

    # All ports
    nmap -p- 192.168.1.10

    # Top 100 ports
    nmap --top-ports 100 192.168.1.10
    ```
  ]
]

#slide(title: "Service and Version Detection")[
  #grid(
    columns: (1fr, 1fr),
    gutter: 6mm,
    align: (top),
  )[
    *Identify what's running:*

    ```bash
    # Basic version detection
    nmap -sV 192.168.1.10

    # Aggressive version detection
    nmap -sV --version-intensity 9 192.168.1.10
    ```
  ][
    *Example Output:*
    ```
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 8.2p1
    80/tcp   open  http    Apache 2.4.41
    3306/tcp open  mysql   MySQL 5.7.22
    ```
  ]
]

#slide(title: "Operating System Detection")[
  #grid(
    columns: (1fr, 1fr),
    gutter: 6mm,
    align: (top),
  )[
    *Fingerprint OS via TCP/IP stack analysis*

    ```bash
    # OS detection (requires root)
    nmap -O 192.168.1.10

    # Aggressive detection + version scanning
    nmap -A 192.168.1.10
    ```
  ][
    *Identifies:*
    - Operating system family
    - Specific version
    - Device type
  ]
]

#slide(title: "NMAP Timing Templates")[
  Control scan speed with -T0 through -T5:

  - *T0 (Paranoid)*: Extremely slow, IDS evasion (5 min between probes)
  - *T1 (Sneaky)*: Slow, IDS evasion (15 sec between probes)
  - *T2 (Polite)*: Slows down to reduce bandwidth
  - *T3 (Normal)*: Default timing
  - *T4 (Aggressive)*: Fast, assumes reliable network
  - *T5 (Insane)*: Very fast, may sacrifice accuracy

  ```bash
  nmap -sS -T4 192.168.1.0/24
  ```
]

#slide(title: "NMAP Output Formats")[
  *Save scan results in various formats:*

  ```bash
  # Normal output (human-readable)
  nmap -oN scan.txt 192.168.1.10

  # XML output (machine-parseable)
  nmap -oX scan.xml 192.168.1.10

  # Grepable output
  nmap -oG scan.gnmap 192.168.1.10

  # All formats at once
  nmap -oA scan_results 192.168.1.10
  ```
]

#slide(title: "Advanced NMAP Techniques")[
  *Evasion and Obfuscation:*

  ```bash
  # Use decoy addresses
  nmap -D RND:10 192.168.1.10

  # Fragment packets
  nmap -f 192.168.1.10

  # Spoof source port
  nmap --source-port 53 192.168.1.10

  # Scan through proxy
  nmap --proxies http://proxy:8080 target.com
  ```
]

#section-slide(title: "NMAP Scripting Engine (NSE)")

#slide(title: "What is NSE?")[
  *NMAP Scripting Engine extends NMAP capabilities*

  - 600+ pre-written scripts
  - Lua-based scripting language
  - Categories: auth, brute, discovery, exploit, vuln, and more

  *Script Categories:*
  - `default` - Safe scripts, run with `-sC`
  - `vuln` - Vulnerability detection
  - `exploit` - Exploitation attempts
  - `brute` - Brute force attacks
  - `discovery` - Advanced enumeration
]

#slide(title: "Using NSE Scripts")[
  ```bash
  # Run default safe scripts
  nmap -sC 192.168.1.10

  # Run specific script
  nmap --script=http-title 192.168.1.10

  # Run multiple scripts
  nmap --script=http-enum,http-headers 192.168.1.10

  # Run all scripts in category
  nmap --script=vuln 192.168.1.10

  # Run with wildcards
  nmap --script="http-*" 192.168.1.10
  ```
]

#slide(title: "Popular NSE Scripts")[
  ```bash
  # HTTP enumeration
  nmap --script=http-enum -p 80 target.com

  # SMB vulnerability detection
  nmap --script=smb-vuln-* -p 445 target.com

  # SSL/TLS analysis
  nmap --script=ssl-enum-ciphers -p 443 target.com

  # DNS zone transfer
  nmap --script=dns-zone-transfer -p 53 ns1.example.com

  # Database enumeration
  nmap --script=mysql-info -p 3306 target.com
  ```
]

#slide(title: "NMAP Practical Workflow")[
  == Four-Phase Approach:

  *Phase 1: Discovery*
  ```bash
  nmap -sn 192.168.1.0/24 -oA discovery
  ```

  *Phase 2: Port Scanning*
  ```bash
  nmap -iL live_hosts.txt -p- --open -T4 -oA ports
  ```

  *Phase 3: Service Enumeration*
  ```bash
  nmap -sV -sC -O -oA services target
  ```

  *Phase 4: Vulnerability Assessment*
  ```bash
  nmap --script=vuln -oA vulns target
  ```
]

#slide(title: "Interpreting NMAP Results")[
  *Port States:*

  - *open* - Service actively accepting connections
  - *closed* - Port accessible but no service listening
  - *filtered* - Firewall blocking probe (inconclusive)
  - *unfiltered* - Port accessible but state undetermined
  - *open|filtered* - Cannot determine (UDP scans)
  - *closed|filtered* - Cannot determine (rare)
]

#slide(title: "Common Port Numbers")[
  #table(
    columns: (auto, auto, 1fr),
    align: (center, left, left),
    table.header([*Port*], [*Service*], [*Description*]),
    [22], [SSH], [Secure Shell],
    [80], [HTTP], [Web traffic],
    [443], [HTTPS], [Encrypted web],
    [3389], [RDP], [Remote Desktop],
    [445], [SMB], [Windows file sharing],
    [3306], [MySQL], [MySQL database],
    [5432], [PostgreSQL], [PostgreSQL database],
    [8080], [HTTP-ALT], [Alternative HTTP],
  )
]

#section-slide(title: "Enumeration")

#slide(title: "What is Enumeration?")[
  *Aggressive phase of information gathering*

  - Extract granular details from identified services
  - Drill deep into specific targets
  - User accounts, shares, configurations
  - Bridge between scanning and exploitation
]

#slide(title: "Enumeration Process")[
  1. Identify service/protocol
  2. Query service for detailed information
  3. Extract data systematically
  4. Validate findings
  5. Document for exploitation phase
]

#slide(title: "SMB/NetBIOS Enumeration")[
  #grid(
    columns: (1fr, 1fr),
    gutter: 6mm,
    align: (top),
  )[
    *Windows network information extraction*

    *Ports:* 137, 139, 445

    ```bash
    # Comprehensive SMB enumeration
    enum4linux -a 192.168.1.10

    # List shares
    smbclient -L //192.168.1.10 -N

    # Share mapping
    smbmap -H 192.168.1.10
    ```
  ][
    *Information Extracted:*
    - Workgroup/domain, OS version
    - Users, groups, password policies
    - Network shares and permissions
  ]
]

#slide(title: "SNMP Enumeration")[
  *Network device configuration extraction*

  *Port:* 161 (UDP)

  ```bash
  # Walk entire MIB tree
  snmpwalk -v 2c -c public 192.168.1.1

  # Comprehensive enumeration
  snmp-check 192.168.1.1

  # Community string scanner
  onesixtyone -c community.txt 192.168.1.0/24
  ```

  *Common Community Strings:* public, private, manager, admin
]

#slide(title: "LDAP Enumeration")[
  #grid(
    columns: (1fr, 1fr),
    gutter: 6mm,
    align: (top),
  )[
    *Directory services (Active Directory)*

    *Ports:* 389 (LDAP), 636 (LDAPS)

    ```bash
    # Query LDAP directory
    ldapsearch -x -h 192.168.1.10 -s base

    # Extract all users
    ldapsearch -x -h 192.168.1.10 \
      -b "dc=example,dc=com" \
      "(objectClass=person)"
    ```
  ][
    *Information Extracted:*
    - Domain structure, user accounts
    - Group memberships, password policies
    - Service accounts, privileged groups
  ]
]

#slide(title: "DNS Enumeration")[
  #grid(
    columns: (1fr, 1fr),
    gutter: 6mm,
    align: (top),
  )[
    *Discover subdomains and network infrastructure*

    *Port:* 53

    ```bash
    # Zone transfer attempt
    dig @ns1.example.com example.com AXFR

    # Comprehensive DNS enumeration
    dnsenum example.com

    # Subdomain discovery
    sublist3r -d example.com
    amass enum -d example.com
    ```
  ][
    *Information Extracted:*
    - All DNS records (A, MX, TXT, NS, CNAME)
    - Subdomains, mail servers, name servers
  ]
]

#slide(title: "Database Enumeration")[
  *Extract database versions, schemas, users*

  ```bash
  # MySQL
  nmap --script mysql-info,mysql-databases \
    -p 3306 192.168.1.10

  # PostgreSQL
  nmap --script pgsql-brute \
    -p 5432 192.168.1.10

  # MSSQL
  nmap --script ms-sql-info,ms-sql-config \
    -p 1433 192.168.1.10
  ```
]

#slide(title: "Enumeration Workflow")[
  *Systematic approach:*

  ```bash
  # SMB/NetBIOS (ports 139/445)
  enum4linux -a 192.168.1.10 | tee enum4linux.txt

  # SNMP (port 161)
  snmp-check 192.168.1.10 | tee snmp.txt

  # LDAP (port 389)
  ldapsearch -x -h 192.168.1.10 -s base | tee ldap.txt

  # HTTP/HTTPS (ports 80/443)
  nikto -h http://192.168.1.10 | tee nikto.txt
  gobuster dir -u http://192.168.1.10 \
    -w /usr/share/wordlists/dirb/common.txt
  ```
]

#section-slide(title: "Best Practices")

#slide(title: "NMAP Best Practices")[
  *Performance:*
  - Use `-T4` for reliable networks
  - Scan top ports first: `--top-ports 1000`
  - Parallelize: scan multiple targets simultaneously
  - Use `--min-rate` and `--max-rate` for rate control

  *Stealth:*
  - SYN scans (`-sS`) over connect scans
  - Randomize: `--randomize-hosts`
  - Fragment packets: `-f`
  - Slow timing: `-T0` or `-T1`
]

#slide(title: "Legal and Ethical Considerations")[
  #color-block(
    title: [Critical:],
    [
      *Always obtain written authorization before scanning*
    ],
  )

  *Requirements:*
  - Stay within defined scope (IP ranges, ports)
  - Use appropriate timing to avoid DoS
  - Document all scan activities with timestamps
  - Respect bandwidth and system resources
]

#slide(title: "Common NMAP Errors")[
  *"You requested a scan type which requires root privileges"*
  - Solution: Use `sudo nmap` or run as administrator

  *"Note: Host seems down"*
  - Solution: Use `-Pn` to skip host discovery
  - Try different discovery methods: `-PS`, `-PA`, `-PU`

  *Slow UDP scans*
  - Solution: Scan only essential UDP ports: `--top-ports 20`
  - Increase parallelism: `--min-parallelism 100`
]

#slide(title: "Defensive Countermeasures")[
  *Organizations can limit enumeration:*

  - Disable unnecessary services
  - Change default SNMP community strings
  - Block anonymous SMB enumeration
  - Require LDAP authentication
  - Disable DNS zone transfers
  - Remove verbose error messages
  - Monitor enumeration attempts
  - Rate limiting and honeypots
]

#section-slide(title: "Key Takeaways")

#slide(title: "Summary")[
  *Critical Points:*

  - Information gathering is systematic, not random
  - NMAP is the foundational tool for network reconnaissance
  - Enumeration provides granular details for exploitation
  - Different services require different enumeration techniques
  - Always operate within legal and authorized boundaries
  - Combine automated tools with manual verification
  - Document everything for reporting
  - Defenders should enumerate their own systems regularly
]

#slide(title: "Practical Next Steps")[
  *Hands-on Practice:*
  1. Install NMAP and explore help: `nmap --help`
  2. Scan your own systems (with permission)
  3. Practice NSE scripts on lab environments
  4. Learn enumeration tools: enum4linux, ldapsearch
  5. Set up detection for NMAP scans

  *Resources:*
  - NMAP Documentation: nmap.org/book
  - NMAP NSE Scripts: nmap.org/nsedoc
  - HackTheBox and TryHackMe
]

#title-slide()
