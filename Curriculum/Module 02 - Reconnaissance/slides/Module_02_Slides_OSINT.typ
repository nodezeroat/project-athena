#import "../../../typst-athena-slides-template/1.0.1/src/lib.typ": *

#show: athena-theme.with(
  font: "Berkeley Mono",
  config-info(
    title: [Module 02: Reconnaissance],
    subtitle: [Open Source Intelligence (OSINT)],
    authors: [*Project Athena*],
    extra: [],
    footer: [Module 02 - OSINT],
  ),
  config-common(
    handout: false,
  ),
)

#title-slide()

#slide(title: "What is OSINT?")[
  *Open Source Intelligence:* Collecting, analyzing, and making decisions based on publicly available information.

  *Key Characteristics:*
  - Publicly accessible (no unauthorized access)
  - Diverse sources (web, social media, public records)
  - Requires analysis (raw data → actionable intelligence)
  - Legal and ethical when done properly
  - Continuous process, not one-time activity

  Unlike classified intelligence, OSINT uses data anyone can legally access.
]

#slide(title: "Why OSINT Matters in Cybersecurity")[
  *Purpose:*
  - *Pre-engagement reconnaissance* - Understand target before testing
  - *Threat intelligence* - Identify threat actors and TTPs
  - *Vulnerability assessment* - Discover exposed assets
  - *Social engineering prep* - Gather information for targeted attacks
  - *Incident response* - Investigate breaches and attribute attacks
  - *Brand protection* - Monitor for impersonation and leaks
]

#section-slide(title: "Types of OSINT")

#slide(title: "1. Personal OSINT (PERSINT)")[
  *Gathering information about individuals*

  *Sources:*
  - Social media (LinkedIn, Twitter, Facebook, Instagram)
  - Public records (property, court documents, voter registration)
  - Data breach databases (Have I Been Pwned, Dehashed)
  - People search engines (Spokeo, Pipl)
  - Resume websites, GitHub profiles
  - Photo metadata (EXIF data)
]

#slide(title: "1. Personal OSINT (PERSINT)")[
  *Information to Collect:*
  - Contact information, employment history
  - Family members, interests, affiliations
  - Security question answers (pet names, birthplaces)
]

#slide(title: "Personal OSINT: Example Workflow")[
  1. Start with known identifier (email, username, phone)
  2. Search social media platforms
  3. Use reverse image search on profile photos
  4. Check data breach databases
  5. Search public records and people search engines
  6. Map relationships and connections
  7. Timeline activities and behavioral patterns

  *Result:* Comprehensive personal profile for social engineering or investigation
]

#slide(title: "2. Organizational OSINT (CORPINT)")[
  *Information about companies and organizations*

  *Sources:*
  - Corporate websites, press releases
  - SEC filings and financial reports
  - Job postings and career pages
  - LinkedIn company pages and employee profiles
  - Business registrations, patents, trademarks
  - News articles, conference presentations
  - Technology stack indicators
]

#slide(title: "2. Organizational OSINT (CORPINT)")[
  *Before pentest, collect:*
  - Employee names (username wordlists)
  - Email format (`first.last@company.com`)
  - Technologies in use (from job posts)
  - Office locations, organizational chart
]

#slide(title: "3. Technical OSINT (TECHINT)")[
  *Network, domain, and infrastructure information*

  *Sources:*
  - WHOIS databases
  - DNS records, SSL/TLS certificates
  - Shodan, Censys (device search engines)
  - BGP routing data, IP geolocation
  - Web archives (Wayback Machine)
  - GitHub/Pastebin (code leaks)
  - CVE databases
]

#slide(title: "3. Technical OSINT (TECHINT)")[
  *Information to Collect:*
  - Domain registration, IP ranges, subdomains
  - Open ports, exposed services
  - Email servers, SPF/DKIM/DMARC configs
  - Exposed credentials or API keys
]

#slide(title: "Technical OSINT: Tools")[
  ```bash
  # WHOIS lookup
  whois example.com
  # DNS enumeration
  dig example.com ANY
  host -t mx example.com
  # Subdomain discovery
  sublist3r -d example.com
  amass enum -d example.com
  # Certificate transparency
  Visit: https://crt.sh/?q=%.example.com
  # Shodan search
  shodan search "hostname:example.com"
  ```
]

#slide(title: "4. Geospatial OSINT (GEOINT)")[
  *Physical locations and spatial relationships*

  *Sources:*
  - Google Maps / Google Earth
  - Satellite imagery (Planet Labs, Sentinel Hub)
  - Street view services
  - Geotagged social media posts
  - Photo metadata (EXIF data)
  - Flight/ship tracking (FlightRadar24, Marine Traffic)
  - Webcams and public cameras
]

#slide(title: "4. Geospatial OSINT (GEOINT)")[
  *Information to Collect:*
  - Facility layouts, entry/exit points
  - Physical security measures
  - Employee parking, surveillance cameras
  - Timezone and working hours patterns
]

#section-slide(title: "OSINT Tools and Frameworks")

#slide(title: "Search Engines and Aggregators")[
  *Traditional Search:*
  - Google, Bing, DuckDuckGo
  - Yandex (excellent image search)

  *Specialized Search Engines:*
  - *Shodan* - Internet-connected devices
  - *Censys* - Internet-wide scan data
  - *ZoomEye* - Cyberspace search
  - *BinaryEdge* - Internet scanning
  - *Greynoise* - Background noise analysis
]

#slide(title: "Social Media Intelligence (SOCMINT)")[
  *Tools:*
  - *Twint* - Twitter intelligence (no API required)
  - *Sherlock* - Find usernames across social networks
  - *Maigret* - Account information by username
  - *Social-Searcher* - Multi-platform search

  ```bash
  # Find username across platforms
  sherlock username123

  # Check email registration
  holehe email@example.com
  ```
]

#slide(title: "Email and Username Investigation")[
  ```bash
  # theHarvester - email harvesting
  theHarvester -d example.com -b google,linkedin

  # h8mail - email breach search
  h8mail -t target@example.com

  # Sherlock - username search
  sherlock username123
  ```

  *Data Breach Databases:*
  - Have I Been Pwned
  - Dehashed
  - LeakCheck
  - Snusbase
]

#slide(title: "Domain and Network Tools")[
  *Essential Tools:*
  - *WHOIS* - Domain registration info
  - *DNSdumpster* - DNS reconnaissance
  - *SecurityTrails* - DNS and domain data
  - *Sublist3r* - Subdomain enumeration
  - *Amass* - Attack surface mapping
  - *Spiderfoot* - Automated OSINT collection

  *Certificate Transparency:*
  - crt.sh - Search SSL/TLS certificates for subdomains
]

#slide(title: "OSINT Frameworks")[
  *Maltego:*
  - Visual link analysis and data mining
  - Transform data relationships into graphs
  - Integrates with numerous data sources

  *Recon-ng:*
  - Web reconnaissance framework
  - Modular Python-based tool
  - Database-driven methodology

  *SpiderFoot:*
  - Automated OSINT collection
  - 200+ modules for different data sources
  - Web-based interface with correlation

  *OSINT Framework:* osintframework.com
]

#slide(title: "Recon-ng Example")[
  ```bash
  recon-ng
  workspaces create example_investigation
  db insert domains
    domain: example.com
  modules load recon/domains-hosts/hackertarget
  modules load recon/domains-contacts/whois_pocs
  run
  show hosts
  ```

  *Benefits:*
  - Modular approach
  - Database stores all findings
  - Extensible with custom modules
]

#slide(title: "Image and Metadata Analysis")[
  *Tools:*
  - *ExifTool* - Read/write metadata in images
  - *Google Images Reverse Search*
  - *TinEye* - Reverse image search
  - *Yandex Images* - Often finds results Google misses

  *Use Cases:*
  - Extract GPS coordinates from photos
  - Find original source of images
  - Identify when/where photo was taken
  - Discover related images and profiles
]

#section-slide(title: "Practical OSINT Workflows")

#slide(title: "Workflow 1: Company Reconnaissance")[
  *Objective:* Gather intelligence about target organization

  *Steps:*
  1. Domain Discovery: `whois`, `amass`, `sublist3r`
  2. Employee Enumeration: LinkedIn search, theHarvester
  3. Technology Stack: Job postings, Wappalyzer, GitHub
  4. Infrastructure Mapping: Shodan, Censys
  5. Document and Analyze: Maltego for visualization

  *Result:* Comprehensive organizational profile with employees, tech stack, and infrastructure
]

#slide(title: "Workflow 2: Person Investigation")[
  *Objective:* Build comprehensive profile of individual

  *Steps:*
  1. Initial Discovery: Search engines, social media
  2. Username Search: Sherlock across platforms
  3. Social Media Analysis: Posts, photos, connections
  4. Public Records: Property, court documents
  5. Digital Footprint: Breach databases, historical data

  *Result:* Timeline of activities, relationships, potential social engineering vectors
]

#slide(title: "Workflow 3: Threat Actor Attribution")[
  *Objective:* Identify and profile threat actor

  *Steps:*
  1. IOC Collection: IP addresses, domains, usernames
  2. Infrastructure Analysis: Passive DNS, WHOIS history
  3. OPSEC Failures: Re-used credentials, patterns
  4. Dark Web Research: Forums, marketplaces
  5. Correlation: Link to known groups (MISP, AlienVault OTX)

  *Result:* Attribution to threat group with supporting evidence
]

#section-slide(title: "Hands-on Exercise")

#slide(title: "Exercise 1: Self-OSINT Audit")[
  *Perform OSINT on yourself:*

  1. Google yourself (name in quotes with variations)
  2. Social media audit (list all accounts)
  3. Data breach check (Have I Been Pwned)
  4. Username search (Sherlock)
  5. Image search (reverse search profile photos)
  6. Public records search
  7. Professional presence (LinkedIn, GitHub)

  *Document:*
  - What's publicly available?
  - What could be used for social engineering?
  - What should be removed or made private?
]

#slide(title: "Exercise 2: Company OSINT")[
  *Choose a company (with permission):*

  1. Run WHOIS and DNS enumeration
  2. Enumerate subdomains (Sublist3r)
  3. Search Shodan for exposed services
  4. Identify 5-10 employees on LinkedIn
  5. Determine email format
  6. Identify technologies from job postings
  7. Create simple organizational chart

  *Result:* Understanding of organization's digital footprint
]

#slide(title: "Exercise 3: Geolocation Challenge")[
  *Take a photo and geolocate it:*

  1. Extract EXIF data (ExifTool)
  2. Identify landmarks and distinctive features
  3. Google Images reverse search
  4. Compare with Google Street View
  5. Determine approximate location
  6. Verify using multiple sources

  *Skills:* Visual analysis, metadata extraction, verification
]

#section-slide(title: "Ethical and Legal Considerations")

#slide(title: "Legal Boundaries")[
  *Public vs. Private:*
  - Accessible ≠ legal to collect
  - Terms of Service violations (civil, not criminal)
  - Anti-scraping laws (CFAA in U.S., Computer Misuse Act in U.K.)
  - Data protection (GDPR in EU)
  - Purpose matters (research vs. harassment)

  #color-block(
    title: [Remember:],
    [
      Just because you *can* find information doesn't mean you *should* collect it
    ],
  )
]

#slide(title: "Ethical Guidelines")[
  1. *Respect Privacy* - Don't cross into stalking/harassment
  2. *Use Responsibly* - Information can harm if misused
  3. *Consider Impact* - Think about consequences
  4. *Lawful Purpose* - Only for legitimate reasons
  5. *Transparent Intent* - Be honest about why
  6. *Secure Storage* - Protect gathered intelligence
  7. *Minimize Harm* - Avoid unnecessary exposure

  *Golden Rule:* Would you be comfortable if someone did this to you?
]

#slide(title: "OSINT for Defense")[
  *Organizations should conduct OSINT on themselves:*

  - *Information Leakage Audit* - What's exposed?
  - *Employee Exposure* - Staff oversharing on social media?
  - *Shadow IT Discovery* - Find forgotten assets
  - *Brand Monitoring* - Detect impersonation/fraud
  - *Data Breach Monitoring* - Check for leaked credentials
  - *Competitive Intelligence* - Understand your visibility

  *Frequency:* Quarterly audits recommended
]

#section-slide(title: "Defensive Measures")

#slide(title: "Personal Protection")[
  *Protect Your Digital Footprint:*

  - Configure social media for maximum privacy
  - Use different emails/usernames for different purposes
  - Remove EXIF data before posting images
  - Limit what you share publicly
  - Use unique passwords (prevent credential stuffing)
  - Regular self-OSINT to find exposures
  - Opt-out from data broker/people search sites
]

#slide(title: "Organizational Protection")[
  *Reduce OSINT Attack Surface:*

  - Employee training on OSINT risks
  - Information classification policies
  - Review job postings (don't reveal too much)
  - WHOIS privacy on domain registrations
  - Breach monitoring for credentials
  - Vendor assessment (third-party exposure)
  - Regular self-OSINT audits

  *Balance:* Transparency for business vs. security
]

#section-slide(title: "Key Takeaways")

#slide(title: "Summary")[
  *Critical Points:*

  - OSINT leverages publicly available information
  - Four main types: Personal, Organizational, Technical, Geospatial
  - Numerous specialized tools for different OSINT tasks
  - Legal and ethical considerations are paramount
  - Valuable for both offensive and defensive security
  - Everyone should understand their digital footprint
  - Organizations must balance transparency with security
  - OSINT skills transferable across many domains
]

#slide(title: "OSINT in the Kill Chain")[
  *Cyber Kill Chain Integration:*

  1. *Reconnaissance* - Passive OSINT gathering
  2. *Weaponization* - Use OSINT to craft targeted attacks
  3. *Delivery* - OSINT informs delivery method
  4. *Exploitation* - Technical OSINT reveals vulnerabilities

  *Defensive Focus:*
  - Understand attacker perspective
  - Reduce attack surface exposure
  - Detect reconnaissance activities
  - Build threat intelligence
]

#slide(title: "Resources")[
  *Books:*
  - "Open Source Intelligence Techniques" by Michael Bazzell
  - "OSINT Essentials" by Justin Seitz
  - "We Are Bellingcat" by Eliot Higgins

  *Websites:*
  - OSINT Framework: osintframework.com
  - Bellingcat Toolkit
  - Intel Techniques: inteltechniques.com

  *Practice:*
  - TryHackMe OSINT Room
  - Trace Labs (OSINT CTF for missing persons)
  - Sector035 OSINT Challenges
]

#title-slide()
