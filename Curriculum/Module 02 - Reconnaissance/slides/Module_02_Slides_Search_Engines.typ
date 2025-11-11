#import "../../../typst-athena-slides-template/1.0.1/src/lib.typ": *

#show: athena-theme.with(
  font: "Berkeley Mono",
  config-info(
    title: [Module 02: Reconnaissance],
    subtitle: [Search Engines for Reconnaissance],
    authors: [*Project Athena*],
    extra: [],
    footer: [Module 02 - Search Engines],
  ),
  config-common(
    handout: false,
  ),
)

#title-slide()

#slide(title: "Search Engines for Reconnaissance")[
  *Evolution Beyond Web Pages*

  Modern search engines provide powerful reconnaissance capabilities:
  - Traditional web search (Google, Bing)
  - Specialized cybersecurity platforms (Shodan, Censys)
  - Discover vulnerable devices, exposed data, network infrastructure
  - Map attack surfaces without directly interacting with targets

  *Key Advantage:* Passive reconnaissance - search engine queries, not target systems
]

#section-slide(title: "Google Dorking (Google Hacking)")

#slide(title: "What is Google Dorking?")[
  *Definition:* Using advanced Google search operators to find security-related information, vulnerabilities, and sensitive data.

  *Why It Works:*
  - Organizations unintentionally expose sensitive information
  - Google's aggressive crawling indexes this data
  - Specific query operators make it searchable
  - Misconfigured servers, forgotten backups, exposed documents

  *Also called:* Google Hacking, Google Fu
]

#slide(title: "Basic Google Operators")[
  *site:* - Limit results to specific domain
  ```
  site:example.com
  site:*.example.com
  ```

  *filetype:* or *ext:* - Search for specific file types
  ```
  site:example.com filetype:pdf
  site:example.com ext:xls
  ```

  *inurl:* - Search for terms in URL
  ```
  inurl:admin
  site:example.com inurl:login
  ```
]

#slide(title: "More Google Operators")[
  *intitle:* - Search for terms in page title
  ```
  intitle:"index of"
  intitle:"dashboard" inurl:admin
  ```

  *intext:* - Search for terms in page body
  ```
  intext:"confidential" site:example.com
  intext:"password" filetype:log
  ```

  *cache:* - View Google's cached version
  ```
  cache:example.com
  ```
]

#slide(title: "Google Dorks: Exposed Directories")[
  *Find directory listings and backups:*

  ```
  intitle:"index of" "parent directory"
  intitle:"index of" "backup"
  intitle:"index of" ".git"
  intitle:"index of" "database"
  ```

  *Result:* Exposed file structures that shouldn't be public

  *Example Finding:*
  - Backup files with database dumps
  - Git repositories with source code
  - Configuration files
  - Password files
]

#slide(title: "Google Dorks: Configuration Files")[
  *Find sensitive configuration files:*

  ```
  site:example.com ext:conf OR ext:config OR ext:cfg
  site:example.com inurl:web.config
  filetype:env "DB_PASSWORD"
  ```

  *Common Findings:*
  - Database credentials
  - API keys and tokens
  - Server configurations
  - Environment variables

  *Real Risk:* Direct access to authentication credentials
]

#slide(title: "Google Dorks: Credentials")[
  *Search for exposed credentials:*

  ```
  site:example.com intext:"password" filetype:xls
  site:example.com filetype:txt "username" "password"
  "index of" intext:credentials
  filetype:log intext:password
  ```

  *GitHub/Pastebin Searches:*
  ```
  site:github.com "API_KEY"
  site:github.com "aws_secret_access_key"
  site:pastebin.com "password" "database"
  ```
]

#slide(title: "Google Dorks: Server Information")[
  *Identify server types and versions:*

  ```
  intitle:"Apache Status" "Server Version"
  intitle:"IIS7" "Detailed Error"
  intitle:"phpinfo()" "PHP Version"
  ```

  *Value for Attackers:*
  - Exact software versions
  - Can match against CVE databases
  - Identify unpatched systems
  - Error messages reveal internal paths
]

#slide(title: "Google Hacking Database (GHDB)")[
  *Exploit Database maintains curated Google dorks*

  *Categories:*
  - Footholds (login pages, vulnerable apps)
  - Files containing usernames
  - Sensitive directories
  - Web server detection
  - Vulnerable files and servers
  - Error messages (information disclosure)
  - Files with passwords, financial data, PII
  - Online shopping info

  *Access:* exploit-db.com/google-hacking-database
]

#slide(title: "Google Dorking Workflow")[
  *Systematic Approach:*

  *Phase 1:* Domain Enumeration
  ```
  site:example.com
  site:*.example.com
  ```

  *Phase 2:* Subdomain Discovery
  ```
  site:*.example.com -www
  ```

  *Phase 3:* Technology Identification
  ```
  site:example.com "powered by"
  site:example.com inurl:wp-content
  ```

  *Phase 4:* Sensitive File Discovery
  ```
  site:example.com filetype:pdf confidential
  site:example.com ext:sql
  ```
]

#section-slide(title: "Shodan: Internet Device Search")

#slide(title: "What is Shodan?")[
  *"The search engine for everything connected to the internet"*

  *Created:* John Matherly (2009)

  *What Shodan Indexes:*
  - Web servers and banners
  - Industrial Control Systems (ICS/SCADA)
  - Network devices (routers, switches, firewalls)
  - IoT devices, webcams, surveillance systems
  - Databases exposed to internet
  - Medical equipment, building management systems
  - Power grid components

  *Unlike Google:* Indexes devices directly, not web pages
]

#slide(title: "How Shodan Works")[
  1. *Scanning* - Continuously scans IPv4 address space
  2. *Banner Grabbing* - Captures service banners with versions
  3. *Indexing* - Stores data in searchable database
  4. *Categorization* - Tags by type, location, organization
  5. *Vulnerability Matching* - Cross-references with CVEs

  *Ports Scanned:*
  - Common: 21, 22, 23, 25, 80, 443, 3389
  - Databases: 3306, 5432, 27017
  - Industrial: 102, 502, 1883
  - And hundreds more...
]

#slide(title: "Shodan Basic Searches")[
  *Search by hostname:*
  ```
  hostname:example.com
  ```

  *Search by IP:*
  ```
  ip:192.168.1.1
  net:192.168.1.0/24
  ```

  *Search by port:*
  ```
  port:22
  port:3389
  ```

  *Search by country/city:*
  ```
  country:US
  city:"New York"
  ```
]

#slide(title: "Shodan Advanced Filters")[
  *Operating System:*
  ```
  os:"Windows"
  os:"Linux"
  ```

  *Product/Software:*
  ```
  product:"Apache"
  product:"nginx"
  product:"MySQL"
  ```

  *Version:*
  ```
  version:"2.4.41"
  product:Apache version:2.4
  ```

  *Vulnerability (CVE):*
  ```
  vuln:CVE-2021-44228 (Log4Shell)
  vuln:CVE-2017-0144 (EternalBlue)
  ```
]

#slide(title: "Shodan Practical Queries")[
  *Find Webcams:*
  ```
  "webcam" has_screenshot:true
  "Server: IP Webcam Server"
  ```

  *Find Remote Desktop:*
  ```
  port:3389 country:US
  "Remote Desktop Protocol"
  ```

  *Find Exposed Databases:*
  ```
  port:27017 product:"MongoDB"
  "MongoDB" -authentication
  port:3306 "MySQL" -authentication
  ```
]

#slide(title: "Shodan for Organizations")[
  *Find Industrial Control Systems:*
  ```
  "Modbus"
  port:502
  "Siemens" country:US
  ```

  *Find Vulnerable Systems:*
  ```
  vuln:CVE-2017-0144
  product:Apache version:2.4.49
  ```

  *Find Your Organization:*
  ```
  org:"Your Company Name"
  hostname:yourcompany.com has_screenshot:true
  ```
]

#slide(title: "Shodan CLI and API")[
  *Command Line Interface:*
  ```bash
  # Install
  pip install shodan

  # Initialize
  shodan init YOUR_API_KEY

  # Search
  shodan search "hostname:example.com"

  # Get host info
  shodan host 8.8.8.8

  # Count results
  shodan count "apache"
  ```
]

#slide(title: "Shodan API Example")[
  *Python API:*
  ```python
  import shodan

  api = shodan.Shodan('YOUR_API_KEY')

  # Search Shodan
  results = api.search('hostname:example.com')

  print(f'Results found: {results["total"]}')

  for result in results['matches']:
      print(f'IP: {result["ip_str"]}')
      print(f'Port: {result["port"]}')
      print(f'Data: {result["data"]}')
  ```
]

#slide(title: "Shodan Alternatives")[
  *Censys* (censys.io)
  - Focus on SSL/TLS certificates
  - Better subdomain discovery via cert transparency
  - Free academic access

  *ZoomEye* (zoomeye.org)
  - Chinese alternative
  - Good Asian network coverage

  *BinaryEdge* (binaryedge.io)
  - Comprehensive scanning
  - DNS, Tor, Torrents

  *Greynoise* (greynoise.io)
  - Internet background noise
  - Distinguishes malicious vs. benign scanning
]

#section-slide(title: "Other Specialized Search Engines")

#slide(title: "Certificate Transparency (crt.sh)")[
  *Search SSL/TLS certificates for subdomains*

  *Use Cases:*
  - Subdomain enumeration
  - Find all domains owned by organization
  - Discover forgotten or test domains

  *Query:*
  ```
  %.example.com
  ```

  *URL:* crt.sh

  *Why Effective:* Certificate transparency logs are public, comprehensive, and hard to hide
]

#slide(title: "GitHub and Pastebin Search")[
  *GitHub Code Search:*
  - Find leaked credentials in public repos
  - Discover API keys and tokens
  - Identify technology stack

  ```
  org:company_name password
  filename:.env DB_PASSWORD
  "authorization: Bearer"
  ```

  *Pastebin Search* (psbdmp.ws)
  - Monitor pastes mentioning organization
  - Find leaked credentials or data
  - Track data breaches
]

#slide(title: "Wayback Machine")[
  *Internet Archive* (archive.org/web)

  *View historical versions of websites*

  *Use Cases:*
  - See old employee directories
  - Find removed documentation
  - Discover changed infrastructure
  - Recover deleted content
  - Find old vulnerabilities or information

  *Example:* Old contact page reveals employee email format no longer on current site
]

#section-slide(title: "Ethical and Legal")

#slide(title: "Legal Considerations")[
  *Passive Nature:*
  - Querying search engine, not target directly
  - Information already publicly accessible

  *BUT - Legal Gray Areas:*
  - Accessing exposed data may still violate laws (CFAA)
  - Some jurisdictions consider accessing misconfigured systems illegal
  - Terms of service violations can have consequences

  #color-block(
    title: [Important:],
    [
      Finding is reconnaissance; *accessing* is intrusion
    ]
  )
]

#slide(title: "Responsible Use")[
  *Guidelines:*

  1. *Don't access exposed systems* - Just document findings
  2. *Responsible disclosure* - Report serious exposures
  3. *Authorization required* - Only access permitted systems
  4. *Document findings* - Keep records of discoveries

  *Notification Dilemma:*
  - If you find medical records, financial data exposed
  - Consider responsible disclosure to organization
  - Report to CERT/CC or similar
  - Balance risk of notification vs. risk of exposure
  - Document decision-making
]

#section-slide(title: "Defensive Measures")

#slide(title: "Preventing Search Engine Exposure")[
  *1. robots.txt Configuration*
  ```
  User-agent: *
  Disallow: /admin/
  Disallow: /config/
  Disallow: /backup/
  ```
  Note: Doesn't prevent crawling, only requests it

  *2. Remove from Index*
  - Google Search Console: Request URL removal
  - Meta tags: `<meta name="robots" content="noindex">`
  - X-Robots-Tag HTTP header

  *3. Authentication and Access Controls*
  - Don't rely on "security through obscurity"
  - Proper access controls, not just hidden URLs
]

#slide(title: "Shodan Protection")[
  *1. Minimize Internet Exposure*
  - Only expose services that must be public
  - Use VPN for administrative access
  - Network segmentation

  *2. Regular Shodan Audits*
  ```bash
  # Monitor your organization
  shodan search 'org:"Your Company"'

  # Monitor your IP ranges
  shodan host YOUR_IP_ADDRESS
  ```

  *3. Set Up Alerts*
  - Use Shodan monitoring service
  - Alert on new exposed services
  - Track changes in footprint
]

#slide(title: "Defensive Monitoring")[
  *Regular Searches:*
  ```
  site:yourcompany.com filetype:pdf confidential
  site:yourcompany.com intitle:"index of"
  site:yourcompany.com ext:sql
  org:"Your Company" vuln:*
  ```

  *Actions:*
  - Quarterly self-audits
  - Remove sensitive content from search results
  - Fix misconfigurations
  - Implement proper access controls
  - Monitor for new exposures
]

#slide(title: "Banner Modification")[
  *Reduce Information Disclosure:*

  - Modify server banners to remove versions
  - Use generic responses
  - Don't advertise technology stack
  - Disable directory listing
  - Remove verbose error messages
  - Strip unnecessary headers

  *Example:*
  - Instead of: "Apache/2.4.29 (Ubuntu)"
  - Use: "Web Server"
]

#section-slide(title: "Practical Exercises")

#slide(title: "Exercise 1: Google Dorking")[
  *Find sensitive information (with permission):*

  1. `site:example.com`
  2. `site:example.com intitle:"index of"`
  3. `site:example.com (filetype:pdf OR filetype:xls)`
  4. `site:example.com (inurl:login OR inurl:admin)`
  5. `site:example.com "powered by"`

  *Document:*
  - What sensitive information found?
  - What file types exposed?
  - What technologies in use?
]

#slide(title: "Exercise 2: Shodan Reconnaissance")[
  *Understand your organization's footprint:*

  1. Search: `org:"Your Organization"`
  2. Search: `hostname:yourcompany.com`
  3. Analyze exposed services and ports
  4. Check vulnerabilities: `org:"Your Org" vuln:*`
  5. Document findings and risk assessment

  *Goal:* Understand what attackers see when they search for you
]

#slide(title: "Exercise 3: Certificate Transparency")[
  *Enumerate subdomains:*

  1. Visit crt.sh
  2. Search for `%.example.com`
  3. Compile list of discovered subdomains
  4. Cross-reference with DNS enumeration
  5. Identify previously unknown assets

  *Skills:* Subdomain discovery, asset inventory, certificate analysis
]

#section-slide(title: "Key Takeaways")

#slide(title: "Summary")[
  *Critical Points:*

  - Traditional search engines (Google, Bing) reveal sensitive data through dorking
  - Shodan and similar platforms index internet-connected devices
  - Search engine reconnaissance is passive but incredibly effective
  - Organizations must monitor their own search engine exposure
  - Legal and ethical considerations apply even to public data
  - Defensive reconnaissance helps understand attack surface
  - Combine multiple search engines for comprehensive coverage
  - Regular monitoring and mitigation reduces exposure
]

#slide(title: "Integration with Methodology")[
  *Search engines fit into reconnaissance:*

  1. *Passive* - No target logs generated
  2. *Early Phase* - Use before active scanning
  3. *Continuous* - New content indexed constantly
  4. *Validation* - Confirm technical findings
  5. *Intelligence* - Combine with OSINT for complete picture

  *Remember:* If search engine can find it, so can attacker—and search queries leave no traces on your systems!
]

#slide(title: "Resources")[
  *Google Hacking:*
  - Google Hacking Database: exploit-db.com/google-hacking-database
  - "Google Hacking for Penetration Testers" by Johnny Long

  *Shodan:*
  - Shodan: shodan.io
  - Shodan Documentation: help.shodan.io
  - "Complete Guide to Shodan" book

  *Practice:*
  - HackTheBox (boxes requiring search engine recon)
  - TryHackMe - Google Dorking Room
  - Shodan Training webinars
]

#title-slide()
