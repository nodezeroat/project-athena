# Introduction to Reconnaissance

Reconnaissance is the initial phase where attackers collect as much information as possible about their target to find vulnerabilities they can exploit. This phase is fundamental in the cyber attack lifecycle, where attackers find and analyze accessible information to plan their attack effectively.

## Types of Reconnaissance

### Passive Reconnaissance

**Definition:** Passive Reconnaissance involves gathering information without directly interacting with the target. This type of reconnaissance is discreet and often harder to detect.

#### Methods

- Utilizing search engines to find information related to the target.
- Examining public records or open databases.
- Scrutinizing social media platforms to gather personal and organizational information.

#### Tools and Techniques

- **Whois:** Retrieve domain registration and hosting information.
- **nslookup:** Query Domain Name System servers for domain-related details.

#### Example

- Gathering a list of email addresses and employee names associated with a specific domain.

### Active Reconnaissance

**Definition:** Involves collecting information by directly interacting with the target system, which is intrusive and can be easily detected.

#### Methods

- Network scanning to identify active devices, services, and ports.
- Sending packets to the target system to gather more information.

#### Tools and Techniques

- **NMAP:** A network scanning tool used to discover devices running on a network and find open ports along with various attributes of the network.
- **Netcat:** Utility to read from and write to network connections.

#### Example

- Scanning the target IP range to find open ports and services.

## Phases of Reconnaissance

1. **Information Gathering:**

   - Collect basic information such as domain names, IP address blocks, and network infrastructure.
   - Utilize tools like Whois, nslookup, and DNS interrogation tools.

1. **Identification:**

   - Identify specific servers, workstations, and network devices.
   - Use tools like NMAP and other network scanning utilities.

1. **Vulnerability Mapping:**

   - Identify potential vulnerabilities in systems, applications, or network configurations.
   - Employ vulnerability scanning tools like Nessus or OpenVAS.

## Real-World Example

### Case: The Target Corporation Breach (2013)

- **Reconnaissance Role:**
  - Attackers performed extensive reconnaissance to find a vulnerable third-party HVAC vendor.
  - Used the vendor’s credentials to infiltrate Target’s network.
  - Mapped out the internal network to plan the subsequent attack phases.

## Real-World Example

- **Case**: The Target Corporation Breach (2013)
- **Reconnaissance Role**: Attackers initially performed reconnaissance to find a vulnerable third-party vendor, leveraging this access to infiltrate Target's network.

## Resources

- <https://redriver.com/security/target-data-breach>
- <https://www.zdnet.com/article/anatomy-of-the-target-data-breach-missed-opportunities-and-lessons-learned/>
