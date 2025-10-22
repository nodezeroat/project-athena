# Information Gathering

Information Gathering, also known as data gathering or reconnaissance, is the process of collecting various forms of data and information about a target system, network, or organization to understand its architecture, vulnerabilities, and security mechanisms. This process is typically the first step in planning a cyber attack or penetration test. It provides attackers or security professionals with a detailed perspective on the target environment, aiding in the identification of potential vulnerabilities and points of entry.

## NMAP (Network Mapper)

NMAP is a powerful open-source tool used for network discovery and security auditing. It can find devices running on a network and discover open ports along with various attributes of the network.

### Uses of NMAP

- **Host Discovery**: Identify active hosts on a network.
- **Port Scanning**: Determine open ports and services running on servers and network devices.
- **Version Detection**: Discover what application and version are running on open ports.
- **OS Detection**: Determine the operating system and hardware characteristics of network devices.

### Basic NMAP Commands

1. **Ping Scan**: `nmap -sn [target]`
1. **Port Scan**: `nmap [target]`
1. **Service Version Detection**: `nmap -sV [target]`
1. **Aggressive Scan**: `nmap -A [target]`

### Hands-on Exercise

- Run basic NMAP commands in a controlled environment.
- Analyze the results to identify active hosts, open ports, and services.

## Enumeration

Enumeration is the process of extracting detailed information about a network or infrastructure, often leading to discovering ways to infiltrate the system.

### Techniques in Enumeration

- **NetBIOS Enumeration**: Extracting information about network shares, users, and groups.
- **SNMP Enumeration**: Gathering data from network devices like routers, switches, and printers.
- **LDAP Enumeration**: Extracting information from LDAP directories.
- **SMTP Enumeration**: Gleaning information from mail servers.

### Tools for Enumeration

1. **Enum4linux**
1. **Nbtscan**
1. **SNMPwalk**

## Resources

- **NMAP Official Documentation**: [NMAP Documentation](https://nmap.org/book/man.html)
- **Books**: "Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Security Scanning" by Gordon Fyodor Lyon.
- **Enumeration Tools Documentation**:
  - Enum4linux: [Github Repository](https://github.com/portcullislabs/enum4linux)
  - Nbtscan: Information available on various cybersecurity websites.
  - SNMPwalk: Included in the NET-SNMP suite (<http://www.net-snmp.org/>)
