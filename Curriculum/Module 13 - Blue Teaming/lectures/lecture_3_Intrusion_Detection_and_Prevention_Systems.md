# Intrusion Detection and Prevention Systems

## Introduction

- IDPS → combination of Intrusion Detection Systems (IDS) + Intrusion Prevention Systems (IPS)
- Nowadays a must-have to network security defenses, especially for detecting, tracking, and blocking malicious traffic and malware.
- IDPS has become part of advanced tools like next-generation firewalls (NGFW), SIEM, and Extended Detection and Response (XDR)

_source: Intrusion Detection and Prevention Systems \[1.\]_

## **IDS vs. IPS**

> Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) are two tools that network administrators use to identify cyber-attacks. IDS and IPS tools are both used to discover online threats but there is a distinct difference in how they operate and what they do.

Intrusion Detection Systems (IDS) → **diagnostic tool**

Intrusion Prevention Systems (IPS) → **diagnostic and incident response tool**

_source: Intrusion Detection and Prevention Systems \[3.\]_

### **Intrusion Detection Systems (IDS)**

1. **Functionality**
   - monitor network traffic and detect unusual or suspicious activities
   - identifies potential threats by comparing network activities to →
     - **previously recorded intrusion patterns (database)**
     - **baseline**
1. **Detection Techniques**
   - **Signature-Based Detection**
     - has a predefined database of attack patterns and signatures.
     - highly effective against known attacks but cannot detect new, unidentified attacks.
   - **Anomaly-Based Detection**
     - utilizing a baseline of normal network behavior, identifies deviations that could indicate a security threat.
     - often enhanced with AI and machine learning, can detect previously unknown attacks but are more prone to false positives.
1. **Limitations**
   - IDS primarily focuses on detection and alerting (not like IPS)
   - does not take action to block or prevent the detected threats → which means that human intervention or additional security measures are necessary for response.

_source: Intrusion Detection and Prevention Systems \[2.\]_

### **Intrusion Prevention Systems (IPS)**

1. **Functionality**
   - extends the capabilities of IDS → taking proactive measures
   - analyzes network traffic content and responds to exploits by blocking malicious traffic and preventing it from interacting with the network.
1. **Detection Techniques**
   - uses both signature-based and anomaly-based detection.
1. **Advantage Over IDS**
   - the advantage is obvious → is both a diagnostic and incident response tool
1. **Potential Disadvantages**
   - the possibility of more false positives due to its proactive blocking measures.
   - it may incorrectly identify legitimate activities as threats, leading to unintended blocking of traffic.

_source: Intrusion Detection and Prevention Systems \[3.\]_

## **A Combined Approach (IDPS)**

In many security infrastructures, IDS and IPS are combined into a single solution known as Intrusion Detection and Prevention Systems (IDPS). This approach integrates the strengths of both systems, offering comprehensive protection by detecting threats (IDS) and actively preventing them (IPS).

In summary, IDS and IPS serve complementary roles in network security. IDS excels at detecting and alerting, while IPS extends this functionality by actively preventing identified threats.

_source: Intrusion Detection and Prevention Systems \[1.\]_

## **Types of IDPS**

### **Host-Based IDPS (HIDPS)**

- HIDPS is deployed directly on individual hosts, such as servers
- focuses on protecting specific endpoints → scanning system files, unauthorized changes and processes running on the system
- effective in monitoring internal activities of a host

_source: Intrusion Detection and Prevention Systems \[1.\]_

### **Network-Based IDPS (NIDPS)**

- monitors network traffic (entire network segment or subnet)
- It's deployed in strategic network locations

_source: Intrusion Detection and Prevention Systems \[1.\]_

## **Recent Advancements in IDPS Technology**

### **Integration in other Solutions**

- IDPS increasingly merging with other advanced security solutions
  - next-generation firewalls (NGFW)
  - Security Information and Event Management (SIEM)
  - and Extended Detection and Response (XDR)
- This integration allows for a more comprehensive security posture, combining the strengths of each system to offer enhanced detection and prevention capabilities.

_source: Intrusion Detection and Prevention Systems \[1.\]_

### **Adoption of Machine Learning and AI**

- Modern IDPS solutions are increasingly using machine learning and AI → process massive data faster
- Detects what traditional signature and anomaly detection methods might miss
- Adjusts learnings practices and behaviours in real-time
- Allows IDPS to adapt quickly to new threats

_source: Intrusion Detection and Prevention Systems \[4.\], Intrusion Detection and Prevention Systems \[5.\]_

### **Industry Cloud Platforms**

- industry-specific cloud platforms offers scalability and functionality to unique industry needs.
- a more targeted approach → enhancing the effectiveness of IDPS in specific operational contexts.

_source: Intrusion Detection and Prevention Systems \[5.\]_

## Product Comparison

| IDPS Solution                        | Throughput     | Vulnerability & Threat Detection | Web & Network Security    | Malware Protection          | Traffic Analysis           | Additional Features          |
| ------------------------------------ | -------------- | -------------------------------- | ------------------------- | --------------------------- | -------------------------- | ---------------------------- |
| Trend Micro TippingPoint NGIPS       | Up to 100 Gbps | Yes                              | Deep pack inspection      | Yes                         | Inbound, outbound, lateral | High availability            |
| Cisco Firepower NGIPS                | Varies         | Embedded security intelligence   | Yes                       | Advanced malware protection | Yes                        | Application analysis         |
| Check Point IPS                      | Up to 1Tbps    | Yes                              | Multiple protocol support | Yes                         | Yes                        | Detailed reporting           |
| Trellix Network Security             | Up to 30 Gbps  | Yes                              | Intrusion prevention      | Yes                         | Yes                        | Self-learning detection      |
| Hillstone S-Series NIPS              | 1 to 12 Gbps   | Yes                              | Antivirus, URL filtering  | Yes                         | Yes                        | Cloud-based management       |
| NSFOCUS NGIPS                        | Up to 20Gbps   | Yes                              | Web security              | Yes                         | Yes                        | DDoS protection              |
| Palo Alto Networks Threat Prevention | -              | Yes                              | Decoder-based analysis    | Advanced malware analysis   | Yes                        | SSL decryption               |
| OSSEC HIDS                           | -              | File integrity monitoring        | -                         | Rootkit/malware detection   | Log-based                  | Compliance auditing          |
| Snort                                | -              | Yes                              | -                         | -                           | Protocol analysis          | Open-source                  |
| Alert Logic MDR                      | -              | Endpoint attack isolation        | -                         | -                           | Real-time visibility       | Managed services             |
| CrowdSec                             | -              | AI/ML                            | -                         | -                           | Behavioral analytics       | Open-source                  |
| SolarWinds Security Event Manager    | -              | -                                | -                         | -                           | Network visibility         | Compliance reporting         |
| Security Onion                       | -              | -                                | -                         | -                           | Comprehensive coverage     | Third-party tool integration |

_source: Intrusion Detection and Prevention Systems \[1.\]_

## References

1. <https://www.esecurityplanet.com/products/intrusion-detection-and-prevention-systems/>
2. <https://www.hindawi.com/journals/js/2023/6048087/>
3. <https://www.comparitech.com/net-admin/ids-vs-ips/>
4. <https://kirkpatrickprice.com/blog/idps-techniques/>
5. <https://rossum.ai/blog/2023-idp-trends/#:~:text=,continue>
