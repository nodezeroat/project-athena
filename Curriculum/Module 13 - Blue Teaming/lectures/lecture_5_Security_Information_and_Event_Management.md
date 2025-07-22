# Security Information and Event Management (SIEM)

## **Introduction**

- SIEM combines **security information management (SIM)** and **security event management (SEM)**
- **aggregating** and **analyzing** event data from various sources like applications, endpoints, firewalls, and networks.
- assists in quick identification of cyber threats through real-time threat monitoring and alerting capabilities.

_source: Security Information and Event Management \[1.\]_

## **Core Functions**

### **Data Correlation and Analysis**

- **Reactive Nature**: Traditional SIEM systems focused on reactive logging and event management.
- **Proactive Shift**: Recent trends show a shift towards more proactive measures, integrating new threat data for better issue identification.
- **AI Integration**: Adoption of AI tools in SIEM systems helps narrow alert windows and automate security responses, moving from reactive to proactive responses.

_source: Security Information and Event Management \[3.\]_

### **Event Log Management**

- **Essential Component**: Involves collection, normalization, and analysis of log data for network visibility and detecting security incidents.
- **Evolution and Challenges**: Modern SIEM solutions are evolving to address dynamic cybersecurity challenges, with an emphasis on cloud-based solutions for flexibility.
- **Combining with SOAR**: Integration with SOAR (Security Orchestration, Automation, and Response) tools extends the usability of SIEM tools, though they remain fundamentally reactive.

_source: Security Information and Event Management \[4.\]_

_source: Security Information and Event Management \[3.\]_

### **Monitoring and Alerting**

- **Real-Time Monitoring**: SIEM is crucial for real-time monitoring and alerting in cloud and on-premise infrastructures.
- **Automation and AI**: Increasing use of AI and automation in SIEM and SOAR tools to save time and improve efficiency in threat response.
- **Cloud Migration**: There is a growing trend to move SIEM and SOAR solutions to the cloud to support scalable resources and enhance automation capabilities.

_source: Security Information and Event Management \[4.\], Security Information and Event Management \[3.\]_

## **Key Capabilities**

- **Threat Analytics**
  - SIEM systems are evolving to address complex security threats, although they primarily focus on logging and event management
- **Cloud Security**
  - The advancement of cloud-based SIEM solutions since 2020 reflects the need for fast, flexible, and customizable security solutions
- **Integrated Compliance**
  - assists in regulatory compliance by continuously collecting and reporting network data in real-time
- **User Behavior Analytics (UBA)**
  - The integration of new threat data in SIEM systems aids in detecting potential phishing efforts and identifying compromise points, aligning with the user behavior analytics approach.
- **Alerting**
- **Incident Response**
  - Combining SIEM with SOAR (Security Orchestration, Automation, and Response) extends the usability of these tools. However, even this combination is reactive rather than proactive, indicating a need for solutions that fill these gaps, such as extended detection and response (XDR).

_source: Security Information and Event Management \[3.\], Security Information and Event Management \[5.\]_

## **Benefits**

- **Rapid Detection and Response**
  - shortens the time required to detect and identify threats
- **Forensic Analysis**
  - forensic investigation by providing detailed logs and historical data
- **Diverse Applications**
  - SIEM can be used for operations support, troubleshooting, and other activities revolving around data or historical logs

_source: Security Information and Event Management \[5.\]_

## **Challenges in Implementing SIEM**

- Requirement of integration with other solutions
- Extensive oversight and control needed from security experts
- Initial and ongoing costs
- Difficulty in differentiating between regular activities and incidents.

_source: Security Information and Event Management \[5.\]_

## Solution Comparison

| SIEM Solution                     | Best For                        | Key Features                                                               | Deployment Options          | Pricing                                                     |
| --------------------------------- | ------------------------------- | -------------------------------------------------------------------------- | --------------------------- | ----------------------------------------------------------- |
| Splunk Enterprise Security        | IT Observability                | Risk classification, threat intelligence, flexible deployment              | Various                     | Starting at $150/month for 1GB data/day                     |
| IBM Security QRadar SIEM          | Global Reach, Large Enterprises | AI and UBA integration, compliance resources, extensive integrations       | On-premises/Cloud           | Community: Free; Software: ~$320/month; SaaS: ~$2,340/month |
| Securonix Unified Defense SIEM    | Future-Looking Vision           | Cloud-native platform, integrated SOAR, long-term search capabilities      | Cloud, On-premises, Hybrid  | Contact for pricing; SaaS available                         |
| Exabeam Fusion                    | Log Storage and Searchability   | UEBA for insider threats, smart timelines, full indexing for log ingestion | SaaS cloud offering         | Contact for pricing; SaaS available                         |
| LogRhythm SIEM Platform           | On-Premises SIEM                | Advanced analytics, prebuilt playbooks, threat detection                   | On-premises                 | Starts under $30,000                                        |
| ManageEngine Log360               | Small Businesses                | Automated security scanning, compliance auditing, threat intelligence feed | Windows Server environments | Contact for pricing                                         |
| Datadog Security Monitoring       | Customization                   | Real-time security monitoring, log management, 600+ integrations           | Cloud-native                | 14-day free trial                                           |
| Logpoint SIEM                     | -                               | AI-driven anomaly detection, UEBA, integrated SOAR                         | Linux, AWS, SaaS            | -                                                           |
| SolarWinds Security Event Manager | Log Aggregation                 | Wide range of log management features                                      | -                           | -                                                           |

_source: Security Information and Event Management \[2.\]_

## References

1. <https://www.selecthub.com/siem/siem/>
2. <https://www.esecurityplanet.com/products/siem-tools/#:~:text=,Premises>
3. <https://securityintelligence.com/articles/soar-and-siem-in-2023-key-trends-and-new-changes/>
4. <https://www.manageengine.com/log-management/siem/siem-functions.html>
5. <https://www.itsasap.com/blog/pros-cons-siem>