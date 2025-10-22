# WiFi Attack Vectors

## 4.1 Introduction

Understanding WiFi attack vectors is essential in the evolving landscape of wireless security. With the increasing prevalence of wireless networks, their vulnerabilities become prime targets for malicious entities. This chapter focuses on the various methods employed by attackers to exploit weaknesses in wireless networks, highlighting the importance of robust security measures.

An attack vector in wireless security is a method or pathway utilized for unauthorized access to a network or for compromising data. These vectors exploit not just technical flaws in hardware and software but also target procedural and human vulnerabilities. Grasping these attack vectors is crucial for anyone responsible for securing a wireless network, as it informs the development of effective defense strategies.

This chapter aims to provide a thorough overview of common and emerging WiFi attack vectors. Covering everything from passive eavesdropping to advanced man-in-the-middle attacks, this chapter will explore the mechanics of these threats and their potential impacts. The goal is to equip you with the necessary knowledge to identify and defend against these security breaches, enhancing the overall protection of wireless networks.

## 4.2 Active vs Passive Attacks

Active and passive attacks are two fundamental categories of cybersecurity threats, particularly in the context of WiFi networks. They differ primarily in their methods of execution and interaction with the target network:

### 4.2.1 Passive Attacks

- Passive attacks involve monitoring or 'eavesdropping' on a network. The attacker intercepts data transmitted over the network without altering the data or affecting the network's operation. The goal is usually to gather information stealthily.
- They are harder to detect because they don't involve any alteration of the network's data or behavior. The network operates normally, unaware of the ongoing surveillance.
- Examples include sniffing to capture unencrypted data packets, listening for network traffic to identify network resources and configurations, and analyzing traffic patterns.
- Measures such as strong encryption (e.g., WPA3 for WiFi), VPNs, and secure protocols help mitigate the risk of passive attacks by ensuring that intercepted data cannot be easily understood.

### 4.2.2 Active Attacks

- Active attacks involve some form of alteration or intervention in the network's operation. The attacker injects, alters, or disrupts data to compromise the network. These attacks are often more aggressive and aim to directly damage, exploit, or disable the network.
- Active attacks are generally easier to detect compared to passive attacks because they involve noticeable changes in network performance or behavior.
- Examples include Man-in-the-Middle attacks, Denial of Service (DoS) attacks, session hijacking, creating rogue access points, and injecting malicious data into the network.
- Prevention strategies involve regular network monitoring, intrusion detection systems, strong authentication protocols, and network security policies to quickly identify and respond to active threats.

## 4.3 Attack Vectors

We will now have a look at the 7 most common WiFi attack vectors, explain how they work, give examples for them and suggest ways of detecting or preventing them.

### 4.3.1 **Eavesdropping/Sniffing**

- **Type**: Passive Attack
- **How it Works**: The attacker captures wireless data as it is transmitted over a network using a sniffer tool. This can include passwords, emails, and other sensitive information if not encrypted.
- **Example**: Using a tool like Wireshark to monitor unsecured WiFi network traffic at a coffee shop.
- **Detection and Prevention**: Encryption (like WPA2 or WPA3) makes sniffed data unreadable. Network monitoring can sometimes identify unusual traffic patterns indicative of sniffing.

### 4.3.2 **Man-in-the-Middle (MITM) Attacks**

- **Type**: Active Attack
- **How it Works**: The attacker intercepts and potentially alters the communication between two parties without their knowledge. This can be done by infiltrating an unsecured WiFi network or using tools to create a false access point.
- **Example**: An attacker sets up an unsecured WiFi hotspot and intercepts data between connected users and the internet.
- **Detection and Prevention**: HTTPS usage, VPNs, and strong network authentication can help prevent MITM attacks. Awareness of network security is also crucial.

### 4.3.3 **Denial of Service (DoS)**

- **Type**: Active Attack
- **How it Works**: The attacker overwhelms the network with excessive traffic or data requests, rendering the network unusable.
- **Example**: Flooding a WiFi network with traffic using a tool like LOIC (Low Orbit Ion Cannon).
- **Detection and Prevention**: Network monitoring for unusual traffic surges, implementing rate limiting, and having robust network infrastructure can mitigate DoS attacks.

### 4.3.4 **Evil Twin Attacks**

- **Type**: Active Attack
- **How it Works**: The attacker sets up a malicious WiFi access point that mimics a legitimate one, tricking users into connecting and transmitting their data through the rogue network.
- **Example**: Creating a WiFi access point with a name similar to a legitimate cafe network to capture customer data.
- **Detection and Prevention**: Users should verify network authenticity before connecting. Networks can use AP (Access Point) fingerprinting to detect rogue APs.

### 4.3.5 **Packet Injection**

- **Type**: Active Attack
- **How it Works**: The attacker injects arbitrary packets into a network. This can be used to disrupt or manipulate normal network operations.
- **Example**: Injecting packets to disrupt a client's connection or to exploit vulnerabilities in the network.
- **Detection and Prevention**: Encryption, strong network protocols, and intrusion detection systems can help identify and prevent packet injection.

### 4.3.6 **WiFi Phishing**

- **Type**: Active Attack
- **How it Works**: Similar to phishing on the internet, WiFi phishing involves creating a fraudulent network or portal to deceive users into entering sensitive information.
- **Example**: Setting up a fake WiFi login page that looks legitimate to capture user credentials.
- **Detection and Prevention**: User education is key. SSL/TLS for websites can help. Networks should use security measures like WPA3 for authentication.

### 4.3.7 **Cracking WiFi Passwords**

- **Type**: Active Attack
- **How it Works**: The attacker uses techniques like brute-force attacks, dictionary attacks, or exploiting WPS (WiFi Protected Setup) vulnerabilities to guess or crack WiFi passwords.
- **Example**: Using a tool like Aircrack-ng to crack weak WiFi passwords.
- **Detection and Prevention**: Using strong, complex passwords, disabling WPS, and monitoring for multiple failed login attempts can prevent password cracking.

## 4.4 Conclusion

This chapter's exploration of WiFi attack vectors reveals a key insight: the majority are active attacks, which are generally easier to detect due to their direct interaction with the network. This understanding is crucial for both network defenders and ethical hackers. While defenders can leverage this for more effective monitoring and response, penetration testers must conduct their assessments with heightened care to avoid unintended network disruptions. Staying vigilant, adhering to ethical practices, and continuously updating security strategies are vital in navigating the evolving landscape of WiFi security.

## Sources

- <https://www.webtitan.com/blog/most-common-wireless-network-attacks/>
- <https://www.examcollection.com/certification-training/security-plus-wireless-attacks-and-their-types.html>
- <https://www.giac.org/paper/gsec/4116/wireless-ids-exposures-attack-vectors-detection/106559>
