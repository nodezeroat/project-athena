# Firewalls

## What is a Firewall?

It must be noted that firewalls are used for filtering of network traffic in internal network. It determines the traffic that should either be permitted or prohibited in line with specific stipulations. The firewall can be thought of as a gatekeeper of your computer’s entrance point where only trusted sources or IP address are allowed into your network.

The incoming traffic, which is allowed in this network, is configured into a firewall. It differentiates between good traffic and malicious data and either permits or denies packets based on preset security criteria.

The packet data contains such information as its source, destination, content and so on which serves as basis for these rules. They allow traffic from suspect sources, but block it to mitigate cyberattacks.

For instance, the picture below illustrates how a firewall lets genuine traffic through to the user’s private network.

![Firewall 1](images/Firewall_1.png)

_source: Firewalls \[3.\]_

However, as you can see on the picture below, the malicious or per rules blocked traffic is not allowed to enter the users private network. The gatekeeper is doing his job pretty good!

![Firewall 2](images/Firewall_2.png)

_source: Firewalls \[4.\]_

## How does a Firewall Work?

Firewalls work by examining data packets passing through them and applying the rules to determine whether to allow or block the traffic. These rules can be based on various factors like IP addresses, port numbers, protocols, or specific types of content.

## Softwarebased Firewall

- **Software-based firewalls** are programs installed on individual computers or devices. They monitor traffic specific to that device, regulating incoming and outgoing connections based on predefined rules. They're often part of antivirus software or operating systems, offering granular control over what enters or leaves a particular device.

## Hardwarebased Firewall

- **Hardware firewalls** are standalone devices positioned between an internal network and an external network (like the internet). They're often implemented within routers or dedicated firewall appliances. Hardware firewalls provide broader protection for entire networks and are managed separately from individual devices.

## Differences Between Software and Hardware Firewalls

1. **Scope:** Software firewalls protect individual devices; hardware firewalls safeguard entire networks.
1. **Location:** Software firewalls are installed directly on devices; hardware firewalls are separate physical devices or integrated within network infrastructure.
1. **Granularity of Control:** Software firewalls offer detailed control per device; hardware firewalls provide broader network-wide protection and can be more challenging to customize for individual devices.

Both types of firewalls are essential in a comprehensive security strategy. Often, a combination of both software and hardware firewalls is used in an organization's network architecture to provide layered security defenses.

## Difference Between a Firewall and Antivirus

### Firewall

- A firewall is essential software or firmware in network security that is used to prevent unauthorized access to a network.
  It is used to inspect the incoming and outgoing traffic with the help of a set of rules to identify and block threats by implementing it in software or hardware form.
  Firewalls can be used in both personal and enterprise settings, and many devices come with one built-in, including Mac, Windows, and Linux computers.

### Antivirus

- Antivirus is also an essential component of network security. It is basically an application or software used to provide security from malicious software coming from the internet.
  An antivirus working is based upon 3 main actions, Detection, Identification, and Removal of threats.
  Antivirus can deal with external threats as well as internal threats by implementing only through software.

## Diffrent types of firewalls

1. **Packet Filtering Firewalls** <br>
   Operation: Examines packets based on pre-defined rules (such as source/destination IP, ports, protocols) and allows or blocks them accordingly. <br>
   Characteristics: Efficient but operates at the network layer (Layer 3) of the OSI model and lacks deep inspection capabilities.

1. **Stateful Inspection Firewalls** <br>
   Operation: Tracks the state of active connections, allowing or denying traffic based on the context of the connection (stateful examination). <br>
   Characteristics: More secure than packet filtering, as it considers the connection state. It operates at network (Layer 3) and transport (Layer 4) layers.

1. **Proxy Firewalls (Application-Level Gateways)** <br>
   Operation: Acts as an intermediary between clients and servers, handling traffic at the application layer. It establishes separate connections for each request. <br>
   Characteristics: Offers enhanced security by inspecting and filtering at Layer 7 (application layer) but can introduce latency.

1. **Next-Generation Firewalls (NGFW)** <br>
   Operation: Integrates traditional firewall features with advanced functionalities like intrusion prevention, application awareness, deep packet inspection, and more. <br>
   Characteristics: Provides comprehensive security by combining various security features to detect and block modern threats.

1. **Deep Packet Inspection (DPI) Firewalls** <br>
   Operation: Analyzes packet contents beyond header information, scrutinizing the actual data payload for specific patterns or anomalies. <br>
   Characteristics: Offers detailed inspection but can impact performance due to resource-intensive packet analysis.

1. **Virtual Firewalls** <br>
   Operation: Designed for virtualized environments, securing traffic within virtual networks or between virtual machines. <br>
   Characteristics: Provides security for virtual environments, similar to physical firewalls but tailored for virtualized networks.

_source: Firewalls \[1.\], Firewalls \[2.\]_

## References

1. <https://www.cisco.com/c/en/us/products/security/firewalls/what-is-a-firewall.html>
2. <https://www.checkpoint.com/cyber-hub/network-security/what-is-firewall/>
3. <https://www.simplilearn.com/ice9/free_resources_article_thumb/Firewall_1.png>
4. <https://www.simplilearn.com/ice9/free_resources_article_thumb/Firewall_2.png>
5. <https://www.simplilearn.com/tutorials/cyber-security-tutorial/what-is-firewall>
