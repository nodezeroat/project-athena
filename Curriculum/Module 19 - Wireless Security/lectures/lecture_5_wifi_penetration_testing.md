# Wireless Penetration Testing Tools and Techniques

## 5.1 Introduction

This chapter ventures into the specialized domain of wireless penetration testing, focusing on two pivotal aspects: password cracking and Evil Twin attacks. We will explore the tools and techniques used in password cracking, highlighting how they reveal vulnerabilities in network security and underscore the need for strong password policies. Additionally, the chapter will dissect Evil Twin attacks, demonstrating how these mimic legitimate WiFi networks to deceive users, and discussing protective measures against such threats. This exploration is crucial not only for penetration testers but also for anyone tasked with safeguarding wireless networks, providing key insights into potential vulnerabilities and their mitigation.

## 5.2 Tools

There are many tools when it comes to WiFi hacking, with the most common ones being the Aircrack-ng Suite, Kismet and Wireshark. In this curriculum, we will focus on those three.

### 5.2.1 Aircrack-ng Suite

- **What Can It Do**: Aircrack-ng is a complete suite of tools for assessing WiFi network security. It focuses on various areas including monitoring, attacking, testing, and cracking.
- **How Does It Work**: It captures network packets and then uses them to perform attacks such as packet injection and cracking WEP and WPA/WPA2-PSK passwords.
- **Useful for Attacks**: It's especially effective for cracking WiFi passwords, performing de-authentication attacks, and testing network defenses against attacks on encryption.

### 5.2.2 Kismet

- **What Can It Do**: Kismet is an open-source WiFi stumbler, sniffer, and intrusion detection system. It passively collects packets to detect both standard WiFi networks and those using hidden SSIDs.
- **How Does It Work**: It works by passively collecting wireless data from supported hardware, detecting network SSIDs, and identifying potential network intrusions.
- **Useful for Attacks**: Kismet is primarily used for network discovery, wardriving, and as a tool for the preliminary stages of penetration testing to gather information about surrounding networks.

### 5.2.3 Wireshark

- **What Can It Do**: Wireshark is a network protocol analyzer. It allows the user to capture and interactively browse the traffic running on a computer network.
- **How Does It Work**: It captures network packets and displays them in as much detail as possible. Users can filter data to analyze specific packets or protocols.
- **Useful for Attacks**: Wireshark is invaluable for analyzing network problems, performing software and protocol development, and as a tool in security and educational environments. It's particularly useful for sniffing and analyzing data packets to understand network traffic and detect vulnerabilities.

## 5.3 Attacking Wireless Networks

Now that we know all the tools we need, we can start using them and attack WiFi networks. Please remember to always stay ethical and only attack wireless networks that are either owned by you or you have the permission to attack.

### 5.3.1 Password Cracking

The process of password cracking in the context of WiFi networks typically involves the following steps:

1. **Monitoring and Capturing Packets**: Using tools like Aircrack-ng or Kismet, monitor and capture the packets from the targeted WiFi network. This often involves setting your device to monitor mode to listen for all wireless traffic in range.
1. **Targeting a Network**: Identify the network whose password you wish to crack. This involves capturing the handshake process between a legitimate user and the access point when the user is authenticating.
1. **Capturing the Handshake**: Wait for a user to authenticate to the network to capture the handshake. This handshake contains the encrypted form of the password.
1. **Cracking the Password**: Use tools like Aircrack-ng to crack the password. This can be done using brute-force attacks, dictionary attacks, or other methods. The tool attempts to decrypt the password by comparing the handshake against possible password combinations.
1. **Accessing the Network**: Once the password is successfully cracked, you can access the WiFi network using the discovered password.

#### See it in action

\[VIDEO AVAILABLE AFTER PRESENTATION\]

### 5.3.2 Evil Twin Attack

An Evil Twin attack involves setting up a rogue access point that appears to be a legitimate part of the targeted WiFi network:

1. **Setting Up a Rogue Access Point**: Use a tool like Kismet to identify the SSID and security protocol of the target WiFi network. Then set up a rogue access point with the same SSID and security settings using a tool like Aircrack-ng.
1. **Deauthentication Attack**: Force users off the legitimate network using a deauthentication attack. This can be done using packet injection tools to disrupt the communication between the user and the legitimate access point.
1. **Redirecting Users to the Rogue AP**: Users disconnected from the legitimate access point will often automatically try to reconnect. Since your rogue AP has the same SSID, some devices may connect to it instead.
1. **Capturing Information**: Once a user is connected to the rogue AP, their internet traffic goes through your network, allowing you to capture sensitive information like login credentials.
1. **MitM Capabilities**: With the user connected to your rogue AP, you can potentially alter or intercept their communications, conduct further attacks, or gain unauthorized access to secure areas of their network.

#### See it in action

\[VIDEO AVAILABLE AFTER PRESENTATION\]

## Sources

- <https://resources.infosecinstitute.com/topics/penetration-testing/red-teaming-main-tools-for-wireless-penetration-tests/>
- <https://www.aircrack-ng.org/doku.php?id=cracking_wpa>
- <https://thecybersecurityman.com/2018/08/11/creating-an-evil-twin-or-fake-access-point-using-aircrack-ng-and-dnsmasq-part-2-the-attack/>
