# The Wireless Network Architecture

## 1.1 Introduction

Wireless networks, a pivotal component of modern communication, enable data transmission over radio frequencies, eliminating the need for wired connections. This lecture offers a comprehensive examination of wireless network architecture, encompassing various types of networks and technologies, and focusing on WLAN security.

## 1.2 Types of Wireless Networks

- **WPAN (Wireless Personal Area Networks):** These are low-power, short-range networks, ideal for personal device connectivity.
- **WLAN (Wireless Local Area Networks):** Medium-sized networks, commonly utilized in homes and offices, operate primarily on 2.4 GHz and 5 GHz radio frequencies.
- **WMAN (Wireless Metropolitan Area Networks):** Large networks designed for city-wide communication.
- **WWAN (Wireless Wide Area Networks):** Extensive networks covering broad areas, often used for cellular communications.

## 1.3 Wireless Technologies

### 1.3.1 Bluetooth

A WPAN technology, Bluetooth facilitates data exchange over short distances and is integral to devices like smartphones and headphones.

- **BLE (Bluetooth Low Energy):** Optimized for low power consumption, it's suitable for devices requiring periodic small data exchanges.
- **BBR (Bluetooth Basic Rate):** The initial standard, offering fundamental connectivity.
- **EDR (Enhanced Data Rate):** Enhances data transfer rates, beneficial for high-throughput needs like audio streaming.

### 1.3.2 WiMAX

Worldwide Interoperability for Microwave Access is a WMAN technology. It's designed for long-range communication, with a focus on providing broadband internet access over large areas.

### 1.3.3 Cellular

Cellular networks are a set of WWAN technologies providing long-range and mobile access to carriers using cell towers.

- **1G:** Introduced in the 1980s, first generation networks were analog and supported only voice calls.
- **2G/GSM:** Global System for Mobile Communications is providing features for digital communication with separate voice and data for both, calls and SMS. Additionally, this standard introduced the use of SIM (Subscriber Identity Module) cards, a key feature for identifying and authenticating subscribers.
- **3G, 4G/LTE and 5G:** The third generation, fourth generation with long term evolution and fifth generation of cellular protocols, each with improved bandwidth and more speed.

### 1.3.4 WLAN

WLAN refers to a wireless network that connects devices over a short distance, typically within a building such as a home, office, or school. It is powered by different versions of the WiFi (Wireless Fidelity) protocol family.

| Generation | Standard | Maximum Bandwidth | Radio Frequency |
| ---------- | -------- | ----------------- | --------------- |
| Wi-Fi 7    | 802.11be | 46120 Mbit/s      | 2.4 GHz, 5 GHz  |
| Wi-Fi 6E   | 802.11ax | 9608 Mbit/s       | 6 GHz           |
| Wi-Fi 6    | 802.11ax | 9608 Mbit/s       | 2.4 GHz, 5 GHz  |
| Wi-Fi 5    | 802.11ac | 6933 Mbit/s       | 5 GHz           |
| Wi-Fi 4    | 802.11n  | 600 Mbit/s        | 2.4 GHz, 5 GHz  |
| Wi-Fi 3    | 802.11g  | 54 Mbit/s         | 2.4 GHz         |
| Wi-Fi 2    | 802.11a  | 54 Mbit/s         | 5 GHz           |
| Wi-Fi 1    | 802.11b  | 11 Mbit/s         | 2.4 GHz         |
| Wi-Fi 0    | 802.11   | 2 Mbit/s          | 2.4 GHz         |

**Note:** Even though there are many other wireless protocols that need to be secured, this module is only focused onto WLAN security.

## 1.4 WLAN Architecture

Wireless Local Area Networks (WLANs) have become a cornerstone of modern networking, allowing devices to connect and communicate over radio frequencies. Unlike wired networks, WLANs provide flexibility and mobility, offering connectivity without the physical constraints of cables. A WLAN typically consists of an access point (AP) that broadcasts a signal, which client devices like laptops, smartphones, and tablets can connect to.

### 1.4.1 Topologies

- **Basic Service Set (BSS):** This is the basic building block of a WLAN. In a BSS, devices communicate with a single access point. It's akin to a simple, standalone network or a cell in the wireless network.
- **Extended Service Set (ESS):** An ESS is a series of interconnected BSSs. This setup allows a device to roam seamlessly from one AP to another within the same network, which is common in larger settings like campuses or office buildings.
- **Mesh Networks:** These networks do not rely on a central AP. Instead, each node in a mesh network can forward data to other nodes, making the network more resilient and flexible.
- **Ad-Hoc Networks (IBSS):** In an Independent Basic Service Set, devices connect directly without an AP, suitable for small, temporary setups.

### 1.4.2 Hardware

- **Access Points (APs):** APs are the heart of a WLAN, broadcasting the wireless signal to which client devices connect. They can vary in capabilities, from basic home routers to more sophisticated enterprise-grade APs.
- **WLAN Controllers:** These are used in larger WLANs to centrally manage multiple APs, handling tasks like load balancing, authentication, and security policies.
- **Client Devices:** Any device with a wireless networking capability can be a client device. This includes laptops, smartphones, and increasingly, IoT devices.

## 1.5 WLAN Operation

In-depth understanding of WLAN operation is crucial for grasping how wireless networks function, handle data, and maintain communication integrity and security.

### 1.5.1 SSIDs

The Service Set Identifier (SSID) is a crucial concept in WLANs, acting as the primary identifier for a wireless network. It's essentially the name of a wireless network that makes it distinguishable from other networks within range and may be configured by the administrator as desired.

- **Function of SSID:** When an access point (AP) broadcasts its presence, it includes the SSID in its beacon frames. This allows client devices to see the network's name when scanning for available connections.
- **SSID Broadcasting:** APs can either broadcast their SSID, making the network visible to all devices within range, or hide it, requiring users to know the SSID beforehand to connect.
- **Security Implications:** While hiding an SSID can seem like a security measure, it's not entirely effective as the SSID can still be discovered through other means, like sniffing data frames. The security of a WLAN depends more on robust encryption and authentication methods.

### 1.5.2 Channels

WLANs use radio frequencies, divided into channels, to transmit and receive data. The 2.4 GHz and 5 GHz bands are common, each with a set of channels.

- **Channel Bandwidth:** Refers to the frequency range that each channel occupies. For instance, in the 2.4 GHz band, channels are typically 20 MHz wide.
- **Channel Utilization:** A key characteristic of WLAN channels is that only one device can effectively transmit data on a channel at any given moment. When multiple devices attempt to use the same channel simultaneously, it leads to collisions and network inefficiencies.
- **Interference and Overlap:** In the 2.4 GHz band, channels often overlap, causing interference. Channels 1, 6, and 11 are widely used as they don't overlap.
- **Channel Selection:** Choosing the right channel is vital for optimal network performance. Factors like neighboring networks, physical obstacles, and device capabilities play a role.

| Frequency Band | Channels | Typical Use               |
| -------------- | -------- | ------------------------- |
| 2.4 GHz        | 1 - 14   | General, broader coverage |
| 5 GHz          | 36 - 165 | High-speed data transfer  |

### 1.5.3 Frames

Frames are the fundamental units of data transmission in WLANs. Understanding their structure is key to comprehending how WLANs manage data.

**Frame Types**

- **Management Frames:** Used for maintaining and managing the network.
  - **Beacon Frames:** Used for advertising and probing SSIDs.
  - **Authentication Frames:** Used for authenticating users to the network.
- **Control Frames:** Aid in the delivery of data.
- **Data Frames:** Carry the user data.

**General Frame Structure**

- **Header:** Contains source and destination addresses, frame control fields, and a sequence number.
- **Payload:** The actual data being transmitted.
- **Frame Check Sequence (FCS):** Used for error checking.

| Frame Part      | Description                | Length in Bytes |
| --------------- | -------------------------- | --------------- |
| Frame Control   | Type, sub-type, and flags  | 2               |
| Duration        | Time to occupy the channel | 2               |
| Address Fields  | Source, destination, etc.  | 6 each          |
| Sequence Number | Order of frames            | 2               |
| Payload         | User data                  | Variable        |
| FCS             | Error checking             | 4               |

### 1.5.4 CSMA/CA

CSMA/CA (Carrier Sense Multiple Access with Collision Avoidance) is a protocol used to reduce the risk of collision in WLANs.

- **Operation:** Before transmitting, a device listens to detect if any other device is transmitting (carrier sense). If the channel is clear, it will send a frame; if not, it waits for a random time period before retrying.
- **RTS/CTS Mechanism:** Request to Send (RTS) and Clear to Send (CTS) frames (Control Frames) are used to reserve the channel for a short duration, reducing the chance of collision in environments with high traffic. The client sends out RTS frames when desiring to transmit data, while the AP replies with CTS frames when ready to accept data from the client for a specific duration.

### 1.5.5 Device Association

This process involves several steps for a device to connect to a WLAN.

- **Discovery:** Devices use probe requests to find networks, and APs respond with probe responses.
- **Authentication:** Authenticates the user to the network. More on this topic will be covered in later lectures.
- **Association:** After authentication, the device sends an association request to the AP. If accepted, the AP responds with an association response, and the device is connected.

**Discovery Options**

- **Active Discovery (SSID Shown)**

  - In active discovery, the AP broadcasts beacon frames at regular intervals, which include the SSID of the network.
  - Client devices scan for these beacon frames to find available networks.
  - The visibility of the SSID makes it easier for devices to locate and identify the network.

- **Passive Discovery (SSID Hidden)**

  - In networks where the SSID is not broadcast, the AP does not include the SSID in its beacon frames.
  - Client devices cannot find these networks automatically during a standard scan.
  - To connect, the client device must be configured with the SSID beforehand.
  - This method is less visible to casual observers but does not significantly increase security, as the SSID can still be intercepted from other frames.

## 1.6 Conclusion

In conclusion, this lecture provides a comprehensive understanding of the various aspects and technologies that constitute modern wireless networking. From exploring different types of wireless networks, such as WPAN, WLAN, WMAN, and WWAN, to delving into the specifics of WLAN operation and security, this lecture offers crucial insights into the design, functionality, and protection of wireless networks. The knowledge imparted is essential for anyone looking to navigate or secure the increasingly wireless landscape of digital communication.

## Sources

- [https://en.wikipedia.org/wiki/IEEE_802.11](https://en.wikipedia.org/wiki/IEEE_802.11)
- [https://en.wikipedia.org/wiki/Wireless_LAN](https://en.wikipedia.org/wiki/Wireless_LAN)
- [https://en.wikipedia.org/wiki/Wi-Fi](https://en.wikipedia.org/wiki/Wi-Fi)
