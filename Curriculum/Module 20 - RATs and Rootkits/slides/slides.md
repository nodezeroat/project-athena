---
marp: true
theme: project-athena
paginate: true
_paginate: false
title: Module 20 - RATs and Rootkits
header: Module 20 - RATs and Rootkits
footer: More on [@h4ckd0tm3/project-athena](https://github.com/h4ckd0tm3/project-athena/)
---

# **RATs and Rootkits**

- Remote Access
  
- Backdoors

![bg right 80%](../figures/fartware.gif)

---

# **RATs**

- Remote Access Trojans
  
- Infostealers
  
- Operationally similar to legitimate tools

---

# **Infostealers**

- *x* got ratted -> Usually just an infostealer
  
- Basic social engineering
  
- Steals tokens, passwords, cookies, etc.
  
- VERY poplar in communities with lots of *young people*
  
- No infra, relies heavily on webhooks or similar

---

# **Real RATs**

- More complex, requires C2 infra
  
  - Not worth for individual targets
  
- Can pivot into Ransomware or related

![bg right 80%](../figures/xmrig.gif)

---

# **RAT Operation**

1) Entry via social engineering
   
2) *current cve* or *0day* to escalate
   
3) Install and start beaconing
   
4) Profit

---

# **Command and Control (C2)**

- Recieve and execute commands
- Exfiltrate data
- Commercial or custom frameworks

![bg right 90%](../figures/cobalt-strike.jpg)

---

# **C2 Communication**

- Beaconing
  - host -> C2
- Crawling
  - C2 -> known hosts
- Traffic obfuscation
  - Redirection
  - C2 over DNS
  - Encryption
  - Mallealbe traffic

---

# **More traffic obfuscation**

- Domain Fronting
- Fast Flux
- DNS Tunneling
- Other generic traffic obfuscation

![bg right 90%](../figures/domain-fronting-scheme.png)

---

# **Persistence**

- Registry
- Startup
- Scheduled Tasks
- DLLs

![bg right 80%](../figures/DLL-load-order.png)

---

# **Protection**

<style>
.container{
    display: flex;
}
.col{
    flex: 1;
}
</style>

<div class="container">
    <div class="col">
        <h3>Prevent infection</h3>
        <ul>
            <li>User training</li>
            <li>Patching</li>
            <li>Minimal permissions</li>
        </ul>
    </div>
    <div class="col">
        <h3>Detect</h3>
        <ul>
            <li>Monitor traffic</li>
            <li>EDR monitoring</li>
        </ul>
    </div>
</div>

---

# **Examples**

- [Discord Bot Infostealer](https://www.trellix.com/blogs/research/java-based-sophisticated-stealer-using-discord-bot-as-eventlistener/)
- [RAT builder RAT](https://cyberpress.org/weaponized-xworm-rat-builder-targeting-script-kiddies/)

---

# **Rootkits**

- Backdoor with typically elevated privileges
- Traditionally requires permissions and/or exploit to install

---

# **Types of Rootkits**

<!-- With only markdown it inserts weird line breaks -->

<style>
.rootkit-container {
    display: flex;
    align-items: flex-start;
}
.rootkit-text {
    flex: 1;
}
.rootkit-image {
    flex: 0 0 auto;
    margin-left: 0px;
}
</style>

<div class="rootkit-container">
    <div class="rootkit-text">
        <ul>
            <li>Userland
                <ul>
                    <li>First type of rootkits</li>
                    <li>Replace glibc, etc.</li>
                </ul>
            </li>
            <li>Kernel
                <ul>
                    <li>Permissions or exploit required</li>
                    <li>Nowadays more protections</li>
                </ul>
            </li>
            <li>Firmware/BIOS/Hypervisor
                <ul>
                    <li>Very rare and complex</li>
                </ul>
            </li>
        </ul>
    </div>
    <div class="rootkit-image">
        <img src="../figures/smm-thinvisor.gif" alt="Rootkit Image">
    </div>
</div>

---

# **Mobile Rootkits**

- State spyware may fall into this category
- Root/jailbreak usually included
- Very rare due to cost of required vulns

---

# **Why Ring0**

- Normally invisible from userspace
- Manipulate structures and install hooks
- Can be detected by earlier/deeper code

![bg right 80%](../figures/idthooked.gif)

---

# **Kernel Protections**

- Non-exposed symbols
- KASLR & SMAP
- Write protection
- Exploit protections
- Integrity checks
- Still not perfect

![bg right 90%](../figures/kernel-protection.png)

---

# **Firmware/BIOS/ Hypervisor**

- Functionally similar to enterprise management software
- Requires high severity vuln to install
- Might start to become more common

![bg right 80%](../figures/cpuid.gif)

---

# **Examples & Reading**

- [Recent Kernel+Userland Rookit](https://www.bleepingcomputer.com/news/security/new-stealthy-pumakit-linux-rootkit-malware-spotted-in-the-wild/)
- [Cosmic Strand UEFI Bootkit](https://securelist.com/cosmicstrand-uefi-firmware-rootkit/106973/)
- [Rootkit Arsenal](https://books.google.com/books/about/The_Rootkit_Arsenal.html?id=aJFVCnwNbMEC)
- [Rootkits and Bootkits](https://nostarch.com/rootkits)



