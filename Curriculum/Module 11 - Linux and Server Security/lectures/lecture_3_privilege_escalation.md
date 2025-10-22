# Privilege escalation

## What is privilege escalation?

- "Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network." - MITRE Framework
- "Privilege Escalation is the act of exploiting a bug, a design flaw, or a configuration oversight in an operating system or software application to gain elevated access to resources that are normally protected from an application or user." - Wikipedia
- "Privilege Escalation is the process of gaining unauthorized access to higher-level permissions or privileges within a system or network." - ChatGPT

### What is the goal?

The goal of almost every privilege escalation is becoming root. The Root user is the administrator account on Linux, who has near limitless permissions.

This may be a sub goal of achieving persistence, credential dumping, lateral movement or of a CTF challenge (Boot 2 Root).

## Basics of Linux Security Model

- Users and Groups on a Linux system are identified by an ID
- Every File has an owner and permissions

![File Permissions](images/file_permissions.jpg)

### Sudo

- Sudo is used to execute commands in the context of another user, which can be the root user
- ```/etc/sudoers``` define who can execute what as who
- In privesc **always** check for sudo privileges
  - ```sudo -l```

## Common Vulnerabilities

Common vulnerabilities are as the name implies the most common way to get privesc on a system:

### File permissions

Sometimes file permissions are misconfigured, giving the attacker access to files that they shouldn't have

- System files like: ```/etc/passwd``` and ```/etc/shadow```
- Config files like: ```*.config``` and ```*.txt```
- User files like: ```.ssh``` and ```.bashrc```

### Credentials

The same applies to misconfigured credentials, giving the attacker access to passwords and keys that they shouldn't have

- Plaintext creds (hardcoded creds in scripts).
- SSH-Keys (/home/user/.ssh/id rsa)
- Bash history (/home/user/.bash history)

### Sudo

Sudo privilege means pretty good chance for privesc!
Unseeming applications often let us privesc:

- 7z
- apt-get
- gdb
- pandoc

To check allowed sudo commands for privesc used GTFOBins, more on it on the next lecture:
<https://gtfobins.github.io/#+sudo>

### SUID

Binaries with setuid bit set, run as owner instead of user
starting the process:

![SUID Example](images/suid_example.jpg)

#### Docker/LXD Group

Docker or LXD group allows spawning of privileged containers.

These containers can:

- Mount host file-system as root
- Read / Write system-files
- Fully compromise host

#### Scheduled Tasks / Cron Jobs

Scheduled Tasks / Cron jobs run regularly on systems and are located at ```/etc/crontab``` or ```/etc/cron.d```

![Crontab](images/crontab.jpg)

#### Kernel / Software Exploits

Check versions and look for public exploits:

- Kernel
  - ```cat /proc/version```
- Software
  - ```sudo −V```

## Enumeration

Now how do you find those vulnerabilities? By searching the system, looking for something that stands out.

- User Files
- Custom scripts and executables
- Version enumeration
- Scheduled Tasks / Cron Job
- Processes running on the system

### Tools

There are many tools that can automate this task in the background, like:

- [LinPeas](https://github.com/carlospolop/PEASS-ng/) - Automated enumeration
- [LinEnum](https://github.com/rebootuser/LinEnum) - Automated enumeration (older)
- [pspy](https://github.com/DominicBreuker/pspy) - List running processes
- [GTFOBins](https://gtfobins.github.io/) - Privesc via sudo/suid binaries
- [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation) - Checklists and information

## Resources

- This lecture is based on a presentation from [chr0x6eos](https://github.com/chr0x6eos).
- <https://delinea.com/blog/linux-privilege-escalation>
- <https://book.hacktricks.xyz/linux-hardening/privilege-escalation>
