# Introduction Linux Security

The second a device is visible to the outside world, with that I mean it gains access to the internet, it becomes a target for bad actors. An insecure, unhardened server is a mere playground for people who want access to your data, or use the server in any other way they please.

Without good security measures a server can be compromised, be part of a DDoS attack and the owner wouldn't even know. Securing a server doesn't start with installing uncountable anti-virus programs but with the choice of the OS.

## Linux Distributions

Most of the Linux distributions are suitable for a secure server, but there are some guidelines which help one to make a good decision.

1. One wants a distribution that is stable. This brings the slight advantage that one doesn't have to debug issues at 3 am in the morning because the unattended rolling upgrade of the server was not compatible with some service.
2. One wants a distribution that has LTS. This common sense, but having a system that gets security patches is incredibly important.
3. One wants a distribution that is well supported. One shouldn't pick a forked Linux distribution from a Github with 5 stars to be the foundation of one's server.

- If one has planned to open ports after the installation, behold and wait with the port forwarding until the whole server is secured and hardened.
- If forced to access the server remotely, one should definitely change the default port for ssh and configure it with public key + password.

## The Basics

What now follows are some basic configuration to restrict access and hinder privilege escalation:

#### Sudo

Sudo is a command that let's users run commands as other users, including the root user. This can be quite dangerous and access should be restricted.

Steps as root:

1. Create a sudo group:
 `groupadd sudousers`
2. Add users to the group:
 `usermod -a -G sudousers <username>`
3. Enter edit mode for the sudo config file:
 `visudo`
4. Tell sudo to only allow user in the sudousers group to use sudo by adding this line at the end:
 `%sudousers   ALL=(ALL:ALL) ALL`

#### Su

Su also enables user to run commands as other user, by switching to other accounts, including root. It is restricted in almost the same way as sudo:

Steps as root:

1. Create a su group:
 `groupadd sudousers`
2. Add users to the group:
 `usermod -a -G sudousers <username>`
3. Edit who can execute the su command:
 `dpkg-statoverride --update --add root suusers 4750 /bin/su`

#### Enforce Secure Passwords

New accounts can set their password to anything, one should use "libpam_pwquality" to enforce good passwords. PAM is responsible for authentication in Linux, it handles password changes and creations. The named packages enable requirements to be set.

Steps as root:

1. Install libpam-pwquality (This will vary from system to system)
 `apt install libpam-pwquality`
2. Tell PAM to use libpam-pwquality by editing `/etc/pam.d/common-password` and changing this line:
 `password      requisite        pam_pwquality.so`
  To this line:
 `password      requisite        pam_pwquality.so retry=3 minlen=10 difok=3 gecoscheck`

These are only example options, for the full list look at [this](https://manpages.debian.org/testing/libpam-pwquality/pam_pwquality.8.en.html) site.

#### Install a Firewall

A basic Linux firewall is managed by iptables, but since it is hard to understand how to create rules for iptables I will demonstrate a simple firewall with ufw. Ufw is a program that is user friendly, but in the background still uses iptables.

Ufw works by letting the user configure rules that allow or deny input or output traffic to or from ports. One can create rules by specifying the port or application to be allowed or denied.

Steps as root:

1. Install ufw (This will vary from system to system)
 `apt install ufw`
2. Allow SSH if needed
 `ufw allow ssh`
4. Deny all incoming traffic by default
 `ufw default deny incoming`
4. Start ufw
 `ufw enable`

To check the status of ufw type: `ufw status numbered`
To delete some rules: `ufw delete <number>`

#### Check Logging

The rsyslog service should normally already be running but one should check.

Steps for root:

1. Check the rsyslog service
 `systemctl status rsyslog`
2. Enable the rsyslog service
 `systemctl enable rsyslog`

## Resources

- <https://www.cisecurity.org/>
- <https://firejail.wordpress.com/>
- <https://www.digitalocean.com/community/tutorials/ufw-essentials-common-firewall-rules-and-commands>
- <https://manpages.debian.org/testing/libpam-pwquality/pam_pwquality.8.en.html>
