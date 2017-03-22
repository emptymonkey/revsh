
# The Beachhead Landing Process

![https://en.wikipedia.org/wiki/Beach_Head_(G.I._Joe)](https://upload.wikimedia.org/wikipedia/en/9/91/Beachhead_G.I._Joe.png)

## Table of Contents

* [Introduction](#toc1)
* [Stages of a Beachhead Landing](#toc2)
 * [Stage 1 - Limited Control](#toc2a)
 * [Stage 2 - Remote Code Execution (RCE)](#toc2b)
 * [Stage 3 - Reverse Shell](#toc2c)
 * [Stage 4 - Reverse Terminal](#toc2d)
 * [Stage 5 - Local Privilege Escalation (LPE)](#toc2e)
 * [Stage 6 - Reverse VPN](#toc2f)
* [A note on netcat.](#toc3)
* [A note on SSH.](#toc4)
* [A note on further training.](#toc5)

## Introduction <a name="toc1"></a>

There are many documents online that break down a cyber attack into various stages. Roughly, these stages are:

1. Passive reconnaissance. (e.g. Google, Shodan, Linkedin, etc.)
2. Active reconnaissance. (e.g. nmap, dns forward / reverse lookups, etc.)
3. Initial compromise.
4. Move laterally.
5. Establish persistence.
6. *...wash, rinse, repeat on your way to the actual target...*
7. Data exfiltration, modification, or destruction.

These lists, while generally intended as overviews, always leave me feeling as though the structure of the process involved in "Initial Compromise" (step #3) is taken for granted. The purpose of this document is to address that gap by codifying some structure around the process involved during initial compromise. I refer to this as the ***Beachhead Landing Process***. In this document I will outline and describe each stage of this process. While this document may be written with a Linux server in mind as the target, this process is the same for other operating systems, albeit by leveraging different tools. 

It should be noted that the stages outlined below are meant as an enumeration of all possible steps in this process. A specific engagement may not have (or need) all of these stages. For example, when faced with a web application with command injection running as root, the operator will be able to skip from stage 1 all the way to stage 6 in one maneuver. In general though, most of the stages listed below will come into play in some form.

revsh was written specifically to enable several of the later stages of this process, and thus empower the operator to escalate, persist, and move laterally with greater ease.

## Stages of a Beachhead Landing <a name="toc2"></a>

### Stage 1 - Limited Control <a name="toc2a"></a>

*Goal: Gain limited Control.*<br>
*Vector: Remote Vulnerability*<br>
*Privilege: Non-privileged User*

The operator will need to begin by identifying a remote vulnerability and exploiting it. This may only grant the operator limited control over the server, such as file upload to the webroot or database field extraction. Beyond a direct attack on a server, other methods used in this phase may include hosting a drive-by malicious web page or by phishing the target's employees in order to gain access directly to their internal network.

### Stage 2 - Remote Code Execution (RCE) <a name="toc2b"></a>

*Goal: Gain arbitrary RCE.*<br>
*Vector: Variable*<br>
*Privilege: Non-privileged User*

Once the operator has found a vulnerability that grants them limited control, they should then expand that control until achieving repeatable arbitrary remote code execution. In the above example of a vulnerable web application with a file upload to webroot vulnerability, this stage could be performed by uploading a webshell.

### Stage 3 - Reverse Shell <a name="toc2c"></a>

*Goal: Establish a reverse shell.*<br>
*Vector: netcat*<br>
*Privilege: Non-privileged User*

In this stage, the arbitrary RCE from stage 2 should be invoked to download a copy of netcat that has the GAPING_SECURITY_HOLE feature enabled. Once downloaded, the operator will open a reverse shell with netcat then proceed with several high priority / low impact tasks. (E.g. fingerprinting the host, assessing the level of system usage by it's owners, as well as identifying any additional services provided by this host.) After the completion of those initial tasks the operator will find that further tasks, such as privilege escalation or lateral movement will be easier to perform from a proper terminal.

It should be noted that there are many other ways to establish a reverse shell without netcat. For a fairly exhaustive list of these techniques, please refer to [pentestmonkey's Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

### Stage 4 - Reverse Terminal <a name="toc2d"></a>

*Goal: Establish a reverse terminal.*<br>
*Vector: revsh*<br>
*Privilege: Non-privileged User*

The operator will now leverage the netcat shell established in stage 3 to download and launch revsh. Beyond a basic shell, there will now be a full terminal for the operator to take advantage of. System interaction will feel more normal at this point with keybindings such as Ctrl-c doing the appropriate thing and several tty aware userland tools becoming available.

In this stage, even as a non-privileged user, revsh allows for point-to-point passthrough network proxies, as well as dynamic socks proxy tunnels. This enables the operator to perform a "behind the host firewall" style attack, run burpsuite through the socks proxy, and use most of the other system tools on Kali by way of proxychains. If privilege escalation is determined to be too risky (for reasons of either system stability or covertness of action) the operator can stop here and still have a fully functioning beachhead within the target environment.

### Stage 5 - Local Privilege Escalation (LPE) <a name="toc2e"></a>

*Goal: Gain LPE.*<br>
*Vector: LPE Vulnerability*<br>
*Privilege: Non-privileged User*

Gaining root level access on a server is only necessary for some offensive forensics (e.g. accessing root SSH keys, memory dumps for in-memory password / key / cert exfiltration, etc.) or to leverage certain system resources, such as ports below 1024 or virtual networking / bridging interfaces. Gaining local privilege escalation will open access to these resources, allowing the operator to establish reverse VPNs. With a normalized system interaction mediated by a terminal, the operator should now move forward by examining the system for poor configurations, improperly handled credentials, or any known privilege escalations for OS / services that could be used for privilege escalation.

### Stage 6 - Reverse VPN <a name="toc2f"></a>

*Goal: Establish a reverse VPN.*<br>
*Vector: revsh*<br>
*Privilege: root*

Upon gaining root privileges on the system the operator will want to take advantage of revsh's built-in TUN/TAP support by initializing a new virtual network device. This will allow for the forwarding of raw IP packets / ethernet frames. This feature can be used by either coupling the TUN interface with an iptables nat rule on the compromised host, or even better, enabling a bridge device between the new TAP interface and a live eth device then simply dhcp requesting an IP address on the target network. Either way, now with a proper IP address that routes onto the target network, all of Kali's tools will work natively. As a result, no further tools need to be moved to the target host, thus reducing the forensic footprint. (No need to build out nmap on the compromised host ever again.) The operator is now set up to begin the lateral movement phase from a much better position than was the case in a pre reverse-vpn world.

## A note on netcat. <a name="toc3"></a>

revsh is not intended as a replacement for netcat. In fact netcat's simplicity allows for an initial remote shell to be established on a target system with high certainty, even when such a system may be obsolete, eccentric, or just plain broken. Using netcat and revsh together allows for a more robust and powerful interaction with the target environment. 

Stages 3 and 4 are broken out into separate stages to account for the worst case in which the target system is unwilling to cooperate with revsh out of the box. I have come across instances where netcat would work where revsh couldn't initially, but after fingerprinting and analysing the target host I was able to finally establish a terminal with a custom revsh built specifically for that target. In the average case, however, the operator won't need to step through both of these stages.

## A note on SSH. <a name="toc4"></a>

SSH is a powerful tool with many of the same features as revsh. There are positives and negatives to using it, however.

Positives:
- It exists on every machine.
- It is feature rich.
- It is extremely stable.

Negatives:
- It doesn't offer a direct method for establishing a reverse shell.
- Opening a reverse tunnel to your Kali host (with the intent of then SSHing down the tunnel to the target host) requires leaving credentials unprotected in the target environment, and thus opening the operator up to a counter-hack event.
- SSH participates in the utmp/wtmp login process, thus announcing the operator's presence through the "who" and "last" commands.
- In many enterprise environments, all logins (and possibly other SSH events) are sent to a central log server for further IDS/IPS analysis and response.

This is not meant to imply that I believe SSH has no place in the cyber threat toolkit; but rather, like netcat, the operator should accept it as yet another tool, while keeping in mind its limitations.

## A note on further training. <a name="toc5"></a>

I chose not to delve too deeply into the skills / techniques required for gaining RCE and LPE, as these are all well documented online and elsewhere. For a more formalized training approach, I would recommend the [Offensive Security Certified Professional](https://www.offensive-security.com/information-security-certifications/oscp-offensive-security-certified-professional/) course offered by [Offensive Security](https://www.offensive-security.com/). This course culminates with a grueling 24 hour exam that bestows the fabled OSCP certification. This training / cert represents the state of the art.

