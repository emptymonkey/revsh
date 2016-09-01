
# Beachhead Landing Process

There are many documents online that break down a cyber attack into various stages. Roughly, these stages are:

1. Passive reconnaissance. (e.g. Google, Shodan, Linkedin, etc.)
2. Active reconnaissance. (e.g. nmap, dns forward / reverse lookups, etc.)
3. Server compromise.
4. Establish persistence.
5. Move laterally.
6. *...wash, rinse, repeat on your way to the actual target...*
7. Data exfiltration, modification, or destruction.

These lists, while generally intended as overviews, always leave me feeling as though the structure of the process involved in "Server Compromise" (step #3) is simply ignored, or perhaps brushed under the rug. The purpose of this document is to address that by codifying some structure around the process involved in a server compromise. I refer to this as the ***Beachhead Landing Process***. In this document I will outline and describe each stage of this process.

It should be noted that the stages outlined below are meant as an enumeration of all possible steps in this process. A specific engagement may not have (or need) all of these stages. For example, when faced with a web application with command injection running as root, the operator will be able to skip from stage 1 all the way to stage 6 in one maneuver. In general though, most of the stages listed below will come into play in some form.

revsh was written specifically to enable / greatly ease several of the later stages of this process.

## Stages of a Beachhead Landing 

### Stage 1 - Limited Control

*Goal: Gain limited Control.*<br>
*Vector: Remote Vulnerability*<br>
*Privilege: Non-privileged User*

The operator will need to begin by identifying a remote vulnerability and exploiting it. This may only grant the operator limited control over the server, such as file upload to the webroot or database field extraction.

### Stage 2 - Remote Code Execution (RCE)

*Goal: Gain arbitrary RCE.*<br>
*Vector: Variable*<br>
*Privilege: Non-privileged User*

Once the operator has found a limited remote functionality vulnerability, they will want to leverage it to grant repeatable arbitrary remote code execution. In the above example of a vulnerable web application with file upload to the webroot, this stage could be performed by uploading a webshell.

### Stage 3 - Reverse Shell

*Goal: Establish a reverse shell.*<br>
*Vector: netcat*<br>
*Privilege: Non-privileged User*

In this stage, the arbitrary RCE from stage 2 will be leveraged to download a copy of netcat that has the GAPING_SECURITY_HOLE feature enabled. Once downloaded, the operator will open a reverse shell with netcat then proceed with several high priority / low impact tasks. (E.g. fingerprinting the host, assessing the level of system usage by it's owners, as well as identifying any additional services provided by this host.) After the completion of the initial tasks the operator may find that further tasks, such as privilege escalation or lateral movement would best be performed from a proper terminal.

### Stage 4 - Reverse Terminal

*Goal: Establish a reverse terminal.*<br>
*Vector: revsh*<br>
*Privilege: Non-privileged User*

The operator will now Leverage the netcat shell established in stage 3 to download and launch revsh. Beyond a basic shell, there will now be a full terminal for the operator to take advantage of. Ctrl-c will now do the appropriate thing. Many system commands that require a terminal to work properly will also now be available.

In this stage, even as a non-privileged user, revsh allows for point-to-point passthrough network proxies, as well as dynamic socks proxy tunnels. This enables the operator to leverage "behind the host firewall" style attacks, burpsuite, and the use of most system tools on Kali by way of proxychains. If privilege escalation is determined to be too risky (for reasons of either system stability or covertness of action) the operator can stop here and still have a fully functioning beachhead within the target environment.

### Stage 5 - Local Privilege Escalation (LPE)

*Goal: Gain LPE.*<br>
*Vector: LPE Vulnerability*<br>
*Privilege: Non-privileged User*

Gaining root level access on a server is only necessary for some offensive forensics (e.g. root SSH keys, memory dumps for in-memory password / key exfil, etc.) or to leverage certain system resources, such as ports below 1024 or virtual networking / bridging interfaces. Gaining local privilege escalation will open access to these resources, and thus allow us to move forward with establishing a reverse VPN. In order to move forward to stage 6 the operator should now examine the system for poor configurations, improperly handled credentials, or any known privilege escalations for OS / services that could be used in privilege escalation.

### Stage 6 - Reverse VPN

*Goal: Establish a reverse VPN.*<br>
*Vector: revsh*<br>
*Privilege: root*

Upon gaining root privileges on the system the operator will want to relaunch revsh to take advantage of the TUN/TAP support. This will allow the operator to forward raw IP packets / ethernet frames. This feature can then be leveraged by using the TUN device and setting up an iptables nat rule on the compromised host. Even better, the operator could enable a bridge device between the new TAP device and a live eth device, then simply dhcp request an IP address on the target network. Either way, now with a proper IP address that routes onto the target network, all of Kali's tools will work natively. As a result, no further tools need to be moved to the target host, thus reducing the forensic footprint. The operator is now set up to begin the lateral movement phase from a much better position than was the case in a pre reverse-vpn world.

## A note on netcat.

revsh is not intended as a replacement for netcat. In fact netcat's simplicity allows for an initial remote shell to be established on a target system with high certainty, even when such a system may be obsolete, eccentric, or just plain broken. Using netcat and revsh together allows for a more robust and powerful interaction with the target environment. 

Stages 3 and 4 are broken out into separate stages to account for the worst case in which the target system is unwilling to cooperate with revsh out of the box. I have come across instances where netcat would work where revsh couldn't initially, but after fingerprinting and analysing the target host I was able to finally establish a terminal with a custom revsh built specifically for that target. In the average case, however, the operator won't need to step through both of these stages.


## A note on SSH.

SSH is a powerful tool with many of the same features as revsh. There are positives and negatives to using it, however.

Positives:
- It exists on every machine.
- It is feature rich.
- After years of use, it is extremely stable.

Negatives:
- It doesn't offer a direct method for establishing a reverse shell.
- Opening a reverse tunnel to your Kali host (with the intent of then SSHing down the tunnel to the target host) requires leaving credentials unprotected in the target environment, and thus opening the operator up to a counter-hack event.
- SSH participates in the utmp/wtmp login process.
- In many enterprise environments, all logins (and possibly other SSH events) are sent to a central log server for further IDS/IPS analysis and response.

This is not meant to imply that I believe SSH has no place in the cyber threat toolkit; but rather, like netcat, the operator should accept it as yet another tool, while keeping in mind its limitations.

## A note on further training.

I chose not to delve too deeply into the skills / techniques used in gaining RCE and LPE, as these are all well documented online and elsewhere. For a more formalized training approach, I would recommend the [Offensive Security Certified Professional](https://www.offensive-security.com/information-security-certifications/oscp-offensive-security-certified-professional/) course offered by [Offensive Security](https://www.offensive-security.com/). This course culminates with a grueling 24 hour exam that bestows the fabled OSCP certification. This training / cert represents the state of the art.

