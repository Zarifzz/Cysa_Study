## Review of Wrong Questions
---
**Simple Object Access Protocol (SOAP)** uses Extensible Markup Language (XML), it allows computers that use different operating systems to communicate. can use HTTP, SMTP, TCP, etc.), but HTTP/S is most common.
If misconfigured or poorly coded, they can be entry points for attackers -> harden this feature, encryption, input validation, authN, etc. 

| Feature      | SOAP                       | REST                  |
| ------------ | -------------------------- | --------------------- |
| **Format**   | XML only                   | JSON, XML, HTML, etc. |
| **Protocol** | Independent, often HTTP/S  | HTTP/S only           |
| **Overhead** | Heavier (more verbose XML) | Lightweight           |
| **Security** | WS-Security standard       | HTTPS + custom        |
| **State**    | Can be stateful            | Stateless             |

**Cloud Access Security Broker (CASB)**
Some of the functions of a CASB include the following:
- Enable single sign-on authentication and enforce access controls and authorizations from the enterprise network to the cloud provider.
- Scan for malware and rogue or noncompliant device access.
- Monitor and audit user and resource activity.
- Mitigate data exfiltration by preventing access to unauthorized cloud services from managed devices.

**The Windows Registry** is a critical component of the operating system containing configuration information for hardware, software, users, and preferences. System hardening involves securing the Registry by restricting access and preventing unauthorized modifications.

**Logging Levels-** Debug is the highest level of logging in a tools such as Windows Event Viewer, providing the most verbose output for troubleshooting purposes by providing detailed information about a software application or system process.

**Administer/Administration** -> means the configuration of the device. VM Administer/Administration means the VM's config settings and such. 

**Risk Mitigation-** After identifying risks, security analyst must implement tools to mitigate risk. Training users how to spot potential social engineering attacks is key. Make sure systems are patched and updated to the latest levels helps to prevent known exploits and vulnerabilities. It is also important to deny access to a network unless explicitly allowed. This prevents accidental exposure.

**Windows Registry Keys-** The Windows Registry is a database for storing operating system, device, and software application configuration information. The support technician can use the Security Accounts Manager (SAM), which stores username information for accounts on the current computer.
SECURITY does not store username information for accounts. Instead, SECURITY is the subkey that links to the security database of the domain the current user logged on to.
DEFAULT is the subkey that contains settings for the LocalSystem account profile, not username information for accounts on the current computer.
SYSTEM does not store username information for accounts. Instead, SYSTEM is the subkey that contains settings for drivers and file systems.

**Central Policy** is a program that checks for the correct attributes in an attribute-based system.
Multi-factor authentication is an authentication process the requires two or more steps.
Role-based access management is an access management strategy where people are granted privileges depending on their role in the organization.
Attribute-based access management is an access management strategy where an attribute is created for every element of an organization's operations.
**Security Documentation**- 

| **Level** | **Mandatory?** | **Details?**      | **Example**                                       |
| --------- | -------------- | ----------------- | ------------------------------------------------- |
| Policy    | ✅ Yes          | ❌ High-level only | “All users must protect company data.”            |
| Standard  | ✅ Yes          | ✅ Specific        | “All data at rest must use AES-256 encryption.”   |
| Procedure | ✅ Yes          | ✅ Very detailed   | “Click X, then Y, then Z to encrypt files.”       |
| Guideline | ❌ No           | ✅ Suggested       | “Consider using BitLocker for laptop encryption.” |

**SSO**- uses third party DB to Authn, not its websites own DB. 

**DLP components-** Endpoint agents, Policy Server, Network agents. 
**DLP remediations:** 
- Alert only: The copying is allowed, but the management system records an incident and may alert an administrator.
- Block: The user is prevented from copying the original file but retains access to it. The user may or may not be alerted to the policy violation, but it will be logged as an incident by the management engine.
- Quarantine: Access to the original file is denied to the user (or possibly any user). This might be accomplished by encrypting the file in place or by moving it to a quarantine area in the file system.
- Tombstone: The original file is quarantined and replaced with one describing the policy violation and how the user can release it again.

Checking the company's firewall logs will help the analyst identify any external connections made by the former employee, which can indicate whether the former employee has shared company data with external parties.

**Full Disclosure** is a mailing list from Nmap that often shows the newest vulnerabilities before other sources.

**CVSS**- The PR metric with 'N' or none suggests a guest or anonymous user has access and can exploit more vulnerabilities. Setting up roles or permissions can prevent full access and most of the vulnerabilities.

**OpenSCAP** is an open-source scanner used to identify system vulnerabilities. It also provides the ability to calculate a Common Vulnerability Scoring System (CVSS) score based on the vulnerabilities identified in the system.

**Security tools-** Internet research tools include Google Earth, Google Maps, webcams, Echosec, Maltego, and Wayback Machine.
IoT hacking tools include Censys, Zniffer, Shodan, Thingful, and beSTORM.


**Different Scans-** 
With an idle scan, the hacker finds a target machine but wants to avoid getting caught, so they find another system to take the blame. This system is frequently called a zombie machine because it is disposable and creates a good distraction for the hacker. The scan directs all requests through the zombie machine. If that zombie machine is flagged, the hacker simply creates another zombie machine and continues with their work.

A full open scan completes a full two-way handshake on all ports. Open ports respond with a SYN/ACK, and closed ports respond with an RST flag, which ends the attempt. The downside of this type of scan (and the reason that it's not frequently used) is that somebody now knows you were there.

An Xmas tree scan gets its name because all the flags are turned on, and the packet is lit up like a Christmas tree. The recipient has no idea what to do with this packet, so either the packet is ignored or dropped. If you get an RST packet, you know the port is closed. If you do not get a response, the port may be open.

A NULL scan sends the packets with no flags set. If the port is open, there will be no response. If the ports are closed, an RST response is returned.


TCP scan Flags
A TCP scan uses the PSH flag to direct the sending system to send buffered data.
A SYN flag is used to start a connection between hosts.
A FIN indicates that no additional information will be sent. A closed port would not return a FIN.
An URG flags a packet as urgent and is not returned by closed ports.

**Nmap commands**
The nmap -sV or nmap -A command lets you probe and discover service details on open ports in a network.
The nmap -sP command lets you know which hosts are running in your network.
The nmap -oN command lets you save the result of an Nmap scan to a file or XML.
The nmap -iL hosts.txt command lists all the hosts in a hosts.txt file if you need to scan more than one host.

**dynamic analysis** involves using vulnerability scanning software to identify vulnerabilities

**Vuln Scanning-** Operational: Vulnerability scanning can, unfortunately, cause operational problems, such as negatively impacting a system's performance or causing services to crash.
Sensitivity levels- The data inventory describes the data in terms of what it contains, such as its classification and sensitivity

Google Earth- Literally just satellite Imagery of the place. 
Google Maps- has the whole street view thing where you can go up and down the streets, on curb level. <- Earth does not have this 

**Nikto**- can identify the type of HTTP server and web applications running on a host and expose vulnerabilities contained within them
**Arachni** Does not have this ^^^

**Exploitability** assesses the likelihood of an attacker weaponizing a vulnerability to achieve its objectives. It's more likely that an attacker will target a vulnerability with a high exploitability score, so it requires urgent attention. Therefore, a high exploitability score is an attractive target.

**Aircrack-ng** tool is primarily for assessing the security of wireless networks

**Colasoft** is a packet crafting software program that can be used to modify flags and adjust other packet content.

**Maltego** uses transforms that automatically collect and apply intelligence data to an investigation, helping investigators quickly identify relationships among entities of many types.
**Recon-ng** uses workspaces to help organize information during web-based reconnaissance. However, Recon-ng is not a feature of Maltego.

**NetAuditor** reports, manages, and diagrams network configurations

**Scan assessment reports**
Classification contains the origin of the scan.
Target includes each host's detailed information.
Services define the network services by their names and ports.
Assessment provides the scanner's assessment.

**A CVSS calculator** can determine the risk and severity of a vulnerability based on three metrics. 
These are called base, temporal, and environmental metrics.

| **Metric Type**   | **Definition**                                                                                                          | **Example**                                                                        |
| ----------------- | --------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Base**          | Inherent severity of the vulnerability, independent of time or environment.<br>Is a vulns unique characteris            | Remote code execution flaw over the internet = High score.                         |
| **Temporal**      | Adjusts Base score based on changes over time.<br>Is the Changeable attributes of a vulnerab                            | Score drops after an official patch is released.                                   |
| **Environme Customizes score based on organization’s specific context.<br>Vulns only present in certain envs or implementations.  ns.  ns.  | Vulnerability on a bank’s payment server = Higher score than on a lab test server. |

**Implementing compensating controls** can help mitigate **successful attacks** by addressing the specific risks and vulnerabilities that allowed the attacks to succeed.

> [!NOTE] Review Chap 5 vuln Assessments
> 


**SCADA**- Controls the whole infrastrucure
**ICS**- Controls certain infrastructure. 

**Data Ex-filtration: Social media platforms** can be used for data exfiltration by exploiting their messaging features, where attackers send sensitive information to external accounts. Furthermore, malicious browser extensions or social media applications can steal user data and transfer it to the attacker's server. Finally, cybercriminals can create fake profiles to establish connections with employees, tricking them into divulging sensitive data or granting access to internal systems.

**Forensics- Slack space** is the space left when a file is written. Since the space may have previously been filled by another file, file fragments are likely to exist and be recoverable

**Levels of Disk Disposition-**  clear, purge and destroy

**Prowler**- The status extended column provides more information on the security finding. In this case, the description may state, MFA is not enabled for the root account.

**CHOOSE THE BEST ANSWERS!!! NOT THE ONES THAT MAYBE/COULD BE IT** 

**The aircrack-ng suite** of tools is commonly used to carry out the attacks to capture a four-way handshake. These tools can be used to discover and monitor wireless networks, perform deauthentication attacks, and intercept the four-way handshake packets.

**inSSIDer Plus** is a wireless network scanner application

**DNSCat2**- DNS connections on port 53 can be used to execute other commands on a remote host, such as shell commands and scripts. This is a common tool hackers use to gain access through firewalls that may prevent other types of connections.

The **countermeasures for a DoS attack** are to:

- Secure remote administration and connectivity testing.
- Perform extensive input validation.
- Configure the firewall to deny ICMP traffic.
- Stop the attacker's data processing from being executed.

**Beacon activity** is commonly detected by capturing metadata about all the sessions established or attempted and analyzing it for patterns that constitute suspicious activity.

**Webhooks** are automated messages sent from an app. The messages are sent to a unique URL and include relevant information about the event and when the event occurred.
**Plugins**, also called extensions, are tools that add functionality to an existing piece of hardware or software without altering the original program. They increase the functionality of security tools.

**SOAR solution tools :**
- It provides a security information and event management (SIEM) platform.
- It generates automated malware signature creation.
- It provides Cyber Threat Intelligence (CTI) feeds.

**phases in a forensics investigation.**: Identification, collection, and reporting

**Root cause analysis** -> "what," "where," and "how" 

**Diamond Model**  -> Find out Attackers TTPs. 

**4 Sections to a Assessment Report**
- Classification contains the origin of the scan.
- Target includes each host's detailed information.
- Services define the network services by their names and ports.
- Assessment provides the scanner's assessment.

**Security Vuln Summary**-  has resolved vulns and cover every host/device scanned. 

**RISK SCORE** = IMPACT x LIKELIHOOD of a threat actor exploiting a vuln. <- Always use it at assess risk

**On-Patch Attacks Logs**- look for stuff that can be spoofed, like two DHCP acknowledgement logs, duplicate of the same thing.
`Get-Eventlog -logname <service or * (all)>` <-look at logs in Powershell Admin
For Logs -> the trouble logs are usually the ones that say failure, trouble, critical, etc. 

##### **Common nmap commands flags:**
- `--top-ports <number>`
**Host Discovery**
- `-sn` → **Ping scan** (skip port scan, just checks which hosts are up).
- `-Pn` → **No ping** (treat all hosts as online — useful when ICMP is blocked).
- `-n` → **No DNS resolution** (faster).
**Port Scanning**
- `-p <ports>` → **Specify ports** (e.g., `-p 22,80,443` or `-p-` for all ports).
- `-F` → **Fast scan** (top 100 ports).
- `--top-ports <number>` → **Scan top ports** by frequency.
**Scan Types**
- `-sS` → **SYN scan** (stealth).
- `-sT` → **TCP connect scan**.
- `-sU` → **UDP scan**.
- `-sA` → **ACK scan** (firewall rule mapping).
- `-sN` → **Null scan** (no flags set).
- `-sF` → **FIN scan**.
- `-sX` → **Xmas scan** (FIN, PSH, URG flags).
- `-sV` → **Version detection**.
- `-O` → **OS detection**.
- `-A` → **Aggressive scan** (OS + version + script + traceroute).
**Timing / Performance**
- `-T0` → `T5`
**Output Options**
- `-oN <file>` → **Normal output**.
- `-oG <file>` → **Grepable output**.
- `-oX <file>` → **XML output**.
- `-oA <basename>` → **Save in all formats** (N, G, X).
**Nmap Scripting Engine (NSE)**
- `--script=default` → **Run default safe scripts**.
- `--script=vuln` → **Check for known vulnerabilities**.
- `--script=safe` → **Safe scripts only**.
- `--script=auth` → **Authentication-related**.
- `--script=brute` → **Brute-force login attempts**.
- `--script=discovery` → **Network discovery** (e.g., SNMP, SMB).
**Common Use Cases**
- `nmap -sS -T1 <target>` → **Stealth scan (IDS evasion)**.
- `nmap -p- -sV <target>` → **Scan all ports + service detection**.
- `nmap -A <target>` → **Aggressive full recon (OS, version, scripts, traceroute)**.
- `nmap -sU -p 53 <target>` → **UDP DNS scan**.
#### WireShark Display filters
- `net 192.168.0.0` → Show all ip addresses on this subnet
- `host 192.168.0.45` → Show all packets with this IP address as the src or dst
**IP Filters**
- `ip.addr == 192.168.1.10` → Show packets to/from a specific IP.
- `ip.src == 192.168.1.10` → Show packets from this source IP.
- `ip.dst == 192.168.1.10` → Show packets to this destination IP.
- `ip.addr == 192.168.1.10 && ip.addr == 192.168.1.20` → Show traffic between two IPs.
**Port & Protocol Filters**
- `tcp.port == 80` → Show TCP traffic on port 80 (HTTP).
- `udp.port == 53` → Show UDP traffic on port 53 (DNS).
- `tcp.dstport == 443` → Show packets going to port 443.
- `tcp.srcport == 22` → Show packets coming from port 22.
**Protocol-Specific**
- `http` → Show only HTTP traffic.
- `dns` → Show only DNS traffic.
- `ftp` → Show only FTP traffic.
- `ssh` → Show only SSH traffic.
- `icmp` → Show only ICMP traffic (pings, etc.).
**Flags / Indicators**
- `tcp.flags.syn == 1 && tcp.flags.ack == 0` → Show TCP SYN packets (connection attempts).
- `tcp.flags.reset == 1` → Show TCP RST packets (connection resets).
- `tcp.flags.fin == 1` → Show TCP FIN packets (session teardown).
**Other Useful Filters**
- `tcp contains "password"` → Show packets with "password" in payload (good for exam scenarios).
- `http.request` → Show only HTTP requests (not responses).
- `http.response` → Show only HTTP responses.
- `frame contains "malware"` → Show frames with a keyword in payload.
- `!(arp or dns)` → Show everything except ARP and DNS traffic.

Subnet Masks 
![[Pasted image 20250825155622.png]]

**Port Scans ->** looks at the device and services (ports)
**Ping Sweep ->** discovers only devices not services 

**Nslookup** is a utility used to query DNS servers to obtain information about the host network, including DNS records and host names.

**Nikito** is OPEN SOURCE.

**The National Vulnerability Database (NVD)** list includes detailed information for each entry in the CVE list, such as impact rating, severity score, and fix information.

**Arachni UI**
The security analyst goes to the dispatcher's section of Arachni. It allows the analyst to load balance workloads by adding or assigning remote machines to perform the scans.
The profiles section provides a way to manage different scans. They can be personal profiles, shared profiles, and global profiles.
The extender section is available on the Burp Suite tool, where third-party providers add the extenders to change the tool's behaviors with scans.
The target section is available on the Burp Suite tool, where the tool records the information about target URLs. Administrators can browse its contents.

**Server-Side Request Forgery (SSRF) -** Leads to unauthorized access to internal server resources, like APIs and such 

**Threat modeling** identifies the principal risks and tactics, techniques, and procedures (TTPs) for which a system may be susceptible through evaluating systems from an attacker's point of view.
Diagrams can show how a security analyst can deconstruct a system into its functional parts to analyze each area for potential weaknesses.
Analyzing systems from a defender's perspective is another way that threat modeling identifies the principal risks and tactics, techniques, and procedures (TTPs) to which a system may be susceptible.

**Snort Inline**- is a modified version of Snort IDS, which is capable of packet manipulation.

**PCII program**- Legal protection for information shared within an ISAC in the United States is given by the PCII program operated by the Department of Homeland Security (DHS).

**Pentbox**- Menu item 2- Network tools takes you to another menu where you can choose to create a honeypot.

**Insider Pawn**- Forgetting a password and giving it to colleagues is an unintentional act. ANY UNINTENTIONAL ACT 
**Intentional insider threat** - INTENTIONALLY BEING MALICIOUS 

**Cloud** 
Rapid elasticity describes a cloud provider's ability to increase or decrease service levels to meet customer needs without requiring hardware changes.
Measured service refers to the way cloud services are measured or metered for billing purposes or according to a service-level agreement.
An on-demand cloud service is available to users at any time.
Cloud service providers use resource pooling to supply services to multiple customers using shared physical resources.

**heuristics programs**  -> data monitoring:
- Bring a file into a virtual testing environment and running it to identify its behavior.
- Detect suspicious files through identification of genetic signatures that are similar to previously known malware.
