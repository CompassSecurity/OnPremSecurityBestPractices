[Back to Overview](README.md)
# Network Measures

# Table of contents
- [Introduction](#introduction)
- [Measures](#measures)
  * [Implement network segmentation & segregation](#implement-network-segmentation---segregation)
  * [Use mail gateway with malware detection](#use-mail-gateway-with-malware-detection)
  * [Secure WiFi networks](#secure-wifi-networks)
  * [Exclusively use encrypted protocols](#exclusively-use-encrypted-protocols)
  * [Restrict outbound traffic and deploy filtering proxy](#restrict-outbound-traffic-and-deploy-filtering-proxy)
  * [Deploy Network Access Control (NAC)](#deploy-network-access-control--nac-)
  * [Deploy DNS sinkhole](#deploy-dns-sinkhole)

<a name="introduction"></a>
## Introduction
Network measures reduce the attack surface of systems, by dividing networks into zones and separating systems from each other.

<a name="measures"></a>
## Measures

### Implement Network Segmentation & Segregation 
Firewalled network zones should be created to isolate systems of different classification. For example, create isolated network zones for:
- DMZ for systems exposed to the Internet
- Client network for end user workstations
- Server network for server systems containing sensitive data
- Domain Controllers
- Management network for management interfaces and management systems (e.g. Jump Hosts)
- Network for Privileged Access Workstations
- Network for VoIP systems

Traffic between the zones should be strictly limited to the required communication. Restrictions should always include a source, a target and a protocol (i.e. no any-to-any rules).

An even better way would be to use the concept of micro-segmentation, whereby network communication is separated on workload level instead of network zones.
An explanation about micro-segmentation can be found on the following VMWare website: https://www.vmware.com/topics/glossary/content/micro-segmentation

### Use Mail Gateway with Malware Detection 
A mail gateway should be deployed, which filters incoming email traffic for malware and detects potential phishing attacks.

### Secure WiFi Networks 
Setup the wireless infrastructure according to security best practices:
- Separate Guest and Enterprise Network
- WPA2 Enterprise preferred (EAP-TLS), enforce authentication server certificate validation by the client 
or use less preferred WPA2 PSK with a strong key (12 characters or more)
- Don’t use WPA or WEP
- Use Rogue Access Point detection
- Enforce client isolation
- Physical protection of Access Points

### Exclusively use Encrypted Protocols 
Only encrypted protocols should be used, both in the internal network and for external communication.

Unencrypted protocols (e.g. Telnet, FTP, HTTP…) should be deactivated or replaced by their secure counterpart (i.e. SSH, HTTPS etc.).

Furthermore, make sure all protocols only support state-of-the-art cryptographic algorithms and use appropriate key lengths for the respective purpose.   
The following website can be helpful for choosing the right algorithms and key lengths: https://www.keylength.com/

### Restrict Outbound Traffic and deploy Filtering Proxy 
Corporate systems should not be allowed to access systems outside of the company. Therefore, restrictive outbound Firewall rules should be deployed. 

Access to the Internet should be provided through a filtering proxy with SSL/TLS splitting.

### Deploy Network Access Control (NAC) 
Ensure that certificate-based NAC (802.1X-2010) is used in combination with MACsec (IEEE 802.1AE) to ensure only authorized devices are connected to the network and to encrypt the connection from the device to the switch on layer 2.

Ideally, every device should support certificate-based NAC in combination with MACsec. However, since this is not always supported, exceptions can be implemented:
- Certificate-based NAC without MACsec for devices that do not support MACsec
- MAC Whitelisting for devices that do not support certificate-based NAC, but restricted on specific ports

### Deploy DNS Sinkhole 
Client machines should only be able to query a dedicated DNS server which performs filtering and logging of the incoming DNS queries. If a query is identified as malicious, the IP of a sinkhole server should be returned instead of the correct IP. This can be used to block unwanted communication. Access to other DNS servers needs to be prohibited through restrictively configured outbound rules.
The following article by SANS contains more information about configuring a DNS sinkhole for Windows DNS servers:   
https://www.sans.org/blog/windows-dns-server-sinkhole-domains-tool/
