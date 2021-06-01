[Back to Overview](README.md)
# Organizational Measures

# Table of contents
- [Introduction](#introduction)
- [Measures](#measures)
  * [Implement Monitoring](#implement-monitoring)
  * [Perform regular off-site backups](#perform-regular-off-site-backups)
  * [Implement patch management process](#implement-patch-management-process)
  * [Maintain Hardware and Software Inventory](#maintain-hardware-and-software-inventory)
  * [Use group based access control](#use-group-based-access-control)
  * [Separate Tier-0 management services](#separate-tier-0-management-services)
  * [Introduce privileged access workstations](#introduce-privileged-access-workstations)
  * [Do regular reviews & vulnerability assessments](#do-regular-reviews---vulnerability-assessments)
  * [Define Emergency Processes](#define-emergency-processes)
  * [Train employees on IT security best practices](#train-employees-on-it-security-best-practices)
  * [Use personalized accounts](#use-personalized-accounts)
  * [Implement four eyes principle](#implement-four-eyes-principle)
  * [Use golden images](#use-golden-images)

<a name="introduction"></a>
## Introduction
Organizational measures relate to the system's environment and the people using it. They can be considered as the approach an organization takes in assessing, developing and implementing controls that secure information and protect personal data. 

<a name="measures"></a>
## Measures

### Implement Monitoring
Setup a monitoring infrastructure. For example, consisting of:
- A centralized logging server and log analytics software (Elk Stack, Splunk, Windows Event Log Forwarding).
- Configuring Windows server and clients to collect logs of security relevant events (https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations).
- Forward logs of all security related systems and services like the web application firewalls, network firewalls and anti-virus / endpoint protection software.
- Forward logs of the DHCP and DNS servers, in order to make inspection of network activity possible.
- Define a process that ensures events are reviewed on a regular basis.
- Define events that should trigger an alert, like multiple failed login attempts or assignment of users to administrative groups.
- Ensure alerts are being sent out to relevant parties (e.g. on-call shifts)
- Define playbooks and processes to act on specific alerts and events

### Perform Regular Off-Site Backups
Make sure that important infrastructure and data is backed up on regular basis.
The following requirements have to be met:
- Define which data and infrastructure need to be backed up and define a retention period accordingly.
- Store backups in a storage secured from unauthorized access.
- Store backups encrypted.
- Perform off-site backups. (Disaster recovery)
- Store backups offline, completely disconnected from any device. (Assume breach of your backup infrastructure)
- Use a separate backup infrastructure (e.g. Windows Server Backup) to perform backups of Domain Controllers. (Tier-0 separation)

### Implement Patch Management Process
A process has to be defined that handles the way servers, workstations, other devices (e.g. Firewalls) and applications are kept up to date with the lastest security updates. Apart from maintenance windows for regular security updates, a special process should be defined, for out-of-band emergency security updates which have to be deployed immediately.

### Maintain Hardware and Software Inventory
Without knowing what systems and software are installed in the environment, it is not possible to keep everything up to date. Therefore it is essential to have an inventory of all hardware devices and installed software and actively maintain it.

### Use Group-Based Access Control
Access to resources should be granted according to predefined groups. For example, employees responsible for human resources should not be able to access the data of the financial department. According AD groups should be defined and the according users should be assigned to those groups.

### Separate Tier-0 Management Services
A compromised management service (e.g. backup server, infrastructure management, monitoring, etc.) in Tier-1 or Tier-2 should not make it possible to compromise the whole domain (Tier-0).

Therefore, all services managing domain controllers and other Tier-0 assets must be built solely for Tier-0 or need to be removed for Tier-0 completely. Examples would be System Center Configuration Manager (SCCM), endpoint protection, backup, etc.
One possibility would be to manually patch all domain controllers and use e.g. Windows Backup as the backup solution.

### Introduce Privileged Access Workstations
Administration of Active Directory and other Tier-0 Servers should only be performed through a Privileged Access Workstation (PAW). 
The following key points have to be considered when deploying a PAW:
- The PAW has to be deployed regarding to the "clean source principle", meaning the source (i.e. the PAW) has to be as secure as the target it accesses (i.e. the Tier-0 servers)
- The host-based firewall on the PAW has to be configured to restrict all traffic to only the required minimum (e.g. downloading updates, connecting via RDP/SSH to targets being managed, etc.)
- Internet access from the PAW has to be locked down, so that only Windows Updates and Azure URLs (if Azure / O365 is being used) are allowed (See: https://docs.microsoft.com/en-us/security/compass/privileged-access-deployment#url-lock-proxy)
- Applications on the PAW should be kept to the minimum and AppLocker should be deployed
- Daily tasks like reading emails or opening office documents and surfing the Internet must not be allowed on the PAW
- Credential Guard should be enabled on the PAW
- If you have a separate bastion forest for the management of your infrastructure, the PAW should be joined to this forest and not the production forest. 

As an example, The host operating system on a laptop or PC could be used as the PAW and via the Hyper-V feature, a shielded VM could be deployed on it to perform daily tasks (email, office, Internet, etc.).
It must not be the other way around, since that would mean that the PAW would consequently be dependent on the host, and this violates the clean source rule.
Another option would be to use two completely separated workstations, one as PAW and one as the workstation for daily tasks.

Some key points to consider when connecting from the PAW to systems in different Tiers:
- A PAW from Tier-0 can be used for administering all Tiers (i.e. 0, 1 and 2) AND the accounts used for connecting to those Tiers must be different for each tier and privileged only in that specific Tier.
- A PAW from Tier-1 can be used for administering Tiers 1 and 2 only AND the accounts used for connecting to those Tiers must be different for each tier and privileged only in that specific Tier.
- A PAW from Tier-2 can be used for administering Tier-2 only AND the accounts used for connecting to Tier-2 must be privileged only in Tier-2.

In addition, please note that a PAW does not replace a Jump Host or the other way around. A Jump Host itself does not add additional security, because it is dependent on the source connecting to it, while the PAW is the source of the connection. (See also: https://docs.microsoft.com/en-us/archive/blogs/johnromsft/closing-the-jump-server-security-gap-with-paws)


### Do Regular Reviews & Vulnerability Assessments
Computer systems present in the corporate network should be checked regularly for known vulnerabilities using automated scanners (e.g. Nessus, Qualys, Rapid7, etc.).
Security issues related to Windows Domain configuration should be assessed regularly (e.g. PingCastle, BloodHound).

- A process should be defined, which makes sure these scans are performed on a regular basis, the findings are evaluated and according actions are taken to mitigate the identified risks.
- A process should be defined to check if users, groups and computers are still needed in the AD and if assigned permissions (e.g. members of high privileged groups) still follow the principle of least privilege.

### Define Emergency Processes
Define guidelines how employees should react in case of a cyberattack. 
Address the following key points:
- Create an incident response policy and plan.
- Create procedures for incident handling and reporting.
- Establish procedures for communicating with outside parties.
- Establish response teams and leaders.
- Prioritize servers and other critical assets.
- Walk through the process and train the involved employees on a regular basis.

### Train Employees on IT Security Best Practices
The employees' security awareness should be regularly trained. For example, by:
- Teaching about secure handling of credentials (choose different passwords for different services, don't write down passwords, use a password manager, lock the laptop, disconnect from RDP...).
- Performing phishing email simulations.
- Explaining physical social engineering attacks like tailgating.

### Use Personalized Accounts
Employees should always use personalized accounts to guarantee traceability and accountability. Technial, non-personal accounts should only be used for machine-to-machine communication.

The use of default/shared accounts should be restricted to disaster recovery cases.

### Implement Four Eyes Principle
Business critical processes should be additionally protected by a four eyes principle (also known as "Two-man rule"), which is a control mechanism that requires activities by individuals within the organization to be controlled and approved by a second independent and competent individual.

### Use Golden Images
Maintain and use golden images to install your systems. These should be hardened regarding to security best practices (e.g. CIS guidelines).
The following link contains a documentation by Microsoft on how to create such an image for a Windows 10 operating system:
https://docs.microsoft.com/en-us/windows/deployment/deploy-windows-mdt/create-a-windows-10-reference-image
