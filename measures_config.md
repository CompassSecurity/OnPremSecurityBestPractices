[Back to Overview](README.md)
# Configurational Measures

# Table of contents
- [Introduction](#introduction)
- [Measures](#measures)
  * [Install EDR or Antivirus](#install-edr-or-antivirus)
  * [Enforce SMB & LDAP signing](#enforce-smb-and-ldap-signing)
  * [Disable or Restrict macros](#disable-or-restrict-macros)
  * [Enforce Multi-Factor Authentication](#enforce-multi-factor-authentication)
  * [Enforce BitLocker on Clients](#enforce-bitlocker-on-clients)
  * [Implement hardening of domain controllers](#implement-hardening-of-domain-controllers)
  * [Implement hardening of other systems](#implement-hardening-of-other-systems)
  * [Deploy strictly configured host-based firewalls](#deploy-strictly-configured-host-based-firewalls)
  * [Raise Active Directory function level](#raise-active-directory-function-level)
  * [Enable detailed audit logs](#enable-detailed-audit-logs)
  * [Enable Credential Guard](#enable-credential-guard)
  * [Enable AppLocker](#enable-applocker)
  * [Disable Spooler service](#disable-spooler-service)
  * [Limit cached credentials](#limit-cached-credentials)

<a name="introduction"></a>
## Introduction
Configurational Measures limit the possibilities for an attacker to gain higher privileges on systems within the domain and increase the overall resilience and robustness of your systems against attacks.

<a name="measures"></a>
## Measures

### Install EDR or Antivirus 
Install and enforce an Endpoint Detection and Response (EDR) or Antivirus solution on all devices.
While a traditional antivirus program detects malware and viruses by signatures, this can easily be bypassed by a sophisticated attacker. Therefore, an EDR system which detects endpoint threats based on behavior and provides real-time response, offers better protection.

When deploying EDR or Antivirus, make sure to prohibit the ability of users to disable it without a password and manage and monitor the solution centrally.

To check the locally installed AntiVirus software you can use PowerShell:   
`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct`

### Enforce SMB and LDAP Signing 
Enable and enforce SMB and LDAP signing on all Windows server and clients.
This can be set under the following group policy setting:   
SMB Signing Server
```
Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options >
Microsoft network server: Digitally sign communications (always)
```
SMB Signing Client
```
Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options ->
Microsoft network client: Digitally sign communications (always)
```

LDAP Signing Server
```
Default Domain Controller Policy > Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options >
Domain controller: LDAP server signing requirements
```
LDAP Signing Client
```
Default Domain Policy > Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options >
Network security: LDAP client signing requirements
```
To check if SMB signing is enforced locally you can use the following PowerShell command and check the "signed" property:   
`Get-SmbConnection | select *`

To check if LDAP signing is enforced on all DCs you can use the following PowerShell script:   
```
$dcs = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
# to test with the currently logged on user, env variables are being used, otherwise change this to e.g. hardcoded user
$username = "$env:userdomain\$env:username"
$credentials = new-object "System.Net.NetworkCredential" -ArgumentList $UserName,(Read-Host "Password" -AsSecureString)
foreach($dc in $dcs){
    $hostname = $dc.Name
    $Null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")
    $LDAPConnect = New-Object System.DirectoryServices.Protocols.LdapConnection "$HostName"
    $LdapConnect.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
    $LDAPConnect.Bind($credentials)
    write-host "signing on DC $hostname`: $($LDAPConnect.SessionOptions.Signing)"
}
```
If you see an error message like "Strong authentication is required for this operation.", then LDAP signing is enforced. If no error appears, LDAP signing is NOT enforced.

### Disable or Restrict Macros 
Disable Macros in Office products completely or only allow signed macros to be executed.
Note that the setting "disable with notification" allows the end user to enable the macro. Oftentimes, phishing attacks try to convince users to enable macros by displaying fake error messages, which is why this setting should not be used.

To check what the macro settings for Word and Excel are on the local machine you can use the following PowerShell commands:   
`(Get-ItemProperty 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Security').VBAWarnings`   
`(Get-ItemProperty 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security').VBAWarnings`

The returned values are described in the following table:

| Value | Macro setting |
|----------|:------------|
| 1 | Enable all macros |
| 2 | Disable all with notification |
| 3 | Disable all except digitally signed macros |
| 4 | Disable all without notification |

### Enforce Multi-Factor Authentication
Enforce Multi-Factor Authentication (MFA) on all logins which support it. Most importantly, MFA should be enforced on all logins allowing remote access to your network, all cloud services (e.g. Office 365, Azure, AWS, Google Cloud,...), all interfaces providing access to security-related systems (e.g. Firewall management interfaces, password management systems, etc.) and in general all internet-facing services. 
While any two-step verification method is better than none, wherever possible a modern MFA like FIDO2 should be used. If not possible, the usage of an authenticator app is preferred over SMS-based 2FA. 

Further details about the security of different MFA methods can be found in the following blog article by Microsoft:   
https://techcommunity.microsoft.com/t5/azure-active-directory-identity/all-your-creds-are-belong-to-us/ba-p/855124 

### Enforce BitLocker on Clients
Use BitLocker to encrypt the hard disk of all workstations.
Bitlocker should be used with a TPM and configured to require at least a PIN on startup.
In addition, the recovery key should not be stored together with the encrypted workstation.

To check if BitLocker is active and display its settings, you can use PowerShell (might have to be run in an elevated PowerShell session):   
`Get-BitLockerVolume | select *`   

For more details about BitLocker please refer to: https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-frequently-asked-questions 

### Implement Hardening of Domain Controllers 
Domain controllers should be hardened regarding to security best practices (e.g. CIS guidelines).
Besides the basic hardening which also applies to non-domain controller systems, they should have no Internet access and not have additional roles or features installed except those required for the Active Directory.

Make sure that separate Group Policy Objects (GPOs) are being used for domain controllers and permissions on those GPOs are set to only allow changes from domain administrators.

### Implement Hardening of Other Systems 
A general hardening for all devices in the network should be implemented according to best practices, e.g. CIS guidelines. Among other things, the following points should be considered:
- Disable unneeded services and features
- Reduce authorized users to a minimum
- Disable weak cryptographic algorithms (e.g. NTLMv1, SMBv1, Kerberos RC4 encryption…)
- Disable NetBIOS and LLMNR
- Disable the Proxy Auto Detection and configure WPAD URL explicitly if required
- Introduce a software update process
- Automatically log off idle Remote Desktop Protocol (RDP) sessions
- Restrict Remote Desktop Protocol (RDP) to Administrators

### Deploy Strictly Configured Host-Based Firewalls
All systems should have a strictly configured host-based firewall. Generally, all traffic should be blocked and only necessary network connections should be allowed based on restricted IPs and Ports (Whitelisting approach).

For example, on client workstations, SMB, RPC and RDP traffic should not be allowed from client to client. Only IP addresses from management systems like PAWs should be able to connect to these services.

On the server side, server-to-server communication should also be restricted as far as possible. Incoming SMB communication is normally only required to the Domain Controller and to file shares, but not between individual servers. In case of a webserver, only the HTTPS service should be available to the client network.

### Disable Spooler Service 
By default, the print spooler service is enabled on a domain controller.
Any authenticated user can remotely connect to the Domain Controller’s print server (spooler service) and request an update on new print jobs. Because the user can ask the domain controller to send the notification to a specific system (e.g. one with unconstrained delegation) the domain controller will test that connection immediately, therefore exposing the computer account credential (since the print spooler is owned by SYSTEM). This can be abused for so-called "relay attacks", where the attacker can use the exposed computer account credential to authenticate against other services in the domain.

To mitigate this, the spooler service must be disabled on all domain controllers.
In addition, the spooler service should also be disabled on all windows servers where the printing functionality is not needed.

### Enable Detailed Audit Logs
Regular log collection is essential to be able to track activities of an attacker during an active investigation or post-mortem analysis. If you do not have detailed logs available, it could be difficult to determine if an attack led to a data breach or not. In some cases, it might also be possible to detect a security incident before data gets stolen.
Therefore, advanced audit log policies should be deployed for all affected domains.

The following key events / activities should be logged on systems and services where relevant:
- Logon (successful and unsuccessful) & Logoff events
- Account changes (e.g., account creation and deletion, account privilege assignment)
- Successful use and attempted (failed) use of privileged accounts
- Process Start / Stop
- Network connections and Network changes
- Changes to, or attempts to change, system security settings and controls
- Application authentication (successful and unsuccessful)
- Application transactions
- Access to files or folders
- Executed scripts (e.g. PowerShell, Visual Basic, JavaScript, etc.)
- Clearing / Deleting of Logfiles

Some basic GPO settings for an audit policy to detect lateral movement are documented in the following cheat sheet:   
https://github.com/CompassSecurity/OnPremSecurityBestPractices/blob/c21a808f0f6e201619175701ef581091474e59a5/lateral_movement_detection_basic_gpo_settings.pdf

### Raise Active Directory Function Level
The Active Directory function level should be raised to the most recent level to ensure that the latest security features can be used.
You can check your current functional level with PowerShell:   
`([System.DirectoryServices.ActiveDirectory.Forest]::Getcurrentforest())`

The following Microsoft documentation lists the added features with each new functional level:   
https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels

### Enable Credential Guard 
The Credential Guard security feature should be enabled to protect credentials from being stolen by an attacker or a malware.

Further information:   
https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard

### Enable AppLocker 
Only programs defined in a whitelist should be allowed to be executed by the user. 

This can be achieved for example by using Microsoft Windows Defender Application Control and Microsoft AppLocker.

Further information:   
https://docs.microsoft.com/en-us/windows/device-security/applocker/applocker-overview

### Limit Cached Credentials
The number of domain passwords that are cached should be deactivated by setting the following policy to 0:   
```
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options
Interactive logon: Number of previous logons to cache (in case domain controller is not available)
```

With a value of 0, the following GPO can also be activated:   
```
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options
Interactive logon: Require Domain Controller authentication to unlock
```
Further information:
- https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj852209(v=ws.11)
