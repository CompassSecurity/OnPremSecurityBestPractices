[Back to Overview](README.md)
# Password Management Measures

# Table of contents
- [Introduction](#introduction)
- [Measures](#measures)
  * [Enforce strong password policy](#enforce-strong-password-policy)
  * [Use unique local administrator credentials](#use-unique-local-administrator-credentials)
  * [Require password for every account](#require-password-for-every-account)
  * [Change default credentials](#change-default-credentials)
  * [Force change of initial passwords](#force-change-of-initial-passwords)
  * [Store credentials securely](#store-credentials-securely)
  * [Configure account lockout](#configure-account-lockout)
  * [Configure strong password on service accounts with SPN](#configure-strong-password-on-service-accounts-with-spn)
  * [Review accounts with never expiring password](#review-accounts-with-never-expiring-password)
  * [Enable Kerberos Pre-Authentication](#enable-kerberos-pre-authentication)
  * [Change krbtgt password regularly](#change-krbtgt-password-regularly)

<a name="introduction"></a>
## Introduction
Password Management Measures prevent users from using weak passwords and reduce the risk of account takeover through password brute-forcing or password hash cracking.

<a name="measures"></a>
## Measures

### Enforce Strong Password Policy 
Strong passwords are at least fourteen characters long, consisting of characters from the four groups mentioned below:
- Lowercase characters
- Uppercase characters
- Numbers
- Special characters

To check the current password policy for all domains in the forest, you can use the following PowerShell command:   
`(Get-ADForest -Current LoggedOnUser).Domains | %{ Get-ADDefaultDomainPasswordPolicy -Identity $_ }`   

Furthermore, the password should be checked against a list of breached passwords, if possible.
Microsofts Azure AD Password Protection feature can also be used in hybrid environments for on-premise Active Directories:   
https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad-on-premises

Note: If you implement a list of banned passwords (password blacklist), there's no need for a policy with special characters and lower- / uppercase characters. In fact, newer guidelines advise against using such policies because of human behavior leading to more predictable passwords. However, for technical accounts like service accounts, it is still recommended. 

### Use Unique Local Administrator Credentials 
The local administrator password should be changed on a regular basis and should be unique on every host (workstations and servers!).

Microsoft LAPS (Local Administrator Password Solution) can be used to automate local credential management.
The LAPS software and the installation and operation guide can be downloaded under the following Microsoft link:
- https://www.microsoft.com/downloads/details.aspx?familyid=6e424d9b-e6dd-41c8-8523-6818fc2f07ec

### Require Password for Every Account 
No account should be allowed to have a blank password. The flag **PASSWD_NOTREQD** should be removed from the **userAccountControl** field on every account.

A list of users which can have an empty password can be extracted with the following PowerShell command:   
`([adsisearcher]'(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))').FindAll()`   

### Change Default Credentials 
Services and third-party devices (e.g. NAS, application servers, monitoring applications…) should have their default credentials changed.
Default passwords can be easy guessed or are found in online documentation and are therefore an easy target for attackers.

### Force Change of Initial Passwords
Initial passwords (e.g. "Sommer2021", "Companyname1234$") can be easily identified using password spraying attacks, whereas an attacker tries a single password on all domain accounts. Since this kind of attack cannot be prevented in an Active Directory, the chance to identify accounts with a valid password is usually high.

Therefore, initial passwords configured by e.g. Helpdesk staff has to be configured to require change on first use (Flag "User must change password at next logon").

### Store Credentials Securely 
Only store passwords in secure places like password managers.

Example of insecure places where to store passwords:
- GPOs to deploy local administrator
- Scripts in SYSVOL shares
- Files on shares
- Object description in Active Directory
- Field userPassword in Active Directory

### Configure Account Lockout
Make sure that an account is locked out for several minutes after a few unsuccessful login attempts.   
- Set the lockout threshold to 10 or fewer attempts
- Set the lockout duration to 15 minutes or more
- Set the reset lockout count value to 15 or more minutes

To check the lockout settings in the current password policy for all domains in the forest, you can use the following PowerShell command:   
`(Get-ADForest -Current LoggedOnUser).Domains | %{ Get-ADDefaultDomainPasswordPolicy -Identity $_ }`   

### Configure Strong Password on Service Accounts with SPN 
Make sure service accounts, especially the ones with SPN, have a strong password with 25 characters or more.

In addition, high-privileged accounts shouldn't have an SPN, as their compromise would have higher impact on the domain.

### Review Accounts with Never Expiring Password 
Check accounts that have a non-expiring password. Make sure that only low privileged service accounts are configured with non-expiring passwords.   
To check accounts with a non-expiring password you can use the following PowerShell command:   
`([adsisearcher]'(&(objectCategory=user)((userAccountControl:1.2.840.113556.1.4.803:=65536)))').FindAll()`   

### Enable Kerberos Pre-Authentication 
Make sure that all accounts require Kerberos pre-authentication. This is enabled by default on every AD account, but can be configured by unchecking **Do not require Kerberos preauthentication** in the "Account" tab.
To check all accounts which do not require Kerberos pre-authentication, you can use the following PowerShell script:   
`([adsisearcher]'(&(objectCategory=user)((userAccountControl:1.2.840.113556.1.4.803:=4194304)))').FindAll()`   

### Change Krbtgt Password Regularly 
The password of the **krbtgt** account should be changed every 40 days.

More information:
- https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-accounts#sec-krbtgt

Warning:
The password should not be changed twice in a short time. More precisely, a complete replication between every domain controller must have been performed before changing the password a second time. Otherwise, authentication will fail due to different passwords being in use.
