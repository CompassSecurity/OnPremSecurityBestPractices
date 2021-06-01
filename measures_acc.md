[Back to Overview](README.md)
# Account & Privilege Management Measures

# Table of contents
- [Introduction](#introduction)
- [Measures](#measures)
  * [Remove local administrator rights](#remove-local-administrator-rights)
  * [Assign permissions according to the Least Privilege Principle](#assign-permissions-according-to-the-least-privilege-principle)
  * [Minimize high privileged administrator accounts](#minimize-high-privileged-administrator-accounts)
  * [Implement least-privilege administrative model](#implement-least-privilege-administrative-model)
  * [Deny logon to other tiers](#deny-logon-to-other-tiers) 
  * [Add sensitive accounts to protected users group](#add-sensitive-accounts-to-protected-users-group)
  * [Disable high privileged account delegation](#disable-high-privileged-account-delegation)
  * [Configure Exchange Split Permissions](#configure-exchange-split-permissions)
  * [Review unconstrained delegation systems](#review-unconstrained-delegation-systems)
  * [Limit users who can add systems to domain](#limit-users-who-can-add-systems-to-domain)
  * [Use group managed service accounts](#use-group-managed-service-accounts)

<a name="introduction"></a>
## Introduction
Account and Privilege Management Measures make sure that users and services have only the minimum of privileges required and highly privileged accounts are protected appropriately.

<a name="measures"></a>
## Measures

### Remove Local Administrator Rights
Local administrator rights on workstations (and possibly also on servers) have to be removed from all users except a separate local account which is managed by LAPS.
If local administrator rights are required, they should be provided only temporary for a limited amount of time. 

As seen in the [Microsoft Vulnerability Report 2021 by BeyondTrust](https://www.beyondtrust.com/resources/whitepapers/microsoft-vulnerability-report), 70% of the critical vulnerabilites could be mitigated by simply removing local administrator rights.

To list the local administrators on the current system and their source you can use the following PowerShell command:   
`Get-LocalGroupMember -Group Administrators`

### Assign Permissions According to the Least Privilege Principle 
The permissions of all the accounts should be granted according to the least privilege principle. Only the minimum permissions required by a user or a service should be available to the account. Accounts should therefore also be separated by certain aspects, e.g. tasks (support account, database administrator, daily business like reading emails,...) classification (public, internal, confidential…), environment (test, preproduction, production…) etc.

A tool like [BloodHound](https://github.com/BloodHoundAD/BloodHound) can be used to audit the permissions in the Active Directory.

### Minimize High-Privileged Administrator Accounts
Review all the accounts in the high-privileged administrative groups and remove the unnecessary privileges if possible:
- Domain Admins
- Enterprise Admins
- BUILTIN\Administrators
- Schema Admins
- Account Operators
- Backup Operators
- Print Operators
- Server Operators

To check the members of these groups you can use the following PowerShell command and specify the respective group name in the CN property:   
`([adsisearcher]"(&(ObjectClass=Group)(CN=Domain Admins))").FindAll() | % { write-host $_.Properties['Member'] }`

For further information, see Microsoft's documentation about Active Directory security groups: https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups

### Implement Least-Privilege Administrative Model
In security assessments of Active Directory domains, we often find an excessive number of accounts that have been granted rights and permissions far beyond those required to perform day-to-day work. This can quickly lead to a compromise of the domain by an attacker, because it is usually trivial to perform pass-the-hash and other credentials stealing attacks.

To partly mitigate this, a hardening of administrative accounts is necessary. For this, consider the following key points:
- The built-in local Administrator account should never be used as a service account nor to log on to local computers (except Safe Mode)   
  &rarr; Apply security controls to disable the Administrator account and deny remote logons (https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-h--securing-local-administrator-accounts-and-groups)   
- The built-in domain Administrator account should only be used for initial build and disaster-recovery   
  &rarr; Add security controls to disable the Administrator account, prevent delegation, deny remote logons, enable smart-card for interactive logon (https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-d--securing-built-in-administrator-accounts-in-active-directory)    
  &rarr; Configure auditing of the disabled built-in Administrator accounts   
- **When admin access is required:**   
  - Access should be provided regarding the administrative tier model (e.g. by creating separate admin groups for every tier)
  - Access should be only temporarily provided (e.g. by adding accounts only for a limited time to those groups)    
    &rarr; Create management accounts for protected groups (https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/appendix-i--creating-management-accounts-for-protected-accounts-and-groups-in-active-directory)   
  - All changes should be performed under supervision and be audited   
    &rarr; Privileged identity/access management software (PIM/PAM) or manual procedures   
- It should be possible to perform disaster-recovery on the whole forest   
  &rarr; Apply security controls to the domain controllers OU in each domain forest on the Built-in Administrators group (only!) to allow local and remote logon   
- Modifications to the properties or membership of the administrative group should be monitored   
  &rarr; Auditing should be configured, alerting to AD owners set and processes defined   

For a complete documentation about how to implement these points, please refer to the following Microsoft documentation: https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models

### Deny Logon to Other Tiers
One of the important points of the tiering model is, that accounts in a tier are denied logon to systems within other tiers.
For this some Group Policy Objects (GPOs) have to be configured and applied.

A minimum setup would be:
- An organizational unit (OU) for each tier (in reality this would be split into more OUs)
- A GPO for each tier to prevent the following logon types from other tiers:
  - Deny access to this computer from the network (type 2)
  - Deny logon as a batch job (type 3)
  - Deny logon as a service (type 4)
  - Deny logon locally (type 1)
  - Deny logon trough Terminal Services (type 10)

### Add Sensitive Accounts to Protected Users Group 
Starting with Windows Server 2012 R2, the Protected Users group offers additional protection for sensitive users by adding restrictions on several credentials-related settings, including:

- Password hashes are not cached
- High cryptographic standards are enforced
- NTLM authentication is prevented
- Kerberos delegation is not possible

All enterprise and domain administrator accounts should be added to this group. Accounts for services and computers should not be members of the Protected Users group. Also, since Managed Service Accounts (MSAs) and group Managed Service Accounts (gMSAs) use Kerberos Constrained Delegation (KCD), do not add these accounts to the Protected Users group, since their functionality will break.   
To prevent locking yourself out of the domain, one emergency account (domain admin) should be excluded from this group. Make sure that this account is secured properly (e.g. strong password and only accessible to a few users) and its activity is monitored and alerted. 
More details: https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts

### Disable High-Privileged Account Delegation 
All high-privileged accounts should be configured with the flag **this account is sensitive and cannot be delegated** active.   
This can be done for example with PowerShell. The following command sets the flag for all members of the "Domain Administrators" group:   
`(Get-ADGroupMember "Domain Admins" | Set-ADUser -AccountNotDelegated $true)`   

Note: As a consequence, it will not be possible anymore to use these accounts through a Kerberos delegation.

To check which accounts have the flag set, you can use the following PowerShell command:   
`([adsisearcher]'(&(objectCategory=user)((userAccountControl:1.2.840.113556.1.4.803:=1048576)))').FindAll()`   

### Configure Exchange Split Permissions 
Exchange should be configured to use the Active Directory split permissions model.
Some Exchange Server installations default to the shared permissions model, which adds potential attack paths within the domain due to the Exchange objects getting high privileges on certain Active Directory objects. These permissions will also be kept if you update your Exchange server to a newer version.

To check if your Exchange Groups might be affected, you can use the following PowerShell script: (Please note that it requires the ActiveDirectory modules installed!)   
```
Import-Module ActiveDirectory
$ADDomain = 'DOMAIN.COM' # change to your domain name here 
$DomainTopLevelObjectDN = (Get-ADDomain $ADDomain).DistinguishedName
$DomainRootPermissions = Get-ADObject -Identity $DomainTopLevelObjectDN -Properties * | Select-Object -ExpandProperty nTSecurityDescriptor | Select-Object -ExpandProperty Access
# This should detect the Exchange relevant groups and if they have too many permissions (WriteDacl):
$DomainRootPermissions | Where-Object {$_.IdentityReference -like "*Exchange*" } | % { $idref = $_.IdentityReference; $adrights = $_.ActiveDirectoryRights; Write-host "Found possible Exchange group: $idref"; if($adrights -like "*WriteDacl*") { Write-warning "This group has WriteDacl permissions!`n`r$adrights"  }else{ Write-host "Permissions are OK.`n`r$adrights"} }
```

Microsoft released a hotfix for Exchange Server 2013 and newer versions which should address the issue:   
https://support.microsoft.com/en-us/topic/reducing-permissions-required-to-run-exchange-server-when-you-use-the-shared-permissions-model-e1972d47-d714-fd76-1fd5-7cdcb85408ed

For more information about the split permissions please refer to:
- https://docs.microsoft.com/en-us/exchange/understanding-split-permissions-exchange-2013-help

### Review Unconstrained Delegation Systems 
Either disable delegation or replace it with resource-based constrained delegation.

As an example scenario where delegation is required, e.g. an IIS server using an SQL database instance as backend, implement the following points to reduce the risk:
- Have low privileged users running both the IIS Server and SQL Server
- Ensure both of these users have very long and complex passwords
- Ensure the SQL Server user hasn't the role sysadmin on the SQL Server and is not local admin on the SQL servers operating system
- Implement hardening measures based on security best practices (e.g. CIS Benchmark) on the IIS and SQL servers and their underlying operating system
- Use resource-based constrained delegation configured on the SQL service user

Always protect all high-privileged accounts from delegation! (e.g. with the flag "Account is sensitive and cannot be delegated")

To list all non-domain controller systems which allow for unconstrained delegation, use the following PowerShell command:   
`([adsisearcher]'(&(objectCategory=computer)(!(primaryGroupID=516)(userAccountControl:1.2.840.113556.1.4.803:=524288)))').FindAll()`

### Limit Users who can add Systems to Domain 
Set the number of computers that can be added to the domain by any domain user by setting the value of **ms-DS-MachineAccountQuota** to zero in the Active Directory.   
To check the current value you can use the following PowerShell command:   
`Get-ADObject ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota`

Another solution is to remove the privilege **SeMachineAccountPrivilege** for the **Authenticated Users** group in the Default Domain Controllers Policy.

Note that if you need to configure an account so it can add computers to the domain, it can be done through 2 methods:
- Preferred: Granting the permission to create computer objects on the OU
- Alternative: Assigning the **SeMachineAccountPrivilege** privilege to a specific group

### Use Group Managed Service Accounts
Implement service accounts as "Group Managed Service Accounts" whenever possible, to make sure the password is rotated regularly by the Active Directory.
Please note, that the computers hosting the service running the GMSA have access to the plaintext password and therefore have to be treated as secure as the service!
(e.g. if the GMSA is member of the protected users group, the computer has to be in Tier-0)
