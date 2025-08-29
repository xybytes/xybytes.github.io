---
title: "When Azure Dynamic Groups Meet Weak ACLs"
date: 2025-08-29 20:00:00 +0300
tags:
  - Azure, Active Directory
categories:
  - Azure
---

Dynamic groups in Entra ID allow administrators to automatically manage group memberships by using user attributes. For instance, if an organization has different departments, it can create separate security groups for each department. By configuring dynamic groups to use the "department" attribute, any new user added to Azure AD will automatically be placed into the appropriate group based on their role.  In [Abusing dynamic groups in Azure AD for privilege escalation](https://www.mnemonic.io/resources/blog/abusing-dynamic-groups-in-azure-ad-for-privilege-escalation/), Cody Burkard shows how misconfigured dynamic groups can be exploited. By inviting a guest account with a crafted User Principal Name, an attacker can trigger group rules based on that attribute and automatically gain elevated privileges. This is possible because attributes like UPN can be user-controlled and many tenants allow broad guest invitations. To mitigate the risk, administrators should avoid using controllable attributes in group rules, restrict guest invitations, and explicitly exclude guest accounts from sensitive groups.  What many people may not realize is that the behavior of dynamic groups can also be exploited in hybrid environments. When users in Entra ID and on-premises Active Directory are synchronized, their attributes are synchronized as well. This means that an attacker who gains elevated privileges in the on-premises AD environment could manipulate user attributes there, which would then sync into Entra ID. If those attributes are used in dynamic group rules, the attacker could leverage this to escalate privileges in Azure by simply changing the relevant attributes on synchronized accounts.  To be precise, neither weak ACLs in Active Directory nor dynamic groups in Entra ID are new concepts or vulnerabilities. Both have been known for years. What is often overlooked, however, is how these two elements intersect in hybrid environments.

Let’s take a practical scenario. Suppose we have a user in Active Directory called _Hacker_ who has _GenericAll_ permissions over another user account, _Elena_. An attacker compromises a tenant using a standard user account with no privileged roles. By default, this account can still enumerate groups and view the rules of dynamic groups. During this reconnaissance, the attacker identifies a dynamic group named _SysAdmins_ and is able to see its membership condition, defined as:

```sql
(user.department -eq "IT")
```

![screenshot]({{site.baseurl}}/assets/images/Dynamic_Group/dynamic_group_rule.png)


The purpose of this rule is to automatically add all users from the IT department to the _SysAdmins_ group in Entra ID. The group has been assigned the _Virtual Machine Contributor_ role at the subscription level, giving its members the ability to deploy and manage machines in Azure. Even though the attacker does not directly control any legitimate IT department accounts, the misconfiguration on the Active Directory side, combined with the way Entra ID uses synchronized attributes, creates a clear path for exploitation. Since Hacker has _GenericAll_ permissions on Elena’s account, they can modify her attributes in Active Directory, including the _department_ field. By changing Elena’s department to IT, her account will automatically be added to the _sysAdmins_ dynamic group when the attributes synchronize to Entra ID.

![screenshot]({{site.baseurl}}/assets/images/Dynamic_Group/bloodhound.png)

```powershell
PS C:\Users\hacker> Get-ADUser -Filter 'Name -like "elena"' -Properties * | Select-Object name,UserPrincipalName,SID,Department | Format-table

name  UserPrincipalName SID                                           Department
----  ----------------- ---                                           ----------
elena elena@xybytes.com S-1-5-21-2797754682-378241684-3788216166-1117 Marketing

PS C:\Users\hacker> Set-ADUser -Identity elena -Department "IT"
PS C:\Users\hacker> Get-ADUser -Filter 'Name -like "elena"' -Properties * | Select-Object name,UserPrincipalName,SID,Department | Format-table

name  UserPrincipalName SID                                           Department
----  ----------------- ---                                           ----------
elena elena@xybytes.com S-1-5-21-2797754682-378241684-3788216166-1117 IT
```

As a result, Elena is automatically added to the _SysAdmins_ group and inherits the Virtual Machine Contributor role in Azure. The attacker, having full control over Elena’s account, can also reset her password or force a password change, fully compromising her identity. This gives the attacker elevated privileges in Azure without ever needing direct access to an administrative account.

![screenshot]({{site.baseurl}}/assets/images/Dynamic_Group/user_added_to_group.png)

## Conclusion

In this short article, my goal was to encourage penetration testers to look beyond isolated issues. In hybrid environments, it is important to connect on-premises vulnerabilities with those in Entra ID. Weak ACLs in Active Directory and misconfigured dynamic groups in Entra ID can combine to create a powerful attack path. Recognizing and testing for these overlaps should be a standard part of every penetration tester’s checklist. The majority of documented exploitation scenarios for dynamic groups do not take ACLs into account. They usually rely on other vectors such as guest invitations, user controlled attributes like the UserPrincipalName, or rules that reference easily manipulated fields. My example shows that when weak ACLs in on-prem Active Directory are combined with attribute based rules in Entra ID, an attacker can abuse synchronization to escalate privileges in ways that are often overlooked. This hybrid attack path is less visible in the public domain but just as critical. Both approaches, attribute abuse and ACL driven escalation, highlight why defenders and testers must evaluate dynamic groups in the wider context of hybrid identity systems, not just in isolation.