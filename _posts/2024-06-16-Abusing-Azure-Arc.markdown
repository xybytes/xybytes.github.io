---
title: "Abusing Azure Arc: From Service Principal Exposed to Reverse Shell"
date: 2024-06-16 13:32:20 +0300
tags:
  - Azure
categories:
  - Azure
---

Over the past year, I have explored the capabilities of Azure Arc, a service that intriguingly integrates and extends on-premises environments with cloud infrastructure. Recognizing its potential from a security perspective, I delved deeper into its vulnerabilities. My findings culminated in a presentation on a new attack vector at Bsides Leeds 2024. In this article, I will provide a comprehensive analysis of how certain a misconfiguration could be exploited by malicious actors to move from an on-premises environment to Azure, thereby putting all machines linked to Azure Arc at risk.

## What is Azure Arc?

Azure Arc is an innovative hybrid cloud platform that empowers users to control and monitor a wide range of servers and databases. This includes traditional Linux and Windows servers located on-premises environment, databases and virtual machines operating in different public clouds. Azure Arc uses Azure's built-in functionalities to easily manage resources in different locations from a central control point.

![Azure Arc Overview]({{site.baseurl}}/assets/images/Azure_Arc/azure_arc_overview.png)

To onboard a new machine in Azure Arc, we must generate a new service principal. This service principal will serve as the authentication entity, allowing the machine to connect to Azure and be enrolled in Azure Arc. The service principal must be assigned the _Azure Connected Machine Onboarding_ role at a minimum.

![Service Account]({{site.baseurl}}/assets/images/Azure_Arc/sp_01.png)

In this case, we assume that the system administrators are not following the principle of least privilege as they have assigned the roles of _Azure Connected Machine Onboarding_ and _Azure Connected Machine Resource Administrator_ to the service principal.

![SP Role]({{site.baseurl}}/assets/images/Azure_Arc/sp_roles.png)

## Add Servers with Azure Arc

Three choices exist for including a new machine. Our emphasis is on _Adding multiple servers_.

![Add machine 01]({{site.baseurl}}/assets/images/Azure_Arc/add_machine_01.png)

To integrate new internal servers (joined domain servers) into Azure Arc, we will utilize GPO method. Before we can onboard new machines using this method, it is crucial to have the installer, _AzureConnectedMachineAgent.msi_, stored in a shared location that can be accessed by the target machines. It is important to ensure that the Domain Controllers, Computers, and Admins all have change permissions for the network share. Once everything is properly set up, we can proceed to download the package and save it to the remote share. By using this system, the onboarding process will automatically begin once the new GPO is applied.

![Add machine 02]({{site.baseurl}}/assets/images/Azure_Arc/add_machine_02.png){:style="display:block; margin-left:auto; margin-right:auto"}

Furthermore, Microsoft provides a deployment toolkit that must be used to initiate the onboarding.

![Deploy tool kit]({{site.baseurl}}/assets/images/Azure_Arc/deploy_github_kit.png){:style="display:block; margin-left:auto; margin-right:auto"}

Inside the _ArcEnableServerGroupPolicy.zip_ file, we will find the following scripts:

- _DeployGPO.ps1_
- _EnableAzureArc.ps1_
- _AzureArcDeployment.psm1_

#### DeployGPO.ps1

This script needs to be executed on a Domain Controller and performs the following actions:

1. Deploys the Azure Arc Servers Onboarding GPO in the local domain
2. Copies the EnableAzureArc.ps1 onboarding script to the network Share

When we run this script, we pass two main parameters: _ServicePrincipalId_ and _ServicePrincipalClientSecret_. Additionally, we provide other parameters such as the domain (e.g., _xybytes.com_), the server where the share is stored (e.g., _dc01.xybytes.com_), and the name of the share (_ArcOnboardShare_ in this case). We also include further details like the tenant ID, resource group, and other necessary information.

```powershell
$ServicePrincipalId="5bc8bc98-6307-407b-adde-07a3425b90d7";
$ServicePrincipalClientSecret="eGm8Q~6ujDQiVh7LKaKsvmM2Cph73eqLL38lRdlm";

.\DeployGPO.ps1 -DomainFQDN xybytes.com -ReportServerFQDN "dc01.xybytes.com" -ArcRemoteShare ArcOnboardShare -ServicePrincipalSecret $ServicePrincipalClientSecret -ServicePrincipalClientId $ServicePrincipalId -SubscriptionId [...] -ResourceGroup AzureArcLAB -Location westeurope -TenantId [...]
```

After running the script, we can verify the GPO created in the Active Directory environment. Once this GPO is applied, machines will automatically begin the onboarding process to Azure Arc.

![GPO]({{site.baseurl}}/assets/images/Azure_Arc/GPO_created.png)

#### EnableAzureArc.ps1

During the onboarding process, this script is executed by machines and performs the following validation checks:

1. Checks if the machine is an Azure VM or a non-Azure machine.
2. Checks the Framework version.
3. Checks the PowerShell version.

If the server fails to meet the specified requirements, all pertinent details, including the operating system, framework version, PowerShell version, VM type, and other relevant information, are saved on a network share for subsequent analysis. In the event that the server satisfies the requirements, the script continues with the following steps:

1. Checks if the Azure Hybrid Instance Metadata Service is already installed.
2. If not installed:
   - Installs the Connected Machine agent on the machine.
   - Connects the server to Azure Arc using a Service Principal.
   - Tags the Azure Arc server with a given tag.
3. Logs any connection errors and the agent code.
4. Verifies the connection status.

#### AzureArcDeployment.psm1

It serves as a wrapper for DPAPI-NG.

```powershell
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
public static class DpapiNgUtil
{
public static string ProtectBase64(string protectionDescriptor, string input)
{
byte[] output = Protect(protectionDescriptor, Encoding.UTF8.GetBytes(input));
return Convert.ToBase64String(output);
}
public static string UnprotectBase64(string input)
[...]
```

## Where is the secret stored, and how is it protected?

While experimenting with Azure Arc, I was curious about the location of the service principal secret. Since machines joining Azure must authenticate to the cloud, they require access to this secret. After some investigation, I found that the secret is stored in a file within the network shared directory named `AzureArcDeploy`.

![enc_sp_00]({{site.baseurl}}/assets/images/Azure_Arc/encrypted_SP_00.png){:style="display:block; margin-left:auto; margin-right:auto"}

The challenge at hand is that this particular secret is encrypted and cannot be decrypted by a regular user.

![enc_sp_01]({{site.baseurl}}/assets/images/Azure_Arc/encrypted_SP_01.png)

It is rather straightforward to determine that this secret is encrypted using DPAPI-NG, a security feature introduced by Microsoft in Windows 8 and Server 2012 R2. DPAPI-NG is an advanced version of DPAPI, designed to enable secure sharing of secrets across multiple users and machines. This means that encrypted secrets with a user or computer account can be decrypted by another user. However, it's worth mentioning that DPAPI-NG decryption is limited to calls made through the MS-GKDI interface, which necessitates network access to a domain controller.

The proof that this secret is encrypted with DPAPI-NG can be found in the _DeployGPO.ps1_ script. Specifically, the following line of code performs the encryption by calling the _ProtectBase64_ function, passing the _$descriptor_ and _$ServicePrincipalSecret_ as inputs. In this case, the descriptor is composed of the Domain Computer and the Domain Controller group SID. This means, as explained in the comments, <u>the ServicePrincipalSecret can only be decrypted by the Domain Controllers and the Domain Computers security groups.</u>

```powershell
# Encrypting the ServicePrincipalSecret to be decrypted only by the Domain Controllers and the Domain Computers security groups
$DomainComputersSID = "SID=" + $DomainComputersSID
$DomainControllersSID = "SID=" + $DomainControllersSID
$descriptor = @($DomainComputersSID, $DomainControllersSID) -join " OR "
Import-Module $PSScriptRoot\AzureArcDeployment.psm1
$encryptedSecret = [DpapiNgUtil]::ProtectBase64($descriptor, $ServicePrincipalSecret)
```

This poses a significant security risk if this script is not modified and left with its default settings. <u>In this scenario, any machine account in the Domain Computers group can decrypt this secret.</u> From an attack perspective, it is not very difficult to create a new machine account in a vulnerable environment, for example, through _machine account quota_ misconfiguration, and use it to decrypt the service principal secret.

Indeed, upon inspecting the _EnableAzureArc.ps1_ script, it becomes apparent that the script leverages the _UnprotectBase64_ function for decrypting the secret. As this function is executed by the machine, it possesses the required privileges to successfully decrypt the secret.

```powershell
Function Get-ServicePrincipalSecret {
try {
Copy-Item (Join-Path $SourceFilesFullPath "AzureArcDeployment.psm1") $workfolder -Force
Import-Module (Join-Path $workfolder "AzureArcDeployment.psm1")
$encryptedSecret = Get-Content (Join-Path $SourceFilesFullPath encryptedServicePrincipalSecret)
$sps = [DpapiNgUtil]::UnprotectBase64($encryptedSecret)
Remove-Item (Join-Path $workfolder "AzureArcDeployment.psm1") -Force
}
catch {
Write-Log -msg "Could not fetch service principal secret: $($_.Exception)" -msgtype ERROR
return $false
}
return $sps
```

## Let’s Exploit It!

We assume the perspective of an attacker:

1. We have successfully penetrated the internal network.
2. We have taken control of the user account _xybytes\chris_ within Active Directory.
3. We have discovered a network share containing the _AzureArcDeploy_ directory.

We assume that we are in a vulnerable environment where the _ms-DS-Machine-Account-Quota_ attribute is set to its default value, allowing a user to create up to 10 machine accounts.

![machine account quote]({{site.baseurl}}/assets/images/Azure_Arc/machine_accout_quote.png)

We can now import _powermad.ps1_ to create a new machine account _fake01_.

![powermad]({{site.baseurl}}/assets/images/Azure_Arc/powermad.png)

At this stage, we need to authenticate using this account. We can either utilize the _runas.exe_ command with the _netonly_ flag or opt for the pass-the-ticket method using _Rubeus.exe_. Let's proceed with the latter option.

![rubeus]({{site.baseurl}}/assets/images/Azure_Arc/rubeus.png){:style="display:block; margin-left:auto; margin-right:auto"}

By having the TGT for _FAKE01_ stored in memory, we can use the following script (_dec.ps1_) to decrypt the service principal secret. Alternatively, we can use other open-source modules such as [SecretManagement.DpapiNG](https://github.com/jborean93/SecretManagement.DpapiNG).

```powershell
Import-Module .\AzureArcDeployment.psm1

$encryptedSecret = Get-Content "\\dc01\ArcOnboardShare\AzureArcDeploy\encryptedServicePrincipalSecret"

$ebs = [DpapiNgUtil]::UnprotectBase64($encryptedSecret)
$ebs
```

![dec]({{site.baseurl}}/assets/images/Azure_Arc/dec.png){:style="display:block; margin-left:auto; margin-right:auto"}

At this point, we can gather the remaining information needed to connect to Azure from the _ArcInfo.json_ file, which is stored on the same network share as the _encryptedServicePrincipalSecret_. This file contains details such as: _TenantId_, _servicePrincipalClientId_, _ResourceGroup_, and more.

```json
{
  "TenantId": "...",
  "ServicePrincipalClientId": "5bc8bc98-6307-407b-adde-07a3425b90d7",
  "ResourceGroup": "AzureArcLAB",
  "SubscriptionId": "...",
  "Location": "westeurope",
  "PrivateLinkScopeId": ""
}
```

With this information, we can use Azure CLI to authenticate as the compromised service principal and begin enumerating machines that are connected to Azure Arc.

![shell01]({{site.baseurl}}/assets/images/Azure_Arc/shell_01.png)

In the example above, we obtained a reverse shell from a server connected to Azure Arc by using a base64-encoded PowerShell reverse shell.

![shell02]({{site.baseurl}}/assets/images/Azure_Arc/shell_02.png)

![shell02]({{site.baseurl}}/assets/images/Azure_Arc/shell_03.png)

![shell03]({{site.baseurl}}/assets/images/Azure_Arc/shell_04.png)

Using this technique, we transitioned from a domain user within an Active Directory environment to Azure. By leveraging the privileges of the service principal, we compromised the remaining machines in the internal infrastructure, successfully returning to the on-premises environment.

### Defenses and Remediations

Azure Arc introduces a new potential miscofiguration for malicious actors, enabling them to transition from on-premises environments to the cloud. It is crucial to review any Microsoft scripts before executing them in a production environment. It is important to undestand that if the deployment script uses the default configuration, any machine account in the Domain Computers group could access the service principal secret. To improve security, we can create a dedicated group in Active Directory containing only the machines we plan to connect to Azure Arc. By incorporating the specific SID of this group into _DeployGPO.ps1_ we can prevent unauthorized machine accounts from accessing the service principal secret, thereby reducing the risk of potential exploits. Additionally, it is important to limit the privileges of the service principal secret by following the principle of least privilege. This ensures that even if the secret is compromised, the attacker cannot run command to other Azure Arc joined VMs.


![sp 01]({{site.baseurl}}/assets/images/Azure_Arc/sp_01.png)