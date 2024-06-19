---
title: "Abusing Azure Arc: From Service Principal Exposed to Reverse Shell"
date: 2024-06-16 13:32:20 +0300
tags:
   - Azure
categories:
   - Azure
---

Over the past year, I have been experimenting with Azure Arc service. I found it to be a fascinating service that combines and extends the internal and on-premises environments, merging them with the cloud. I believed it would be an intriguing service to explore from a security standpoint, and my intuition proved to be correct. I had the opportunity to present this new attack vector at Bsides Leeds 2024, and in this article, I will delve into greater detail on how these attacks are explored and can be utilized by malicious actors to transition from the on-premises environment to Azure, and subsequently compromise all the machines connected to Azure Arc.

## What is Azure Arc?

Azure Arc is an innovative hybrid cloud platform that empowers users to control and monitor a wide range of servers and databases. This includes traditional Linux and Windows servers located on-premises environment, databases and virtual machines operating in different public clouds. Azure Arc uses Azure's built-in functionalities to easily manage resources in different locations from a central control point.

![Azure Arc Overview]({{site.baseurl}}/assets/images/Azure_Arc/azure_arc_overview.png)

To onboard a new machine in Azure Arc, it's essential to create a new service principal. This service principal will serve as the authentication entity for connecting to Azure and adding the machine to Azure Arc. Following this, you should at least assign the Azure Connected Machine Onboarding role to the service principal.

![SP_01]({{site.baseurl}}/assets/images/Azure_Arc/sp_01.png)

In this scenario, suppose the system administrator lacks expertise and is about to assign the roles of Azure Connected Machine Onboarding and Azure Connected Machine Resource Administrator.

![SP Role]({{site.baseurl}}/assets/images/Azure_Arc/sp_roles.png)

## Add Servers with Azure Arc

Three choices exist for including a new machine. Our emphasis is on Adding multiple servers.

![Add machine]({{site.baseurl}}/assets/images/Azure_Arc/add_machine_01.png)

To integrate a new internal server (a joined domain server) into Azure Arc, we will utilize Group Policy Objects (GPO). Before we can onboard a new machine using Group Policy Object (GPO), it is crucial to have the installer, AzureConnectedMachineAgent.msi, stored in a shared location that can be accessed by the target machines. This information is detailed in point 2, which specifies the requirement for a remote share to host the Windows Installer package. It is important to ensure that the Domain Controllers, Computers, and Admins all have change permissions for the network share. Once everything is properly set up, we can proceed to download the package and save it to the remote share.

![Add machine]({{site.baseurl}}/assets/images/Azure_Arc/add_machine_02.png)

Simplifying the process, Microsoft offers a deployment toolkit.

![Add machine]({{site.baseurl}}/assets/images/Azure_Arc/deploy_github_kit.png)

Within the ArcEnableServerGroupPolicy zip file, we'll discover the script DeployGPO.ps1, EnableAzureArc.ps1 and AzureArcDeployment.psm1

### DeployGPO.ps1

This script needs to be executed in a Domain Controller and makes the following actions:

1. Deploys the Azure Arc Servers Onboarding GPO in the local domain
2. Copies the EnableAzureArc.ps1 onboarding script to the network Share

When we run this script, we pass two main parameters: `ServicePrincipalId` and `ServicePrincipalClientSecret`. Additionally, we provide other parameters such as the domain (e.g., `xybytes.com`), the server where the share is stored (e.g., `dc01.xybytes.com`), and the name of the share (`ArcOnboardShare` in this case). We also include further details like the tenant ID, resource group, and other necessary information.

```powershell
$ServicePrincipalId="5bc8bc98-6307-407b-adde-07a3425b90d7";
$ServicePrincipalClientSecret="eGm8Q~6ujDQiVh7LKaKsvmM2Cph73eqLL38lRdlm";

.\DeployGPO.ps1 -DomainFQDN xybytes.com -ReportServerFQDN "dc01.xybytes.com" -ArcRemoteShare ArcOnboardShare -ServicePrincipalSecret $ServicePrincipalClientSecret -ServicePrincipalClientId $ServicePrincipalId -SubscriptionId [...] -ResourceGroup AzureArcLAB -Location westeurope -TenantId [...]
```

Now we can check the GPO created in the AD environment. When this GPO is applied, the machines will automatically start the onboarding process to Azure Arc.

![GPO]({{site.baseurl}}/assets/images/Azure_Arc/GPO_created.png)

### EnableAzureArc.ps1

During the onboarding process, this script is executed by the machines and performs the following validation checks:

1. Checks if the machine is an Azure VM or a non-Azure machine.
2. Checks the Framework version.
3. Checks the PowerShell version.

If the server doesn't meet the requirements, all the information from the server, such as OS, Framework version, PowerShell version, VM type, etc., is stored in a network share for further analysis.

If the server meets the requirements, the script proceeds as follows:

1. Checks if the Azure Hybrid Instance Metadata Service is already installed.
2. If not installed:
   - Installs the Connected Machine agent on the machine.
   - Connects the server to Azure Arc using a Service Principal.
   - Tags the Azure Arc server with a given tag.
3. Logs any connection errors and the agent code.
4. Checks the `azcmagent.exe` version and updates the agent if a new version is found in the network folder.
5. Verifies the connection status.
6. If the server is disconnected, logs the last errors from the `azcmagent.exe` agent to the shared folder.

### AzureArcDeployment.psm1

Wrapper for DPAPI-NG features

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

While experimenting with Azure Arc, I kept wondering about the location of the service principal secret. Machines joining Azure must be authenticated to the cloud, requiring access to the service principal secret. After some searching, I discovered that the secret was stored in a file within the network shared directory named `AzureArcDeploy`.

![enc_sp_00]({{site.baseurl}}/assets/images/Azure_Arc/encrypted_SP_00.png)

The challenge at hand is that this particular secret is encrypted and cannot be decrypted by a regular user.

![enc_sp_01]({{site.baseurl}}/assets/images/Azure_Arc/encrypted_SP_01.png)

The secret is encrypted using DPAPI-NG, a security feature introduced by Microsoft in Windows 8 and Server 2012 R2. DPAPI-NG enhances the security framework, allowing for the secure sharing of secrets across different users and machines. This means that encrypted secrets can be decrypted by another user or machine. However, it's worth mentioning that DPAPI-NG decryption is limited to calls made through the MS-GKDI interface, which necessitates network access to a domain controller.

The proof that this secret was encrypted with DPAPI-NG can be found in the `DeployGPO.ps1` script. Specifically, the following line of code performs the encryption by calling the `ProtectBase64` function, passing the `$descriptor` and `$ServicePrincipalSecret` as inputs. In this case, the descriptor is composed of the domain computer SID and the Domain Controller group SID. This means, as explained in the comments, that the `ServicePrincipalSecret` can only be decrypted by the Domain Controllers and the Domain Computers security groups.

```powershell
# Encrypting the ServicePrincipalSecret to be decrypted only by the Domain Controllers and the Domain Computers security groups
$DomainComputersSID = "SID=" + $DomainComputersSID
$DomainControllersSID = "SID=" + $DomainControllersSID
$descriptor = @($DomainComputersSID, $DomainControllersSID) -join " OR "
Import-Module $PSScriptRoot\AzureArcDeployment.psm1
$encryptedSecret = [DpapiNgUtil]::ProtectBase64($descriptor, $ServicePrincipalSecret)
```

This poses a significant security risk if this script is not modified and left with its default settings. In this scenario, any machine account in the Domain Computers group can decrypt this secret. From an attack perspective, it is not very difficult to create a new machine account in a vulnerable environment, for example, through machine account quota misconfiguration, and use it to decrypt the service principal secret.

Indeed, upon inspecting the EnableAzureArc.ps1 script, it becomes apparent that the script leverages the `UnprotectBase64` function for decrypting the secret. As this function is executed by the machine, it possesses the required privileges to successfully decrypt the secret.

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

We assum the perspective of an attacker:

1. We have successfully penetrated the internal network.
2. We have taken control of the user account xybytes\chris within Active Directory.
3. We have discovered a network share containing the AzureArcDeploy directory.

In order to ensure that the machine account quota is set to its default configuration, our priority is to verify if a regular user can create up to 10 machine accounts. These accounts will be located within the domain computers group.

![machine account quote]({{site.baseurl}}/assets/images/Azure_Arc/machine_accout_quote.png)

We can now improt pwoermand to create a new machine account fake01

![powermad]({{site.baseurl}}/assets/images/Azure_Arc/powermad.png)

At this stage, authentication is required for this account. You can utilize `runas.exe` command with the `netonly` flag or proceed with the pass-the-ticket option using `Rubeus`. Let's proceed with the latter choice.

![rubeus]({{site.baseurl}}/assets/images/Azure_Arc/rubeus.png)

By having the TGT for FAKE01 stored in memory, we can use the following script (`dec.ps1`) to decrypt the Service principal secret.

```powershell
Import-Module .\AzureArcDeployment.psm1

$encryptedSecret = Get-Content "\\dc01\ArcOnboardShare\AzureArcDeploy\encryptedServicePrincipalSecret"

$ebs = [DpapiNgUtil]::UnprotectBase64($encryptedSecret)
$ebs
```

![dec]({{site.baseurl}}/assets/images/Azure_Arc/dec.png)

At this point, we can gather the remaining information needed to connect to Azure from the ArcInfo.json file, which is stored on the same network share as the encryptedServicePrincipalSecret file. This file contains essential details such as TenantId, servicePrincipalClientId, ResourceGroup, and more. With this information, we can use the Azure CLI to authenticate as the service principal and begin enumerating machines that are joined to Azure Arc.

![shell01]({{site.baseurl}}/assets/images/Azure_Arc/shell_01.png)

In the example above, we attempted to obtain a reverse shell from a server we discovered, named server01, using a base64-encoded PowerShell reverse shell.

![shell02]({{site.baseurl}}/assets/images/Azure_Arc/shell_02.png)

![shell02]({{site.baseurl}}/assets/images/Azure_Arc/shell_03.png)

![shell03]({{site.baseurl}}/assets/images/Azure_Arc/shell_04.png)

### Defenses and Remediations

Azure Arc introduces a new potential vulnerability for hackers, enabling them to transition from on-premises environments to the cloud. It is crucial to thoroughly review any Microsoft deployment script before executing it in a production environment and network. Be mindful that if the deployment script uses the default configuration, any machine account in Domain Computers group could access the service principal secret. To enhance security, create a dedicated group in Active Directory containing only the machines you plan to connect to Azure Arc. By incorporating this specific SID into the DeployGPO script, you can prevent unauthorized machine accounts from accessing the service principal secret, thereby reducing the risk of potential exploits. Additionally, it is important to limit the privileges of the service principal secret by following the principle of least privilege. This ensures that even if the secret is compromised, the attacker cannot move laterally into the cloud.
