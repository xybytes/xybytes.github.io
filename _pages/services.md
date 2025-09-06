---
title: "Services"
permalink: /services/
layout: services
author_profile: true
---

<div style="background:#003366; color:white; padding:2rem; border-radius:10px; margin-bottom:2rem;">
  <h1 style="margin-top:0;">Active Directory and Entra ID (Formerly Azure AD) Assessments</h1>
  <p>
    Almost all companies that use Microsoft products or services on-premises use <strong>Active Directory</strong> as their identity provider. 
    Additionally, companies using <strong>Microsoft 365 or Azure-based services</strong> use Microsoft Entra ID as an identity platform, often in a hybrid configuration with their on-premises network.
  </p>
  <p>
    Since these products are a common component in many enterprises, threat actors have focused on understanding and abusing common insecurities in Active Directory and Entra ID.
  </p>
  <p>
    During an assessment, <strong>Outsider Security</strong> investigates the state of security of the parts of the infrastructure in scope and provides actionable advice to improve the security posture. 
    Outsider Security can scope an assessment to only Active Directory or Entra ID, or assess it as a complete hybrid configuration.
  </p>
</div>

---

<div style="background:white;color:#003366;  padding:2rem; border-radius:10px; box-shadow:0 2px 5px rgba(0,0,0,0.1); margin-bottom:2rem;">
  <h2 style="color:#003366;">Active Directory Assessment</h2>
  <p>
    An organization’s Active Directory domains are often many years old, containing configuration changes accumulated over the years. 
    Since Active Directory is notoriously difficult to configure fully securely, in almost every test, Outsider Security identifies issues that can be exploited from any workstation in the organization.
  </p>
  <p>
    Unfortunately, these are often the same issues that threat actors abuse, including ransomware operators that try to gain high privileges from where they can roll out their ransomware and extort the organization for data recovery.
  </p>

  <p>
    During an Active Directory assessment, Outsider Security uses open source and private tooling to analyze the AD domains in the organization. 
    Privileges are mapped and explored to identify if administration is performed securely and if resources in the network are sufficiently protected.
  </p>

  <p>
    If the Active Directory structure is more complex (e.g., multiple domains, forests, trusts), these are mapped and taken into account for the analysis. 
    While each test is unique, the following components are often analyzed:
  </p>

  <ul>
    <li>Privilege delegation model</li>
    <li>Admin account protection and separation</li>
    <li>Least privilege configuration</li>
    <li>Group policy settings</li>
    <li>PKI configuration (Active Directory Certificate Services)</li>
    <li>Kerberos configuration</li>
  </ul>

  <p>
    An Active Directory assessment can be conducted either as a <strong>penetration test</strong> or as a <strong>review</strong>:
  </p>
  <ul>
    <li><strong>Review:</strong> Outsider Security is provided with a highly privileged user to analyze vulnerabilities or misconfigurations.</li>
    <li><strong>Penetration Test:</strong> Outsider Security starts with a low-privilege user and attempts to escalate privileges in scope.</li>
  </ul>

  <p>
    Both approaches provide insight into how attackers could abuse the identified vulnerabilities and how to remediate them.
  </p>
</div>

---

<div style="background:#f8f9fa;color:#003366; padding:2rem; border-radius:10px; box-shadow:0 2px 5px rgba(0,0,0,0.1);">
  <h2 style="color:#003366;">Microsoft Entra (Azure AD) Assessment</h2>
  <p>
    A typical Entra ID configuration consists of organizations using <strong>Microsoft 365</strong> with Microsoft Entra ID as an identity platform at its core. 
    Entra ID may be integrated with the on-premises Active Directory in a hybrid setup or used as a standalone service.
  </p>

  <p>
    Since Entra ID is the identity provider for not only Microsoft 365 but also an organization’s Azure resources and potential third-party applications, it is a <strong>vital component</strong> in the security strategy.
  </p>

  <p>
    Outsider Security offers <strong>Entra ID assessments</strong>, during which potential weaknesses and misconfigurations are identified. 
    An Entra ID assessment gives insight into the risks associated with the current usage of Entra ID and which improvements can be made.
  </p>

  <p>Example areas investigated include:</p>
  <ul>
    <li>Administrator role usage, MFA adoption and enforcement</li>
    <li>Conditional Access configuration</li>
    <li>Application security and configuration</li>
    <li>Tenant configuration and hardening</li>
  </ul>

  <p>
    An Entra ID assessment can also cover:
  </p>
  <ul>
    <li>Intune for device management</li>
    <li>Hybrid setups with on-premises Active Directory</li>
    <li>Identity usage in Azure RBAC rights</li>
  </ul>

  <p>
    An Entra ID assessment is performed as a <strong>review</strong>. Outsider Security is provided with a read-only administrator account to analyze the configuration using different in-house developed and open-source tools.
  </p>
</div>
