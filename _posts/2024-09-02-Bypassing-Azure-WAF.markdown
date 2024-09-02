---
title: "Bypassing Azure WAF"
date: 2024-09-02 01:00:00 +0300
tags:
  - Azure,WAF,XSS
categories:
  - Azure
---

Web Application Firewalls (WAFs) are critical components in securing web applications, acting as the first line of defense by filtering and monitoring incoming web traffic to protect against a wide range of threats, including SQL injection, cross-site scripting, and other attacks targeting application vulnerabilities. WAFs examine HTTP requests, block malicious traffic, and allow legitimate requests to pass through, ensuring that applications remain secure and available to legitimate users. Azure, like many other cloud providers, offers a robust WAF feature integrated within its Application Gateway. This service allows clients to easily deploy a WAF in front of their applications, providing advanced protection against malicious payloads, unauthorized access, and other potentially harmful traffic. In addition to filtering malicious traffic, Azure’s WAF supports various monitoring and logging features that help clients maintain visibility over their web application’s security posture.

## Setting Up Azure WAF

Configuring the WAF in the Azure portal is a straightforward process. To demonstrate the WAF's capabilities, I first needed a web application vulnerable to DOM XSS. Here's the example I used as vulnerable web application:

```html
<!DOCTYPE html>
<html lang="en">
  <script>
    var pos = document.URL.indexOf("context=") + 8;
    document.write(decodeURIComponent(document.URL.substring(pos)));
  </script>
</html>
```

![azure_waf_01]({{site.baseurl}}/assets/images/Azure_WAF/reflected.png){:style="display:block; margin-left:auto; margin-right:auto"}

To speed up the process, I chose to use Azure Static Web Apps. Next, I set up an Azure Application Gateway and configured its backend pool to point to the static web app. I also assigned a public IP address to the gateway and created a Virtual Network. Additionally, I added a DNS record for this public IP under `azurecloud.pro` to simplify management. With these initial configurations complete, I proceeded to create a WAF policy.

![azure_waf_02]({{site.baseurl}}/assets/images/Azure_WAF/resource_group.png){:style="display:block; margin-left:auto; margin-right:auto"}

Under the managed rules, I enabled the OWASP_3.2 rule set, which is a pre-configured rule set enabled by default. This rule set protects your web application from common threats as defined by the OWASP Top Ten categories. Managed by the Azure WAF service, the rules are updated regularly to address new attack signatures, ensuring up-to-date protection for your applications

![azure_waf_03]({{site.baseurl}}/assets/images/Azure_WAF/owasp_rule.png){:style="display:block; margin-left:auto; margin-right:auto"}

## Bypass Azure WAF

The first step is to evaluate which types of payloads the firewall blocks and how it responds to these malicious inputs. To do this, I attempted various ways to trigger the WAF, and it wasn’t very difficult. As demonstrated above, when inserting payloads like `<script>alert(1)</script>` or `<img src=0 onerror=alert(1)>`, the response from the firewall is a "403 Forbidden" error.

![azure_waf_04]({{site.baseurl}}/assets/images/Azure_WAF/waf_block.png){:style="display:block; margin-left:auto; margin-right:auto"}

Conducting a manual investigation is neither a convenient nor an efficient approach in this case. Due to the vast number of potential tags and events, testing every possible permutation and combination of payloads to identify edge cases that are not covered by the WAF proved to be a challenge. Therefore, I decided to change my strategy and move towards an automated process.

Given the abundance of open-source tools available on GitHub, I didn't want to reinvent the wheel. Instead, I conducted some research to find a tool suitable for this purpose. After some searching, I discovered **DOMscan**.

As described, **DOMscan** is a straightforward tool designed to scan websites for DOM-based XSS vulnerabilities and open redirects. Its approach is as follows:

1. Load a specified URL in a headless browser (using Chromium via Puppeteer).
2. Parse the provided URL and extract all parameters.
3. For each parameter, inject a payload and then check:
   - If any new console messages appear, and if so, print them to STDOUT.
   - If there is a redirect, check whether it includes a marker.
   - If a marker is found within the DOM.

Using this tool, I could automate the testing process, efficiently identifying potential vulnerabilities without the need for exhaustive manual checks. **DOMscan** uses the Puppeteer library, which allows for automated web page interaction using a headless (invisible) Chromium browser.

After setting up the tool on my Kali machine, I started the fuzzer and went to grab a cup of tea. To my surprise, when I returned, a pop-up was displayed on the Chrome browser, waiting for my confirmation.

![azure_waf_05]({{site.baseurl}}/assets/images/Azure_WAF/domscan_01.png){:style="display:block; margin-left:auto; margin-right:auto"}

![azure_waf_06]({{site.baseurl}}/assets/images/Azure_WAF/domscan_02.png){:style="display:block; margin-left:auto; margin-right:auto"}

In the end the follow payload where found to be able to bypass Azure WAF.

```html
#'%22%3E%3Cdetails/open/ontoggle=alert()%3E
#'%22%3E%3Cscript%3Ealert()%3C/script%3E #'%22%3E%3Csvg/onload=alert()%3E
#'%22%3E%3Cimg%20src=x%20onerror=alert()%3E%3C/img%3E
#%3CsVg/onLy=1%20onLoaD=alert%60%60//
#jaVasCript:/*-/*%60/*\%60/*'/*%22/**/(/*%20*/oNcliCk=alert()%20)//%0D%0A%0d%0a//%3C/stYle/%3C/titLe/%3C/teXtarEa/%3C/scRipt/--!%3E\x3csVg/%3CsVg/oNloAd=alert()//%3E\x3e
#47ru84eat47ru84ea'%22%3E%3Cimg%20src=x%20onerror=alert()%3E
```

![Alert XSS]({{site.baseurl}}/assets/images/Azure_WAF/alert_xss.gif)


These payloads successfully bypassed the WAF’s defenses and triggered an alert box, confirming our proof of concept. In a real-world scenario, this vulnerability could allow attackers to inject malicious scripts into a vulnerable application, potentially compromising sensitive user data and the overall system integrity. This finding is particularly significant because not all cloud providers are willing to address such vulnerabilities. For instance, while the Microsoft Security Response Center acknowledged that my report contained valuable information, they determined that it did not meet their criteria for a security vulnerability requiring remediation. Therefore, organizations should not rely solely on default, out-of-the-box solutions. They must continually test and adapt their security controls to keep pace with evolving threats.
