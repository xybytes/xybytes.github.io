---
title: "Exploiting SNI SSRF to access Azure Identity Management Service"
date: 2024-07-29 01:00:00 +0300
tags:
  - Azure,SSRF,SNI,Proxy,Metadata
categories:
  - Azure
---

Server-side request forgery (SSRF) is a well-known vulnerability that has gained renewed attention in recent years, particularly in cloud environments. Hackers and penetration testers have increasingly focused on exploiting this vulnerability to access sensitive information. Initially, SSRF was used to access the metadata of Amazon EC2 instances, providing valuable details about the instance. In response to widespread exploitation, Amazon implemented new security mechanisms. The metadata endpoint, accessible from within any EC2 machine at http://169.254.169.254, offers various data about the instance.There are two versions of the metadata endpoint. The first version (IMDSv1) allows access via GET requests, making it vulnerable to SSRF attacks. The second version (IMDSv2) introduces additional security measures by requiring a token, obtained through a PUT request with a specific HTTP header, to access the metadata. This added complexity makes it more challenging to exploit the endpoint through SSRF. In a recent presentation at BSides Leeds 2024, Oliver Morton demonstrated how a misconfigured SNI proxy could be exploited to bypass the protections of the AWS IMDSv2 service. Inspired by his presentation, I decided to explore the same concept with Azure VM metadata to assess whether this could pose a potential security risk in Azure. The extreme flexibility of SNI, along with the ability to craft specific headers in requests and change request methods, makes this an intriguing area for further investigation.

## SNI, Is It Something I Can Eat?

Server Name Indication (SNI) is an extension to the Transport Layer Security (TLS) protocol, outlined in RFC 6066. Its main function is to allow clients using TLS (commonly associated with HTTPS) to specify the intended server's hostname during the TLS handshake. This feature is particularly useful for servers hosting multiple virtual servers on the same IP address, as it enables the server to choose the correct SSL certificate based on the hostname provided. SNI ensures that clients connect to the intended server by including the hostname or domain name in the handshake process, facilitating the selection of the appropriate TLS certificate before the secure connection is fully established. Since its introduction in 2003, SNI has gained widespread support across web browsers and other TLS client software. During the TLS handshake, the client sends the server name in the ServerName field within the ServerNameList field of the SNI extension, included in the ClientHello message. This allows the server to identify the requested server name and make decisions accordingly, such as selecting the correct TLS certificate, before replying with the ServerHello message, which includes the server's certificate. It's important to note that the ServerName field is not encrypted during this initial exchange, as it occurs before the session keys used for encryption are established. There is a newer extension known as Encrypted SNI (ESNI), designed to prevent the SNI from being intercepted by attackers. However, ESNI, launched in 2018 with backing from Cloudflare and Mozilla, is not yet an official standard or widely implemented.

## SNI Proxy

To allow clients to connect securely to an SSL/TLS-enabled website, a central endpoint is needed. In cases where multiple websites are hosted at the same location, a reverse proxy or load balancer is commonly used to fulfill this role. These devices function as intermediaries, deciding which internal web server should process the client's request. They receive the TLS handshake, which includes the SNI field, and use it to route the request to the appropriate back-end server. The SNI proxy or load balancer may act as a TLS terminator, in which case it is responsible for providing the correct TLS certificate to establish a secure connection with the client. After the connection is established, it communicates with the back-end server, which may or may not use TLS itself, and relays the messages between the client and server. Alternatively, if the proxy or load balancer does not perform TLS termination, it functions as a TCP proxy, passing the entire TCP stream to the back-end server, which then handles the TLS termination process.

![azure_ssrf_01]({{site.baseurl}}/assets/images/Azure_SSRF/sni_proxy.png)

The SNI proxy could have a misconfiguration that allows a potential attacker to control requests using the SNI field. In other words, an attacker could manipulate the SNI field to send a request to an arbitrary host, bypassing intended restrictions. In the case of Azure Identity Management, this vulnerability could be exploited to trick the proxy into sending a request to itself, enabling the attacker to extract the access token from the instance metadata.

![azure_ssrf_02]({{site.baseurl}}/assets/images/Azure_SSRF/sni_proxy_exploit.png){:style="display:block; margin-left:auto; margin-right:auto"}

This is the vulnerable Nginx proxy configuration that could lead to issues, making the proxy susceptible to SNI-based SSRF attacks:

```conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 768;
}

http {

        log_format  main  '$remote_addr - $remote_user [$time_local] "$request" ' '$status $body_bytes_sent "$http_referer"' '"$http_user_agent" "$http_x_forwarded_for"';
	access_log  /var/log/nginx/access.log  main;

        sendfile on;
	tcp_nopush on;
        keepalive_timeout   65;
	types_hash_max_size 2048;

        include /etc/nginx/mime.types;
	default_type application/octet-stream;


	#ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
	#ssl_prefer_server_ciphers

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}

stream {
    log_format basic '$remote_addr [$time_local]'
    '$protocol $status $bytes_sent $bytes_received'
    '$session_time';
    map $ssl_server_name $targetBackend {
        ~^www\.example\.com$ 127.0.0.1;
        ~^www.example\.com $ssl_server_name;
        ~.* $ssl_server_name;
    }
    server {
        listen 443 ssl;
        resolver 8.8.8.8;
        proxy_pass $targetBackend:80;
        ssl_preread on;
        ssl_certificate ./ssl/proxy.crt;
        ssl_certificate_key ./ssl/proxy.key;
    }
}
```

The vulnerable part of the configuration is:

```conf
stream {
    log_format basic '$remote_addr [$time_local]'
    '$protocol $status $bytes_sent $bytes_received'
    '$session_time';
    map $ssl_server_name $targetBackend {
        ~^www\.example\.com$ 127.0.0.1;
        ~^www.example\.com $ssl_server_name;
        ~.* $ssl_server_name;
    }
    server {
        listen 443 ssl;
        resolver 8.8.8.8;
        proxy_pass $targetBackend:80;
        ssl_preread on;
        ssl_certificate ./ssl/proxy.crt;
        ssl_certificate_key ./ssl/proxy.key;
    }
}
```

As Oliver explained in his presentation, several requirements need to be met for this vulnerability to be exploited, and the same applies to Azure VM metadata:

1. The SNI proxy must be only one hop away from the Instance Metadata Service (IMDS).
2. The attacker must have control over the headers sent in the request.
3. The SNI proxy must not add an X-Forwarded-For header.
4. The SNI proxy must route subsequent requests to the same Azure VM instance.
5. The SNI proxy must not perform sufficient validation of the SNI field.
6. The SNI field "must" contain a domain name.
7. The SNI proxy must terminate TLS, as the Azure Identity managed service does not accept TLS connections.
8. The SNI proxy must be configured to connect to port 80 upstream.

## Azure Instance Metadata Service

The Azure Instance Metadata Service (IMDS) provides valuable information about currently running virtual machine instances, enabling you to manage and configure your VMs effectively. This service offers data such as SKU, storage, network configurations, and upcoming maintenance events. For a comprehensive list of available data, refer to the Endpoint Categories Summary. IMDS is accessible for running instances of both virtual machines (VMs) and scale set instances. All endpoints support VMs created and managed using Azure Resource Manager. However, only the Attested category and the Network portion of the Instance category support VMs created using the classic deployment model, with the Attested endpoint offering limited functionality. IMDS operates as a REST API available at the well-known, non-routable IP address 169.254.169.254, which can only be accessed from within the VM. This ensures that communication between the VM and IMDS never leaves the host. It's important to have your HTTP clients bypass web proxies within the VM when querying IMDS and treat the IP address 169.254.169.254 in the same manner as 168.63.129.16.

A simple way to access the metadata from the VM itself is by using the curl command. For example, if you have a Linux Azure VM deployed on Azure with Identity Management enabled, you can retrieve metadata by running:

```bash
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:true | jq
```

In the response, we can obtain the access token associated with the VM's identity. Depending on the RBAC permissions assigned to this VM, we can use this token to move laterally within the cloud environment and access other systems and resources.

## Exploiting SNI SSRF

If a vulnerable SNI proxy is set up on an Azure Linux VM instance, configured to terminate TLS and forward traffic to port 80 based on the server specified in the SNI field, it can be exploited to access the Azure VM metadata service. This exploit requires a DNS record that resolves to 169.254.169.254, like couldhacker.site in this scenario.

```bash
➜  ~ nslookup couldhacker.site
Server:		8.8.8.8
Address:	8.8.8.8#53

Non-authoritative answer:
Name:	couldhacker.site
Address: 169.254.169.254
```

In this scenario, we can use our malicious domain and include the necessary `Metadata:true` header in the request.

![azure_ssrf_03]({{site.baseurl}}/assets/images/Azure_SSRF/exploit_azure_ssrf.png){:width="200%"}

## Mitigations

In this post, we demonstrate how a misconfigured proxy could potentially be utilized to exploit SSRF in Azure Virtual Machine, allowing an attacker to obtain an access token for malicious activities within the Azure environment. It is important to note that vulnerable SNI proxies are more versatile than typical SSRF vulnerabilities, making it possible to bypass the secure by design protection for Azure IMDS. By forcing the proxy to send a valid request, an attacker can acquire a valid JWT token for the server. Additionally, emphasizing the significance of logging, including the requesting IP address of the user in web access logs and as an X-Forwarded-For HTTP request header in the onward URL request is crucial. While the target server may not immediately act on this information, preserving this trace can aid in forensic investigations.
