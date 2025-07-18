---
title: "Azure Application Proxy Hijacking"
date: 2024-11-05 22:30:00 +0300
tags:
  - Azure, Azure Machine Learning
categories:
  - Azure
---

Azure Application Proxy offers a groundbreaking solution for remote users who need access to on-premises web applications. It is integrated with Microsoft Entra ID for single sign-on and offers a seamless user experience without sacrificing security. The technology is based on two main components: the Application Proxy Server and the Application Proxy Connector.

The diagram below showcases the overall structure and function of the Azure application proxy at a high level. Let’s explore how it operates.

![screenshot]({{site.baseurl}}/assets/images/Azure_Application_Proxy_Hijacking/Azure_App_Proxy_Intro.png)

1. User accesses an application via an endpoint and is redirected to a cloud-based authentication service's sign-in page.
2. Upon successful sign-in, the authentication service issues a token to the user's device.
3. The device forwards this token to a cloud-based proxy service. The proxy service retrives the user and security principal names from the token and passes the request to its connector component. Application Proxy then sends the request to the Application Proxy connector.
4. For systems with single sign-on configured, the connector conducts any extra authentication needed for the user.
5. The connector forwards the request to the on-premises application.
6. The response is sent through the connector and Application Proxy service to the user.

### A Deep Dive into Azure Application Proxy

Before looking into the details of a new attack method that allows a bad attacker to redirect the traffic of an application proxy to a harmful website, it's important to understand how this system is set up. Let's start by learning how to configure Azure Application Proxy, which will help us understand its possible weaknesses better. To install an Application Proxy connector, the first thing to do is to sign in to the Azure portal. During installation, you will be asked to sign in with your Azure AD account, which is an important step to start the service.

![screenshot]({{site.baseurl}}/assets/images/Azure_Application_Proxy_Hijacking/Download_Connector.png)

<div align="center">
    <img src="/assets/images/Azure_Application_Proxy_Hijacking/Connector_Installation_01.png" />
</div>

<div style="height: 20px;"></div>

<div align="center">
    <img src="/assets/images/Azure_Application_Proxy_Hijacking/Connector_Installation_02.png" />
</div>

<div style="height: 20px;"></div>

Once the installation is complete, a brief waiting period is required. After this, simply refresh your list of connectors and you should see your hostname appear, indicating a successful setup. The connector will be listed under _Connectors_ in the Azure Application Proxy section.

![screenshot]({{site.baseurl}}/assets/images/Azure_Application_Proxy_Hijacking/Application_Proxy_Company_Azure.png)

After successfully deploying the connector, the next step involves creating a new application. This application will be the destination for the traffic forwarded by our installed connector.

![screenshot]({{site.baseurl}}/assets/images/Azure_Application_Proxy_Hijacking/Enterprise_Application.png)

We set up a test website on our local server using IIS. You can access this page from our network at the following URL: `http://server01.xybytes.com`. For simplicity, we have opted to install the web server and connector on the same computer. Remember, however, that this setup is not required. The connector and web server can be run on different machines, as long as they can talk to each other with ease.

![screenshot]({{site.baseurl}}/assets/images/Azure_Application_Proxy_Hijacking/local_domain.png)

Additionally, this page is now externally available at the URL `https://companyportal.xybytes.com/`, as illustrated in the image below.

![screenshot]({{site.baseurl}}/assets/images/Azure_Application_Proxy_Hijacking/external_domain.png)

Now that we have the application endpoint and our connector is healthy, we can start analyzing the TLS traffic with Burp Suite. First, when registering the connector, a login request is sent to Azure. We get a JWT in return. This token is essential to authenticating further requests to the cloud.

```http
POST /76515347-005a-4ad9-b56e-0440219d98f8/oauth2/v2.0/token HTTP/1.1
x-client-SKU: MSAL.Desktop
x-client-Ver: 4.51.0.0
x-client-CPU: x64
x-client-OS: Windows Server 2019 Standard
x-anchormailbox: upn:<azure_username>
x-client-current-telemetry: 5|1003,0,,,|0,1,1
x-client-last-telemetry: 5|0|||
x-ms-lib-capability: retry-after, h429
client-request-id: be52007f-c27c-43b1-9294-0596ac0b2ca3
return-client-request-id: true
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Host: login.microsoftonline.com
Content-Length: 249
Expect: 100-continue
Connection: close

client_id=55747057-9b5d-4bd4-b387-abf52a8bd489&scope=openid+offline_access+profile+https%3A%2F%2Fproxy.cloudwebappproxy.net%2Fregisterapp%2Fuser_impersonation&grant_type=password&username<azure_username>password<azure_user_password>client_info=1
```

```http
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache
Pragma: no-cache
Content-Type: application/json; charset=utf-8
Expires: -1
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
P3P: CP="DSP CUR OTPi IND OTRi ONL FIN"
x-ms-request-id: ff5b90fd-b0ee-4c8c-b720-8cdd9cc23700
x-ms-ests-server: 2.1.16571.6 - NEULR1 ProdSlices
X-XSS-Protection: 0
Content-Disposition: inline; filename=userrealm.json
Set-Cookie: fpc=AqetinMal8RGvfQCZUGNiTgBJjmbAQAAAFIiz9wOAAAA; expires=Mon, 27-Nov-2023 15:46:33 GMT; path=/; secure; HttpOnly; SameSite=None
Set-Cookie: x-ms-gateway-slice=estsfd; path=/; secure; httponly
Date: Sat, 28 Oct 2023 15:46:32 GMT
Connection: close
Content-Length: 168

{
    "token_type": "Bearer",
    "scope": "https://proxy.cloudwebappproxy.net/registerapp/user_impersonation",
    "expires_in": 4057,
    "ext_expires_in": 4057,
    "access_token": "eyJ0eXAiOiJKV1QiL[...]",
    "refresh_token": "0.AYEAR1NRdloA2Uq1bgRAIZ2Y-FdwdFVdm9RLs4er9SqL1ImBAO4.AgABAAEAAAAty[...]",
    "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjlHbW[...]",
    "client_info": "eyJ1aWQiOiI5MzVlM2NlNy01Yjc5LTRkOWMtYTJiOS0wZTlkMWIzMWMyZTQ[...]"
}
```

After receiving a JWT token, the connector can start a POST request to the `/register/RegisterConnector` endpoint. The request is made to offer a CSR. The main reason for taking this step is to get a certificate that will be used for future connections to Azure, enabling secure and authenticated communications.

```http
POST /register/RegisterConnector HTTP/1.1
Content-Type: application/xml; charset=utf-8
Host: 76515347-005a-4ad9-b56e-0440219d98f8.registration.msappproxy.net
Content-Length: 4233
Expect: 100-continue
Accept-Encoding: gzip, deflate, br
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<RegistrationRequest xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Registration" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
   <Base64Csr>MIIDiTCCAnECAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMTt&#xD;
jgQ3n+ERngp4witB1bC2ldDL1sRgmabhjmhGiz92rbOaALoSzJ3YM5gO10OwKaeL&#xD;
NqDZ0mvoTH4ZDUUmYm1aIqIRidIOI/iBFR0MYY1CEa+xI96OF9qQV2m6ESTVdUGL&#xD;
qfHVvDQJQq2Pyc5l4kHUmxw9R5XWD+nMRpNEqiWzAoorKp9rskHIcb6OA3LTf4dz&#xD;
pVcsv5F0etnt1i3t2s5LhSFxgT4ZTBkqQAF/6A1pUFWt3a8mZ+l3CM1x3po426Dz&#xD;
[...]
</Base64Csr>
   <AuthenticationToken>
   .eyJhdWQiOiJodHRwczovL3By[...]
   </AuthenticationToken>
   <Base64Pkcs10Csr i:nil="true" />
   <Feature>ApplicationProxy</Feature>
   <FeatureString>ApplicationProxy</FeatureString>
   <RegistrationRequestSettings>
      <SystemSettingsInformation xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RegistrationCommons" xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Utilities.SystemSettings" i:type="a:SystemSettings">
         <a:MachineName>server01.xybytes.com</a:MachineName>
         <a:OsLanguage>1033</a:OsLanguage>
         <a:OsLocale>0409</a:OsLocale>
         <a:OsSku>7</a:OsSku>
         <a:OsVersion>10.0.17763</a:OsVersion>
      </SystemSettingsInformation>
      <PSModuleVersion>1.5.3437.0</PSModuleVersion>
      <SystemSettings xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Utilities.SystemSettings" i:type="a:SystemSettings">
         <a:MachineName>server01.xybytes.com</a:MachineName>
         <a:OsLanguage>1033</a:OsLanguage>
         <a:OsLocale>0409</a:OsLocale>
         <a:OsSku>7</a:OsSku>
         <a:OsVersion>10.0.17763</a:OsVersion>
      </SystemSettings>
   </RegistrationRequestSettings>
   <TenantId>76515347-005a-4ad9-b56e-0440219d98f8</TenantId>
   <UserAgent>ApplicationProxyConnector/1.5.3437.0</UserAgent>
</RegistrationRequest>
```

```http
HTTP/1.1 200 OK
Content-Length: 4547
Content-Type: application/xml; charset=utf-8
Date: Sat, 28 Oct 2023 15:46:40 GMT
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<RegistrationResult xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Registration" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
   <Certificate>MIIMhzCCC2+gAwIBAgIQwPmd5DvIeqZDxsytaVoThTANBg[...]T+jn1ZVNXePbY60Pyx7pjfpUFDO27CvIiCg==</Certificate>
   <ErrorMessage />
   <IsSuccessful>true</IsSuccessful>
</RegistrationResult>
```

The server's response is a certificate that is cached safely on the machine. The certificate plays an important role in the authentication of the connector because the Azure Application Proxy relies on mutual authentication using client-side certificates. It is essential for the authentication of the connector endpoint and is saved in the Windows registry, particularly under `HKEY_LOCAL_MACHINE`. In order to correctly intercept traffic using Burp Suite, one has to install the `server01` application proxy certificate in the TLS client certificate section in the software. If this is not done, requests will not be authenticated and will therefore always result in an HTTP 403 forbidden response.

The connector initiates a request for a bootstrap to `https://<tenant-id>.pta.bootstrap.msappproxy.net/ConnectorBootstrap`. This request involves sending an XML document. Authentication occurs through the use of a certificate generated during the registration phase. Additionally, the computer name is included in the request sent to Azure AD.

```http
POST /ConnectorBootstrap HTTP/1.1
Content-Type: application/xml; charset=utf-8
Host: 76515347-005a-4ad9-b56e-0440219d98f8.bootstrap.msappproxy.net
Content-Length: 3904
Accept-Encoding: gzip, deflate, br
Connection: close

<BootstrapRequest
	xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalerDataModel"
	xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
	<AgentSdkVersion>1.5.3437.0</AgentSdkVersion>
	<AgentServiceAccountName>NT Authority\NetworkService</AgentServiceAccountName>
	<AgentVersion>1.5.3437.0</AgentVersion>
	<BootstrapAddOnRequests i:nil="true"/>
	<BootstrapDataModelVersion>1.5.3437.0</BootstrapDataModelVersion>
	<ConnectorId>a170d9a0-e82c-4093-a5a1-833d49fef370</ConnectorId>
	<ConnectorVersion i:nil="true"/>
	<ConsecutiveFailures>0</ConsecutiveFailures>
	<CurrentProxyPortResponseMode>Primary</CurrentProxyPortResponseMode>
	<FailedRequestMetrics
		xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel"/>
		<InitialBootstrap>false</InitialBootstrap>
		<IsAgentServiceAccountGmsa>false</IsAgentServiceAccountGmsa>
		<IsProxyPortResponseFallbackDisabledFromRegistry>true</IsProxyPortResponseFallbackDisabledFromRegistry>
		<LatestDotNetVersionInstalled>461814</LatestDotNetVersionInstalled>
		<MachineName>server01.xybytes.com</MachineName>
		<OperatingSystemLanguage>1033</OperatingSystemLanguage>
		<OperatingSystemLocale>0409</OperatingSystemLocale>
		<OperatingSystemSKU>7</OperatingSystemSKU>
		<OperatingSystemVersion>10.0.17763</OperatingSystemVersion>
		<PerformanceMetrics
			xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel">
			<a:CpuAggregates>
				<a:AggregatedCpuData>
					<a:AverageCpu>93</a:AverageCpu>
					<a:DataCollectionInterval>PT1M</a:DataCollectionInterval>
					<a:MaxCpu>100</a:MaxCpu>
					<a:TimeCollected>2023-12-02T20:06:26.0384254Z</a:TimeCollected>
				</a:AggregatedCpuData>
				<a:AggregatedCpuData>
					<a:AverageCpu>44</a:AverageCpu>
					<a:DataCollectionInterval>PT1M</a:DataCollectionInterval>
					<a:MaxCpu>100</a:MaxCpu>
					<a:TimeCollected>2023-12-02T20:07:32.1413882Z</a:TimeCollected>
				</a:AggregatedCpuData>
				<a:AggregatedCpuData>
					<a:AverageCpu>18</a:AverageCpu>
					<a:DataCollectionInterval>PT1M</a:DataCollectionInterval>
					<a:MaxCpu>91</a:MaxCpu>
					<a:TimeCollected>2023-12-02T20:08:37.3220956Z</a:TimeCollected>
				</a:AggregatedCpuData>
				<a:AggregatedCpuData>
					<a:AverageCpu>14</a:AverageCpu>
					<a:DataCollectionInterval>PT1M</a:DataCollectionInterval>
					<a:MaxCpu>71</a:MaxCpu>
					<a:TimeCollected>2023-12-02T20:09:40.6718756Z</a:TimeCollected>
				</a:AggregatedCpuData>
				<a:AggregatedCpuData>
					<a:AverageCpu>58</a:AverageCpu>
					<a:DataCollectionInterval>PT1M</a:DataCollectionInterval>
					<a:MaxCpu>100</a:MaxCpu>
					<a:TimeCollected>2023-12-02T20:10:47.5532007Z</a:TimeCollected>
				</a:AggregatedCpuData>
				<a:AggregatedCpuData>
					<a:AverageCpu>99</a:AverageCpu>
					<a:DataCollectionInterval>PT1M</a:DataCollectionInterval>
					<a:MaxCpu>100</a:MaxCpu>
					<a:TimeCollected>2023-12-02T20:12:23.8769724Z</a:TimeCollected>
				</a:AggregatedCpuData>
				<a:AggregatedCpuData>
					<a:AverageCpu>99</a:AverageCpu>
					<a:DataCollectionInterval>PT1M</a:DataCollectionInterval>
					<a:MaxCpu>100</a:MaxCpu>
					<a:TimeCollected>2023-12-02T20:14:04.8238886Z</a:TimeCollected>
				</a:AggregatedCpuData>
			</a:CpuAggregates>
			<a:CurrentActiveBackendWebSockets>0</a:CurrentActiveBackendWebSockets>
			<a:CurrentActiveGrpcRequests>0</a:CurrentActiveGrpcRequests>
			<a:FaultedServiceBusConnectionCount>0</a:FaultedServiceBusConnectionCount>
			<a:FaultedWebSocketConnectionCount>0</a:FaultedWebSocketConnectionCount>
			<a:LastBootstrapLatency>2414</a:LastBootstrapLatency>
			<a:TimeGenerated>2023-12-02T20:14:45.3859459Z</a:TimeGenerated>
		</PerformanceMetrics>
		<ProxyDataModelVersion>1.5.3437.0</ProxyDataModelVersion>
		<RequestId>45a4a55a-d85c-4b10-a396-04ceeec94541</RequestId>
		<SubscriptionId>76515347-005a-4ad9-b56e-0440219d98f8</SubscriptionId>
		<SuccessRequestMetrics
			xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel"/>
			<TriggerErrors/>
			<UpdaterStatus>Running</UpdaterStatus>
			<UseServiceBusTcpConnectivityMode>false</UseServiceBusTcpConnectivityMode>
			<UseSpnegoAuthentication>false</UseSpnegoAuthentication>
		</BootstrapRequest>
```

The response to the bootstrap request is a list of listener endpoints. Each endpoint within this list is defined by a specific shared access key and URL.

```http
HTTP/1.1 200 OK
Content-Length: 11224
Content-Type: application/xml; charset=utf-8
Date: Sat, 02 Dec 2023 20:15:05 GMT
Connection: close

<BootstrapResponse
	xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalerDataModel"
	xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
	<BackendSessionTimeoutMilliseconds>305000</BackendSessionTimeoutMilliseconds>
	<BootstrapAddOnResponses i:nil="true"/>
	<BootstrapClientAddOnSettings i:nil="true"
		xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel"/>
		<BootstrapEndpointOverride i:nil="true"/>
		<CheckForTrustRenewPeriodInMinutes>360</CheckForTrustRenewPeriodInMinutes>
		<ConfigRequestTimeoutMilliseconds>20000</ConfigRequestTimeoutMilliseconds>
		<ConfigurationEndpointFormat>https://{0}:{1}/subscriber/admin</ConfigurationEndpointFormat>
		<ConnectionLimit>200</ConnectionLimit>
		<ConnectivitySettings>{"ServicePointManagerSettings":[...]</ConnectivitySettings>
		<ConnectorState>Ok</ConnectorState>
		<DnsLookupCacheTtl>PT30M</DnsLookupCacheTtl>
		<DnsRefreshTimeoutMilliseconds>120000</DnsRefreshTimeoutMilliseconds>
		<ErrorEndpointFormat>https://{0}:{1}/subscriber/error</ErrorEndpointFormat>
		<LogicalResponseTimeoutMilliseconds>1200000</LogicalResponseTimeoutMilliseconds>
		<MaxBootstrapAddOnRequestsLength>0</MaxBootstrapAddOnRequestsLength>
		<MaxFailedBootstrapRequests>2172</MaxFailedBootstrapRequests>
		<MaxServicePointIdleTimeMilliseconds>100000</MaxServicePointIdleTimeMilliseconds>
		<MinutesInTrustLifetimeBeforeRenew>0</MinutesInTrustLifetimeBeforeRenew>
		<PayloadEndpointFormat>https://{0}:{1}/subscriber/payload</PayloadEndpointFormat>
		<PayloadRequestTimeoutMilliseconds>20000</PayloadRequestTimeoutMilliseconds>
		<PeriodicBootstrapIntervalMilliseconds>600000</PeriodicBootstrapIntervalMilliseconds>
		<PeriodicBootstrapRetryStrategy
			xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.FlightingFeatures.RetryStrategies">
			<a:AndThen>
				<a:First>
					<a:Periodic>
						<a:Interval>00:10:00</a:Interval>
						<a:MaxAttempts>1</a:MaxAttempts>
					</a:Periodic>
				</a:First>
				<a:Second>
					<a:Randomized>
						<a:AndThen>
							<a:First>
								<a:ExponentialBackoff>
									<a:MaxAttempts>5</a:MaxAttempts>
									<a:MaxDelay>01:00:00</a:MaxDelay>
									<a:MinDelay>00:00:03</a:MinDelay>
								</a:ExponentialBackoff>
							</a:First>
							<a:Second>
								<a:Periodic>
									<a:Interval>01:00:00</a:Interval>
									<a:MaxAttempts i:nil="true"/>
								</a:Periodic>
							</a:Second>
						</a:AndThen>
						<a:PlusOrMinusPercent>20</a:PlusOrMinusPercent>
					</a:Randomized>
				</a:Second>
			</a:AndThen>
		</PeriodicBootstrapRetryStrategy>
		<PortoSettings
			xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel">
			<a:AppProxyRootCaNames
				xmlns:b="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
				<b:string>DigiCert</b:string>
			</a:AppProxyRootCaNames>
			<a:ConnectorChannelShutdownDelay>P1D</a:ConnectorChannelShutdownDelay>
			<a:RustConnectorSettings
				xmlns:b="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
				<b:KeyValueOfstringstring>
					<b:Key>RustConnectorHttp2KeepaliveInterval</b:Key>
					<b:Value>3m45s</b:Value>
				</b:KeyValueOfstringstring>
				<b:KeyValueOfstringstring>
					<b:Key>RustConnectorHttp2KeepaliveTimeout</b:Key>
					<b:Value>20s</b:Value>
				</b:KeyValueOfstringstring>
				<b:KeyValueOfstringstring>
					<b:Key>RustConnectorDownloadStreamBufferSize</b:Key>
					<b:Value>8192</b:Value>
				</b:KeyValueOfstringstring>
				<b:KeyValueOfstringstring>
					<b:Key>RustConnectorOpenBackendConnectionTimeout</b:Key>
					<b:Value>5s</b:Value>
				</b:KeyValueOfstringstring>
				<b:KeyValueOfstringstring>
					<b:Key>RustConnectorEnableDnsQueryEx</b:Key>
					<b:Value>false</b:Value>
				</b:KeyValueOfstringstring>
			</a:RustConnectorSettings>
		</PortoSettings>
		<ProxyPortResponseFallbackPeriod>P1D</ProxyPortResponseFallbackPeriod>
		<RelayReceiveTimeout>P10675199DT2H48M5.4775807S</RelayReceiveTimeout>
		<ResponseEndpointFormat>https://{0}:{1}/subscriber/connection</ResponseEndpointFormat>
		<ResponseRetryDelayFactor>2</ResponseRetryDelayFactor>
		<ResponseRetryInitialDelayMilliseconds>200</ResponseRetryInitialDelayMilliseconds>
		<ResponseRetryTotalAttempts>5</ResponseRetryTotalAttempts>
		<ResponseSigningEnabled>false</ResponseSigningEnabled>
		<ServiceMessage/>
		<SignalingListenerEndpoints
			xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel">
			<a:SignalingListenerEndpointSettings i:type="a:ServiceBusSignalingListenerEndpointSettings">
				<a:IsAvailable>true</a:IsAvailable>
				<a:Name>cwap-eur1-dwc2/76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac</a:Name>
				<a:Domain>servicebus.windows.net</a:Domain>
				<a:Namespace>cwap-eur1-dwc2</a:Namespace>
				<a:ReliableSessionEnabled>false</a:ReliableSessionEnabled>
				<a:Scheme>sb</a:Scheme>
				<a:ServicePath>76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac</a:ServicePath>
				<a:SharedAccessKey>N9P7We[...]</a:SharedAccessKey>
				<a:SharedAccessKeyName>Connector</a:SharedAccessKeyName>
			</a:SignalingListenerEndpointSettings>
			<a:SignalingListenerEndpointSettings i:type="a:ServiceBusSignalingListenerEndpointSettings">
				<a:IsAvailable>true</a:IsAvailable>
				<a:Name>cwap-eur1-frc2/76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac</a:Name>
				<a:Domain>servicebus.windows.net</a:Domain>
				<a:Namespace>cwap-eur1-frc2</a:Namespace>
				<a:ReliableSessionEnabled>false</a:ReliableSessionEnabled>
				<a:Scheme>sb</a:Scheme>
				<a:ServicePath>76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac</a:ServicePath>
				<a:SharedAccessKey>uzfbEM[...]</a:SharedAccessKey>
				<a:SharedAccessKeyName>Connector</a:SharedAccessKeyName>
			</a:SignalingListenerEndpointSettings>
			<a:SignalingListenerEndpointSettings i:type="a:ServiceBusSignalingListenerEndpointSettings">
				<a:IsAvailable>true</a:IsAvailable>
				<a:Name>cwap-eur1-neur2/76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac</a:Name>
				<a:Domain>servicebus.windows.net</a:Domain>
				<a:Namespace>cwap-eur1-neur2</a:Namespace>
				<a:ReliableSessionEnabled>false</a:ReliableSessionEnabled>
				<a:Scheme>sb</a:Scheme>
				<a:ServicePath>76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac</a:ServicePath>
				<a:SharedAccessKey>Wj+w82[...]</a:SharedAccessKey>
				<a:SharedAccessKeyName>Connector</a:SharedAccessKeyName>
			</a:SignalingListenerEndpointSettings>
			<a:SignalingListenerEndpointSettings i:type="a:ServiceBusSignalingListenerEndpointSettings">
				<a:IsAvailable>true</a:IsAvailable>
				<a:Name>cwap-eur1-weur2/76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac</a:Name>
				<a:Domain>servicebus.windows.net</a:Domain>
				<a:Namespace>cwap-eur1-weur2</a:Namespace>
				<a:ReliableSessionEnabled>false</a:ReliableSessionEnabled>
				<a:Scheme>sb</a:Scheme>
				<a:ServicePath>76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac</a:ServicePath>
				<a:SharedAccessKey>aVnIe4[...]</a:SharedAccessKey>
				<a:SharedAccessKeyName>Connector</a:SharedAccessKeyName>
			</a:SignalingListenerEndpointSettings>
			<a:SignalingListenerEndpointSettings i:type="a:ServiceBusSignalingListenerEndpointSettings">
				<a:IsAvailable>true</a:IsAvailable>
				<a:Name>cwap-eur1-dwc2/76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac_reliable</a:Name>
				<a:Domain>servicebus.windows.net</a:Domain>
				<a:Namespace>cwap-eur1-dwc2</a:Namespace>
				<a:ReliableSessionEnabled>true</a:ReliableSessionEnabled>
				<a:Scheme>sb</a:Scheme>
				<a:ServicePath>76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac_reliable</a:ServicePath>
				<a:SharedAccessKey>h8eHDtV+hCKT[...]</a:SharedAccessKey>
				<a:SharedAccessKeyName>Connector</a:SharedAccessKeyName>
			</a:SignalingListenerEndpointSettings>
			<a:SignalingListenerEndpointSettings i:type="a:ServiceBusSignalingListenerEndpointSettings">
				<a:IsAvailable>true</a:IsAvailable>
				<a:Name>cwap-eur1-frc2/76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac_reliable</a:Name>
				<a:Domain>servicebus.windows.net</a:Domain>
				<a:Namespace>cwap-eur1-frc2</a:Namespace>
				<a:ReliableSessionEnabled>true</a:ReliableSessionEnabled>
				<a:Scheme>sb</a:Scheme>
				<a:ServicePath>76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac_reliable</a:ServicePath>
				<a:SharedAccessKey>Eylbko[...]</a:SharedAccessKey>
				<a:SharedAccessKeyName>Connector</a:SharedAccessKeyName>
			</a:SignalingListenerEndpointSettings>
			<a:SignalingListenerEndpointSettings i:type="a:ServiceBusSignalingListenerEndpointSettings">
				<a:IsAvailable>true</a:IsAvailable>
				<a:Name>cwap-eur1-neur2/76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac_reliable</a:Name>
				<a:Domain>servicebus.windows.net</a:Domain>
				<a:Namespace>cwap-eur1-neur2</a:Namespace>
				<a:ReliableSessionEnabled>true</a:ReliableSessionEnabled>
				<a:Scheme>sb</a:Scheme>
				<a:ServicePath>76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac_reliable</a:ServicePath>
				<a:SharedAccessKey>7ILHWq[...]</a:SharedAccessKey>
				<a:SharedAccessKeyName>Connector</a:SharedAccessKeyName>
			</a:SignalingListenerEndpointSettings>
			<a:SignalingListenerEndpointSettings i:type="a:ServiceBusSignalingListenerEndpointSettings">
				<a:IsAvailable>true</a:IsAvailable>
				<a:Name>cwap-eur1-weur2/76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac_reliable</a:Name>
				<a:Domain>servicebus.windows.net</a:Domain>
				<a:Namespace>cwap-eur1-weur2</a:Namespace>
				<a:ReliableSessionEnabled>true</a:ReliableSessionEnabled>
				<a:Scheme>sb</a:Scheme>
				<a:ServicePath>76515347-005a-4ad9-b56e-0440219d98f8_07975fa6-6f9b-4e2c-b8e5-a241afaf72ac_reliable</a:ServicePath>
				<a:SharedAccessKey>cpCESV[...]</a:SharedAccessKey>
				<a:SharedAccessKeyName>Connector</a:SharedAccessKeyName>
			</a:SignalingListenerEndpointSettings>
		</SignalingListenerEndpoints>
		<Triggers/>
		<TrustRenewEndpoint>https://cwap-weur-1.renewtrust.msappproxy.net/renewTrust</TrustRenewEndpoint>
	</BootstrapResponse>
```

After obtaining the bootstrap information, connections are established to each specified endpoint, such as `https://cwap-eur1-frc2.servicebus.windows.net/$servicebus/websocket`. This conenction open a persistent websocket channel linked to the [Azure Service Bus](https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-messaging-overview). In this particular scenario, the messaging used the [AMQP standard](https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-amqp-overview) over WebSockets. It's noteworthy that the [shared access signature (SAS)](https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas) authentication for these connections leverages key information obtained from the bootstrap response. After the connection is initialised, agents are waiting for a connection request. The screenshot below displays the WebSocket messages intercepted using Burp Suite.

<div align="center">
    <img src="/assets/images/Azure_Application_Proxy_Hijacking/websocket.png" />
</div>

<div style="height: 20px;"></div>

When a websocket triggers a signal, the connector initiates a request to `/subscriber/admin`. The response to this request is a JSON payload, which contains essential information directing the connector on where to route the inbound request.

```http
GET /subscriber/admin?requestId=163da8cb-bda6-421a-9967-4d816e1b142e HTTP/1.1
x-cwap-dnscachelookup-result: Miss
x-cwap-connector-usesdefaultproxy: NotUsed
x-cwap-connector-version: 1.5.3437.0
x-cwap-datamodel-version: 1.5.3437.0
x-cwap-connector-sp-connections: 0
x-cwap-transid: 19adff76-0221-441c-b7a0-05e7b7272c26
x-cwap-sessionid: a56286d9-9184-4453-af15-69b2f2c978ad
x-cwap-certificate-authentication: notProcessed
Host: vm18-proxy-appproxy-neur-dub01p-3.connector.msappproxy.net
Connection: close
```

```http
HTTP/1.1 200 OK
Content-Length: 1247
x-cwap-certificate-authentication: Success
Date: Sat, 02 Dec 2023 21:08:40 GMT
Connection: close

{
    "Endpoints": {
        "a15be13f-9348-491a-aeb3-e2b567e77412": {
            "AlternateLogin": 0,
            "ApiFlow": 0,
            "BackendAuthNMode": 0,
            "BackendCertValidationMode": 1,
            "BackendUrl": "http://server01.xybytes.com/",
            "EnableHttpOnlyCookie": false,
            "EnableLinkTranslation": false,
            "EnableSecureCookie": false,
            "EncryptedClientSecret": "MIIBoAYJKoZIhvcNAQcDoIIBkTCCAY0CAQIxg[...]",
            "FrontendUrl": "https://companyportal.xybytes.com/",
            "Id": "a15be13f-9348-491a-aeb3-e2b567e77412",
            "InactiveTimeoutSec": 85,
            "IsAccessibleViaZTNAClient": false,
            "IsPersistentCookieEnabled": false,
            "IsTranslateHostHeaderInRequestEnabled": true,
            "IsTranslateHostHeaderInResponseEnabled": true,
            "IsWildCardApp": false,
            "Spn": null,
            "WafSettings": "{\"wafProvider\":null,\"wafIpRanges\":[],\"wafAllowedHeaders\":null}"
        }
    }
}
```

Finally, a response with the data posted from the target HTTP server arrives at Azure: The response posted from the web server is contained within the body of a POST request.

```http
POST /subscriber/connection?requestId=d8c481b1-59b5-431a-a88e-b51881184742 HTTP/1.1
x-cwap-dnscachelookup-result: Hit
x-cwap-connector-usesdefaultproxy: NotUsed
x-cwap-connector-version: 1.5.3437.0
x-cwap-datamodel-version: 1.5.3437.0
x-cwap-connector-sp-connections: 0
x-cwap-transid: 19adff76-0221-441c-b7a0-05e7b7272c26
x-cwap-sessionid: a56286d9-9184-4453-af15-69b2f2c978ad
x-cwap-certificate-authentication: notProcessed
x-cwap-headers-size: 247
x-cwap-connector-be-latency-ms: 66
x-cwap-payload-total-attempts: 0
x-cwap-connector-loadfactor: 8
x-cwap-response-total-attempts: 1
x-cwap-connector-all-latency-ms: 1727
Host: vm18-proxy-appproxy-neur-dub01p-3.connector.msappproxy.net
Content-Length: 950
Connection: close

HTTP/1.1 200 OK
Date: Sat, 02 Dec 2023 21:08:40 GMT
Content-Length: 703
Content-Type: text/html
Last-Modified: Thu, 26 Oct 2023 15:52:01 GMT
Accept-Ranges: bytes
Etag: "2051c35b248da1:0"
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS Windows Server</title>
<style type="text/css">
<!--
body {
	color:#000000;
	background-color:#0072C6;
	margin:0;
}

#container {
margin-left:auto;
margin-right:auto;
text-align:center;
}

a img {
border:none;
}

-->
</style>

</head>
<body>
<div id="container">
<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img src="iisstart.png" alt="IIS" width="960" height="600" /></a>
</div>
</body>
</html>
```

### Uncovering Azure Application Proxy Hijacking Attack

Let's go through the steps of an Azure Application Proxy Hijacking Attack. Here, we're presuming that a hacker has exploited a server that has a connector. They want to hijack traffic from the intranet web application of the company and redirect it to a malicious URL in the attacker's system.

<div align="center">
    <img src="/assets/images/Azure_Application_Proxy_Hijacking/server_compromise.png" />
</div>

<div style="height: 20px;"></div>

The following diagram illustrates a detailed workflow of how this exploit operates, showcasing the specifics of the attack mechanism.

![screenshot]({{site.baseurl}}/assets/images/Azure_Application_Proxy_Hijacking/attacker_scenario.png)

Our goal is to mirror the connector on server01, routing its traffic to our own server. By doing this, our server will become the new endpoint of the Azure Application Proxy URL, `https://companyportal.xybytes.com/`. To simplify the setup, we'll install both the internal portal and the connector on the same machine, `server01.xybytes.com`. After that, we'll set up an application in the application proxy that maps `https://companyportal.xybytes.com/` to `http://server01.xybytes.com`. Thus, when users go to the external URL, their requests are directed to our connector, which then gets the webpage hosted on an IIS server on the same computer. The initial step in doing all this is to export the connector certificate. This step is necessary, for as mentioned earlier, the identity of the connector is established by the same certificate. As the connector certificate is made non-exportable, we resort to using Mimikatz to extract it and export it in.pfx format. Once we extract it, we copy this certificate on our attacker machine, where we have established a test server with Rebex and installed a connector using another tenant. This perfectly replicates the attacker infrastructure. We move ahead to set up the connector request to go through Burp Suite with the help of ProxyCap so that we can install the certificate in Burp Suite in the Client TLS certificate section. The target domain is `*.msappproxy.net`. If we implement successfully, we should be able to see the bootstrap request being accepted by Burp Suite, thereby establishing a web socket channel. Observe that even when executed from a different tenant, the connection is authenticated since the connector of server01, thanks to the imported certificate,.

![screenshot]({{site.baseurl}}/assets/images/Azure_Application_Proxy_Hijacking/bootstrap_impersonate.png)

Concurrently, in our attacker's Azure infrastructure, the connector will appear as non-active, indicating that our server is functioning as a connector for the target company.

![screenshot]({{site.baseurl}}/assets/images/Azure_Application_Proxy_Hijacking/Inactive_Attacker_Connector.png)

Connectors are designed to function optimally most of the time. There is no assurance that traffic will be evenly distributed over all connectors, nor is there a connection preference for sessions. Requests are randomly allocated to different instances of the Application Proxy service. Consequently, this approach generally leads to a near-even distribution of traffic among the connectors. In our scenario, to expedite the process and ensure that the application proxy utilizes our specified connection, we initiate a restart of the company's connector on server01. This strategic move triggers Azure to transition to the new connector, effectively redirecting the traffic flow to our desired endpoint. From this point forward, our injected connector begins functioning as if it were the original server01 connector. As a result, Azure Application Proxy starts forwarding incoming requests to it. The victim remains unaware of the change since the external Azure proxy URL remains the same, not raising any suspicion. At this phase, the attacker can set up a malicious site. For instance, they could create a site to infect the target machine or design a fake clone page of the internal application. This clone page could be used to deceive users into entering their credentials, thinking they are accessing a legitimate internal application. This attack is particularly deceptive as it retains its effectiveness even when the application uses pre-authentication with Microsoft ID. Users, unaware of the underlying scheme, continue to use their standard AD credentials. They remain oblivious to the fact that, post-login, they will be redirected to a website that is not affiliated with their company. For the successful execution of this process, it's crucial to modify the hosts file on the attacker's machine by adding a new entry. This entry should direct the domain `server01.xybytes.com` to the IP address 127.0.0.1. This modification is essential to ensure that the connector correctly resolves the DNS name and accesses the web page hosted on our server.

![screenshot]({{site.baseurl}}/assets/images/Azure_Application_Proxy_Hijacking/hijacking_01.png)

The image below illustrates how the Enterprise Application URL of the target company is linked to our malicious web page.

![screenshot]({{site.baseurl}}/assets/images/Azure_Application_Proxy_Hijacking/hijacking_02.png)

What I hoped to illustrate in this article is how it is possible for someone to use a connector certificate outside of its intended server, which would allow them to pretend to be that particular connector. The main point here is that an attacker could tamper with traffic directly from a hacked server where the Azure Application Proxy connector is installed without having to export the certificate or redirect traffic. Though this method is easier, it still needs the attacker to remain active on the server and manage traffic in the network. However, in this situation, an attacker might continue to use this technique even when they lose direct access to the hacked server. Therefore, it's important to handle Azure Application Proxy certificates as valuable assets that should be closely monitored.