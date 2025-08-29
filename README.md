
![DFIR-O365RC](./logo.png)

[![Publish Docker image to Dockerhub](https://github.com/ANSSI-FR/DFIR-O365RC/actions/workflows/dockerhub.yml/badge.svg)](https://github.com/ANSSI-FR/DFIR-O365RC/actions/workflows/dockerhub.yml/badge.svg)
[![Publish module to PowerShell Gallery](https://github.com/ANSSI-FR/DFIR-O365RC/actions/workflows/psgallery.yml/badge.svg)](https://github.com/ANSSI-FR/DFIR-O365RC/actions/workflows/psgallery.yml/badge.svg)

---
## Table of contents:

1. [Module description](#module-description)
2. [Installation and prerequisites](#installation-and-prerequisites)
   1. [Using Docker](#using-docker)
   2. [Manual Installation](#manual-installation)
3. [Managing the DFIR-O365RC application](#managing-the-dfir-o365rc-application)
   1. [Creating the application](#creating-the-application)
   2. [Updating the application](#updating-the-application)
   3. [Removing the application](#removing-the-application)

4. [Permissions and license requirements](#permissions-and-license-requirements)
5. [Functions included in the module](#functions-included-in-the-module)
6. [Files generated](#files-generated)



DFIR-O365RC was presented at SSTIC 2021 (Symposium sur la sécurité des technologies de l'information et des communications). Slides and a recording of the presentation, in French, are available [here](https://www.sstic.org/2021/presentation/collecte_de_journaux_office_365_avec_dfir-o365rc/).

⚠️ On March 31, 2024, [Microsoft deprecated the authentication method](https://techcommunity.microsoft.com/t5/exchange-team-blog/mfa-app-id-deprecation-in-exchange-online/ba-p/4036067) we used for DFIR-O365RC. This led to the release of the version 2.0.0 in August 2024, with **breaking changes** regarding authentication and a global refactoring of the code. ⚠️



## Module description

The DFIR-O365RC PowerShell module is a set of functions that allow a forensic analyst to collect logs relevant for Microsoft 365 compromises and conduct Entra ID investigations.

The logs are generated in JSON format and retrieved from two main data sources: 

- Microsoft 365 [Unified Audit Log](https://learn.microsoft.com/en-us/purview/audit-search?tabs=microsoft-purview-portal) ;
- Microsoft Entra [sign-ins logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins) and [audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs).

Those two data sources can be queried from different endpoints:

| **Data source / Endpoint**  | **Retention** | **Performance**  |  **Scope** |
|---|---|---|---|
| Unified Audit Log / [Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/module/exchange/search-unifiedauditlog?view=exchange-ps) | 90 days  |  Poor | All Microsoft 365 logs (Entra included) |
| Unified Audit Log / [Purview](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.beta.security/new-mgbetasecurityauditlogquery?view=graph-powershell-beta) | 180 days | Good | All Microsoft 365 logs (Entra included) |
| Unified Audit Log / [Office 365 Management API](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-apis-overview) \* |  7 days |  Good | All Microsoft 365 logs (Entra included) |
| Microsoft Entra logs / [Microsoft Graph PowerShell](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-powershell-reporting) |  30 days | Good  | Entra sign-ins and audit logs only |
| Microsoft Entra logs / [Microsoft Graph REST API](https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0) |  30 days | Good  | Entra sign-ins and audit logs only |

\* The *Office 365 Management API* is intended to analyze data in real time with a SIEM. DFIR-O365RC is a forensic tool, its aim is not to monitor a Microsoft 365 environment in real time.



DFIR-O365RC will fetch data from:

- Microsoft Entra Logs using _Microsoft Graph PowerShell_ because performance is good and it wraps around the _Microsoft Graph REST API_ ;
- By default, Unified Audit Log using *Exchange Online PowerShell*: despite poor performance this is the only usable option for now ;
- Optionally, Unified Audit Log using *Purview*. The retention is 180 days, it has good performance but it is still in beta and bugs in the back-end make it unusable for now.

If you are investigating Microsoft 365 malicious activity, the `Search-O365` (from _Exchange Online PowerShell_) will also fetch the Mailbox Audit Log, although the `Search-MailboxAuditLog` cmdlet is [being deprecated](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/update-on-the-deprecation-of-admin-audit-log-cmdlets/ba-p/4172019).

If you are investigating other Azure resources, with DFIR-O365RC:

- you can get the [Azure Monitor Activity log](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log?tabs=powershell) using the [Az.Monitor PowerShell module](https://learn.microsoft.com/en-us/powershell/module/az.monitor/get-azactivitylog), with a retention of 90 days. This log focuses on activities in _Azure Resource Manager_ (related to an Azure subscription) ;
- you can get the [Azure DevOps audit log](https://learn.microsoft.com/en-us/azure/devops/organizations/audit/azure-devops-auditing?view=azure-devops&tabs=preview-page) using the [Azure DevOps Services REST API](https://learn.microsoft.com/en-us/rest/api/azure/devops/audit/audit-log/query?view=azure-devops-rest-7.2&tabs=HTTP), with a retention of 90 days. This log focuses on activities in _Azure DevOps_ (related to an Azure DevOps organization).



## Installation and prerequisites


### Using Docker

_This is the recommended way of using DFIR-O365RC_

Just type :

```bash
sudo docker run --rm -v .:/mnt/host -it anssi/dfir-o365rc:latest
```

DFIR-O365RC is ready to use:

```bash
PowerShell 7.4.2
DFIR-O365RC: PowerShell module for Microsoft 365 and Entra ID log collection
https://github.com/ANSSI-FR/DFIR-O365RC
PS /mnt/host/output>
```

If you would like to build your Docker image manually, clone the repository and use `docker compose` (or the legacy `docker-compose`) to build the image, run the container and mount a volume (in the `output/` folder):

```bash
sudo docker compose run dfir-o365rc
# using legacy Compose V1
sudo docker-compose run dfir-o365rc
```

### Using PowerShell

You can install the module on *PowerShell Desktop* and *PowerShell Core*.

Please note that the `Connect-ExchangeOnline` cmdlet [requires Microsoft .NET Framework 4.7.2 or later](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#windows).

To install the module from the PowerShell Gallery :
```powershell
Install-Module -Name DFIR-O365RC
```

You can also install the module manually by cloning the DFIR-O365RC repository, install the required dependencies (check [DFIR-O365RC.psd1](DFIR-O365RC/DFIR-O365RC.psd1)) and add the [DFIR-O365RC directory](DFIR-O365RC/) in one of your PowerShell's modules path.

## Managing the DFIR-O365RC application

### Creating the application

Once the module is imported, you will need to create an Entra application, which will handle the log collection process for you.

To do so:

1) Create a self-signed certificate and get the base64-encoded public part:

   On Linux, using PowerShell Core or the Docker container:

   ```bash
   openssl req -new -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -out exampleDFIRO365RC.crt -keyout exampleDFIRO365RC.key -batch
   openssl pkcs12 -inkey exampleDFIRO365RC.key -in exampleDFIRO365RC.crt -export -out exampleDFIRO365RC.pfx # Enter a password for the certificate
   openssl x509 -in exampleDFIRO365RC.crt -outform DER -out - | base64 | tr -d "\n"
   ```

   On Windows, using PowerShell:

   ```powershell
   $certificate = New-SelfSignedCertificate -Subject "CN=exampleDFIRO365RC" -KeySpec KeyExchange -NotBefore (Get-Date) -NotAfter (Get-Date).AddDays(365)
   $certificatePassword = Read-Host -MaskInput "Please enter a password for the certificate"
   $certificateSecurePassword = ConvertTo-SecureString -String $certificatePassword -AsPlainText -Force
   Export-PfxCertificate -Cert $certificate -FilePath exampleDFIRO365RC.pfx -Password $certificateSecurePassword
   Write-Host ([System.Convert]::ToBase64String($certificate.GetRawCertData()))
   ```

2) Use the `New-Application` cmdlet from the DFIR-O365RC module:

   ```powershell
   $certificateb64="<base64-encoded public part from step 1>"
   New-Application -certificateb64 $certificateb64
   ```

   Optionally, if you would like to be able to gather logs in the subscriptions of the tenant (not needed if you do not plan to use `Get-AzRMActivityLogs`):

   ```powershell
   New-Application -certificateb64 $certificateb64 -subscriptions
   ```

   Optionally, if you would like to be able to gather logs in the Azure DevOps organizations of the tenant (this can take a long time and is not needed if you do not plan to use `Get-AzDevOpsActivityLogs`):

   ```powershell
   New-Application -certificateb64 $certificateb64 -organizations
   ```

   To create the application, you will need to log in to Azure several times, using a **highly privileged** account.

   One the application is created, you will get an output similar to:

   ```powershell
   Done creating the application with the required permissions
   Please use the following identifiers: 
   WARNING: AppID: xxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   WARNING: Tenant: example.onmicrosoft.com
   ```

### Updating the application

Once the application is created, you can still, using the `Update-Application` cmdlet from the module, update its credentials and permissions:

- You can add a new certificate to the application:

  `Update-Application -certificateb64 <base64-encoded public part>`

- You can specify new subscriptions in which you would like to be able to gather logs:

  `Update-Application -subscriptions`

- You can specify new Azure DevOps organizations in which you would like to be able to gather logs:

  `Update-Application -organizations`

- You can update the permissions of the application, which is especially useful if you have an old application and the permissions have been updated since you created it:

  `Update-Application -permissions`

### Removing the application

Once you are done with the log collection you can delete the application using the `Remove-Application` cmdlet from the module.

To remove the application, you will need to log in to Azure several times, using a **highly privileged** account.

If the application was able to gather logs of subscriptions or Azure DevOps organizations, you will need to add the `-organizations` and/or `-subscriptions` switches.



## Permissions and license requirements

⚠️

Starting with version 2.0.0, the tool is now running in the context of a Service Principal with [App-only access / Application permissions](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview#app-only-access-access-without-a-user). 

To use version 2.0.0 and up, you will need to [create an application](#creating-the-application).

Once the application is created, the script will run using the application's credentials and permissions.

⚠️

The application will be created with the least possible required permission set:

- `Exchange.ManageAsApp` for the `Office 365 Exchange Online` API (required to be able to run Exchange Online PowerShell cmdlets)
- `AuditLog.Read.All` for the `Microsoft Graph` API (required for Microsoft Entra log collection)
- `AuditLogsQuery.Read.All` for the `Microsoft Graph` API (required for Unified Audit Log collection using Purview)
- `Application.Read.All` and `DelegatedPermissionGrant.Read.All` for the `Microsoft Graph` API (required for the enrichment of Microsoft Entra logs related to applications and service principals)
- `Device.Read.All` for the `Microsoft Graph` API (required for the enrichment of Microsoft Entra logs related to devices)
- `User.Read.All` for the `Microsoft Graph` API (required for getting information on the users)
- `UserAuthenticationMethod.Read.All` for the `Microsoft Graph` API (required for getting information on the users' authentication methods)
- `Organization.Read.All` for the `Microsoft Graph` API (required for getting general information on the tenant)
- `View-only audit logs` in `Exchange Online` (required to use the `Search-UnifiedAuditLog` cmdlet)

Optionally (if using the `-subscriptions` switch):

- For the selected subset of subscriptions: `Reader` role on `Microsoft.Insights/eventtypes/*` (required to get the Azure Monitor Activity log)

Optionally (if using the `-organizations` switch):

- For the selected subset of Azure DevOps subscriptions: `View audit log` (required to get the Azure DevOps audit log)



In order to retrieve Microsoft Entra logs with the Microsoft Graph API you need at least one user with a [Microsoft Entra ID P1](https://www.microsoft.com/en-us/security/business/microsoft-entra-pricing) license. This license can be purchased for a single user or can be included in some license plans such as the *Microsoft 365 Business Premium* plan.



 ## Functions included in the module

The module has 10 functions:

| **Function**  | **Data Source**  | Retention | **Performance**  |  **Completeness** | **Details** |
|---|---|---|---|---|---|
| `Get-O365Full` | Unified Audit Log | 90 days / 180 days* |  Poor | All Unified Audit Log | By default, retrieve the whole Unified Audit Log. This should only be used on a small tenant or a short period of time.<br />You can also use this cmdlet to gather events for some specific [record types](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#enum-auditlogrecordtype---type-edmint32). |
| `Get-O365Light` | Unified Audit Log | 90 days / 180 days* |  Good | A subset of Unified Audit Log only | Only a subset of *operations*, which are considered of interest, are retrieved. |
| `Get-O365Defender` | Unified Audit Log | 90 days / 180 days* |  Good | A subset of Unified Audit Log only | Retrieves Microsoft Defender for Microsoft 365 related events. Requires at least one [Office 365 E5](https://www.microsoft.com/en-us/microsoft-365/enterprise/office-365-e5?activetab=pivot:overviewtab) license or a license plan which includes Microsoft Defender for Office 365. |
| `Get-AADLogs` | Microsoft Entra Logs | 30 days |  Good | All Microsoft Entra Logs | Get tenant information and all Microsoft Entra logs: sign-ins logs and audit logs. |
| `Get-AADApps` | N/A | N/A |  Good | Complete | Microsoft Entra ID service principals and their applications, oauth2PermissionGrants and appRoleAssignments |
| `Get-AADDevices` | N/A | N/A |  Good | Complete | Microsoft Entra ID devices and their owners/users |
| `Get-AADUsers` | N/A | N/A |  Good | Complete | Microsoft Entra ID users and their authentication methods |
| `Search-O365` | Unified Audit Log / Mailbox Audit Log** | 90 days / 180 days* | Poor | A subset of Unified Audit Log only | Search for activity related to specific users, IP addresses or free texts. |
| `Get-AzRMActivityLogs` | Azure Monitor Activity log | 90 days |  Good | All Azure Monitor Activity log | Get all Azure Monitor Activity log for a selected subset of subscriptions. |
| `Get-AzDevOpsActivityLogs` | Azure DevOps audit log | 90 days |  Good | All Azure DevOps audit log | Get all Azure DevOps audit log for a selected subset of Azure DevOps organizations. |

\* You can get 180 days of retention using Purview, compared to the default 90 days of retention using Exchange Online.

** When searching for users, the `Search-O365` cmdlet will also search in the Mailbox Audit Log.



Each function as a comment-based help which you can invoke with the *Get-Help* cmdlet. 

```powershell
# Display comment-based help
PS> Get-Help Get-O365Full
# Display comment-based help with examples
PS> Get-Help Get-O365Full -Examples
```
Each function takes as a parameter:

- a start date (`-startDate`) ;
- an end date (`-endDate`) ;
- the application identifier of the application (`-appId`), which is obtained when [creating the application](#creating-the-application) ;
- the tenant name (`-tenant`) ;
- the path to the certificate in PFX format (`-certificatePath`), which is obtained when [creating the application](#creating-the-application).



**Examples**:

For readability, we will assume that:

```powershell
$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$tenant = "example.onmicrosoft.com"
$certificatePath = "./example.pfx"
```

On a real case, those parameters are gathered when [creating the application](#creating-the-application).



In order to retrieve Microsoft Entra Logs from the past 30 days as well as general information on the tenant:

```powershell
$endDate = Get-Date
$startDate = $endDate.AddDays(-30)
Get-AADLogs -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath
```

Get Microsoft Entra service principals and their application, oauth2PermissionGrant and appRoleAssignment:

```powershell
$endDate = Get-Date
$startDate = $endDate.AddDays(-30)
Get-AADApps --appId $appId -tenant $tenant -certificatePath $certificatePath
```

Get Microsoft Entra devices and their owners and users:

```powershell
$endDate = Get-Date
$startDate = $endDate.AddDays(-30)
Get-AADDevices -appId $appId -tenant $tenant -certificatePath $certificatePath
```

Get Microsoft Entra users and their authentication methods settings:

```powershell
Get-AADUsers -appId $appId -tenant $tenant -certificatePath $certificatePath -authenticationMethods
```

Retrieve Unified Audit log events considered of interest from the past 30 days, except those related to Entra ID, which were already retrieved by the first command:

```powershell
$endDate = Get-Date
$startDate = $endDate.AddDays(-30)
Get-O365Light -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -operationsSet "allButAzureAD"
```

Retrieve Unified Audit log events considered of interest in a time window between -90 days and -30 days from now:

```powershell
$endDate = (Get-Date).AddDays(-30)
$startDate = (Get-Date).AddDays(-90)
Get-O365Light -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath
```

If mailbox audit is enabled you can also retrieve `MailboxLogin` operations using the dedicated switch:

_Beware of a global limit of 50.000 events per search_

```powershell
Get-O365Light -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -mailboxLogin
```

If there are users with Office 365 E5 licenses or if there is a Microsoft Defender for Office 365 Plan in the tenant you can retrieve Microsoft Defender related logs from the past 90 days:

```powershell
$endDate = Get-Date
$startDate = $endDate.AddDays(-90)
Get-O365Defender -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath
```

To retrieve all Unified Audit Log events between Christmas Eve 2020 and Boxing day 2020: 

_Beware that performance using that cmdlet is poor_

```powershell
$endDate = Get-Date "12/26/2020"
$startdate = Get-Date "12/24/2020"
Get-O365Full -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath
```

You can use the search function to look for IP addresses, activity related to specific users or perform a freetext search in the Unified Audit Log:

```powershell
$endDate = Get-Date
$startDate = $endDate.AddDays(-90)

# Retrieve events which contains the "Python" or "Python3" free text
Search-O365 -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -freeTexts "Python","Python3"

# Retrieve events related to the IP adresses 8.8.8.8 and 4.4.4.4.
Search-O365 -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -IPAddresses "8.8.8.8","4.4.4.4"

# Retrieve events related to users user1@example.onmicrosoft.com and user2@example.onmicrosoft.com
Search-O365 -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -userIds "user1@example.onmicrosoft.com","user2@example.onmicrosoft.com"
```

When searching for specific **users**, `Search-O365` will also search in the Mailbox Audit Log. That's because, depending on the user's license level and settings, some of the mailbox logs might not be present in the Unified Audit Log.




To retrieve all Azure Resource Manager activity logs from the subscriptions the application has access to:
```powershell
$endDate = Get-Date
$startDate = $endDate.AddDays(-90)
Get-AzRMActivityLogs -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath
```



To retrieve all Azure DevOps activity logs from the organizations the application has access to:

```powershell
$endDate = Get-Date
$startDate = $endDate.AddDays(-90)
Get-AzDevOpsActivityLogs -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath
```



 ## Files generated

All files generated are in JSON format.

_Launching several cmdlet which uses Purview and will write to the same output file can result in an invalid JSON because of a "naive" concatenation_

- `Get-AADApps` will create in the `azure_ad_apps` folder:
  - a JSON file containing existing and deleted applications: `AADApps_example.onmicrosoft.com_applications_raw.json`;
  - a JSON file containing existing and deleted service principals: `AADApps_example.onmicrosoft.com_service_principals_raw.json`;
  - a JSON file containing the enriched service principals: `AADApps_example.onmicrosoft.com.json`.

- `Get-AADDevices` will create in the `azure_ad_devices` folder:
  - a JSON file containing existing and deleted devices: `AADDevices_example.onmicrosoft.com_devices_raw.json`;
  - a JSON file containing the enriched devices: `AADDevices_example.onmicrosoft.com.json`.

- `Get-AADUsers` will create in the `azure_ad_users` folder:
  - a JSON file containing existing and deleted users: `AADUsers_example.onmicrosoft.com_users_raw.json`;
  - a JSON file containing users' authentication settings: `AADUsers_example.onmicrosoft.com_users_settings_raw.json`;
  - a JSON file containing the enriched users: `AADUsers_example.onmicrosoft.com.json`.

- `Get-AADLogs` will create:
  - in the `azure_ad_tenant` folder:
    - a JSON file containing general information on the tenant: `AADTenant_example.onmicrosoft.com.json`.

  - in the `azure_ad_audit` folder:
    - JSON files containing Microsoft Entra audit logs: `AADAuditLog_example.onmicrosoft.com_YYYY-MM-DD.json`.

  - in the `azure_ad_signin` folder:
    - JSON files containing Microsoft Entra sign-in logs: `YYYY-MM-DD/AADSigninLog_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00.json`.

- `Get-AzRMActivityLogs` will create:
  - in the `azure_rm_subscriptions` folder:
    - a JSON file containing general information on the subscriptions: `AzRMsubscriptions_example.onmicrosoft.com.json`.

  - in the `azure_rm_activity` folder:
    - JSON files containing Azure Monitor Activity logs: `YYYY-MM-DD/AzRM_example.onmicrosoft.com_%SubscriptionID%_YYYY-MM-DD_HH-00-00.json`.

- `Get-AzDevOpsActivityLogs` will create:
  - in the `azure_DevOps_orgs` folder:
    - a JSON file containing general information on the Azure DevOps organizations: `AzdevopsOrgs_example.onmicrosoft.com.json`.

  - in the `azure_DevOps_activity` folder:
    - JSON files containing Azure DevOps audit logs: `YYYY-MM-DD/AzDevOps_example.onmicrosoft.com_%AzureDevOpsOrg%_YYYY-MM-DD_HH-00-00.json`.

- `Get-O365Full` will create in the `O365_unified_audit_logs` folder (respectively `O365_unified_audit_logs_purview` when using Purview):
  - JSON files containing Unified Audit logs: `YYYY-MM-DD/UnifiedAuditLog_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00.json` (respectively `*/UnifiedAuditLogPurview_*` when using Purview);
  - JSON files containing Unified Audit logs for specified [RecordTypes](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#enum-auditlogrecordtype---type-edmint32): `YYYY-MM-DD/UnifiedAuditLog_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00_%RecordType%.json` (respectively `*/UnifiedAuditLogPurview_*` when using Purview).

- `Get-O365Light` will create in the `O365_unified_audit_logs` folder (respectively `O365_unified_audit_logs_purview` when using Purview):
  - JSON files containing Unified Audit logs for a subset of *operations*, which are considered of interest: `YYYY-MM-DD/UnifiedAuditLog_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00.json` (respectively `*/UnifiedAuditLogPurview_*` when using Purview).
- `Get-O365Defender` will create in the `O365_unified_audit_logs` folder (respectively `O365_unified_audit_logs_purview` when using Purview):
  - JSON files containing Unified Audit logs for the [RecordTypes](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#enum-auditlogrecordtype---type-edmint32) associated with Defender: `YYYY-MM-DD/UnifiedAuditLog_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00_%RecordType%.json` (respectively `*/UnifiedAuditLogPurview_*` when using Purview).
- `Search-O365` will create:
  - in the `O365_unified_audit_logs` folder (respectively `O365_unified_audit_logs_purview` when using Purview):
    - JSON files containing Unified Audit logs for the specified `RequestType` (`FreeText`, `IPAddresses`, or`UserIds`): `YYYY-MM-DD/UnifiedAuditLog_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00_%RequestType%_YYYY-MM-DD-HH-MM-SS.json` (respectively `*/UnifiedAuditLogPurview_*` when using Purview). `YYYY-MM-DD-HH-MM-SS` represents the time when the collect was done. When searching for `FreeText`, an additional `_%i` is added at the end, which indicates this is the result from the search of the `%i`-th free text.

  - in the `Exchange_mailbox_audit_logs` folder:
    - JSON files containing Mailbox Audit logs (only when searching  for UserIDs): `YYYY-MM-DD/MailboxAuditLog_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00_UserIds_YYYY-MM-DD-HH-MM-SS_%UserID%.json`. `YYYY-MM-DD-HH-MM-SS` represents the time when the collect was done. `%UserID%` indicates this is the result from the search of this UserID.




Launching the various functions will generate a directory structure similar to this one:

```
output
│   Get-AADApps.log
│   Get-AADDevices.log
│   Get-AADLogs.log
│   Get-AzDevOpsActivityLogs.log
│   Get-AzRMActivityLogs.log
│   Get-O365Defender.log
│   Get-O365Full.log
│   Get-O365Light.log
│   Search-O365.log
│
├───azure_ad_apps
│       AADApps_example.onmicrosoft.com.json
│       AADApps_example.onmicrosoft.com_applications_raw.json
│       AADApps_example.onmicrosoft.com_service_principals_raw.json
│
├───azure_ad_audit
│       AADAuditLog_example.onmicrosoft.com_YYYY-MM-DD.json
│       [...]
│
├───azure_ad_devices
│       AADDevices_example.onmicrosoft.com.json
│       AADDevices_example.onmicrosoft.com_devices_raw.json
│
├───azure_ad_signin
│   ├───YYYY-MM-DD
│   │       AADSigninLog_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00.json
│   │       [...]
│   │
│   ├───[...]
│
├───azure_ad_tenant
│       AADTenant_example.onmicrosoft.com.json
│
├───azure_ad_users
│       AADUsers_divreponse.onmicrosoft.com.json
│       AADUsers_divreponse.onmicrosoft.com_users_raw.json
│       AADUsers_divreponse.onmicrosoft.com_users_settings_raw.json
|
├───azure_DevOps_activity
│   ├───YYYY-MM-DD
│   │       AzDevOps_example.onmicrosoft.com_%AzureDevOpsOrg%_YYYY-MM-DD_HH-00-00.json
│   │       [...]
│   │
│   ├───[...]
│
├───azure_DevOps_orgs
│       AzdevopsOrgs_example.onmicrosoft.com.json
├───azure_rm_activity
│   ├───YYYY-MM-DD
│   │       AzRM_example.onmicrosoft.com_%SubscriptionID%_YYYY-MM-DD_HH-00-00.json
│   │       [...]
│   │
│   ├───[...]
│
├───azure_rm_subscriptions
│       AzRMsubscriptions_example.onmicrosoft.com.json
│
├───Exchange_mailbox_audit_logs
│   └───YYYY-MM-DD
│   │       MailboxAuditLog_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00_UserIds_YYYY-MM-DD-HH-MM-SS_%UserID%.json
│   │       [...]
│   │
│   ├───[...]
│
├───O365_unified_audit_logs
│   ├───YYYY-MM-DD
│   │       UnifiedAuditLog_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00.json
│   │       UnifiedAuditLog_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00_%RecordType%.json
│   │       UnifiedAuditLog_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00_UserIds_YYYY-MM-DD-HH-MM-SS.json
│   │       UnifiedAuditLog_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00_IPAddresses_YYYY-MM-DD-HH-MM-SS.json
│   │       UnifiedAuditLog_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00_FreeText_YYYY-MM-DD-HH-MM-SS_%i.json
│   │       [...]
│   │
│   ├───[...]
│
└───O365_unified_audit_logs_purview
│   ├───YYYY-MM-DD
│   │       UnifiedAuditLogPurview_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00.json
│   │       UnifiedAuditLogPurview_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00_%RecordType%.json
│   │       UnifiedAuditLogPurview_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00_UserIds_YYYY-MM-DD-HH-MM-SS.json
│   │       UnifiedAuditLogPurview_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00_IPAddresses_YYYY-MM-DD-HH-MM-SS.json
│   │       UnifiedAuditLogPurview_example.onmicrosoft.com_YYYY-MM-DD_HH-00-00_FreeText_YYYY-MM-DD-HH-MM-SS_%i.json
│   │       [...]
│   │
│   ├───[...]
```
