function Get-EntraIDPermissions {
    <#
    .SYNOPSIS
    The Get-EntraIDPermissions function is the inner function that handles getting Entra ID permissions
    #>

    param (
        [String]$logFile = "Get-EntraIDPermissions.log"
    )

    "Getting Entra ID permissions 'AuditLog.Read.All', 'AuditLogsQuery.Read.All', 'Application.Read.All', 'DelegatedPermissionGrant.Read.All', 'Device.Read.All', 'User.Read.all', 'UserAuthenticationMethod.Read.All' and 'Organization.Read.All' for 'Microsoft Graph'" | Write-Log -LogPath $logFile
    $graphApi = (Get-MgServicePrincipal -Filter "AppID eq '00000003-0000-0000-c000-000000000000'" -ErrorAction Stop)
    if ($graphApi -eq $null){
        return $null
    }
    $graphAuditLogReadAll = $graphApi.AppRoles | Where-Object { $_.Value -eq 'AuditLog.Read.All' }
    $graphAuditLogsQueryReadAll = $graphApi.AppRoles | Where-Object { $_.Value -eq 'AuditLogsQuery.Read.All' }
    $graphApplicationReadAll = $graphApi.AppRoles | Where-Object { $_.Value -eq 'Application.Read.All' }
    $graphDelegatedPermissionGrandReadAll = $graphApi.AppRoles | Where-Object { $_.Value -eq 'DelegatedPermissionGrant.Read.All' }
    $graphDeviceReadAll = $graphApi.AppRoles | Where-Object { $_.Value -eq 'Device.Read.All' }
    $graphUserReadAll = $graphApi.AppRoles | Where-Object { $_.Value -eq 'User.Read.All' }
    $graphUserAuthenticationMethodReadAll = $graphApi.AppRoles | Where-Object { $_.Value -eq 'UserAuthenticationMethod.Read.All' }
    $graphOrganizationReadAll = $graphApi.AppRoles | Where-Object { $_.Value -eq 'Organization.Read.All' }
    $graphRequiredAccess = @{
        ResourceAppId = $graphApi.AppId ;
        ResourceAccess = @(
            @{
                Id = $graphAuditLogReadAll.Id ;
                Type = "Role"
            },
            @{
                Id = $graphAuditLogsQueryReadAll.Id ;
                Type = "Role"
            },
            @{
                Id = $graphApplicationReadAll.Id ;
                Type = "Role"
            },
            @{
                Id = $graphDelegatedPermissionGrandReadAll.Id ;
                Type = "Role"
            },
            @{
                Id = $graphUserReadAll.Id ;
                Type = "Role"
            },
            @{
                Id = $graphUserAuthenticationMethodReadAll.Id ;
                Type = "Role"
            },
            @{
                Id = $graphDeviceReadAll.Id ;
                Type = "Role"
            },
            @{
                Id = $graphOrganizationReadAll.Id ;
                Type = "Role"
            }
        )
    }
    return $graphRequiredAccess
}

function Wait-AdminConsent {
    <#
    .SYNOPSIS
    The Wait-AdminConsent function is the inner function which will wait for the admin consent
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$appId,
        [Parameter(Mandatory = $true)]
        [String]$servicePrincipalId,
        [String]$logFile = "Wait-AdminConsent.log"
    )
    
    $tenantID = (Get-MgOrganization -ErrorAction Stop).Id
    Write-Host "Sleeping 30 seconds for the application to be correctly deployed / updated"
    Start-Sleep -Seconds 30
    $consentURL = "https://login.microsoftonline.com/$tenantID/adminconsent?client_id=$($appId)"
    Write-Warning "Please use a web browser to open the page $consentURL and do an admin consent for the application (error AADSTS500113 is expected after the consent)"
    "Displaying the URI for the admin consent" | Write-Log -LogPath $logFile
    $hasConsented = $False
    $graphRequiredAccess = Get-EntraIDPermissions -logFile $logFile
    $graphRequiredAccessIds = $graphRequiredAccess.ResourceAccess | Select-Object -ExpandProperty Id | sort
    while (-not $hasConsented){
        $roleAssignements = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipalId
        if ($roleAssignements){
            $roleAssignementsIds = $roleAssignements | Select-Object -ExpandProperty AppRoleId | sort
            $IdsDiff = $graphRequiredAccessIds | Where {$roleAssignementsIds -NotContains $_}
            if ($IdsDiff -eq $null){
                $hasConsented = $true
            }
        }
        Start-Sleep -Seconds 1
    }
}

function Add-OrganizationPermissions {

    <#
    .SYNOPSIS
    The Add-OrganizationPermissions function is the inner function that handles adding the application to the Azure DevOps organizations
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$servicePrincipalId,
        [String]$logFile = "Add-OrganizationPermissions.log"
    )

    Write-Warning "Please log in to Entra ID using a privileged account which has access to the targeted organizations"
    Connect-AzUser -logFile $logFile
    $token = Get-AzAccessToken -ResourceUrl "499b84ac-1321-427f-aa17-267ca6975798" -AsSecureString:$false -ErrorAction Stop
    
    $tenantId = (Get-AzTenant).Id
    $azureDevOpsOrganizationsRaw = Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.Token)"} -Method Get -ContentType "application/json" -ErrorAction Stop -Uri "https://aexprodweu1.vsaex.visualstudio.com/_apis/EnterpriseCatalog/Organizations?tenantId=$tenantId"
    $azureDevOpsOrganizationsNameAndId = $azureDevOpsOrganizationsRaw | ConvertFrom-CSV | ForEach-Object {$_ | Select-Object "Organization Name", "Organization Id"}

    Write-Host "Your account has access to the following organizations:"
    "Your account has access to the following organizations:" | Write-Log -LogPath $logFile
    $azureDevOpsOrganizationsNameAndId | Out-Host
    $azureDevOpsOrganizationsNameAndId | Write-Log -LogPath $logFile
    $choice = Read-Host "Do you want to collect logs for all [a], specific [s] or no [N] organization ? [a/s/N]"
    if ($choice.ToUpper() -eq "A" -or $choice.ToUpper() -eq "S"){
        if ($choice.ToUpper() -eq "S"){
            [System.Collections.ArrayList]$wantedOrganizationsNameAndId = @{}
            $read = $True
            Write-Host "Leave Blank and press 'Enter' to Stop"
            while ($read){
                $potentialOrganizationId = Read-Host "Please enter the organization IDs, one by one, and press 'Enter'"
                if ($potentialOrganizationId){
                    $selectedInput = $azureDevOpsOrganizationsNameAndId | Where-Object {$_."Organization Id" -eq $potentialOrganizationId}
                    if ($null -ne $selectedInput){
                        $wantedOrganizationsNameAndId.Add($selectedInput) | Out-Null
                        Write-Host "Added $potentialOrganizationId"
                    }
                    else {
                        Write-Warning "Invalid organization ID, please try again"
                    }
                }
                else {
                    $read = $False
                }
            }
        }
        elseif ($choice.ToUpper() -eq "A"){
            $wantedOrganizationsNameAndId = $azureDevOpsOrganizationsNameAndId
        }

        foreach ($organization in $wantedOrganizationsNameAndId){
            $organizationName = $organization.'Organization Name'
            Write-Host "Adding service principal to organization $organizationName ($($organization.'Organization Id'))"
            "Adding service principal to organization $organizationName ($($organization.'Organization Id'))" | Write-Log -LogPath $logFile
            $isSuccess = (Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.Token)"} -Method POST -ContentType "application/json" -ErrorAction Stop -Uri "https://vsaex.dev.azure.com/$organizationName/_apis/serviceprincipalentitlements?api-version=7.1-preview.1" -Body "{`"accessLevel`": {`"accountLicenseType`": `"stakeholder`"},`"servicePrincipal`": {`"origin`": `"aad`",`"originId`": `"$servicePrincipalId`",`"subjectKind`": `"servicePrincipal`"}}").isSuccess
            while ($isSuccess -ne "True"){
                try {
                    $isSuccess = (Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.Token)"} -Method POST -ContentType "application/json" -ErrorAction Stop -Uri "https://vsaex.dev.azure.com/$organizationName/_apis/serviceprincipalentitlements?api-version=7.1-preview.1" -Body "{`"accessLevel`": {`"accountLicenseType`": `"stakeholder`"},`"servicePrincipal`": {`"origin`": `"aad`",`"originId`": `"$servicePrincipalId`",`"subjectKind`": `"servicePrincipal`"}}").isSuccess
                }
                catch {
                    Write-Warning "Service principal is not yet available to $organizationName ($($organization.'Organization Id'))"
                    "Service principal is not yet available to $organizationName ($($organization.'Organization Id'))" | Write-Log -LogPath $logFile -LogLevel Warning
                    Start-Sleep -Seconds 1
                }
            }
            $securityNamespaces = Get-AzDevOpsRestAPIResponseUser -uri "https://dev.azure.com/$organizationName/_apis/securitynamespaces" -logFile $logFile
            $auditLogServiceNamescapeId = $securityNamespaces | Where-Object {$_.displayName -eq "AuditLog"} | Select-Object -ExpandProperty namespaceId
            $auditLogReadBit = $securityNamespaces | Where-Object {$_.displayName -eq "AuditLog"} | Select-Object -ExpandProperty actions | Where-Object {$_.name -eq "Read"} | Select-Object -ExpandProperty bit
            $servicePrincipals = Get-AzDevOpsRestAPIResponseUser -uri "https://vssps.dev.azure.com/$organizationName/_apis/graph/serviceprincipals?api-version=7.1-preview.1" -logFile $logFile
            $domain = $servicePrincipals | Where-Object {$_.originId -eq $servicePrincipalId} | Select-Object -ExpandProperty domain
            $null = Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.Token)"} -Method POST -ContentType "application/json" -ErrorAction Stop -Uri "https://dev.azure.com/$organizationName/_apis/AccessControlEntries/$auditLogServiceNamescapeId"  -Body "{`"token`":`"AllPermissions`",`"merge`":true,`"accessControlEntries`":[{`"descriptor`":`"Microsoft.VisualStudio.Services.Claims.AadServicePrincipal;$domain\\$servicePrincipalId`",`"allow`":$auditLogReadBit,`"deny`":0}]}"
        }
        Write-Host "Done assigning roles on organizations for the application"
        "Done assigning roles on organizations for the application" | Write-Log -LogPath $logFile
    }
    else {
        Write-Warning "No organization was selected"
        "No organization was selected" | Write-Log -LogPath $logFile -LogLevel Warning
    }
}

function Add-SubscriptionPermissions {

    <#
    .SYNOPSIS
    The Add-SubscriptionPermissions function is the inner function that handles adding the application to the Azure Resource Manager subscriptions
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$servicePrincipalId,
        [String]$logFile = "Add-SubscriptionPermissions.log"
    )

    Write-Warning "Please log in to Entra ID using a privileged account which has access to the targeted subscriptions"
    Connect-AzUser -logFile $logFile

    $subscriptionsNameAndId = Get-AzSubscription -ErrorAction Stop | Select-Object Name, Id
    Write-Host "Your account has access to the following subscriptions:"
    "Your account has access to the following subscriptions:" | Write-Log -LogPath $logFile
    $subscriptionsNameAndId | Out-Host
    $subscriptionsNameAndId | Write-Log -LogPath $logFile
    $choice = Read-Host "Do you want to be able to collect logs for all [a], specific [s] or no [N] subscription ? [a/s/N]"
    if ($choice.ToUpper() -eq "A" -or $choice.ToUpper() -eq "S"){
        $alreadyExistingCheckRoleDefinition = Get-AzRoleDefinition -Name "LogCollectionDFIRO365RC" -ErrorAction Stop -WarningAction:SilentlyContinue
        if ($null -ne $alreadyExistingCheckRoleDefinition){
            $role = $alreadyExistingCheckRoleDefinition
        }
        else {
            $role = Get-AzRoleDefinition "Reader" -ErrorAction Stop
            $role.Id = $null
        }
        $role.Name = "LogCollectionDFIRO365RC"
        $role.Description = "Can view activity logs"
        $role.Actions.Clear()
        $role.Actions.Add("Microsoft.Insights/eventtypes/*")
        $role.AssignableScopes.Clear()
        if ($choice.ToUpper() -eq "S"){
            [System.Collections.ArrayList]$wantedSubscriptionsNameAndId = @{}
            $read = $True
            Write-Host "Leave Blank and press 'Enter' to Stop"
            while ($read){
                $potentialSubscriptionId = Read-Host "Please enter the subscription IDs, one by one, and press 'Enter'"
                if ($potentialSubscriptionId){
                    $selectedInput = $subscriptionsNameAndId | Where-Object {$_.Id -eq $potentialSubscriptionId}
                    if ($null -ne $selectedInput){
                        $wantedSubscriptionsNameAndId.Add($selectedInput) | Out-Null
                        Write-Host "Added $potentialSubscriptionId"
                    }
                    else {
                        Write-Warning "Invalid subscription ID, please try again"
                    }
                }
                else {
                    $read = $False
                }
            }
        }
        elseif ($choice.ToUpper() -eq "A"){
            $wantedSubscriptionsNameAndId = $subscriptionsNameAndId
        }
        foreach ($subscription in $wantedSubscriptionsNameAndId){
            Write-Host "Adding subscription $($subscription.Name) ($($subscription.Id)) to the list of scopes"
            "Adding subscription $($subscription.Name) ($($subscription.Id)) to the list of scopes" | Write-Log -LogPath $logFile
            $role.AssignableScopes.Add("/subscriptions/$($subscription.Id)")
        }
        if ($role.AssignableScopes.length -gt 0){
            if ($null -ne $alreadyExistingCheckRoleDefinition){
                $roleDefinition = Set-AzRoleDefinition -Role $role -ErrorAction Stop
            }
            else {
                $roleDefinition = New-AzRoleDefinition -Role $role -ErrorAction Stop
            }
        }
        else {
            Write-Warning "No subscription was selected"
            "No subscription was selected" | Write-Log -LogPath $logFile -LogLevel Warning
        }

        foreach ($subscription in $wantedSubscriptionsNameAndId){
            $alreadyExistingCheckRoleAssignement = Get-AzRoleAssignment -ObjectId $servicePrincipalId -RoleDefinitionId $roleDefinition.Id -Scope "/subscriptions/$($subscription.Id)" -ErrorAction Stop
            if ($null -eq $alreadyExistingCheckRoleAssignement){
                Write-Host "Assigning role for scope $($subscription.Name) ($($subscription.Id))"
                "Assigning role for scope $($subscription.Name) ($($subscription.Id))" | Write-Log -LogPath $logFile
                $null = New-AzRoleAssignment -ObjectId $servicePrincipalId -Scope "/subscriptions/$($subscription.Id)" -RoleDefinitionId $roleDefinition.Id -ErrorAction Stop
            }
            else {
                Write-Host "Scope $($subscription.Name) ($($subscription.Id)) is already assigned"
                "Scope $($subscription.Name) ($($subscription.Id)) is already assigned" | Write-Log -LogPath $logFile
            }
        }
        Write-Host "Done assigning roles on subscriptions for the application"
        "Done assigning roles on subscriptions for the application" | Write-Log -LogPath $logFile
    }
    else {
        Write-Warning "You have not selected any subscription"
        "You have not selected any subscription" | Write-Log -LogPath $logFile -LogLevel Warning
    }
}

function Update-Application {
    <#
    .SYNOPSIS
    The Update-Application function will update an existing application to add a certificate.
    The "-organizations" switch will allow the application to collect logs from Azure DevOps organizations.
    The "-subscriptions" switch will allow the application to collect logs from Azure Resource Manager subscriptions

    .EXAMPLE

    PS C:\>$certificateb64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("example.der"))
    PS C:\>Update-Application -certificateb64 $certificateb64
    Update the application to add a certificate ("example.der").

    PS C:\>$certificateb64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("example.der"))
    PS C:\>Update-Application -certificateb64 $certificateb64 -organizations -subscriptions
    Update the application to add a certificate ("example.der") and access to Azure DevOps organizations and Azure Resource Manager subscriptions.
    #>
    
    param (
        [Parameter(Mandatory = $false)]
        [String]$certificateb64,
        [Parameter(Mandatory = $false)]
        [Switch]$subscriptions,
        [Parameter(Mandatory = $false)]
        [Switch]$organizations,
        [String]$logFile = "Update-Application.log"
    )

    $currentPath = (Get-Location).path
    $logFile = $currentPath + "\" + $logFile

    Connect-MicrosoftGraphUser -logFile $logFile

    Write-Host "Check for already existing DFIR-O365 applications"
    "Check for already existing DFIR-O365 applications" | Write-Log -LogPath $logFile
    $alreadyExistingAppCheck = Get-MgApplication -Filter "startswith(DisplayName,'LogCollectionDFIRO365RC_')" -ErrorAction Stop
    if ($alreadyExistingAppCheck){
        if ($alreadyExistingAppCheck.length -gt 1){
            Write-Error $alreadyExistingAppCheck.length + " LogCollectionDFIRO365RC applications are present. Please delete all but one existing applications"
            $alreadyExistingAppCheck.length + " LogCollectionDFIRO365RC applications are present" | Write-Log -LogPath $logFile -LogLevel Error
        }
        else {
            $applicationName = "$($alreadyExistingAppCheck.DisplayName)"
            Write-Host "A LogCollectionDFIRO365RC application already exists: $applicationName"
            "A LogCollectionDFIRO365RC application already exists: $applicationName" | Write-Log -LogPath $logFile
            if ("" -ne $certificateb64){
                $confirmation = Read-Host "Do you want to add the provided certificate to the application $applicationName ? [y/N]"
                if ($confirmation.ToUpper() -eq "Y"){
                    Write-Host "Loading the certificate"
                    "Loading the certificate" | Write-Log -LogPath $logFile
                    try {
                        $rawCertificate = [Convert]::FromBase64String($certificateb64)
                        $X509certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate)
                        Write-Host "Adding the provided certificate to the existing application"
                        "Adding the provided certificate to the existing application" | Write-Log -LogPath $logFile
                        $keyCreds = @{ 
                            Type = "AsymmetricX509Cert";
                            Usage = "Verify";
                            key = $rawCertificate;
                            startDateTime = $X509certificate.NotBefore;
                            endDateTime = $X509certificate.NotAfter;
                            displayName = $(New-Guid).Guid;
                        }
                        $alreadyExistingAppCheck.KeyCredentials += $keyCreds
                        Update-MgApplication -ApplicationId $alreadyExistingAppCheck.Id -KeyCredentials $alreadyExistingAppCheck.KeyCredentials
                    }
                    catch {
                        Write-Warning "Error loading and adding the new certificate. - $($_.Exception.Message)"
                        "Error loading and adding the new certificate. - $($_.Exception.Message)" | Write-Log -LogPath $logFile -LogLevel Warning
                    }
                }
                else {
                    Write-Warning "Not adding the provided certificate to the existing application"
                    "Not adding the provided certificate to the existing application" | Write-Log -LogPath $logFile -LogLevel Warning
                }
            }
            $alreadyExistingServicePrincipalCheck = Get-MgServicePrincipal -ErrorAction Stop | Where-Object { $_.DisplayName.StartsWith("LogCollectionDFIRO365RC_") }
            if ($alreadyExistingServicePrincipalCheck){
                if ($alreadyExistingServicePrincipalCheck.length -gt 1){
                    Write-Warning $alreadyExistingServicePrincipalCheck.length + " LogCollectionDFIRO365RC_ service principals are present. Please delete all but one existing service principals"
                    $alreadyExistingServicePrincipalCheck.length + " LogCollectionDFIRO365RC_ service principals are present" | Write-Log -LogPath $logFile -LogLevel Warning
                }
                else {
                    if ($subscriptions){
                        Add-SubscriptionPermissions -servicePrincipalId $alreadyExistingServicePrincipalCheck.Id -logFile $logFile
                    }
                    if ($organizations){
                        Add-OrganizationPermissions -servicePrincipalId $alreadyExistingServicePrincipalCheck.Id -logFile $logFile
                    }
                }
            }
        }
    }
    else {
        Write-Error "No application was found. Please call New-Application to create an application instead"
        "No application was found. Please call New-Application to create an application instead" | Write-Log -LogPath $logFile -LogLevel Error
    }
}

function New-Application {

    <#
    .SYNOPSIS
    The New-Application function will create an application in Entra ID and corresponding service principals in Entra ID and Exchange Online, with the right permissions. This will be used to do the log collection.
    The function will take as an input a base64 (public) certificate to import into the application.
    The "-organizations" switch will allow the application to collect logs from Azure DevOps organizations.
    The "-subscriptions" switch will allow the application to collect logs from Azure Resource Manager subscriptions.

    .EXAMPLE

    PS C:\>$certificateb64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("example.der"))
    PS C:\>New-Application -certificateb64 $certificateb64
    Create an application with the required permissions, with a certificate ("example.der").

    PS C:\>$certificateb64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("example.der"))
    PS C:\>New-Application -certificateb64 $certificateb64 -organizations -subscriptions
    Create an application with the required permissions, with a certificate ("example.der") and access to Azure DevOps organizations and Azure Resource Manager subscriptions.
    #>
    
    param (
        [Parameter(Mandatory = $true)]
        [String]$certificateb64,
        [Parameter(Mandatory = $false)]
        [Switch]$subscriptions,
        [Parameter(Mandatory = $false)]
        [Switch]$organizations,
        [String]$logFile = "New-Application.log"
    )

    $currentPath = (Get-Location).path
    $logFile = $currentPath + "\" + $logFile
    $applicationName = "LogCollectionDFIRO365RC_" + $(New-Guid).Guid

    Connect-MicrosoftGraphUser -logFile $logFile

    $tenantPrincipalDomain = (Get-MgDomain | Where-Object { $_.Isdefault -eq $True }).Id

    Write-Host "Check for already existing DFIR-O365 applications"
    "Check for already existing CF66J756VDFIR-O365 applications" | Write-Log -LogPath $logFile
    $alreadyExistingCheck = Get-MgApplication -Filter "startswith(DisplayName,'LogCollectionDFIRO365RC_')" -ErrorAction Stop
    if ($alreadyExistingCheck){
        Write-Error "A LogCollectionDFIRO365RC_* application already exists. Please call Update-Application instead"
        "A LogCollectionDFIRO365RC_* application already exists. Please call Update-Application instead" | Write-Log -LogPath $logFile -LogLevel Error
    }
    else {
        "Getting Entra ID permission 'Exchange.ManageAsApp' for 'Office 365 Exchange Online'" | Write-Log -LogPath $logFile
        $exchangeApi = (Get-MgServicePrincipal -Filter "AppID eq '00000002-0000-0ff1-ce00-000000000000'" -ErrorAction Stop)
        $exchangeManageAsAppPermission = $exchangeApi.AppRoles | Where-Object { $_.Value -eq 'Exchange.ManageAsApp' }
        $exchangeRequiredAccess = @{
            ResourceAppId = $exchangeApi.AppId ;
            ResourceAccess = @(
                @{
                    Id = $exchangeManageAsAppPermission.Id ;
                    Type = "Role"
                }
            )
        }

        if ($null -eq $exchangeApi){
            Write-Warning "Application 'Office 365 Exchange Online' could not be found in your tenant. You won't be able to use the Get-O365' functions"
            "Application 'Office 365 Exchange Online' could not be found in your tenant. You won't be able to use the Get-O365' functions" | Write-Log -LogPath $logFile -LogLevel Warning
        }

        $graphRequiredAccess = Get-EntraIDPermissions -logFile $logFile

        Write-Host "Creating application $applicationName with the required permissions"
        "Creating application $applicationName with the required permissions" | Write-Log -LogPath $logFile
        if ($null -eq $exchangeApi){
            if ($null -ne $graphRequiredAccess){
                $myApp = New-MgApplication -DisplayName $applicationName -RequiredResourceAccess $graphRequiredAccess -ErrorAction Stop
            }
            else {
                $myApp = New-MgApplication -DisplayName $applicationName -ErrorAction Stop
            }
        }
        else {
            if ($null -ne $graphRequiredAccess){
                $myApp = New-MgApplication -DisplayName $applicationName -RequiredResourceAccess $exchangeRequiredAccess,$graphRequiredAccess -ErrorAction Stop
            }
            else {
                $myApp = New-MgApplication -DisplayName $applicationName -RequiredResourceAccess $exchangeRequiredAccess -ErrorAction Stop
            }
        }

        "Creating service principal" | Write-Log -LogPath $logFile
        $mySP = New-MgServicePrincipal -AppId $myApp.AppID -ErrorAction Stop

        Write-Host "Loading the certificate"
        "Loading the certificate" | Write-Log -LogPath $logFile
        try {
            $rawCertificate = [Convert]::FromBase64String($certificateb64)
            $X509certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate)
            Write-Host "Adding credentials to the application"
            "Adding credentials to the application" | Write-Log -LogPath $logFile
            $keyCreds = @{ 
                Type = "AsymmetricX509Cert";
                Usage = "Verify";
                key = $rawCertificate;
                startDateTime = $X509certificate.NotBefore;
                endDateTime = $X509certificate.NotAfter;
                displayName = $(New-Guid).Guid;
            }
            Update-MgApplication -ApplicationId $myApp.Id -KeyCredentials $keyCreds
        }
        catch {
            Write-Warning "Error loading and adding the certificate. The application will be created, but you will need to call Update-Certificate to add the certificate to the application (or do it using the GUI). - $($_.Exception.Message)"
            "Error loading and adding the certificate. The application will be created, but you will need to call Update-Certificate to add the certificate to the application (or do it using the GUI). - $($_.Exception.Message)" | Write-Log -LogPath $logFile -LogLevel Warning
        }

        Wait-AdminConsent -appId $myApp.AppId -servicePrincipalId $mySP.Id -logFile $logFile

        if ($subscriptions){
            Add-SubscriptionPermissions -servicePrincipalId $mySP.Id -logFile $logFile
        }

        if ($organizations){
            Add-OrganizationPermissions -servicePrincipalId $mySP.Id -logFile $logFile
        }

        Connect-ExchangeOnlineUser -logFile $logFile

        try {
            $exoSP = New-ServicePrincipal -AppId $myApp.AppId -ObjectId $mySP.Id -DisplayName $applicationName -ErrorAction Stop
        }
        catch {
            $_.Exception.Message | Write-Log -LogPath $logFile -LogLevel Error
            Write-Warning "Can't create Service Principal in Exchange Online. Please check that you have access to Exchange Online using PowerShell. You won't be able to use Get-O365' functions. Exiting"
            "Can't create Service Principal in Exchange Online. Please check that you have access to Exchange Online using PowerShell. You won't be able to use Get-O365' functions. Exiting" | Write-Log -LogPath $logFile -LogLevel Warning
            Write-Host "Done creating the application with some of the required permissions"
            Write-Host "Please use the following identifiers: "
            Write-Warning "AppID: $($myApp.AppID)"
            "AppID: $($myApp.AppID)" | Write-Log -LogPath $logFile
            Write-Warning "Tenant: $tenantPrincipalDomain"
            "Tenant: $tenantPrincipalDomain" | Write-Log -LogPath $logFile
            exit
        }
        $roleGroupName = $applicationName + "_RG"
        try {
            $null = New-RoleGroup -Name $roleGroupName -Roles "View-only audit logs" -Members $exoSP.Id -ErrorAction Stop
            Write-Host "Done creating the application with the required permissions"
            Write-Host "Please use the following identifiers: "
            Write-Warning "AppID: $($myApp.AppID)"
            "AppID: $($myApp.AppID)" | Write-Log -LogPath $logFile
            Write-Warning "Tenant: $tenantPrincipalDomain"
            "Tenant: $tenantPrincipalDomain" | Write-Log -LogPath $logFile
        }
        catch {
            $_.Exception.Message | Write-Log -LogPath $logFile -LogLevel Error
            Write-Warning "Organization Customization was not enabled on this tenant. Enabling it"
            "Organization Customization was not enabled on this tenant. Enabling it" | Write-Log -LogPath $logFile -LogLevel Warning
            Enable-OrganizationCustomization
            Write-Warning "Organization Customization was enabled. It may take up to 4 hours before being propagated. When it is propagated, please call Remove-Application and New-Application again"
        }
    }
}

function Remove-Application {

    <#
    .SYNOPSIS
    The Remove-Application function will delete every application, service principal and role groups which were created in Entra ID and Exchange Online for DFIR-O365RC.
    The "-organizations" switch will delete the application from Azure DevOps organizations.
    The "-subscriptions" switch will delete the application from Azure Resource Manager subscriptions.

    .EXAMPLE
    
    PS C:\>Remove-Application
    Deletes every application, service principal and role groups which were created in Entra ID and Exchange Online for DFIR-O365RC.

    PS C:\>Remove-Application -organizations -subscriptions
    Deletes every application, service principal and role groups which were created in Entra ID, Exchange Online, Azure DevOps organizations and Azure Resource Manager subscriptions for DFIR-O365RC.

    #>
    
    param (
        [Parameter(Mandatory = $false)]
        [Switch]$subscriptions,
        [Parameter(Mandatory = $false)]
        [Switch]$organizations,
        [String]$logFile = "Remove-Application.log"
    )

    $currentPath = (Get-Location).path
    $logFile = $currentPath + "\" + $logFile

    Connect-MicrosoftGraphUser -logFile $logFile

    Write-Host "Check for already existing DFIR-O365 applications"
    "Check for already existing DFIR-O365 applications" | Write-Log -LogPath $logFile
    $alreadyExistingCheck = Get-MgApplication -Filter "startswith(DisplayName,'LogCollectionDFIRO365RC_')" -ErrorAction Stop
    if ($alreadyExistingCheck){
        if ($alreadyExistingCheck.length -gt 1){
            foreach ($application in $alreadyExistingCheck){
                Write-Host "Removing application: $($application.DisplayName)"
                "Removing application: $($application.DisplayName)" | Write-Log -LogPath $logFile
                $confirmation = Read-Host "Continue ? [y/N]"
                if ($confirmation.ToUpper() -eq "Y"){
                    Remove-MgApplication -ApplicationId $application.Id -Confirm:$false
                }
            }
        }
        else {
            Write-Host "Removing application: $($alreadyExistingCheck.DisplayName)"
            "Removing application: $($alreadyExistingCheck.DisplayName)" | Write-Log -LogPath $logFile
            $confirmation = Read-Host "Continue ? [y/N]"
            if ($confirmation.ToUpper() -eq "Y"){
                Remove-MgApplication -ApplicationId $alreadyExistingCheck.Id -Confirm:$false
            }
        }
    }

    if ($subscriptions -or $organizations){
        Write-Warning "Please log in to Entra ID using a privileged account which has access to the targeted subscriptions / organizations"
        Connect-AzUser -logFile $logFile
        if ($subscriptions){
            Write-Host "Check for already existing DFIR-O365 Entra ID role assignments for role LogCollectionDFIRO365RC"
            "Check for already existing DFIR-O365 Entra ID role assignments for role LogCollectionDFIRO365RC" | Write-Log -LogPath $logFile
            try {
                $alreadyExistingCheckRoleAssignement = Get-AzRoleAssignment -RoleDefinitionName "LogCollectionDFIRO365RC" -ErrorAction Stop
            }
            catch {
                $errorMessage = $_.Exception.Message
                if ($errormessage -like "*No subscription was found in the default profile*"){
                    Write-Warning "No subsriptions were found"
                    "No subsriptions were found" | Write-Log -LogPath $logFile -LogLevel Warning
                }
                else {
                    Write-Error $errorMessage
                    $errorMessage | Write-Log -LogPath $logFile -LogLevel Error
                }
                $alreadyExistingCheckRoleAssignement = $null
            }
            if ($alreadyExistingCheckRoleAssignement){
                if ($alreadyExistingCheckRoleAssignement.length -gt 1){
                    foreach ($roleAssignement in $alreadyExistingCheckRoleAssignement){
                        Write-Host "Removing LogCollectionDFIRO365RC role assignement for object ID: $($roleAssignement.ObjectId)"
                        "Removing LogCollectionDFIRO365RC role assignement for object ID: $($roleAssignement.ObjectId)" | Write-Log -LogPath $logFile
                        $confirmation = Read-Host "Continue ? [y/N]"
                        if ($confirmation.ToUpper() -eq "Y"){
                            Remove-AzRoleAssignment -RoleDefinitionName "LogCollectionDFIRO365RC" -ObjectId $roleAssignement.ObjectId
                        }
                    }
                }
                else {
                    Write-Host "Removing LogCollectionDFIRO365RC role assignement for object ID: $($alreadyExistingCheckRoleAssignement.ObjectId)"
                    "Removing LogCollectionDFIRO365RC  role assignement for object ID: $($alreadyExistingCheckRoleAssignement.ObjectId)" | Write-Log -LogPath $logFile           
                    $confirmation = Read-Host "Continue ? [y/N]"
                    if ($confirmation.ToUpper() -eq "Y"){
                        Remove-AzRoleAssignment -RoleDefinitionName "LogCollectionDFIRO365RC" -ObjectId $alreadyExistingCheckRoleAssignement.ObjectId
                    }
                }
            }
        
            Write-Host "Check for already existing DFIR-O365 Entra ID role definitions"
            "Check for already existing DFIR-O365 Entra ID role definitions" | Write-Log -LogPath $logFile
            try {
                $alreadyExistingCheckRoleDefinition = Get-AzRoleDefinition -Name "LogCollectionDFIRO365RC" -ErrorAction Stop -WarningAction:SilentlyContinue
            }
            catch {
                $errorMessage = $_.Exception.Message
                if ($errormessage -like "No subscription was found in the default profile*"){
                    Write-Warning "No subsriptions were found"
                    "No subsriptions were found" | Write-Log -LogPath $logFile -LogLevel Warning
                }
                else {
                    Write-Error $errorMessage
                    $errorMessage | Write-Log -LogPath $logFile -LogLevel Error
                }
                $alreadyExistingCheckRoleDefinition = $null
            }

            if ($alreadyExistingCheckRoleDefinition){
                if ($alreadyExistingCheckRoleDefinition.length -gt 1){
                    foreach ($roleDefinition in $alreadyExistingCheckRoleDefinition){
                        Write-Host "Removing role definition LogCollectionDFIRO365RC, ID: $($roleDefinition.Id)"
                        "Removing role definition LogCollectionDFIRO365RC, ID: $($roleDefinition.Id)" | Write-Log -LogPath $logFile
                        $confirmation = Read-Host "Continue ? [y/N]"
                        if ($confirmation.ToUpper() -eq "Y"){
                            Remove-AzRoleDefinition -Id $roleDefinition.Id -Confirm:$false -Force
                        }
                    }
                }
                else {
                    Write-Host "Removing role definition LogCollectionDFIRO365RC, ID: $($alreadyExistingCheckRoleDefinition.Id)"
                    "Removing role definition LogCollectionDFIRO365RC, ID: $($alreadyExistingCheckRoleDefinition.Id)" | Write-Log -LogPath $logFile
                    $confirmation = Read-Host "Continue ? [y/N]"
                    if ($confirmation.ToUpper() -eq "Y"){
                        Remove-AzRoleDefinition -Id $alreadyExistingCheckRoleDefinition.Id -Confirm:$false -Force
                    }
                }
            }
        }

        if ($organizations){
            Write-Host "Check for already existing DFIR-O365 service principals in DevOps organizations"
            "Check for already existing DFIR-O365 service principals in DevOps organizations" | Write-Log -LogPath $logFile
            $token = Get-AzAccessToken -ResourceUrl "499b84ac-1321-427f-aa17-267ca6975798" -AsSecureString:$false -ErrorAction Stop
            $tenantId = (Get-AzTenant).Id
            $azureDevOpsOrganizationsRaw = Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.Token)"} -Method Get -ContentType "application/json" -ErrorAction Stop -Uri "https://aexprodweu1.vsaex.visualstudio.com/_apis/EnterpriseCatalog/Organizations?tenantId=$tenantId"
            if ($null -ne $azureDevOpsOrganizationsRaw){
                $azureDevOpsOrganizationsNameAndId = $azureDevOpsOrganizationsRaw | ConvertFrom-CSV | ForEach-Object {$_ | Select-Object "Organization Name", "Organization Id"}
                foreach ($organization in $azureDevOpsOrganizationsNameAndId){
                    $organizationName = $organization.'Organization Name'
                    Write-Host "Checking presence of DFIR-O365RC Service Principals in $organizationName ($($organization.'Organization Id')) Azure DevOps organization"
                    "Checking presence of DFIR-O365RC Service Principals in $organizationName ($($organization.'Organization Id')) Azure DevOps organization" | Write-Log -LogPath $logFile
                    $servicePrincipals = Get-AzDevOpsRestAPIResponseUser -uri "https://vssps.dev.azure.com/$organizationName/_apis/graph/serviceprincipals?api-version=7.1-preview.1" -logFile $logFile
                    $servicePrincipalsToDelete = $servicePrincipals | Where-Object {$_.displayName -like "LogCollectionDFIRO365RC_*"}
                    foreach ($servicePrincipalToDelete in $servicePrincipalsToDelete){
                        $storageKey = Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.Token)"} -Method GET -uri "https://vssps.dev.azure.com/$organizationName/_apis/graph/storagekeys/$($servicePrincipalToDelete.descriptor)?api-version=7.1-preview.1" -ErrorAction Stop
                        Write-Host "Deleting $($servicePrincipalToDelete.displayName) in $organizationName"
                        "Deleting $($servicePrincipalToDelete.displayName) in $organizationName" | Write-Log -LogPath $logFile
                        $confirmation = Read-Host "Continue ? [y/N]"
                        if ($confirmation.ToUpper() -eq "Y"){
                            $null = Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.Token)"} -Method DELETE -Uri "https://vsaex.dev.azure.com/$organizationName/_apis/serviceprincipalentitlements/$($storageKey.value)?api-version=7.1-preview.1" -ErrorAction Stop
                        }
                    }
                }
            }
            else {
                Write-Error "Error while fetching Azure DevOps Organizations"
                "Error while fetching Azure DevOps Organizations" | Write-Log -LogPath $logFile -LogLevel "ERROR"
            }
        }
    }

    Connect-ExchangeOnlineUser -logFile $logFile
    
    Write-Host "Check for already existing DFIR-O365 service principals in Exchange Online"
    "Check for already existing DFIR-O365 service principals in Exchange Online" | Write-Log -LogPath $logFile
    $alreadyExistingCheck = Get-ServicePrincipal -ErrorAction Stop | Where-Object { $_.DisplayName.StartsWith("LogCollectionDFIRO365RC_") }
    if ($alreadyExistingCheck){
        if ($alreadyExistingCheck.length -gt 1){
            foreach ($servicePrincipal in $alreadyExistingCheck){
                Write-Host "Removing service principal: $($servicePrincipal.DisplayName)"
                "Removing service principal: $($servicePrincipal.DisplayName)" | Write-Log -LogPath $logFile
                $confirmation = Read-Host "Continue ? [y/N]"
                if ($confirmation.ToUpper() -eq "Y"){
                    Remove-ServicePrincipal -Id $servicePrincipal.ObjectId -Confirm:$false
                }
            }
        }
        else {
            Write-Host "Removing service principal: $($alreadyExistingCheck.DisplayName)"
            "Removing service principal: $($alreadyExistingCheck.DisplayName)" | Write-Log -LogPath $logFile
            $confirmation = Read-Host "Continue ? [y/N]"
            if ($confirmation.ToUpper() -eq "Y"){
                Remove-ServicePrincipal -Id $alreadyExistingCheck.ObjectId -Confirm:$false
            }
        }
    }

    Write-Host "Check for already existing DFIR-O365 role groups in Exchange Online"
    "Check for already existing DFIR-O365 role groups in Exchange Online" | Write-Log -LogPath $logFile
    $alreadyExistingCheck = Get-RoleGroup | Where-Object { $_.Name.StartsWith("LogCollectionDFIRO365RC_") }
    if ($alreadyExistingCheck){
        if ($alreadyExistingCheck.length -gt 1){
            foreach ($roleGroup in $alreadyExistingCheck){
                Write-Host "Removing role group: $($roleGroup.Name)"
                "Removing role group: $($roleGroup.Name)" | Write-Log -LogPath $logFile
                $confirmation = Read-Host "Continue ? [y/N]"
                if ($confirmation.ToUpper() -eq "Y"){
                    Remove-RoleGroup -Identity $roleGroup.Identity -Confirm:$false
                }
            }
        }
        else {
            Write-Host "Removing role group: $($alreadyExistingCheck.Name)"
            "Removing role group: $($alreadyExistingCheck.Name)" | Write-Log -LogPath $logFile
            $confirmation = Read-Host "Continue ? [y/N]"
            if ($confirmation.ToUpper() -eq "Y"){
                Remove-RoleGroup -Identity $alreadyExistingCheck.Identity -Confirm:$false
            }
        }
    }
}