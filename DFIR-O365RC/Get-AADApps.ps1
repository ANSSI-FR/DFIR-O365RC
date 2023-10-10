Function Get-AADApps {

    <#
    .SYNOPSIS
    The Get-AADApps function dumps in JSON files Azure AD applications and Service Principals related events for a specific time range and enriches the object with the application or service principal configuration.

    .EXAMPLE
    
    PS C:\>$enddate = get-date
    PS C:\>$startdate = $enddate.adddays(-30)

    PS C:\>Get-AADApps -startdate $startdate -enddate $enddate

    Dump all Azure AD applications and Service Principals related events.

    #>
    
    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$Enddate,
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDate,
        [Parameter(Mandatory = $false)]
        [boolean]$DeviceCode=$false,
        [Parameter(Mandatory = $false)]
        [String]$logfile = "Get-AADApps.log"
    )
    $currentpath = (get-location).path

    $logfile = $currentpath + "\" +  $logfile
    "Getting MSGraph Oauth token"  | Write-Log -LogPath $logfile
    Clear-MsalTokenCache
    $token = Get-OAuthToken -Service MSGraph -Logfile $logfile -DeviceCode $DeviceCode
    $user = $token.Account.UserName
    $tenant = ($user).split("@")[1]
    $foldertoprocess = $currentpath + '\azure_ad_apps'
    if ((Test-Path $foldertoprocess) -eq $false){New-Item $foldertoprocess -Type Directory | Out-Null}
    $outputfile = $foldertoprocess + "\AADApps_" + $tenant + ".json"
    

    # Get Service Principal related events
    "Getting all Service principal related events via auditlog"   | Write-Log -LogPath $logfile 
    $Auditstart = "{0:s}" -f $StartDate + "Z"
    $Auditend = "{0:s}" -f $Enddate + "Z"
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=(activityDisplayName eq 'Consent to application' or activityDisplayName eq 'Add app role assignment to service principal' or activityDisplayName eq 'Add delegated permission grant' or activityDisplayName eq 'Add service principal credentials' or activityDisplayName eq 'Add service principal' or activityDisplayName eq 'Add OAuth2PermissionGrant') and activityDateTime gt $($Auditstart) and activityDateTime lt $($Auditend)"
    $app = Get-MsalClientApplication | Where-Object{$_.ClientId -eq "1b730954-1685-4b74-9bfd-dac224a7b894"}
    $SPEvents = Get-RestAPIResponse -RESTAPIService "MSGraph" -uri $uri  -logfile $logfile -app $app -user $user
    
    #Get all Service Principals
    "Getting all service principals"   | Write-Log -LogPath $logfile 
    $uriSP = "https://graph.microsoft.com/v1.0/servicePrincipals/"
    $ALLServicePrincipals = Get-RestAPIResponse -RESTAPIService "MSGraph" -uri $uriSP  -logfile $logfile -app $app -user $user
    $sp_outputfile = $foldertoprocess + "\AADApps_" + $tenant + "_service_principals_raw.json"
    $ALLServicePrincipals | ConvertTo-Json -Depth 99 |  out-file $sp_outputfile -encoding UTF8 

    $EnrichedSPEvents = @()
    $UniqServicePrincipals = $SPEvents | Select-Object -ExpandProperty targetResources | Group-Object -Property id
    #Loop through Service Principals in activity logs
    foreach($ServicePrincipal in $UniqServicePrincipals)
        {
        
        #Get Service Principal object
        $SPObject =  $ALLServicePrincipals | where-object {$_.Id -eq $ServicePrincipal.Name}
        $EventsperSP = $SPEvents | where-object { $_.targetResources.id -eq $ServicePrincipal.Name}
        
        if($SPObject)
        {
        "Getting Oauth PermissionGrants for $($ServicePrincipal.Name) Service principal"   | Write-Log -LogPath $logfile 
        $uriOauth = "https://graph.microsoft.com/v1.0/servicePrincipals/$($ServicePrincipal.Name)/oauth2PermissionGrants/" 
        $SPOAuth = Get-RestAPIResponse -RESTAPIService "MSGraph" -uri $uriOauth   -logfile $logfile -app $app -user $user
        $delegatedconsentautorisations = (($SPOAuth | Group-Object -Property scope).Name) -join ","
        $delegatedconsentTypes = (($SPOAuth | Group-Object -Property consentType).Name) -join ","

        "Getting appRoleAssignments for $($ServicePrincipal.Name) Service principal"   | Write-Log -LogPath $logfile 
        $uriOauth = "https://graph.microsoft.com/v1.0/servicePrincipals/$($ServicePrincipal.Name)/appRoleAssignments/" 
        $SPOAuth = Get-RestAPIResponse -RESTAPIService "MSGraph" -uri $uriOauth   -logfile $logfile -app $app -user $user
        $appRoleIdAssignements = (($SPOAuth | Group-Object -Property appRoleId).Name) -join ","
       
        $EventsperSP  |  add-member -MemberType NoteProperty -Name appRoleIdAssignements -Value $appRoleIdAssignements  -force
        $EventsperSP  |  add-member -MemberType NoteProperty -Name delegatedconsentautorisations -Value $delegatedconsentautorisations  -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name delegatedconsentTypes -Value $delegatedconsentTypes -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name ServicePrincipalId -Value $SPObject.id -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name appDescription -Value $SPObject.appDescription  -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name verifiedPublisher -Value $SPObject.verifiedPublisher -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name accountEnabled -Value $SPObject.accountEnabled -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name appDisplayName -Value $SPObject.appDisplayName -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name appId -Value $SPObject.appId -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name appOwnerOrganizationId -Value $SPObject.appOwnerOrganizationId -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name createdDateTime -Value $SPObject.createdDateTime -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name homepage -Value $SPObject.homepage -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name loginUrl -Value $SPObject.loginUrl -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name replyUrls  -Value $SPObject.replyUrls  -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name addIns   -Value $SPObject.addIns   -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name appRoles  -Value $SPObject.appRoles   -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name info  -Value $SPObject.info  -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name oauth2PermissionScopes  -Value $SPObject.oauth2PermissionScopes -force

        $EnrichedSPEvents += $EventsperSP
        }
        #If operation such as consent fails ServicePrincipal is not created. Or Service Principal can be deleted after the operation...
        else{
        "The Service principal $($ServicePrincipal.Name) does not exist in the tenant, operation failed or Service Principal was deleted"   | Write-Log -LogPath $logfile 
        $EventsperSP  |  add-member -MemberType NoteProperty -Name appRoleIdAssignements -Value "NotAvailable"  -force
        $EventsperSP  |  add-member -MemberType NoteProperty -Name delegatedconsentautorisations -Value "NotAvailable"  -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name delegatedconsentTypes -Value "NotAvailable" -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name ServicePrincipalId -Value "NotAvailable" -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name appDescription -Value "NotAvailable"  -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name verifiedPublisher -Value "NotAvailable" -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name accountEnabled -Value "NotAvailable" -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name appDisplayName -Value "NotAvailable" -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name appId -Value "NotAvailable" -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name appOwnerOrganizationId -Value "NotAvailable" -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name createdDateTime -Value "NotAvailable" -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name homepage -Value "NotAvailable" -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name loginUrl -Value "NotAvailable" -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name replyUrls  -Value "NotAvailable"  -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name addIns   -Value "NotAvailable"   -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name appRoles  -Value "NotAvailable"   -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name info  -Value "NotAvailable"  -force
        $EventsperSP |  add-member -MemberType NoteProperty -Name oauth2PermissionScopes  -Value "NotAvailable" -force

        $EnrichedSPEvents += $EventsperSP


        }    
 
    }

   

    # Get Application related events
    "Getting all Application events via auditlog"   | Write-Log -LogPath $logfile 
    $Auditstart = "{0:s}" -f $StartDate + "Z"
    $Auditend = "{0:s}" -f $Enddate + "Z"
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=(activityDisplayName eq 'Add application' or startswith(activityDisplayName,'Update application')) and activityDateTime gt $($Auditstart) and activityDateTime lt $($Auditend)"
    $app = Get-MsalClientApplication | Where-Object{$_.ClientId -eq "1b730954-1685-4b74-9bfd-dac224a7b894"}
    $AppEvents = Get-RestAPIResponse -RESTAPIService "MSGraph" -uri $uri  -logfile $logfile -app $app -user $user
    
    #Get all Apps
    "Getting all Apps"   | Write-Log -LogPath $logfile 
    $uriAPP = "https://graph.microsoft.com/v1.0/applications/"
    $ALLApps = Get-RestAPIResponse -RESTAPIService "MSGraph" -uri $uriAPP  -logfile $logfile -app $app -user $user
    #Get all deleted Apps
    "Getting all deleted Apps"   | Write-Log -LogPath $logfile 
    $uriDelAPPs = "https://graph.microsoft.com/v1.0/directory/deleteditems/microsoft.graph.application"
    $DelApps = Get-RestAPIResponse -RESTAPIService "MSGraph" -uri $uriDelAPPs  -logfile $logfile -app $app -user $user
    #merge existing and deleted Apps
    $ALLApps += $DelApps

    $apps_outputfile = $foldertoprocess + "\AADApps_" + $tenant + "_applications_raw.json"
    $ALLApps | ConvertTo-Json -Depth 99 |  out-file $apps_outputfile -encoding UTF8 

    $EnrichedAppEvents = @()
    $UniqApps = $AppEvents| Select-Object -ExpandProperty targetResources | Group-Object -Property id
    #Loop through Apps present in activity logs

    foreach($UniqApp in $UniqApps)
        {
        
        #Get Service Principal object
        $AppObject =  $ALLApps | where-object {$_.Id -eq $UniqApp.Name}
        $EventsperApp = $AppEvents | where-object { $_.targetResources.id -eq $UniqApp.Name}
        
        if($AppObject)
        {

        $EventsperApp |  add-member -MemberType NoteProperty -Name appId -Value $AppObject.appId -force
        $EventsperApp |  add-member -MemberType NoteProperty -Name deletedDateTime -Value $AppObject.deletedDateTime -force
        $EventsperApp |  add-member -MemberType NoteProperty -Name applicationTemplateId -Value $AppObject.applicationTemplateId -force
        $EventsperApp |  add-member -MemberType NoteProperty -Name createdDateTime -Value $AppObject.createdDateTime -force
        $EventsperApp |  add-member -MemberType NoteProperty -Name appDisplayName -Value $AppObject.displayName -force
        $EventsperApp |  add-member -MemberType NoteProperty -Name appDescription -Value $AppObject.description -force
        $EventsperApp |  add-member -MemberType NoteProperty -Name groupMembershipClaims -Value $AppObject.groupMembershipClaims -force
        $EventsperApp |  add-member -MemberType NoteProperty -Name identifierUris -Value $AppObject.identifierUris -force       
        $EventsperApp |  add-member -MemberType NoteProperty -Name isDeviceOnlyAuthSupported -Value $AppObject.isDeviceOnlyAuthSupported -force   
        $EventsperApp |  add-member -MemberType NoteProperty -Name isFallbackPublicClient -Value $AppObject.isFallbackPublicClient -force   
        $EventsperApp |  add-member -MemberType NoteProperty -Name publisherDomain -Value $AppObject.publisherDomain -force     
        $EventsperApp |  add-member -MemberType NoteProperty -Name signInAudience -Value $AppObject.signInAudience -force            
        $EventsperApp |  add-member -MemberType NoteProperty -Name verifiedPublisher -Value $AppObject.verifiedPublisher -force         
        $EventsperApp |  add-member -MemberType NoteProperty -Name defaultRedirectUri -Value $AppObject.defaultRedirectUri -force       
        $EventsperApp |  add-member -MemberType NoteProperty -Name addIns -Value $AppObject.addIns -force        
        $EventsperApp |  add-member -MemberType NoteProperty -Name appRoles -Value $AppObject.appRoles -force            
        $EventsperApp |  add-member -MemberType NoteProperty -Name  info -Value $AppObject.info -force   
        $EventsperApp |  add-member -MemberType NoteProperty -Name keyCredentials -Value $AppObject.keyCredentials -force        
        $EventsperApp |  add-member -MemberType NoteProperty -Name optionalClaims -Value $AppObject.optionalClaims -force       
        $EventsperApp |  add-member -MemberType NoteProperty -Name passwordCredentials -Value $AppObject.passwordCredentials -force  
        $EventsperApp |  add-member -MemberType NoteProperty -Name publicClient -Value $AppObject.publicClient -force       
        $EventsperApp |  add-member -MemberType NoteProperty -Name requiredResourceAccess -Value $AppObject.requiredResourceAccess -force            
        $EventsperApp |  add-member -MemberType NoteProperty -Name web -Value $AppObject.web -force            
        
        $EnrichedAppEvents += $EventsperApp
        }
        
        else{
        "The App $($UniqApp.Name) does not exist in the tenant"   | Write-Log -LogPath $logfile 


        $EventsperApp |  add-member -MemberType NoteProperty -Name appId -Value "NotAvailable"  -force
        $EventsperApp |  add-member -MemberType NoteProperty -Name deletedDateTime -Value "NotAvailable"  -force
        $EventsperApp |  add-member -MemberType NoteProperty -Name applicationTemplateId -Value "NotAvailable"  -force
        $EventsperApp |  add-member -MemberType NoteProperty -Name createdDateTime -Value "NotAvailable"  -force
        $EventsperApp |  add-member -MemberType NoteProperty -Name appDisplayName -Value "NotAvailable"  -force
        $EventsperApp |  add-member -MemberType NoteProperty -Name appDescription -Value "NotAvailable"  -force
        $EventsperApp |  add-member -MemberType NoteProperty -Name groupMembershipClaims -Value "NotAvailable"  -force
        $EventsperApp |  add-member -MemberType NoteProperty -Name identifierUris -Value "NotAvailable"  -force       
        $EventsperApp |  add-member -MemberType NoteProperty -Name isDeviceOnlyAuthSupported -Value "NotAvailable"  -force   
        $EventsperApp |  add-member -MemberType NoteProperty -Name isFallbackPublicClient -Value "NotAvailable"  -force   
        $EventsperApp |  add-member -MemberType NoteProperty -Name publisherDomain -Value "NotAvailable"  -force     
        $EventsperApp |  add-member -MemberType NoteProperty -Name signInAudience -Value "NotAvailable"  -force            
        $EventsperApp |  add-member -MemberType NoteProperty -Name verifiedPublisher -Value "NotAvailable"  -force         
        $EventsperApp |  add-member -MemberType NoteProperty -Name defaultRedirectUri -Value "NotAvailable"  -force       
        $EventsperApp |  add-member -MemberType NoteProperty -Name addIns -Value "NotAvailable"  -force        
        $EventsperApp |  add-member -MemberType NoteProperty -Name appRoles -Value "NotAvailable"  -force            
        $EventsperApp |  add-member -MemberType NoteProperty -Name  info -Value "NotAvailable"  -force   
        $EventsperApp |  add-member -MemberType NoteProperty -Name keyCredentials -Value "NotAvailable"  -force        
        $EventsperApp |  add-member -MemberType NoteProperty -Name optionalClaims -Value "NotAvailable"  -force       
        $EventsperApp |  add-member -MemberType NoteProperty -Name passwordCredentials -Value "NotAvailable"  -force  
        $EventsperApp |  add-member -MemberType NoteProperty -Name publicClient -Value "NotAvailable"  -force       
        $EventsperApp |  add-member -MemberType NoteProperty -Name requiredResourceAccess -Value "NotAvailable"  -force            
        $EventsperApp |  add-member -MemberType NoteProperty -Name web -Value "NotAvailable"  -force   


        $EnrichedAppEvents += $EventsperApp
        }    
 
    }

   
    $nbEnrichedAppEvents = ($EnrichedAppEvents | Measure-Object).count
    "Collected $($nbEnrichedAppEvents) enriched Applications related events"   | Write-Log -LogPath $logfile 

    
    $nbEnrichedSPEvents = ($EnrichedSPEvents | Measure-Object).count
    "Collected $($nbEnrichedSPEvents) enriched Service principal related events"   | Write-Log -LogPath $logfile  
    $TotalEnrichedEvents = $nbEnrichedSPEvents + $nbEnrichedAppEvents
    "Dumping $($TotalEnrichedEvents) enriched  events to $($outputfile)"   | Write-Log -LogPath $logfile  
    
    @($EnrichedAppEvents; $EnrichedSPEvents) | ConvertTo-Json -Depth 99 |  out-file $outputfile -encoding UTF8 
}
