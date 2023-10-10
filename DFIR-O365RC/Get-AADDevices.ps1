Function Get-AADDevices {

    <#
    .SYNOPSIS
    The Get-AADApps function dumps in JSON files Azure AD devices related events for a specific time range and enriches the object with the device configuration.

    .EXAMPLE
    
    PS C:\>$enddate = get-date
    PS C:\>$startdate = $enddate.adddays(-30)

    PS C:\>Get-AADDevices -startdate $startdate -enddate $enddate

    Dump all Azure AD devices related events.

    #>
    
    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$Enddate,
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDate,
        [Parameter(Mandatory = $false)]
        [boolean]$Allevents=$true,
        [Parameter(Mandatory = $false)]
        [boolean]$DeviceCode=$false,
        [Parameter(Mandatory = $false)]
        [String]$logfile = "Get-AADDevices.log"
    )
    $currentpath = (get-location).path

    $logfile = $currentpath + "\" +  $logfile
    "Getting MSGraph Oauth token"  | Write-Log -LogPath $logfile
    Clear-MsalTokenCache
    $token = Get-OAuthToken -Service MSGraph -Logfile $logfile -DeviceCode $DeviceCode
    $user = $token.Account.UserName
    $tenant = ($user).split("@")[1]
    $foldertoprocess = $currentpath + '\azure_ad_devices'
    if ((Test-Path $foldertoprocess) -eq $false){New-Item $foldertoprocess -Type Directory | Out-Null}
    $outputfile = $foldertoprocess + "\AADDevices_" + $tenant + ".json"
    

    # Get devices related events
    
    $Auditstart = "{0:s}" -f $StartDate + "Z"
    $Auditend = "{0:s}" -f $Enddate + "Z"
    if($Allevents -eq $false)
        {
            "Getting all important device related events via auditlog"   | Write-Log -LogPath $logfile 
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=(activityDisplayName eq 'Add device' or activityDisplayName eq 'Device no longer compliant' or activityDisplayName eq 'Add registered users to device' or activityDisplayName eq 'Add registered owner to device' or activityDisplayName eq 'Delete device' or activityDisplayName eq 'Device no longer managed' or activityDisplayName eq 'Remove registered users from device' or activityDisplayName eq 'Remove registered owner from device') and activityDateTime gt $($Auditstart) and activityDateTime lt $($Auditend)"
        }
    else {
        "Getting all device related events via auditlog"   | Write-Log -LogPath $logfile 
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=(activityDisplayName eq 'Add device' or activityDisplayName eq 'Device no longer compliant' or activityDisplayName eq 'Add registered users to device' or activityDisplayName eq 'Add registered owner to device' or activityDisplayName eq 'Delete device' or activityDisplayName eq 'Device no longer managed' or activityDisplayName eq 'Remove registered users from device' or activityDisplayName eq 'Remove registered owner from device' or activityDisplayName eq 'Update device') and activityDateTime gt $($Auditstart) and activityDateTime lt $($Auditend)"
        
    }
    $app = Get-MsalClientApplication | Where-Object{$_.ClientId -eq "1b730954-1685-4b74-9bfd-dac224a7b894"}
    $DeviceEvents = Get-RestAPIResponse -RESTAPIService "MSGraph" -uri $uri  -logfile $logfile -app $app -user $user
    
    #Get all Service Principals
    "Getting all devices"   | Write-Log -LogPath $logfile 
    $uriSP = "https://graph.microsoft.com/v1.0/devices"
    $ALLDevices = Get-RestAPIResponse -RESTAPIService "MSGraph" -uri $uriSP  -logfile $logfile -app $app -user $user
    $nbALLDevices = ($ALLDevices | Measure-Object).count
    "Total number of devices in tenant is $($nbALLDevices)"   | Write-Log -LogPath $logfile  
    
    $EnrichedDeviceEvents = @()
    $UniqDevices = $DeviceEvents | Select-Object -ExpandProperty targetResources | Group-Object -Property id
    #Loop through devices in activity logs
    foreach($UniqDevice in $UniqDevices)
        {
        
        #Get Service Principal object
        $DeviceObject =  $ALLDevices | where-object {$_.id -eq $UniqDevice.Name}
        $EventsperDevice = $DeviceEvents | where-object { $_.targetResources.id -eq $UniqDevice.Name}
        
        if($DeviceObject)
        {
        "Get owners and users for $($UniqDevice.Name) device"    | Write-Log -LogPath $logfile 
        $uriOwners = "https://graph.microsoft.com/v1.0/devices/$($UniqDevice.Name)/registeredOwners/" 
        $DeviceOwners = Get-RestAPIResponse -RESTAPIService "MSGraph" -uri $uriOwners   -logfile $logfile -app $app -user $user
        $owners = (($DeviceOwners | Group-Object -Property userPrincipalName).Name) -join ","
        $olanguage = (($DeviceOwners | Group-Object -Property preferredLanguage).Name) -join ","

        $uriUsers = "https://graph.microsoft.com/v1.0/devices/$($UniqDevice.Name)/registeredUsers/" 
        $DeviceUsers = Get-RestAPIResponse -RESTAPIService "MSGraph" -uri $uriUsers   -logfile $logfile -app $app -user $user
        $users = (($DeviceUsers | Group-Object -Property userPrincipalName).Name) -join ","
        $ulanguage = (($DeviceUsers | Group-Object -Property preferredLanguage).Name) -join ","

        $EventsperDevice  |  add-member -MemberType NoteProperty -Name deviceowners -Value $owners  -force
        $EventsperDevice  |  add-member -MemberType NoteProperty -Name owners_language -Value $olanguage  -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name deviceusers -Value $users -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name users_language -Value $ulanguage -force

        $EventsperDevice |  add-member -MemberType NoteProperty -Name deletedDateTime -Value $DeviceObject.deletedDateTime -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name accountEnabled -Value $DeviceObject.accountEnabled -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name approximateLastSignInDateTime -Value $DeviceObject.approximateLastSignInDateTime -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name complianceExpirationDateTime -Value $DeviceObject.complianceExpirationDateTime -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name createdDateTime -Value $DeviceObject.createdDateTime -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name deviceMetadata -Value $DeviceObject.deviceMetadata -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name deviceVersion -Value $DeviceObject.deviceVersion -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name displayName -Value $DeviceObject.displayName -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name extensionAttributes -Value $DeviceObject.extensionAttributes -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name externalSourceName -Value $DeviceObject.externalSourceName -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name isCompliant -Value $DeviceObject.isCompliant -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name isManaged -Value $DeviceObject.isManaged -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name manufacturer -Value $DeviceObject.manufacturer -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name mdmAppId -Value $DeviceObject.mdmAppId -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name model -Value $DeviceObject.model -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name onPremisesLastSyncDateTime -Value $DeviceObject.onPremisesLastSyncDateTime -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name onPremisesSyncEnabled -Value $DeviceObject.onPremisesSyncEnabled -force      
        $EventsperDevice |  add-member -MemberType NoteProperty -Name operatingSystem -Value $DeviceObject.operatingSystem -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name physicalIds -Value $DeviceObject.physicalIds -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name profileType -Value $DeviceObject.profileType -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name sourceType -Value $DeviceObject.sourceType -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name systemLabels -Value $DeviceObject.systemLabels -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name trustType -Value $DeviceObject.trustType -force
        $EventsperDevice |  add-member -MemberType NoteProperty -Name alternativeSecurityIds -Value $DeviceObject.alternativeSecurityIds -force
        $EnrichedDeviceEvents += $EventsperDevice
        }
    
        else{
            "The device $($UniqDevice.Name) does not exist in the tenant"   | Write-Log -LogPath $logfile 
    
    
            $EventsperDevice |  add-member -MemberType NoteProperty -Name appId -Value "NotAvailable"  -force
            $EventsperDevice  |  add-member -MemberType NoteProperty -Name deviceowners -Value "NotAvailable"  -force
            $EventsperDevice  |  add-member -MemberType NoteProperty -Name owners_language -Value "NotAvailable"  -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name deviceusers -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name users_language -Value "NotAvailable" -force
    
            $EventsperDevice |  add-member -MemberType NoteProperty -Name deletedDateTime -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name accountEnabled -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name approximateLastSignInDateTime -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name complianceExpirationDateTime -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name createdDateTime -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name deviceMetadata -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name deviceVersion -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name displayName -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name extensionAttributes -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name externalSourceName -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name isCompliant -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name isManaged -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name manufacturer -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name mdmAppId -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name model -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name onPremisesLastSyncDateTime -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name onPremisesSyncEnabled -Value "NotAvailable" -force      
            $EventsperDevice |  add-member -MemberType NoteProperty -Name operatingSystem -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name physicalIds -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name profileType -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name sourceType -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name systemLabels -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name trustType -Value "NotAvailable" -force
            $EventsperDevice |  add-member -MemberType NoteProperty -Name alternativeSecurityIds -Value "NotAvailable" -force
            
    
            $EnrichedDeviceEvents += $EventsperDevice
            }    
 
    }

   
   
    $nbEnrichedDeviceEvents = ($EnrichedDeviceEvents | Measure-Object).count
    
    "Dumping $($nbEnrichedDeviceEvents) enriched  events to $($outputfile)"   | Write-Log -LogPath $logfile  
    
    $EnrichedDeviceEvents | ConvertTo-Json -Depth 99 |  out-file $outputfile -encoding UTF8 
}
