Function Get-O365Light {

    <#
    .SYNOPSIS
    The Get-O365Light function dumps in JSON files all or some operations set from a defined subset of the O365 Unified Audit Log for a specific time range.

    .EXAMPLE
    PS C:\>$enddate = get-date
    PS C:\>$startdate = $enddate.adddays(-90)

    PS C:\>Get-O365Light -startdate $startdate -enddate $enddate

    Dump all unified audit logs from the defined subset
    .EXAMPLE
    Get-O365Light -startdate $startdate -enddate $enddate -RecordSet "AzureADOnly" -logfile "UnifiedAzureADOnly.log"
    Dump AzureAD only operations since last week from the defined subset  and write log to UnifiedAzureADOnly.log
    #>
    
    param (

        [Parameter(Mandatory = $true)]
        [DateTime]$Enddate,
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDate,
        [Parameter(Mandatory = $false)]
        [ValidateSet("All","AllbutAzureAD","ExchangeOnly","OneDrive_Sharepoint_Teams_YammerOnly", "AzureADOnly", "SecurityAlerts")] 
        [String]$Operationsset = "All",
        [Parameter(Mandatory = $false)]
        [boolean]$MailboxLogin=$false,
        [Parameter(Mandatory = $false)]
        [boolean]$DeviceCode=$false,
        [Parameter(Mandatory = $false)]
        [String]$logfile = "Get-O365Light.log"
    )

    "Getting EXO Oauth token"  | Write-Log -LogPath $logfile
    Clear-MsalTokenCache
    $token = Get-OAuthToken -Service EXO -Logfile $logfile -DeviceCode $DeviceCode
    $user = $token.Account.UserName
    $currentpath = (get-location).path
    $o365existing = Get-PSSession | where-object{$_.ComputerName -eq "outlook.office365.com"}
    if($o365existing){
        "Detected existing EXO session - removing and sleeping for session tear down" | Write-Log -LogPath $logfile -LogLevel "Warning" 
        $o365existing | remove-pssession -confirm:$false
        start-sleep -seconds 15
    }

    $Alloperations= @()

    $myObject = [PSCustomObject]@{
        GroupName= "OneDrive_Sharepoint_Teams_Yammer";
        Operations = '"TeamsTenantSettingChanged", "TeamSettingChanged", "Set-CSTeamsAppPermissionPolicy", "New-CSTeamsAppPermissionPolicy", "AppInstalled","FileMalwareDetected", "SupervisorAdminToggled", "NetworkSecurityConfigurationUpdated",  "SoftDeleteSettingsUpdated", "SiteCollectionAdminAdded", "NetworkAccessPolicyChanged", "GeoAdminAdded", "SharingPolicyChanged", "DeviceAccessPolicyChanged", "AddedToGroup", "PermissionLevelModified", "AnonymousLinkCreated", "AnonymousLinkUsed","SharingInvitationAccepted" , "SharingInvitationBlocked" , "UnmanagedSyncClientBlocked", "MemberRoleChanged"'
    }

    $Alloperations += $myObject


    $myObject = [PSCustomObject]@{
        GroupName= "AzureAD";
        Operations = '"Register connector","Verify domain","Add verified domain","Remove verified domain","Disable Desktop Sso for a specific domain","Add application","Add app role assignment to service principal","Update application","Update application – Certificates and secrets management","Update application – Certificates and secrets management ","Add delegated permission grant","Add OAuth2PermissionGrant","Add unverified domain","Add group", "Add member to group", "Delete group", "Remove member from group", "Update group","Consent to application", "Add app role assignment grant to user", "Add delegation entry", "Add service principal", "Add service principal credentials", "Remove delegation entry", "Remove service principal", "Remove service principal credentials", "Set delegation entry", "Add member to role", "Remove member from role",  "Add app role assignment grant to user", "New-ConditionalAccessPolicy", "Set-AdminAuditLogConfig", "Set-ConditionalAccessPolicy", "Update domain", "Set federation settings on domain", "Set domain authentication", "Add partner to company", "Add domain to company"'
    }

    $Alloperations += $myObject

    if($MailboxLogin -eq $true)
    {
        
        Write-Host "Retrieving MailboxLogin operations, If mailbox auditing is enabled beware that you might exceed the threshold of 50.000 Exchange Online operations results per search" -ForegroundColor "Yellow" -BackgroundColor "Black"
        write-host  "Continue? (Y/N) "
        $response = read-host
        if ( $response -ne "Y" ) { exit }
        "Retrieving MailboxLogin operations, If mailbox auditing is enabled beware that you might exceed the threshold of 50.000 Exchange Online operations results per search" | Write-Log -LogPath $logfile -LogLevel "Warning"
        $myObject = [PSCustomObject]@{
        GroupName= "Exchange";
        Operations = '"Add-MailboxPermission", "AddFolderPermissions", "Add-RecipientPermission", "Remove-RecipientPermission", "New-InboxRule", "Set-InboxRule", "Set-TransportRule", "New-TransportRule", "Hard Delete user", "Remove-MailboxPermission", "RemoveFolderPermissions", "UpdateInboxRules", "Set-CASMailbox", "Set-Mailbox","SearchCreated", "SearchExported","MailboxLogin"'
        }
    }
    else 
    {
        $myObject = [PSCustomObject]@{
            GroupName= "Exchange";
            Operations = '"Add-MailboxPermission", "AddFolderPermissions", "Add-RecipientPermission", "Remove-RecipientPermission", "New-InboxRule", "Set-InboxRule", "Set-TransportRule", "New-TransportRule", "Hard Delete user", "Remove-MailboxPermission", "RemoveFolderPermissions", "UpdateInboxRules", "Set-CASMailbox", "Set-Mailbox","SearchCreated", "SearchExported"'
            }   
    }
    $Alloperations += $myObject

    $myObject = [PSCustomObject]@{
        GroupName= "SecurityAlerts";
        Operations = '"AlertEntityGenerated", "AlertTriggered"'
    }

    $Alloperations += $myObject

    if($Operationsset -eq "All")
    {
        $Operationstoprocess = $Alloperations
        "Fetching all operations from the subset, this is the default configuration" | Write-Log -LogPath $logfile   
    }
    Elseif($Operationsset -eq "AllbutAzureAD")
    {
        $Operationstoprocess =   $Alloperations | where-object{$_.GroupName -ne "AzureAD"}
        "Fetching all operations from the subset, except Azure AD related operations" | Write-Log -LogPath $logfile  
    }
    Elseif($Operationsset -eq "ExchangeOnly")
    {
        $Operationstoprocess =   $Alloperations | where-object{$_.GroupName -eq "Exchange"}
        "Fetching only Exchange Online operations from the subset" | Write-Log -LogPath $logfile  
    }
    Elseif($Operationsset -eq "OneDrive_Sharepoint_Teams_YammerOnly")
    {
        $Operationstoprocess =   $Alloperations | where-object{$_.GroupName -eq "OneDrive_Sharepoint_Teams_Yammer"}
        "Fetching only Onedrive, SharePoint, Teams and Yammer operations from the subset" | Write-Log -LogPath $logfile 
    }
    Elseif($Operationsset -eq "SecurityAlerts")
    {
        $Operationstoprocess =   $Alloperations | where-object{$_.GroupName -eq "SecurityAlerts"}
        "Fetching Security Alerts operations from the subset" | Write-Log -LogPath $logfile 
    } 
    
    Elseif($Operationsset -eq "AzureADOnly")
    {
        $Operationstoprocess =   $Alloperations | where-object{$_.GroupName -eq "AzureAD"}
        "Fetching only Azure AD operations from the subset" | Write-Log -LogPath $logfile 
    }


    $Launchsearch =
    {
    Param($app, $user, $newstartdate, $newenddate, $Operationstoprocess,$currentpath)
    $datetoprocess = ($newstartdate.ToString("yyyy-MM-dd"))
    $logfile = $currentpath + "\UnifiedAudit" + $datetoprocess + ".log"
    $unifiedauditfolder = $currentpath + "\O365_unified_audit_logs"
    if ((Test-Path $unifiedauditfolder) -eq $false){New-Item $unifiedauditfolder -Type Directory}
    "Processing O365 logs for day $($datetoprocess)"| Write-Log -LogPath $logfile
    $token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes "https://outlook.office365.com/.default"    
    $sessionName = "EXO_" + [guid]::NewGuid().ToString()
    $tenant = ($token.Account.UserName).split("@")[1]
    $outputdate = "{0:yyyy-MM-dd}" -f ($datetoprocess)
    $foldertoprocess = $unifiedauditfolder + "\" + $datetoprocess
    if ((Test-Path $foldertoprocess) -eq $false){New-Item $foldertoprocess -Type Directory}

    $outputfile = $foldertoprocess + "\UnifiedAuditLog_" + $tenant + "_" + $outputdate + ".json"
    Connect-EXOPsearchUnified -token $token -sessionName $sessionName -logfile $logfile

    foreach($operationsset in $Operationstoprocess)
        {
            $token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes "https://outlook.office365.com/.default"
            "Refreshing token - valid till " + $token.ExpiresOn.LocalDateTime.Tostring() | Write-Log -LogPath $logfile
   
            try {
                $trysearch = Search-UnifiedAuditLog -StartDate $newstartdate -EndDate $newenddate -operations $operationsset.Operations -ResultSize 1 -ErrorAction Stop
              
            }
            catch {
                "Retrieving Unified audit logs failed, rebuilding EXO session " | Write-Log -LogPath $logfile -LogLevel "Warning"  
                Get-PSSession | Remove-PSSession -Confirm:$false
                $token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes "https://outlook.office365.com/.default"
                Start-Sleep -Seconds 15
                $sessionName = "EXO_" + [guid]::NewGuid().ToString()
                Connect-EXOPsearchUnified -token $token -sessionName $sessionName -logfile $logfile
                $trysearch = Search-UnifiedAuditLog -StartDate $newstartdate -EndDate $newenddate -operations $operationsset.Operations  -ResultSize 1
                }
            if($trysearch)
                {
                    $countobjects = $trysearch.ResultCount
                    "Dumping $($countobjects) $($operationsset.GroupName) records between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newstartdate,$newenddate) | Write-Log -LogPath $logfile
                    if($countobjects -gt 50000)
                    {
                        "More than 50000 $($operationsset.GroupName) records between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss} - some records might be missing" -f ($newstarthour,$newendhour) | Write-Log -LogPath $logfile -LogLevel "Warning" 
                    }
                        $sessionName  = [guid]::NewGuid().ToString()
                        Get-LargeUnifiedAuditLog -sessionName $sessionName -StartDate $newstartdate -EndDate $newenddate -operations $operationsset.Operations -outputfile $outputfile -logfile $logfile -requesttype "Operations"
                }
            }
            
        "Removing PSSession and sleeping 10 seconds for session tear down"  | Write-Log -LogPath $logfile 
        Get-PSSession | Remove-PSSession -Confirm:$false
        Start-Sleep -Seconds 10
    }


$totaltimespan = (New-TimeSpan -Start $StartDate -End $Enddate)

if(($totaltimespan.hours -eq 0) -and ($totaltimespan.minutes -eq 0) -and ($totaltimespan.seconds -eq 0))
    {$totaldays = $totaltimespan.days
    $totalloops = $totaldays
    }
else
    {$totaldays = $totaltimespan.days + 1
    $totalloops = $totaltimespan.days
    }


Get-RSJob | Remove-RSJob -Force

$token = Get-OAuthToken -Service EXO -silent $true -LoginHint $user -Logfile $logfile
$app = Get-MsalClientApplication | Where-Object{$_.ClientId -eq "a0c73c16-a7e3-4564-9a95-2bdf47383716"}
if($null -eq $app)
{
    "No token cache available for EXO service asking for new token" | Write-Log -LogPath $logfile -LogLevel "Warning"
    $token = Get-OAuthToken -Service EXO -Logfile $logfile -DeviceCode $DeviceCode
    $app = Get-MsalClientApplication | Where-Object{$_.ClientId -eq "a0c73c16-a7e3-4564-9a95-2bdf47383716"}    
}

"Checking permissions for $($user)"| Write-Log -LogPath $logfile
$sessionName = "EXO_" + [guid]::NewGuid().ToString()
$void = Connect-EXOPsearchUnified -token $token -sessionName $sessionName -logfile $logfile
try {
    $trysearch = Search-UnifiedAuditLog -StartDate (get-date).adddays(-90) -EndDate (get-date) -RecordType $recordtype -ResultSize 1

}
catch {
    $errormessage = $_.Exception.Message
    if ($errormessage -like "*The term 'Search-UnifiedAuditLog'*") {
        "$user does not have the required permissions to get Office 365 Unified Audit Logs : doees not have the 'View-Only Audit Logs' role on https://admin.exchange.microsoft.com/. See https://learn.microsoft.com/en-us/purview/audit-log-search?view=o365-worldwide#before-you-search-the-audit-log. Cannot continue" | Write-Error  
        "$user does not have the required permissions to get Office 365 Unified Audit Logs : doees not have the 'View-Only Audit Logs' role on https://admin.exchange.microsoft.com/. See https://learn.microsoft.com/en-us/purview/audit-log-search?view=o365-worldwide#before-you-search-the-audit-log. Cannot continue" | Write-Log -LogPath $logfile -LogLevel "Error"  
        exit
    }
}

For ($d=0; $d -le $totalloops ; $d++)
{
    if($d -eq 0)
        {
        $newstartdate = $StartDate
        $newenddate = get-date("{0:yyyy-MM-dd} 00:00:00.000" -f ($newstartdate.AddDays(1)))
        }
    elseif($d -eq $totaldays)
        {
        $newenddate = $Enddate   
        $newstartdate = get-date("{0:yyyy-MM-dd} 00:00:00.000" -f ($newenddate))
        }
    else {
        $newstartdate = $newenddate
        $newenddate = $newenddate.AddDays(+1)
        }

    $token = Get-OAuthToken -Service EXO -silent $true -LoginHint $user -Logfile $logfile
    $app = Get-MsalClientApplication | Where-Object{$_.ClientId -eq "a0c73c16-a7e3-4564-9a95-2bdf47383716"}
    if($null -eq $app)
    {
        "No token cache available for EXO service asking for new token" | Write-Log -LogPath $logfile -LogLevel "Warning"
        $token = Get-OAuthToken -Service EXO -Logfile $logfile -DeviceCode $DeviceCode
        $app = Get-MsalClientApplication | Where-Object{$_.ClientId -eq "a0c73c16-a7e3-4564-9a95-2bdf47383716"}    
    }
    "Lauching job number $($d) with startdate {0:yyyy-MM-dd} {0:HH:mm:ss} and enddate {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newstartdate,$newenddate) | Write-Log -LogPath $logfile
    $datetoprocess = ($newstartdate.ToString("yyyy-MM-dd"))
    $jobname = "UnifiedAudit" + $datetoprocess
 
    Start-RSJob -Name $jobname -ScriptBlock $Launchsearch -FunctionsToImport Connect-EXOPsearchUnified, write-log, Get-LargeUnifiedAuditLog -ArgumentList $app, $user, $newstartdate, $newenddate, $Operationstoprocess , $currentpath

    $nbjobrunning = (Get-RSJob | where-object {$_.State -eq "running"}  | Measure-Object).count
    while($nbjobrunning -ge 3)
            {
            start-sleep -seconds 2
            $nbjobrunning = (Get-RSJob | where-object {$_.State -eq "running"}  | Measure-Object).count
            }
    $jobsok = Get-RSJob | where-object {$_.State -eq "Completed"}
    if($jobsok)
        {
        foreach($jobok in $jobsok)
            {
            "Runspace Job $($jobok.Name) finished - dumping log"  | Write-Log -LogPath $logfile    
            $logfilename = $jobok.Name + ".log"    
            get-content $logfilename | out-file $logfile -Encoding UTF8 -append
            remove-item $logfilename -confirm:$false -force
            $jobok | remove-rsjob
            "Runspace Job $($jobok.Name) finished - job removed"  | Write-Log -LogPath $logfile 
            }
        }
    $jobsnok = Get-RSJob | where-object {$_.State -eq "Failed"}
    if($jobsnok)
        {
        foreach($jobnok in $jobsnok)
            {
            "Runspace Job $($jobnok.Name) failed with error $($jobnok.Error)"  | Write-Log -LogPath $logfile -LogLevel "Error"      
            "Runspace Job $($jobnok.Name) failed - dumping log"  | Write-Log -LogPath $logfile -LogLevel "Error"   
            $logfilename = $jobnok.Name + ".log"    
            get-content $logfilename | out-file $logfile -Encoding UTF8 -append
            remove-item $logfilename -confirm:$false -force
            $jobnok | remove-rsjob
            "Runspace Job $($jobnok.Name) failed - job removed"  | Write-Log -LogPath $logfile -LogLevel "Error"   
            }
        }


    }

   #Waiting for final jobs to complete
   $nbjobrunning = (Get-RSJob | where-object {$_.State -eq "running"}  | Measure-Object).count
   while($nbjobrunning -ge 1)
           {
           start-sleep -seconds 2
           $nbjobrunning = (Get-RSJob | where-object {$_.State -eq "running"}  | Measure-Object).count
           }
   $jobsok = Get-RSJob | where-object {$_.State -eq "Completed"}
   if($jobsok)
   {
   foreach($jobok in $jobsok)
       {
       "Runspace Job $($jobok.Name) finished - dumping log"  | Write-Log -LogPath $logfile    
       $logfilename = $jobok.Name + ".log"    
       get-content $logfilename | out-file $logfile -Encoding UTF8 -append
       remove-item $logfilename -confirm:$false -force
       $jobok | remove-rsjob
       "Runspace Job $($jobok.Name) finished - job removed"  | Write-Log -LogPath $logfile 
       }
   }
$jobsnok = Get-RSJob | where-object {$_.State -eq "Failed"}
if($jobsnok)
   {
   foreach($jobnok in $jobsnok)
       {
       "Runspace Job $($jobnok.Name) failed with error $($jobnok.Error)"  | Write-Log -LogPath $logfile -LogLevel "Error"      
       "Runspace Job $($jobnok.Name) failed - dumping log"  | Write-Log -LogPath $logfile -LogLevel "Error"   
       $logfilename = $jobnok.Name + ".log"    
       get-content $logfilename | out-file $logfile -Encoding UTF8 -append
       remove-item $logfilename -confirm:$false -force
       $jobnok | remove-rsjob
       "Runspace Job $($jobnok.Name) failed - job removed"  | Write-Log -LogPath $logfile -LogLevel "Error"   
       }
   }

}
