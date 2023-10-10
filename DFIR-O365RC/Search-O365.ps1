Function Search-O365 {

    <#
    .SYNOPSIS
    The Search-O365 function dumps in JSON files results of a freetext, IP or UserId search from the O365 Unified Audit Log for a specific time range.

    .EXAMPLE
    PS C:\>$enddate = get-date
    PS C:\>$startdate = $enddate.adddays(-90)

    PS C:\>Search-O365 -startdate $startdate -enddate $enddate -Freetext "Python"

    Search for Python user agent in unified audit logs

    .EXAMPLE
    Search-O365 -startdate $startdate -enddate $enddate -IPAddresses X.X.X.X
    Dump all the unified audit logs entries by the specified IP addresses. You specify multiple IP addresses separated by commas.
    #>
    
    param (

        [Parameter(Mandatory = $true)]
        [DateTime]$Enddate,
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDate,
        [Parameter(Mandatory = $false, ParameterSetName="Freetext")]
        [String]$Freetext,
        [Parameter(Mandatory = $false, ParameterSetName="IPAddresses")]
        [String]$IPAddresses,
        [Parameter(Mandatory = $false, ParameterSetName="UserIds")]
        [System.Array]$UserIds,        
        [Parameter(Mandatory = $false)]
        [boolean]$DeviceCode=$false,
        [Parameter(Mandatory = $false)]
        [String]$logfile = "Search-O365.log"
    )

    if($Freetext)
        {
        $requesttype = "freetext"
        $searchstring = $Freetext
        "Searching freetext $($Freetext) in Unified audit logs"  | Write-Log -LogPath $logfile
        }
    elseif($IPAddresses)
        {
        $requesttype = "IPAddresses"
        $searchstring = $IPAddresses
        "Searching IPAddresses $($IPAddresses) in Unified audit logs"  | Write-Log -LogPath $logfile
        }
    elseif($UserIds)
        {
        $requesttype = "UserIds"
        $searchstring = $UserIds
        "Searching UserIds $($UserIds) in Unified audit logs"  | Write-Log -LogPath $logfile
        }

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


    $Launchsearch =
    {
    Param($app, $user, $newstartdate, $newenddate, $requesttype, $searchstring, $currentpath)
    $datetoprocess = ($newstartdate.ToString("yyyy-MM-dd"))
    $logfile = $currentpath + "\UnifiedAudit" + $datetoprocess + ".log"
    $unifiedauditfolder = $currentpath + "\O365_unified_audit_logs"
    if ((Test-Path $unifiedauditfolder) -eq $false){New-Item $unifiedauditfolder -Type Directory}
    "Processing O365 logs for day $($datetoprocess)"| Write-Log -LogPath $logfile
    $token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes "https://outlook.office365.com/.default"    
    $sessionName = "EXO_" + [guid]::NewGuid().ToString()
    $tenant = ($token.Account.UserName).split("@")[1]
    $outputdate = "{0:yyyy-MM-dd}" -f ($datetoprocess)
    $actualdate = $(get-date -f yyyy-MM-dd-hh-mm-ss)
    $foldertoprocess = $unifiedauditfolder + "\" + $datetoprocess
    if ((Test-Path $foldertoprocess) -eq $false){New-Item $foldertoprocess -Type Directory}

    $outputfile = $foldertoprocess + "\UnifiedAuditLog_" + $tenant + "_" + $outputdate + "_" + $requesttype + "_" + $actualdate + ".json"
    $commandNames = "Search-UnifiedAuditLog","Search-MailboxAuditLog"
    Connect-EXOPsearchUnified -token $token -sessionName $sessionName -logfile $logfile -commandNames $commandNames


        $token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes "https://outlook.office365.com/.default"
        "Refreshing token - valid till " + $token.ExpiresOn.LocalDateTime.Tostring() | Write-Log -LogPath $logfile
   
            try {
                if($requesttype -eq "freetext")
                    {$trysearch = Search-UnifiedAuditLog -StartDate $newstartdate -EndDate $newenddate -FreeText $searchstring -ResultSize 1 -ErrorAction Stop}
                elseif($requesttype -eq "IPAddresses")
                    {$trysearch = Search-UnifiedAuditLog -StartDate $newstartdate -EndDate $newenddate -IPAddresses $searchstring -ResultSize 1 -ErrorAction Stop}
                elseif($requesttype -eq "UserIds")
                    {$trysearch = Search-UnifiedAuditLog -StartDate $newstartdate -EndDate $newenddate -UserIds $searchstring -ResultSize 1 -ErrorAction Stop}
            }
            catch {
                "Retrieving Unified audit logs failed, rebuilding EXO session " | Write-Log -LogPath $logfile -LogLevel "Warning"  
                Get-PSSession | Remove-PSSession -Confirm:$false
                $token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes "https://outlook.office365.com/.default"
                Start-Sleep -Seconds 15
                $sessionName = "EXO_" + [guid]::NewGuid().ToString()
                $commandNames = "Search-UnifiedAuditLog","Search-MailboxAuditLog"
                Connect-EXOPsearchUnified -token $token -sessionName $sessionName -logfile $logfile -commandNames $commandNames
                if($requesttype -eq "freetext")
                    {$trysearch = Search-UnifiedAuditLog -StartDate $newstartdate -EndDate $newenddate -FreeText $searchstring -ResultSize 1}
                elseif($requesttype -eq "IPAddresses")
                    {$trysearch = Search-UnifiedAuditLog -StartDate $newstartdate -EndDate $newenddate -IPAddresses $searchstring -ResultSize 1}
                elseif($requesttype -eq "UserIds")
                    {$trysearch = Search-UnifiedAuditLog -StartDate $newstartdate -EndDate $newenddate -UserIds $searchstring -ResultSize 1}
                }
            if($trysearch)
                {
                    $countobjects = $trysearch.ResultCount
                    "Dumping $($countobjects) UAL records between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newstartdate,$newenddate) | Write-Log -LogPath $logfile
                    if($countobjects -gt 50000)
                    {
                        "More than 50000 records between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss} - some records might be missing" -f ($newstarthour,$newendhour) | Write-Log -LogPath $logfile -LogLevel "Warning" 
                    }
                        $sessionName  = [guid]::NewGuid().ToString()
                        if($requesttype -eq "UserIds")
                        {Get-LargeUnifiedAuditLog -sessionName $sessionName -StartDate $newstartdate -EndDate $newenddate -searchtable $searchstring -outputfile $outputfile -logfile $logfile -requesttype $requesttype }
                        else {
                            Get-LargeUnifiedAuditLog -sessionName $sessionName -StartDate $newstartdate -EndDate $newenddate -searchstring $searchstring -outputfile $outputfile -logfile $logfile -requesttype $requesttype  
                        }
                        
                }

                $outputfile = $foldertoprocess + "\MailboxAuditLog_" + $tenant + "_" + $outputdate + "_" + $requesttype + "_" + $actualdate + ".json"
                if($requesttype -eq "UserIds")
                {
                    try {
                        Search-MailboxAuditLog -StartDate $newstartdate -EndDate $newenddate -Identity $searchstring[0] -LogonTypes Admin,Delegate,Owner -IncludeInactiveMailbox -ShowDetails -ResultSize 1 -ErrorAction Stop
                    }
                    catch {
                        if ($_.CategoryInfo.Reason -ne "ManagementObjectNotFoundException") 
                        {
                            "Retrieving Mailbox audit logs failed, rebuilding EXO session" | Write-Log -LogPath $logfile -LogLevel "Warning"  
                            Get-PSSession | Remove-PSSession -Confirm:$false
                            $token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes "https://outlook.office365.com/.default"
                            Start-Sleep -Seconds 15
                            $sessionName = "EXO_" + [guid]::NewGuid().ToString()
                            $commandNames = "Search-UnifiedAuditLog","Search-MailboxAuditLog"
                            Connect-EXOPsearchUnified -token $token -sessionName $sessionName -logfile $logfile -commandNames $commandNames
                        }
                    }
                    "Dumping MailboxAudit records between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newstartdate,$newenddate) | Write-Log -LogPath $logfile
                    Get-MailboxAuditLog -StartDate $newstartdate -EndDate $newenddate -outputfile $outputfile -logfile $logfile -UserIds $searchstring
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
$commandNames = "Search-UnifiedAuditLog","Search-MailboxAuditLog"
$void = Connect-EXOPsearchUnified -token $token -sessionName $sessionName -logfile $logfile -commandNames $commandNames
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
 
    Start-RSJob -Name $jobname -ScriptBlock $Launchsearch -FunctionsToImport Connect-EXOPsearchUnified, write-log, Get-LargeUnifiedAuditLog,Get-MailboxAuditLog -ArgumentList $app, $user, $newstartdate, $newenddate, $requesttype, $searchstring , $currentpath

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
