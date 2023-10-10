
Function Get-AzRMActivityLogs {

    <#
    .SYNOPSIS
    The Get-AzRMActivityLogs function dumps in JSON files Azure activity logs for a specific time range.

    .EXAMPLE
    
    PS C:\>$enddate = get-date
    PS C:\>$startdate = $enddate.adddays(-30)

    PS C:\>Get-AzRMActivityLogs -startdate $startdate -enddate $enddate

    Dump all Azure activity logs available for the tenant
    .EXAMPLE 
    
    Get-AzRMActivityLogs -startdate $startdate -enddate $enddate -SelectSubscription:$true
    Dump Azure activity logs for a given subscription in the tenant
    #>
    
    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$Enddate,
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDate,
        [Parameter(Mandatory = $false)]
        [boolean]$SelectSubscription=$false,
        [Parameter(Mandatory = $false)]
        [boolean]$DeviceCode=$false,
        [Parameter(Mandatory = $false)]
        [String]$logfile = "Get-AzRMActivityLogs.log"
    )
    $currentpath = (get-location).path
    $logfile = $currentpath + "\" +  $logfile
    "Getting AzRM Oauth token"  | Write-Log -LogPath $logfile
    Clear-MsalTokenCache
    $token = Get-OAuthToken -Service AzRM -Logfile $logfile -DeviceCode $DeviceCode
    $user = $token.Account.UserName

   
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

$tenant = ($user).split("@")[1]
$azsubscriptionsfolder = $currentpath + "\azure_rm_subscriptions"
if ((Test-Path $azsubscriptionsfolder) -eq $false){New-Item $azsubscriptionsfolder -Type Directory | Out-Null}
$outputfile = $azsubscriptionsfolder + "\AzRMsubscriptions_" + $tenant + ".json"
$uri = "https://management.azure.com/Subscriptions?api-version=2016-06-01"
$azsubscriptionsinfo = Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.AccessToken)"} -Uri $Uri -Method Get -ContentType "application/json" -ErrorAction Stop

$nbsubscriptions = ($azsubscriptionsinfo.value | Measure-Object).count
if($nbsubscriptions -eq 0)
{
    Write-Host "No Azure subscription to process, exiting" 
    "The tenant has $($nbsubscriptions) subscription, exiting"  | Write-Log -LogPath $logfile  -Level "ERROR"
    exit
}
else
    {
    Write-Host "The tenant has $($nbsubscriptions) subscriptions:" 
    "The tenant has $($nbsubscriptions) subscriptions"  | Write-Log -LogPath $logfile
    $azsubscriptionsinfo.value | ForEach-Object{write-host "$($_.displayName) | $($_.subscriptionId)"}  
    }
if($SelectSubscription -eq $false)
    {
        Write-Host "Processing activity logs for all subscriptions." 
        "Processing activity logs for all subscriptions, dumping all subscriptions information to $($outputfile) "  | Write-Log -LogPath $logfile   
        $subidtoprocess = $azsubscriptionsinfo.value
    }
else
    {
        Write-Host "Please enter a subscription ID:"
        $subid = read-host
        $subidtoprocess = $azsubscriptionsinfo.value | Where-Object{$_.subscriptionId -eq $subid}
        if($subidtoprocess)
            {
                Write-Host "Processing activity logs only for $($subidtoprocess.displayName) subscription." 
                "Processing activity logs only for $($subidtoprocess.displayName) subscription, dumping all subscriptions information to $($outputfile) "  | Write-Log -LogPath $logfile     
            }
        else{
            Write-Host "Subscription ID is incorrect, exiting" 
            "Subscription ID is incorrect, exiting"  | Write-Log -LogPath $logfile -Level "ERROR"
            exit
        }
    }

$azsubscriptionsinfo.value | ConvertTo-Json -Depth 99 |  out-file $outputfile -encoding UTF8 


    $Launchsearch =
    {
    Param($app, $user, $newstartdate, $newenddate ,$currentpath,$subscriptionID)
   
    $datetoprocess = ($newstartdate.ToString("yyyy-MM-dd"))
    $logfile = $currentpath + "\AzRM_" + $subscriptionID + "_" + $datetoprocess + ".log"
    $tenant = ($user).split("@")[1]

    $azRMActivityfolder = $currentpath + "\azure_rm_activity"
    if ((Test-Path $azRMActivityfolder) -eq $false){New-Item $azRMActivityfolder -Type Directory}
    
    $totalhours = [Math]::Floor((New-TimeSpan -Start $newstartdate -End $newenddate).Totalhours) 
    if($totalhours -eq 24){$totalhours--}
    
    For ($h=0; $h -le $totalhours ; $h++)
        {
        if($h -eq 0)
            {
            $newstarthour = $newstartdate
            $newendhour = $newstartdate.AddMinutes(59 - $newstartdate.Minute).AddSeconds(60 - $newstartdate.Second)    
            }
        elseif($h -eq $totalhours)
            {
            $newstarthour = $newendhour
            $newendhour = $newenddate
            }
        else {
            $newstarthour = $newendhour
            $newendhour = $newstarthour.addHours(1)   
            }
        "Processing Azure activity logs between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newstarthour,$newendhour)  | Write-Log -LogPath $logfile  

        $outputdate = "{0:yyyy-MM-dd}_{0:HH-00-00}" -f ($newstarthour)
        $Auditstart = "{0:s}" -f $newstarthour + "Z"
        $Auditend  = "{0:s}" -f $newendhour + "Z"


        $uri =  "https://management.azure.com/subscriptions/$($subscriptionID)/providers/microsoft.insights/eventtypes/management/values?api-version=2015-04-01&`$filter=eventTimestamp ge $($Auditstart) and eventTimestamp le $($AuditEnd)"
        $AzRMactivityEvents = Get-RestAPIResponse -RESTAPIService "AzRM" -uri $uri  -logfile $logfile -app $app -user $user
        $foldertoprocess = $azRMActivityfolder + "\" + $datetoprocess
        if ((Test-Path $foldertoprocess) -eq $false){New-Item $foldertoprocess -Type Directory}
        $outputfile = $foldertoprocess + "\AzRM_" + $tenant + "_" + $subscriptionID + "_" + $outputdate + ".json"
        if($AzRMactivityEvents)
            {
            $nbAzRMactivityEvents = ($AzRMactivityEvents | Measure-Object).count
            "Dumping $($nbAzRMactivityEvents) Azure activity logs events to $($outputfile)"   | Write-Log -LogPath $logfile
            $AzRMactivityEvents | ConvertTo-Json -Depth 99 |  out-file $outputfile -encoding UTF8 
            }
        else {
            "No Azure activity logs event to dump to $($outputfile)"   | Write-Log -LogPath $logfile -LogLevel "Warning" 
            }    
        }
    }

foreach($sub in $subidtoprocess)
{
    Write-Host "Starting processing activity logs for $($sub.displayName) subscription." 
    "Starting processing activity logs for $($sub.displayName) subscription."  | Write-Log -LogPath $logfile 

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
    #Refresh token
    $token = Get-OAuthToken -Service AzRM -silent $true -LoginHint $user -Logfile $logfile
    $app = Get-MsalClientApplication | Where-Object{$_.ClientId -eq "1950a258-227b-4e31-a9cf-717495945fc2"}
    if($null -eq $app)
    {
        "No token cache available for AzRM service asking for new token" | Write-Log -LogPath $logfile -LogLevel "Warning"
        $token = Get-OAuthToken -Service AzRM -Logfile $logfile -DeviceCode $DeviceCode
        $app = Get-MsalClientApplication | Where-Object{$_.ClientId -eq "1950a258-227b-4e31-a9cf-717495945fc2"}    
    }
    "Lauching job number $($d) with startdate {0:yyyy-MM-dd} {0:HH:mm:ss} and enddate {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newstartdate,$newenddate) | Write-Log -LogPath $logfile
    $datetoprocess = ($newstartdate.ToString("yyyy-MM-dd"))
    $subscriptionID = $sub.subscriptionId
    $jobname =  "AzRM_" + $subscriptionID + "_" + $datetoprocess
    Start-RSJob -Name $jobname  -ScriptBlock $Launchsearch -FunctionsToImport  write-log, Get-RestAPIResponse -ArgumentList $app, $user, $newstartdate, $newenddate, $currentpath, $subscriptionID
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
}









