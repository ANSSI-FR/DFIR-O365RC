
Function Get-AzDevOpsActivityLogs {

    <#
    .SYNOPSIS
    The Get-AzDevOpsActivityLogs function dumps in JSON files Azure DevOps activity logs for a specific time range.

    .EXAMPLE
    
    PS C:\>$enddate = get-date
    PS C:\>$startdate = $enddate.adddays(-30)

    PS C:\>Get-AzDevOpsActivityLogs -startdate $startdate -enddate $enddate

    Dump all Azure DevOps activity logs available the user has access to
    .EXAMPLE 
    
    Get-AzDevOpsActivityLogs -startdate $startdate -enddate $enddate -SelectOrg:$true
    Dump Azure DevOps activity logs for a given organization
    #>
    
    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$Enddate,
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDate,
        [Parameter(Mandatory = $false)]
        [boolean]$SelectOrg=$false,
        [Parameter(Mandatory = $false)]
        [boolean]$DeviceCode=$false,
        [Parameter(Mandatory = $false)]
        [String]$logfile = "Get-AzDevOpsActivityLogs.log"
    )
    $currentpath = (get-location).path
    $logfile = $currentpath + "\" +  $logfile
    "Getting AzDevOps Oauth token"  | Write-Log -LogPath $logfile
    Clear-MsalTokenCache
    $token = Get-OAuthToken -Service AzDevOps -Logfile $logfile -DeviceCode $DeviceCode
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
$azdevorgfolder = $currentpath + "\azure_DevOps_orgs"
if ((Test-Path $azdevorgfolder) -eq $false){New-Item $azdevorgfolder -Type Directory | Out-Null}
$outputfile = $azdevorgfolder + "\AzdevopsOrgs_" + $tenant + ".json"

$urime = "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=6.0-preview.1"
$me = Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.AccessToken)"} -Uri $urime -Method Get -ContentType "application/json" -ErrorAction Stop
$uriorgs = "https://app.vssps.visualstudio.com/_apis/accounts?memberId=$($me.id)&api-version=6.0-preview.1"
$azdevopsorgs = Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.AccessToken)"} -Uri $uriorgs -Method Get -ContentType "application/json" -ErrorAction Stop

$nbazdevopsorgs = ($azdevopsorgs.value | Measure-Object).count

if($nbazdevopsorgs -eq 0)
{
    Write-Host "No Azure DevOps organization to process, exiting" 
    "The user has $($nbazdevopsorgs) Azure DevOps organization attached, exiting"  | Write-Log -LogPath $logfile  -Level "ERROR"
    exit
}
else
    {
    Write-Host "The user has $($nbazdevopsorgs) Azure DevOps organization attached:" 
    "The user has $($nbazdevopsorgs) Azure DevOps organization attached"  | Write-Log -LogPath $logfile
    $azdevopsorgs.value | ForEach-Object{write-host "$($_.accountName) | $($_.accountId)"}  
    }
if($SelectOrg -eq $false)
    {
        Write-Host "Processing activity logs for all Azure DevOps organizations." 
        "Processing activity logs for all Azure DevOps organizations, dumping all organizations information to $($outputfile) "  | Write-Log -LogPath $logfile   
        $orgidtoprocess = $azdevopsorgs.value
    }
else
    {
        Write-Host "Please enter a Azure DevOps organization ID:"
        $orgid = read-host
        $orgidtoprocess = $azdevopsorgs.value | Where-Object{$_.accountId -eq $orgid}
        if($orgidtoprocess)
            {
                Write-Host "Processing activity logs only for $($orgidtoprocess.accountName) Azure DevOps organization." 
                "Processing activity logs only for $($orgidtoprocess.accountName) Azure DevOps organization, dumping all organizations information to $($outputfile) "  | Write-Log -LogPath $logfile     
            }
        else{
            Write-Host "Azure DevOps organization ID is incorrect, exiting" 
            "Azure DevOps organization ID is incorrect, exiting"  | Write-Log -LogPath $logfile -Level "ERROR"
            exit
        }
    }

$azdevopsorgs.value | ConvertTo-Json -Depth 99 |  out-file $outputfile -encoding UTF8 


    $Launchsearch =
    {
    Param($app, $user, $newstartdate, $newenddate ,$currentpath,$orgname)
   
    $datetoprocess = ($newstartdate.ToString("yyyy-MM-dd"))
    $logfile = $currentpath + "\AzDevOps_" + $orgname + "_" + $datetoprocess + ".log"
    $tenant = ($user).split("@")[1]

    $azDevOpsActivityfolder = $currentpath + "\azure_DevOps_activity"
    if ((Test-Path $azDevOpsActivityfolder) -eq $false){New-Item $azDevOpsActivityfolder -Type Directory}
    
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
        "Processing Azure DevOps activity logs between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newstarthour,$newendhour)  | Write-Log -LogPath $logfile  

        $outputdate = "{0:yyyy-MM-dd}_{0:HH-00-00}" -f ($newstarthour)
        $Auditstart = "{0:s}" -f $newstarthour + "Z"
        $Auditend  = "{0:s}" -f $newendhour + "Z"

        $uri = "https://auditservice.dev.azure.com/$($orgname)/_apis/audit/auditlog?startTime=$($Auditstart)&endTime=$($Auditend)&api-version=6.0-preview.1"
        $AzDevOpsactivityEvents = Get-RestAPIResponse -RESTAPIService "AzDevOps" -uri $uri  -logfile $logfile -app $app -user $user
        $foldertoprocess = $azDevOpsActivityfolder + "\" + $datetoprocess
        if ((Test-Path $foldertoprocess) -eq $false){New-Item $foldertoprocess -Type Directory}
        $outputfile = $foldertoprocess + "\AzDevOps_" + $tenant + "_" + $orgname + "_" + $outputdate + ".json"
        if($AzDevOpsactivityEvents)
            {
            $nbAzDevOpsactivityEvents = ($AzDevOpsactivityEvents | Measure-Object).count
            "Dumping $($nbAzDevOpsactivityEvents) Azure DevOps activity logs events to $($outputfile)"   | Write-Log -LogPath $logfile
            $AzDevOpsactivityEvents | ConvertTo-Json -Depth 99 |  out-file $outputfile -encoding UTF8 
            }
        else {
            "No Azure DevOps activity logs event to dump to $($outputfile)"   | Write-Log -LogPath $logfile -LogLevel "Warning" 
            }    
        }
    }

foreach($org in $orgidtoprocess)
{
    Write-Host "Starting processing activity logs for $($org.accountName) Azure DevOps organization." 
    "Starting processing activity logs for $($org.accountName) Azure DevOps organization."  | Write-Log -LogPath $logfile 

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
    $token = Get-OAuthToken -Service AzDevOps -silent $true -LoginHint $user -Logfile $logfile
    $app = Get-MsalClientApplication | Where-Object{$_.ClientId -eq "1950a258-227b-4e31-a9cf-717495945fc2"}
    if($null -eq $app)
    {
        "No token cache available for AzDevOps service asking for new token" | Write-Log -LogPath $logfile -LogLevel "Warning"
        $token = Get-OAuthToken -Service AzDevOps -Logfile $logfile -DeviceCode $DeviceCode
        $app = Get-MsalClientApplication | Where-Object{$_.ClientId -eq "1950a258-227b-4e31-a9cf-717495945fc2"}    
    }
    "Lauching job number $($d) with startdate {0:yyyy-MM-dd} {0:HH:mm:ss} and enddate {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newstartdate,$newenddate) | Write-Log -LogPath $logfile
    $datetoprocess = ($newstartdate.ToString("yyyy-MM-dd"))
    $orgname = $org.accountName
    $jobname =  "AzDevOps_" + $orgname + "_" + $datetoprocess
    Start-RSJob -Name $jobname  -ScriptBlock $Launchsearch -FunctionsToImport  write-log, Get-RestAPIResponse -ArgumentList $app, $user, $newstartdate, $newenddate, $currentpath, $orgname
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









