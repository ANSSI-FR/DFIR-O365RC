
Function Get-AADLogs {

    <#
    .SYNOPSIS
    The Get-AADLogs function dumps in JSON files Azure AD signins logs and Azure AD audit logs for a specific time range.

    .EXAMPLE
    
    PS C:\>$enddate = get-date
    PS C:\>$startdate = $enddate.adddays(-30)

    PS C:\>Get-AADLogs -stardate $startdate -enddate $enddate 

    Dump all Azure AD logs available
    #>
    
    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$Enddate,
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDate,
        [Parameter(Mandatory = $false)]
        [ValidateSet("All","AuditOnly","SigninOnly")] 
        [String]$Dumplogs = "All",
        [Parameter(Mandatory = $false)]
        [boolean]$DeviceCode=$false,
        [Parameter(Mandatory = $false)]
        [String]$logfile = "Get-AADLogs.log"
    )
    $currentpath = (get-location).path
    $logfile = $currentpath + "\" +  $logfile
    "Getting MSGraph Oauth token"  | Write-Log -LogPath $logfile
    Clear-MsalTokenCache
    $token = Get-OAuthToken -Service MSGraph -Logfile $logfile -DeviceCode $DeviceCode
    $user = $token.Account.UserName

    if($Dumplogs -eq "All")
        {"Processing signins and audit logs"  | Write-Log -LogPath $logfile}
    elseif($Dumplogs -eq "AuditOnly")
        {"Processing audit logs only"  | Write-Log -LogPath $logfile}
    else
        {"Processing signins logs only"  | Write-Log -LogPath $logfile}
 
   
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
#Test the directory size
$tenant = ($user).split("@")[1]
$aadtenantfolder = $currentpath + "\azure_ad_tenant"
if ((Test-Path $aadtenantfolder) -eq $false){New-Item $aadtenantfolder -Type Directory | Out-Null}
$outputfile = $aadtenantfolder + "\AADTenant_" + $tenant + ".json"
$tenantsize = "normal"
$uri = "https://graph.microsoft.com/v1.0/organization"
$tenantinfo = Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.AccessToken)"} -Uri $Uri -Method Get -ContentType "application/json" -ErrorAction Stop
if($tenantinfo.value.directorySizeQuota.used -ge 100000)
    {
    if($Dumplogs -eq "All" -or $Dumplogs -eq "SigninOnly")
        {
        Write-Host "Directory size is huge, processing might be long, as a consequence signins logs will be filtered" -ForegroundColor "Yellow" -BackgroundColor "Black"
        "Directory size is huge, processing might be long, as a consequence signins logs will be filtered"  | Write-Log -LogPath $logfile -LogLevel "Warning"  
        }
    else {
        Write-Host "Directory size is huge, processing might be long" -ForegroundColor "Yellow" -BackgroundColor "Black"
        "Directory size is huge, processing might be long"  | Write-Log -LogPath $logfile -LogLevel "Warning"  
        }
    if($Dumplogs -eq "All")
        {    
        Write-Host "You might also want to dump Signins and audit logs separately by using the Dumplogs switch" -ForegroundColor "Yellow" -BackgroundColor "Black"
        "Processing signins and audit logs depsite the tenant size"  | Write-Log -LogPath $logfile -LogLevel "Warning"   
        }
     
    $tenantsize = "huge"
    }
else {
    "Normal size tenant, dumping all logs"  | Write-Log -LogPath $logfile   
}
"Dumping tenant information in azure_ad_tenant folder"  | Write-Log -LogPath $logfile   
$tenantinfo | ConvertTo-Json -Depth 99 |  out-file $outputfile -encoding UTF8 


    $Launchsearch =
    {
    Param($app, $user, $newstartdate, $newenddate ,$currentpath,$tenantsize,$Dumplogs)
    $datetoprocess = ($newstartdate.ToString("yyyy-MM-dd"))
    $logfile = $currentpath + "\AAD" + $datetoprocess + ".log"
    $aadauditfolder = $currentpath + "\azure_ad_audit"
    if ((Test-Path $aadauditfolder) -eq $false){New-Item $aadauditfolder -Type Directory}
    "Processing AAD logs for day $($datetoprocess)"| Write-Log -LogPath $logfile
    
    #Get AAD Audit logs 
    if(($Dumplogs -eq "All") -or ($Dumplogs -eq "AuditOnly"))
        {
        $outputdate = "{0:yyyy-MM-dd}" -f ($newstartdate)
        $tenant = ($user).split("@")[1]
        $outputfile = $aadauditfolder + "\AADAuditLog_" + $tenant + "_" + $outputdate + ".json"
        $Auditstart = "{0:s}" -f $newstartdate + "Z"
        $Auditend = "{0:s}" -f $newenddate + "Z"
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime gt $($Auditstart) and activityDateTime lt $($Auditend)"
        $AADAuditEvents = Get-MSGraphResponse -uri $uri  -logfile $logfile -app $app -user $user
        if($AADAuditEvents)
            {
            $AADAuditEvents | ConvertTo-Json -Depth 99 |  out-file $outputfile -encoding UTF8 
            $nbAADAuditEvents = ($AADAuditEvents | Measure-Object).count
            "Dumping $($nbAADAuditEvents) AAD audit events to $($outputfile)"   | Write-Log -LogPath $logfile
            }
        else {
            "No AAD audit event to dump to $($outputfile)"   | Write-Log -LogPath $logfile -LogLevel "Warning" 
            }
        }
    #Get AAD Signin logs 
    if(($Dumplogs -eq "All") -or ($Dumplogs -eq "SigninOnly"))
        {
        # Check if Azure P1 is enabled
        $token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes "https://graph.microsoft.com/.default"
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1"
        $P1Enabled = $true
        try {    
            Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.AccessToken)"} -Uri $Uri -Method Get -ContentType "application/json" -ErrorAction Stop
            }
        catch {
            if($error[0] -like "*RequestFromNonPremiumTenant*")
                {
                $P1Enabled = $false
                "Azure AD P1 not enabled on tenant, enable it if you wish to retrieve signin logs via MSGraph but be aware of additional costs" | Write-Log -LogPath $logfile -LogLevel "Warning"  
                }
            }
            if($P1Enabled -eq $true)
            {
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
                "Processing signIns logs between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newstarthour,$newendhour)  | Write-Log -LogPath $logfile  
                $outputdate = "{0:yyyy-MM-dd}_{0:HH-00-00}" -f ($newstarthour)
            
            
                $aadsigninfolder = $currentpath + "\azure_ad_signin"
                if ((Test-Path $aadsigninfolder) -eq $false){New-Item $aadsigninfolder -Type Directory}

                $Signinstart = "{0:s}" -f $newstarthour + "Z"
                $Signinend = "{0:s}" -f $newendhour + "Z"
                if($tenantsize -eq "normal")
                {
                $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime gt $($Signinstart) and createdDateTime lt $($Signinend)"
                }
                else {
            
                $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime gt $($Signinstart) and createdDateTime lt $($Signinend) and status/errorCode eq 0 and (appId eq '00000002-0000-0ff1-ce00-000000000000' or appId eq '1b730954-1685-4b74-9bfd-dac224a7b894' or appId eq 'a0c73c16-a7e3-4564-9a95-2bdf47383716' or appId eq '00000003-0000-0ff1-ce00-000000000000'  or appId eq '6eb59a73-39b2-4c23-a70f-e2e3ce8965b1' or appId eq 'cb1056e2-e479-49de-ae31-7812af012ed8' or appId eq '1950a258-227b-4e31-a9cf-717495945fc2' or appId eq 'fb78d390-0c51-40cd-8e17-fdbfab77341b' or appId eq '04b07795-8ddb-461a-bbee-02f9e1bf7b46')"  
                }
                $AADSigninEvents = Get-MSGraphResponse -uri $uri  -logfile $logfile -app $app -user $user
                $foldertoprocess = $aadsigninfolder + "\" + $datetoprocess
                if ((Test-Path $foldertoprocess) -eq $false){New-Item $foldertoprocess -Type Directory}
                $outputfile = $foldertoprocess + "\AADSigninLog_" + $tenant + "_" + $outputdate + ".json"
                if($AADSigninEvents)
                    {
                    $nbADSigninEvents = ($AADSigninEvents | Measure-Object).count
                    "Dumping $($nbADSigninEvents) AAD signIns events to $($outputfile)"  | Write-Log -LogPath $logfile
                    $AADSigninEvents | ConvertTo-Json -Depth 99 | out-file $outputfile -encoding UTF8 
                    }
                else{"No AAD signIns events to dump to $($outputfile)"  | Write-Log -LogPath $logfile -LogLevel "Warning"}
                }
            }
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
    #Refresh token
    $token = Get-OAuthToken -Service MSGraph -silent $true -LoginHint $user -Logfile $logfile
    $app = Get-MsalClientApplication | Where-Object{$_.ClientId -eq "1b730954-1685-4b74-9bfd-dac224a7b894"}
    if($null -eq $app)
    {
        "No token cache available for MSGraph service asking for new token" | Write-Log -LogPath $logfile -LogLevel "Warning"
        $token = Get-OAuthToken -Service MSGraph -Logfile $logfile -DeviceCode $DeviceCode
        $app = Get-MsalClientApplication | Where-Object{$_.ClientId -eq "1b730954-1685-4b74-9bfd-dac224a7b894"}    
    }
    "Lauching job number $($d) with startdate {0:yyyy-MM-dd} {0:HH:mm:ss} and enddate {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newstartdate,$newenddate) | Write-Log -LogPath $logfile
    $datetoprocess = ($newstartdate.ToString("yyyy-MM-dd"))
    $jobname = "AAD" + $datetoprocess
    Start-RSJob -Name $jobname  -ScriptBlock $Launchsearch -FunctionsToImport  write-log, Get-MSGraphResponse -ArgumentList $app, $user, $newstartdate, $newenddate, $currentpath, $tenantsize, $Dumplogs

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









