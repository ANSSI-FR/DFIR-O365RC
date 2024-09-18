
function Get-AADLogs {

    <#
    .SYNOPSIS
    The Get-AADLogs function dumps in JSON files Entra ID devices related events for a specific time range. Please note that a Microsoft Entra ID P1 tenant is required to get sign in logs and more than a week of audit logs.

    .EXAMPLE

    PS C:\>$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    PS C:\>$tenant = "example.onmicrosoft.com"
    PS C:\>$certificatePath = "./example.pfx"
    PS C:\>$endDate = Get-Date
    PS C:\>$startDate = $endDate.AddDays(-30)

    PS C:\>Get-AADLogs -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath

    Dump all Entra ID logs for the last 30 days.

    PS C:\>Get-AADLogs -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -dumpLogs "all"

    Dump all Entra ID logs for the last 30 days.

    PS C:\>Get-AADLogs -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -dumpLogs "auditOnly"

    Dump all Entra ID audit logs for the last 30 days.

    PS C:\>Get-AADLogs -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -dumpLogs "signInsOnly"

    Dump all Entra ID sign ins for the last 30 days.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$endDate,
        [Parameter(Mandatory = $true)]
        [DateTime]$startDate,
        [Parameter(Mandatory = $true)]
        [String]$certificatePath,
        [Parameter(Mandatory = $true)]
        [String]$appId,
        [Parameter(Mandatory = $true)]
        [String]$tenant,
        [Parameter(Mandatory = $false)]
        [ValidateSet("all","auditOnly","signInsOnly")]
        [String]$dumpLogs = "all",
        [Parameter(Mandatory = $false)]
        [String]$logFile = "Get-AADLogs.log"
    )

    $currentPath = (Get-Location).path
    $logFile = $currentPath + "\" + $logFile

    if ($dumpLogs -eq "all"){
        "Processing sign in and audit logs" | Write-Log -LogPath $logFile
    }
    elseif ($dumpLogs -eq "auditOnly"){
        "Processing audit logs only" | Write-Log -LogPath $logFile
    }
    else {
        "Processing sign in logs only" | Write-Log -LogPath $logFile
    }

    $maxStartDate = (Get-Date).AddDays(-30)
    if ($startDate -lt $maxStartDate){
        Write-Warning "You can only get 30 days with Audit Log. Setting startDate to $maxStartDate"
        "You can only get 30 days with Audit Log. Setting startDate to $maxStartDate" | Write-Log -LogPath $logFile -LogLevel "Warning"
        $startDate = $maxStartDate
        if ($endDate -lt $startDate){
            Write-Host "Incompatible endDate: $endDate. Exiting"
            "Incompatible endDate: $endDate. Exiting" | Write-Log -LogPath $logFile
            exit
        }
    }

    $launchSearch =
    {
        param($newStartDate, $newEndDate, $currentPath, $tenantSize, $dumpLogs, $P1Enabled, $cert, $appId, $tenant)

        $dateToProcess = ($newStartDate.ToString("yyyy-MM-dd"))
        $logFile = $currentPath + "\AAD" + $dateToProcess + ".log"

        Connect-MicrosoftGraphApplication -certificate $cert -appId $appId -tenant $tenant -logFile $logFile

        # Get Entra ID audit logs 
        if (($dumpLogs -eq "all") -or ($dumpLogs -eq "auditOnly")){
            $AzureADAuditFolder = $currentPath + "\azure_ad_audit"
            if ((Test-Path $AzureADAuditFolder) -eq $false){
                New-Item $AzureADAuditFolder -Type Directory
            }

            "Processing Entra ID audit logs for day $($dateToProcess)" | Write-Log -LogPath $logFile
            $outputdate = "{0:yyyy-MM-dd}" -f ($newStartDate)
            $outputFile = $AzureADAuditFolder + "\AADAuditLog_" + $tenant + "_" + $outputdate + ".json"
            $auditStart = "{0:s}" -f $newStartDate + "Z"
            $auditEnd = "{0:s}" -f $newEndDate + "Z"
            $AzureADAuditEvents = Get-MicrosoftGraphLogs -type "AuditLogs" -dateStart $auditStart -dateEnd $auditEnd -certificate $cert -appId $appId -tenant $tenant -logFile $logFile
            if ($AzureADAuditEvents){
                $nbAzureADAuditEvents = ($AzureADAuditEvents | Measure-Object).Count
                "Dumping $($nbAzureADAuditEvents) Entra ID audit events to $($outputFile)" | Write-Log -LogPath $logFile
                $AzureADAuditEvents | ConvertTo-Json -Depth 99 | Out-File $outputFile -Encoding UTF8
            }
            else {
                "No Entra ID audit event to dump to $($outputFile)" | Write-Log -LogPath $logFile -LogLevel "Warning" 
            }
        }

        # Get Entra ID sign in logs 
        if (($dumpLogs -eq "all") -or ($dumpLogs -eq "signInsOnly"))
        {
            if ($P1Enabled -eq $true){
                $totalHours = [Math]::Floor((New-TimeSpan -Start $newStartDate -End $newEndDate).TotalHours)
                if ($totalHours -eq 24){
                    $totalHours--
                }
                for ($h=0; $h -le $totalHours; $h++){
                    if ($h -eq 0){
                        $newStartHour = $newStartDate
                        $newEndHour = $newStartDate.AddMinutes(59 - $newStartDate.Minute).AddSeconds(60 - $newStartDate.Second)
                    }
                    elseif ($h -eq $totalHours){
                        $newStartHour = $newEndHour
                        $newEndHour = $newEndDate
                    }
                    else {
                        $newStartHour = $newEndHour
                        $newEndHour = $newStartHour.addHours(1)
                    }
                    "Processing sign in logs between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newStartHour, $newEndHour) | Write-Log -LogPath $logFile
                    $outputDate = "{0:yyyy-MM-dd}_{0:HH-00-00}" -f ($newStartHour)

                    $AzureADSignInsFolder = $currentPath + "\azure_ad_signin"
                    if ((Test-Path $AzureADSignInsFolder) -eq $false){
                        New-Item $AzureADSignInsFolder -Type Directory
                    }

                    $signInsStart = "{0:s}" -f $newStartHour + "Z"
                    $signInsEnd = "{0:s}" -f $newEndHour + "Z"
                    $AzureADSignInEvents = Get-MicrosoftGraphLogs -type "SignIns" -tenantSize $tenantSize -dateStart $signInsStart -dateEnd $signInsEnd -certificate $cert -appId $appId -tenant $tenant -logFile $logFile
                    $folderToProcess = $AzureADSignInsFolder + "\" + $dateToProcess
                    if ((Test-Path $folderToProcess) -eq $false){
                        New-Item $folderToProcess -Type Directory
                    }
                    $outputFile = $folderToProcess + "\AADSigninLog_" + $tenant + "_" + $outputdate + ".json"
                    if ($AzureADSignInEvents){
                        $nbADSigninEvents = ($AzureADSignInEvents | Measure-Object).Count
                        "Dumping $($nbADSigninEvents) Entra ID sign in events to $($outputFile)" | Write-Log -LogPath $logFile
                        $AzureADSignInEvents | ConvertTo-Json -Depth 99 | Out-File $outputFile -Encoding UTF8 
                    }
                    else {
                        "No Entra ID sign in events to dump to $($outputFile)" | Write-Log -LogPath $logFile -LogLevel "Warning"
                    }
                }
            }
            else {
                "No Entra ID P1 licence: can't dump sign in logs using API between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newStartDate, $newEndDate) | Write-Log -LogPath $logFile -LogLevel "Warning"
            }
        }
    }

    $cert, $null, $null = Import-Certificate -certificatePath $certificatePath -logFile $logFile

    Get-RSJob | Remove-RSJob -Force

    Connect-MicrosoftGraphApplication -certificate $cert -appId $appId -tenant $tenant -logFile $logFile
 
    $AzureADTenantFolder = $currentPath + "\azure_ad_tenant"
    if ((Test-Path $AzureADTenantFolder) -eq $false){
        New-Item $AzureADTenantFolder -Type Directory | Out-Null
    }
    $outputFile = $AzureADTenantFolder + "\AADTenant_" + $tenant + ".json"

    # Test the directory size
    $tenantSize = "normal"
    $tenantInformation = Get-MgOrganization -ErrorAction Stop
    if ($tenantInformation.AdditionalProperties.directorySizeQuota.used -ge 100000){
        $tenantSize = "huge"
        if ($dumpLogs -eq "all" -or $dumpLogs -eq "signInsOnly"){
            Write-Warning "Directory size is huge, processing might be long. As a consequence, sign in logs will be filtered on some specific applications"
            "Directory size is huge, processing might be long. As a consequence, sign in logs will be filtered on some specific applications" | Write-Log -LogPath $logFile -LogLevel "Warning"
        }
        else {
            Write-Warning "Directory size is huge, processing of audit logs might be long"
            "Directory size is huge, processing of audit logs might be long" | Write-Log -LogPath $logFile -LogLevel "Warning"
        }
        Write-Host "You might also want to dump sign in logs and audit logs separately by using the dumpLogs switch"
        "You might also want to dump sign in logs and audit logs separately by using the dumpLogs switch" | Write-Log -LogPath $logFile
    }
    else {
        "Tenant of a normal size, dumping all logs" | Write-Log -LogPath $logFile
    }

    "Dumping tenant information in azure_ad_tenant folder" | Write-Log -LogPath $logFile
    $tenantInformation | ConvertTo-Json -Depth 99 | Out-File $outputFile -Encoding UTF8 

    # Check if Microsoft Entra ID P1 is enabled
    "Checking Microsoft Entra ID P1"| Write-Log -LogPath $logFile
    $P1Enabled = $true
    try {
        $null = Get-MgBetaAuditLogSignIn -Top 1 -All -ErrorAction Stop
    }
    catch {
        if ($_.ErrorDetails.Message -like "*RequestFromNonPremiumTenant*"){
            $P1Enabled = $false
            Write-Warning "Entra ID P1 is not enabled tenant-wide. You should buy at least one Entra ID P1 licence to be able to retrieve the full audit log"
            "Entra ID P1 is not enabled tenant-wide. You should buy at least one Entra ID P1 licence to be able to retrieve the full audit log" | Write-Log -LogPath $logFile -LogLevel "Warning"
            $maxStartDate = (Get-Date).AddDays(-7)
            if ($startDate -lt $maxStartDate){
                Write-Warning "Entra ID P1 not enabled tenant-wide, you can only get 7 days of Audit Log. Setting startDate to $maxStartDate"
                "Entra ID P1 not enabled tenant-wide, you can only get 7 days of Audit Log. Setting startDate to $maxStartDate" | Write-Log -LogPath $logFile -LogLevel "Warning"
                $startDate = [DateTime]$maxStartDate.ToString("yyyy-MM-dd")
                if ($endDate -lt $startDate){
                    Write-Error "Incompatible endDate: $endDate. Exiting"
                    "Incompatible endDate: $endDate. Exiting" | Write-Log -LogPath $logFile -LogLevel "Error"
                    exit
                }
            }
        }
    }    

    $totalTimeSpan = (New-TimeSpan -Start $startDate -End $endDate)
    if (($totalTimeSpan.Hours -eq 0) -and ($totalTimeSpan.Minutes -eq 0) -and ($totalTimeSpan.Seconds -eq 0)){
        $totalDays = $totalTimeSpan.days
        $totalLoops = $totalDays
    }
    else {
        $totalDays = $totalTimeSpan.days + 1
        $totalLoops = $totalTimeSpan.days
    }

    for ($d=0; $d -le $totalLoops; $d++){
        if ($d -eq 0){
            $newStartDate = $startDate
            $newEndDate = Get-Date("{0:yyyy-MM-dd} 00:00:00.000" -f ($newStartDate.AddDays(1)))
        }
        elseif ($d -eq $totalDays){
            $newEndDate = $endDate
            $newStartDate = Get-Date("{0:yyyy-MM-dd} 00:00:00.000" -f ($newEndDate))
        }
        else {
            $newStartDate = $newEndDate
            $newEndDate = $newEndDate.AddDays(1)
        }

        "Lauching job number $($d) with startDate {0:yyyy-MM-dd} {0:HH:mm:ss} and endDate {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newStartDate, $newEndDate) | Write-Log -LogPath $logFile
        $dateToProcess = ($newStartDate.ToString("yyyy-MM-dd"))
        $jobName = "AAD" + $dateToProcess

        Start-RSJob -Name $jobName -ScriptBlock $launchSearch -FunctionsToImport Write-Log, Connect-MicrosoftGraphApplication, Get-MicrosoftGraphLogs -ArgumentList $newStartDate, $newEndDate, $currentPath, $tenantSize, $dumpLogs, $P1Enabled, $cert, $appId, $tenant

        $maxJobRunning = 3
        if ($tenantSize -eq "huge"){
            $maxJobRunning = 1
        }

        $jobRunningCount = (Get-RSJob | Where-Object {$_.State -eq "Running"} | Measure-Object).Count
        while ($jobRunningCount -ge $maxJobRunning){
            Start-Sleep -Seconds 1
            $jobRunningCount = (Get-RSJob | Where-Object {$_.State -eq "Running"} | Measure-Object).Count
        }
        $jobsDone = Get-RSJob | Where-Object {$_.State -eq "Completed"}
        if ($jobsDone){
            foreach ($jobDone in $jobsDone){
                "Runspace Job $($jobDone.Name) has finished - dumping log" | Write-Log -LogPath $logFile
                $logFileName = $jobDone.Name + ".log"
                Get-Content $logFileName | Out-File $logFile -Encoding UTF8 -Append
                Remove-Item $logFileName -Confirm:$false -Force
                $jobDone | Remove-RSJob
                "Runspace Job $($jobDone.Name) finished - job removed" | Write-Log -LogPath $logFile
            }
        }
        $jobsFailed = Get-RSJob | Where-Object {$_.State -eq "Failed"}
        if ($jobsFailed){
            foreach ($jobFailed in $jobsFailed){
                "Runspace Job $($jobFailed.Name) failed with error $($jobFailed.Error)" | Write-Log -LogPath $logFile -LogLevel "Error"
                "Runspace Job $($jobFailed.Name) failed - dumping log" | Write-Log -LogPath $logFile -LogLevel "Error"
                $logFileName = $jobFailed.Name + ".log"
                Get-Content $logFileName | Out-File $logFile -Encoding UTF8 -Append
                Remove-Item $logFileName -Confirm:$false -Force
                $jobFailed | Remove-RSJob
                "Runspace Job $($jobFailed.Name) failed - job removed" | Write-Log -LogPath $logFile -LogLevel "Error"
            }
        }
    }

    # Waiting for final jobs to complete
    $jobRunningCount = (Get-RSJob | Where-Object {$_.State -eq "Running"} | Measure-Object).Count
    while ($jobRunningCount -ge 1){
        Start-Sleep -Seconds 1
        $jobRunningCount = (Get-RSJob | Where-Object {$_.State -eq "Running"} | Measure-Object).Count
    }
    $jobsDone = Get-RSJob | Where-Object {$_.State -eq "Completed"}
    if ($jobsDone){
        foreach ($jobDone in $jobsDone){
            "Runspace Job $($jobDone.Name) has finished - dumping log" | Write-Log -LogPath $logFile
            $logFileName = $jobDone.Name + ".log"
            Get-Content $logFileName | Out-File $logFile -Encoding UTF8 -Append
            Remove-Item $logFileName -Confirm:$false -Force
            $jobDone | Remove-RSJob
            "Runspace Job $($jobDone.Name) finished - job removed" | Write-Log -LogPath $logFile
        }
    }
    $jobsFailed = Get-RSJob | Where-Object {$_.State -eq "Failed"}
    if ($jobsFailed){
        foreach ($jobFailed in $jobsFailed){
            "Runspace Job $($jobFailed.Name) failed with error $($jobFailed.Error)" | Write-Log -LogPath $logFile -LogLevel "Error"
            "Runspace Job $($jobFailed.Name) failed - dumping log" | Write-Log -LogPath $logFile -LogLevel "Error"
            $logFileName = $jobFailed.Name + ".log"
            Get-Content $logFileName | Out-File $logFile -Encoding UTF8 -Append
            Remove-Item $logFileName -Confirm:$false -Force
            $jobFailed | Remove-RSJob
            "Runspace Job $($jobFailed.Name) failed - job removed" | Write-Log -LogPath $logFile -LogLevel "Error"
        }
    }
}
