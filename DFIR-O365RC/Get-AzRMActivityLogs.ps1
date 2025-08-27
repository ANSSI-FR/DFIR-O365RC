
function Get-AzRMActivityLogs {

    <#
    .SYNOPSIS
    The Get-AzRMActivityLogs function dumps in JSON files Azure Resource Manager activity logs for a specific time range.

    .EXAMPLE

    PS C:\>$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    PS C:\>$tenant = "example.onmicrosoft.com"
    PS C:\>$certificatePath = "./example.pfx"
    PS C:\>$endDate = Get-Date
    PS C:\>$startDate = $endDate.AddDays(-90)

    PS C:\>Get-AzRMActivityLogs -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath

    Dump all Azure Resource Manager activity logs for the last 90 days.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$startDate,
        [Parameter(Mandatory = $true)]
        [DateTime]$endDate,
        [Parameter(Mandatory = $true)]
        [String]$certificatePath,
        [Parameter(Mandatory = $true)]
        [String]$appId,
        [Parameter(Mandatory = $true)]
        [String]$tenant,
        [Parameter(Mandatory = $false)]
        [String]$logFile = "Get-AzRMActivityLogs.log"
    )
    $currentPath = (Get-Location).path

    $null, $needPassword, $certificateSecurePassword = Import-Certificate -certificatePath $certificatePath -logFile $logFile

    Connect-AzApplication -logFile $logFile -certificatePath $certificatePath -certificateSecurePassword $certificateSecurePassword -needPassword $needPassword -tenant $tenant -appId $appId

    $azureSubscriptionsFolder = $currentPath + "\azure_rm_subscriptions"

    if ((Test-Path $azureSubscriptionsFolder) -eq $false){
        New-Item $azureSubscriptionsFolder -Type Directory | Out-Null
    }

    $subscriptionsRaw = Get-AzSubscription -ErrorAction Stop
    $subscriptionsNameAndId =  $subscriptionsRaw | Select-Object Name, Id
    Write-Host "This application has access to the following subscriptions:"
    "This application has access to the following subscriptions:" | Write-Log -LogPath $logFile
    $subscriptionsNameAndId | Out-Host
    $subscriptionsNameAndId | Write-Log -LogPath $logFile
    $choice = Read-Host "Do you want to collect Azure Resource Manager activity logs for all [a], specific [s] or no [N] subscription ? [a/s/N]"
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
    else {
        Write-Error "No subscription was selected. Exiting"
        "No subscription was selected. Exiting" | Write-Log -LogPath $logFile -LogLevel Error
        exit
    }

    $outputFile = $azureSubscriptionsFolder + "\AzRMsubscriptions_" + $tenant + ".json"
    $subscriptionsRaw | ConvertTo-Json -Depth 99 | Out-File $outputFile -Encoding UTF8

    $launchSearch =
    {
        param($newStartDate, $newEndDate, $currentPath, $subscriptionId, $appId, $tenant, $certificatePath, [SecureString]$certificateSecurePassword, [Bool]$needPassword)

        Select-AzSubscription -SubscriptionID $subscriptionId -ErrorAction Stop

        $dateToProcess = ($newStartDate.ToString("yyyy-MM-dd"))
        $logFile = $currentPath + "\AzRM_" + $subscriptionId + "_" + $dateToProcess + ".log"
        $tenant = ($user).split("@")[1]

        $azureRMActivityFolder = $currentPath + "\azure_rm_activity"
        if ((Test-Path $azureRMActivityFolder) -eq $false){
            New-Item $azureRMActivityFolder -Type Directory
        }

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
            "Processing Azure Resource Manager activity logs between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newStartHour, $newEndHour) | Write-Log -LogPath $logFile

            $outputDate = "{0:yyyy-MM-dd}_{0:HH-00-00}" -f ($newStartHour)
            $dateStart = "{0:s}" -f $newStartHour + "Z"
            $dateEnd  = "{0:s}" -f $newEndHour + "Z"

            $folderToProcess = $azureRMActivityFolder + "\" + $dateToProcess
            if ((Test-Path $folderToProcess) -eq $false){
                New-Item $folderToProcess -Type Directory
            }
            $outputFile = $folderToProcess + "\AzRM_" + $tenant + "_" + $subscriptionId + "_" + $outputDate + ".json"
            Get-AzureRMActivityLog -dateStart $dateStart -dateEnd $dateEnd -certificatePath $certificatePath -certificateSecurePassword $certificateSecurePassword -needPassword $needPassword -appId $appId -tenant $tenant -logFile $logFile -outputFile $outputFile
        }
    }

    $totalTimeSpan = (New-TimeSpan -Start $startDate -End $endDate)

    if (($totalTimeSpan.Hours -eq 0) -and ($totalTimeSpan.Minutes -eq 0) -and ($totalTimeSpan.Seconds -eq 0)){
        $totaldays = $totalTimeSpan.days
        $totalLoops = $totaldays
    }
    else {
        $totaldays = $totalTimeSpan.days + 1
        $totalLoops = $totalTimeSpan.days
    }

    Get-RSJob | Remove-RSJob -Force

    foreach ($subscription in $wantedSubscriptionsNameAndId){
        Write-Host "Starting processing Azure Resource Manager activity logs for $($subscription.Name) subscription"
        "Starting processing Azure Resource Manager activity logs for $($subscription.Name) subscription" | Write-Log -LogPath $logFile

        for ($d=0; $d -le $totalLoops; $d++){
            if ($d -eq 0){
                $newStartDate = $startDate
                $newEndDate = Get-Date("{0:yyyy-MM-dd} 00:00:00.000" -f ($newStartDate.AddDays(1)))
            }
            elseif ($d -eq $totaldays){
                $newEndDate = $endDate
                $newStartDate = Get-Date("{0:yyyy-MM-dd} 00:00:00.000" -f ($newEndDate))
            }
            else {
                $newStartDate = $newEndDate
                $newEndDate = $newEndDate.AddDays(1)
            }

            "Lauching job number $($d) with startDate {0:yyyy-MM-dd} {0:HH:mm:ss} and endDate {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newStartDate, $newEndDate) | Write-Log -LogPath $logFile
            $dateToProcess = ($newStartDate.ToString("yyyy-MM-dd"))
            $subscriptionId = $subscription.Id
            $jobName = "AzRM_" + $subscriptionId + "_" + $dateToProcess

            Start-RSJob -Name $jobName -ScriptBlock $launchSearch -FunctionsToImport Write-Log, Connect-AzApplication, Get-AzureRMActivityLog -ArgumentList $newStartDate, $newEndDate, $currentPath, $subscriptionId, $appId, $tenant, $certificatePath, $certificateSecurePassword, $needPassword

            $maxJobRunning = 3

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
}