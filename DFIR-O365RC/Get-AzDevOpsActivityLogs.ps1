
function Get-AzDevOpsActivityLogs {

    <#
    .SYNOPSIS
    The Get-AzDevOpsActivityLogs function dumps in JSON files Azure DevOps activity logs for a specific time range.

    .EXAMPLE

    PS C:\>$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    PS C:\>$tenant = "example.onmicrosoft.com"
    PS C:\>$certificatePath = "./example.pfx"
    PS C:\>$endDate = Get-Date
    PS C:\>$startDate = $endDate.AddDays(-90)

    PS C:\>Get-AzDevOpsActivityLogs -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath

    Dump all Azure DevOps activity logs for the last 90 days.
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
        [String]$logFile = "Get-AzDevOpsActivityLogs.log"
    )
    $currentPath = (Get-Location).path

    $cert, $needPassword, $certificateSecurePassword = Import-Certificate -certificatePath $certificatePath -logFile $logFile

    Connect-AzApplication -logFile $logFile -certificatePath $certificatePath -certificateSecurePassword $certificateSecurePassword -needPassword $needPassword -tenant $tenant -appId $appId
    $token = Get-AzAccessToken -ResourceUrl "499b84ac-1321-427f-aa17-267ca6975798" -AsSecureString:$false -ErrorAction Stop
    $tenantId = (Get-AzTenant).Id

    $azureDevOpsOrganizationsFolder = $currentPath + "\azure_DevOps_orgs"
    if ((Test-Path $azureDevOpsOrganizationsFolder) -eq $false){
        New-Item $azureDevOpsOrganizationsFolder -Type Directory | Out-Null
    }

    $azureDevOpsOrganizationsRaw = Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.Token)"} -Method Get -ContentType "application/json" -ErrorAction Stop -Uri "https://aexprodweu1.vsaex.visualstudio.com/_apis/EnterpriseCatalog/Organizations?tenantId=$tenantId"
    if ($azureDevOpsOrganizationsRaw.Contains("Azure DevOps Services | Sign In")){
        Write-Warning "Could not enumerate the organizations the application has access to (this is a known bug from Microsoft). Please enter the name of the subscriptions manually"
        "Could not enumerate the organizations the application has access to (this is a known bug from Microsoft). Please enter the name of the subscriptions manually" | Write-Log -LogPath $logFile
        [System.Collections.ArrayList]$wantedOrganizationsNameAndId = @{}
        $read = $True
        Write-Host "Leave Blank and press 'Enter' to Stop"
        while ($read){
            $inputOrganizationName = Read-Host "Please enter the organization names, one by one, and press 'Enter'"
            if ($inputOrganizationName){
                $selectedInput = @{
                    "Organization Name" = $inputOrganizationName ;
                    "Organization Id" = "000000000000000000"
                }
                $wantedOrganizationsNameAndId.Add($selectedInput) | Out-Null
                Write-Host "Added $inputOrganizationName"
            }
            else {
                $read = $False
            }
        }
    }
    else {
        $outputFile = $azureDevOpsOrganizationsFolder + "\AzdevopsOrgs_" + $tenant + ".json"
        $azureDevOpsOrganizationsRaw | ConvertFrom-CSV | ConvertTo-Json -Depth 99 | Out-File $outputFile -Encoding UTF8
        $azureDevOpsOrganizationsNameAndId = $azureDevOpsOrganizationsRaw | ConvertFrom-CSV | ForEach-Object {$_ | Select-Object "Organization Name", "Organization Id"}
        Write-Host "The following organizations are accessible in your Entra ID tenant:"
        "The following organizations are accessible in your Entra ID tenant:" | Write-Log -LogPath $logFile
        $azureDevOpsOrganizationsNameAndId | Out-Host
        $azureDevOpsOrganizationsNameAndId | Write-Log -LogPath $logFile
        $choice = Read-Host "Do you want to collect Azure DevOps activity logs for all [a], specific [s] or no [N] organizations ? [a/s/N]"
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
        else {
            Write-Error "No organization was selected. Exiting"
            "No organization was selected. Exiting" | Write-Log -LogPath $logFile -LogLevel Error
            exit
        }
    }

    $launchSearch =
    {
        param($newStartDate, $newEndDate, $currentPath, $organizationName, $appId, $tenant, $certificatePath, [SecureString]$certificateSecurePassword, [Bool]$needPassword)

        $dateToProcess = ($newStartdate.ToString("yyyy-MM-dd"))
        $logFile = $currentPath + "\AzDevOps_" + $organizationName + "_" + $dateToProcess + ".log"

        $azureDevOpsActivityFolder = $currentPath + "\azure_DevOps_activity"
        if ((Test-Path $azureDevOpsActivityFolder) -eq $false){
            New-Item $azureDevOpsActivityFolder -Type Directory
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
            "Processing Azure DevOps activity logs between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newStartHour, $newEndHour) | Write-Log -LogPath $logFile

            $outputDate = "{0:yyyy-MM-dd}_{0:HH-00-00}" -f ($newStartHour)

            $auditStart = "{0:s}" -f $newStartHour + "Z"
            $auditEnd = "{0:s}" -f $newEndhour + "Z"
            $uri = "https://auditservice.dev.azure.com/$($organizationName)/_apis/audit/auditlog?startTime=$($auditStart)&endTime=$($auditEnd)&api-version=7.1-preview.1"
            $folderToProcess = $azureDevOpsActivityFolder + "\" + $dateToProcess
            if ((Test-Path $folderToProcess) -eq $false){
                New-Item $folderToProcess -Type Directory
            }
            $outputFile = $folderToProcess + "\AzDevOps_" + $tenant + "_" + $organizationName + "_" + $outputDate + ".json"

            Get-AzDevOpsAuditLogs -certificatePath $certificatePath -certificateSecurePassword $certificateSecurePassword -needPassword $needPassword -tenant $tenant -appId $appId -uri $uri -logFile $logFile -outputFile $outputFile
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

    foreach ($organization in $wantedOrganizationsNameAndId){
        Write-Host "Starting processing Azure DevOps activity logs for $($organization.'Organization Name') ($($organization.'Organization Id')) Azure DevOps organization"
        "Starting processing Azure DevOps activity logs for $($organization.'Organization Name') ($($organization.'Organization Id')) Azure DevOps organization" | Write-Log -LogPath $logFile

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
            $organizationName = $organization.'Organization Name'
            $jobName = "AzDevOps_" + $organizationName + "_" + $dateToProcess

            Start-RSJob -Name $jobName -ScriptBlock $Launchsearch -FunctionsToImport Write-Log, Get-AzDevOpsAuditLogs -ArgumentList $newStartDate, $newEndDate, $currentPath, $organizationName, $appId, $tenant, $certificatePath, $certificateSecurePassword, $needPassword

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