function Get-O365Purview {

    <#
    .SYNOPSIS
    The Get-O365Purview function is the inner function that handles the different jobs and calling of Get-UnifiedAuditLogPurview functions
    #>

    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Unfiltered","Operations","RecordTypes","FreeText","IPAddresses","UserIds")]
        [String]$requestType,
        [Parameter(Mandatory = $false)]
        [string[]]$recordTypes = @(),
        [Parameter(Mandatory = $false)]
        [string[]]$operations = @(),
        [Parameter(Mandatory = $false)]
        [string[]]$freeTexts = @(),
        [Parameter(Mandatory = $false)]
        [string[]]$IPAddresses = @(),
        [Parameter(Mandatory = $false)]
        [string[]]$userIds = @(),
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
        [String]$logFile = "Get-O365Purview.log"
    )

    $currentPath = (Get-Location).path

    $dateDelta = $endDate - $startDate
    if ($dateDelta -gt 180){
        Write-Error "You can not query more than 180 days using Purview. Exiting"
        "You can not query more than 180 days using Purview. Exiting" | Write-Log -LogPath $logFile -LogLevel "Error"
        exit
    }

    $launchSearch =
    {
        param($cert, $appId, $tenant, $newStartDate, $newEndDate, $requestType, $recordTypes, $operations, $freeTexts, $IPAddresses, $userIds, $currentPath)
     
        $dateToProcess = ($newStartDate.ToString("yyyy-MM-dd"))
        $actualdate = $(get-date -f yyyy-MM-dd-hh-mm-ss)
        $logFile = $currentPath + "\UnifiedAuditLogPurview_" + $dateToProcess + ".log"

        $unifiedAuditFolder = $currentPath + "\O365_unified_audit_logs_purview"
        if ((Test-Path $unifiedAuditFolder) -eq $false){
            New-Item $unifiedAuditFolder -Type Directory
        }

        $folderToProcess = $unifiedAuditFolder + "\" + $dateToProcess
        if ((Test-Path $folderToProcess) -eq $false){
            New-Item $folderToProcess -Type Directory
        }

        "Connecting to Microsoft Graph" | Write-Log -LogPath $logFile -LogLevel "Info"
        Connect-MicrosoftGraphApplication -certificate $cert -appId $appId -tenant $tenant -logFile $logFile

        "Processing Unified Audit Log (using Purview) entries between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newStartDate, $newEndDate) | Write-Log -LogPath $logFile
        $outputDate = "{0:yyyy-MM-dd}" -f ($dateToProcess)
        $outputFile = $folderToProcess + "\UnifiedAuditLogPurview_" + $tenant + "_" + $outputDate + ".json"
        $sessionName = $(New-Guid).Guid

        if ($requestType -eq "Unfiltered"){
            # Used in Get-O365Full with no parameters
            Get-UnifiedAuditLogPurview -startDate $newStartDate -endDate $newEndDate -sessionName $sessionName -requestType $requestType -certificate $cert -appId $appId -tenant $tenant -logFile $logFile -outputFile $outputFile
        }
        elseif ($requestType -eq "RecordTypes"){
            # Used in Get-O365Full with the "recordTypes" parameter
            # Used in Get-O365Defender
            Get-UnifiedAuditLogPurview -startDate $newStartDate -endDate $newEndDate -sessionName $sessionName -requestType $requestType -recordTypes $recordTypes -certificate $cert -appId $appId -tenant $tenant -logFile $logFile -outputFile $outputFile
        }
        elseif ($requestType -eq "Operations"){
            # Used in Get-O365Light
            Get-UnifiedAuditLogPurview -startDate $newStartDate -endDate $newEndDate -sessionName $sessionName -requestType $requestType -operations $operations -certificate $cert -appId $appId -tenant $tenant -logFile $logFile -outputFile $outputFile
        }
        elseif ($requestType -eq "UserIds"){
            # Used in Search-O365
            $outputFile = $folderToProcess + "\UnifiedAuditLogPurview_" + $tenant + "_" + $outputDate + "_" + $requestType + "_" + $actualDate + ".json"
            Get-UnifiedAuditLogPurview -startDate $newStartDate -endDate $newEndDate -sessionName $sessionName -requestType $requestType -userIds $userIds -certificate $cert -appId $appId -tenant $tenant -logFile $logFile -outputFile $outputFile
        }
        elseif ($requestType -eq "FreeText"){
            # Used in Search-O365
            for ($i=0; $i -lt $($freeTexts.Count); $i++){
                $freeText = $freeTexts[$i]
                "Collecting events (using Purview) for freeText $($i+1) (`"$freeText`") between $newStartDate - $newEndDate" | Write-Log -LogPath $logFile -LogLevel "Info"
                $outputFile = $folderToProcess + "\UnifiedAuditLogPurview_" + $tenant + "_" + $outputDate + "_" + $requestType + "_" + $actualDate + "_" + $i + ".json"
                Get-UnifiedAuditLogPurview -startDate $newStartDate -endDate $newEndDate -sessionName $sessionName -requestType $requestType -freeText $freeText -certificate $cert -appId $appId -tenant $tenant -logFile $logFile -outputFile $outputFile
            }
        }
        elseif ($requestType -eq "IPAddresses"){
            # Used in Search-O365
            $outputFile = $folderToProcess + "\UnifiedAuditLogPurview_" + $tenant + "_" + $outputDate + "_" + $requestType + "_" + $actualDate + ".json"
            Get-UnifiedAuditLogPurview -startDate $newStartDate -endDate $newEndDate -sessionName $sessionName -requestType $requestType -IPAddresses $IPAddresses -certificate $cert -appId $appId -tenant $tenant -logFile $logFile -outputFile $outputFile
        }
    }

    $cert, $null, $null = Import-Certificate -certificatePath $certificatePath -logFile $logFile

    Get-RSJob | Remove-RSJob -Force
    
    $newStartDate = $startDate
    $newEndDate = $endDate

    "Lauching job with startDate {0:yyyy-MM-dd} and endDate {1:yyyy-MM-dd}" -f ($newStartDate, $newEndDate) | Write-Log -LogPath $logFile
    $dateToProcess = ($newStartDate.ToString("yyyy-MM-dd"))
    $jobName = "UnifiedAuditLogPurview_" + $dateToProcess

    Start-RSJob -Name $jobName -ScriptBlock $launchSearch -FunctionsToImport Get-UnifiedAuditLogPurview, Write-Log -ArgumentList $cert, $appId, $tenant, $newStartDate, $newEndDate, $requestType, $recordTypes, $operations, $freeTexts, $IPAddresses, $userIds, $currentPath

    $maxJobRunning = 1

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

function Get-O365 {

    <#
    .SYNOPSIS
    The Get-O365 function is the inner function that handles the different jobs and calling of Get-LargeUnifiedAuditLog and Get-MailboxAuditLog functions
    #>

    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Unfiltered","Operations","RecordTypes","FreeText","IPAddresses","UserIds")]
        [String]$requestType,
        [Parameter(Mandatory = $false)]
        [string[]]$recordTypes = @(),
        [Parameter(Mandatory = $false)]
        [string[]]$operations = @(),
        [Parameter(Mandatory = $false)]
        [string[]]$freeTexts = @(),
        [Parameter(Mandatory = $false)]
        [string[]]$IPAddresses = @(),
        [Parameter(Mandatory = $false)]
        [string[]]$userIds = @(),
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
        [String]$logFile = "Get-O365.log"
    )

    $currentPath = (Get-Location).path

    $launchSearch =
    {
        param($cert, $appId, $tenant, $newStartDate, $newEndDate, $requestType, $recordTypes, $operations, $freeTexts, $IPAddresses, $userIds, $currentPath)

        $dateToProcess = ($newStartDate.ToString("yyyy-MM-dd"))
        $actualdate = $(get-date -f yyyy-MM-dd-hh-mm-ss)
        $logFile = $currentPath + "\UnifiedAuditLog_" + $dateToProcess + ".log"

        $unifiedAuditFolder = $currentPath + "\O365_unified_audit_logs"
        if ((Test-Path $unifiedAuditFolder) -eq $false){
            New-Item $unifiedAuditFolder -Type Directory
        }

        "Connecting to Exchange Online" | Write-Log -LogPath $logFile -LogLevel "Info"
        Connect-ExchangeOnlineApplication -logFile $logFile -certificate $cert -appId $appId -organization $tenant

        "Processing Unified Audit Log entries for day $($dateToProcess)" | Write-Log -LogPath $logFile
        $folderToProcess = $unifiedAuditFolder + "\" + $dateToProcess
        if ((Test-Path $folderToProcess) -eq $false){
            New-Item $folderToProcess -Type Directory
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
            "Processing Unified Audit Log entries between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newStartHour, $newEndHour) | Write-Log -LogPath $logFile
            $outputDate = "{0:yyyy-MM-dd}_{0:HH-00-00}" -f ($newStartHour)
            $outputFile = $folderToProcess + "\UnifiedAuditLog_" + $tenant + "_" + $outputDate + ".json"
            $sessionName = $(New-Guid).Guid

            if ($requestType -eq "Unfiltered"){
                # Used in Get-O365Full with no parameters
                Get-LargeUnifiedAuditLog -startDate $newStartHour -endDate $newEndHour -sessionName $sessionName -outputFile $outputFile -logFile $logFile -requestType $requestType -certificate $cert -appId $appId -tenant $tenant              
            }
            elseif ($requestType -eq "RecordTypes"){
                # Used in Get-O365Full with the "recordTypes" parameter
                # Used in Get-O365Defender
                foreach ($recordType in $recordTypes){
                    "Collecting $recordType events for $newStartHour - $newEndHour" | Write-Log -LogPath $logFile -LogLevel "Info"
                    $outputFile = $folderToProcess + "\UnifiedAuditLog_" + $tenant + "_" + $outputDate + "_" + $recordType + ".json"
                    Get-LargeUnifiedAuditLog -startDate $newStartHour -endDate $newEndHour -sessionName $sessionName -recordType $recordType -outputFile $outputFile -logFile $logFile -requestType $requestType -certificate $cert -appId $appId -tenant $tenant
                }
            }
            elseif ($requestType -eq "Operations"){
                # Used in Get-O365Light
                Get-LargeUnifiedAuditLog -startDate $newStartHour -endDate $newEndHour -sessionName $sessionName -operations $operations -outputFile $outputFile -logFile $logFile -requestType $requestType -certificate $cert -appId $appId -tenant $tenant
            }
            elseif ($requestType -eq "UserIds"){
                # Used in Search-O365
                $outputFile = $folderToProcess + "\UnifiedAuditLog_" + $tenant + "_" + $outputDate + "_" + $requestType + "_" + $actualDate + ".json"
                Get-LargeUnifiedAuditLog -startDate $newStartHour -endDate $newEndHour -sessionName $sessionName -userIds $userIds -outputFile $outputFile -logFile $logFile -requestType $requestType -certificate $cert -appId $appId -tenant $tenant
                
                $mailboxAuditFolder = $currentPath + "\Exchange_mailbox_audit_logs"
                if ((Test-Path $mailboxAuditFolder) -eq $false){
                    New-Item $mailboxAuditFolder -Type Directory
                }
                $mailboxAuditFolderToProcess = $mailboxAuditFolder + "\" + $dateToProcess
                if ((Test-Path $mailboxAuditFolderToProcess) -eq $false){
                    New-Item $mailboxAuditFolderToProcess -Type Directory
                }
                $outputfileWithoutJson = $mailboxAuditFolderToProcess + "\MailboxAuditLog_" + $tenant + "_" + $outputdate + "_" + $requesttype + "_" + $actualdate
                "Processing MailboxAudit entries between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss}" -f ($newStartHour, $newEndHour) | Write-Log -LogPath $logFile
                Get-MailboxAuditLog -startDate $newStartHour -endDate $newEndHour -outputFileWithoutJson $outputFileWithoutJson -logFile $logFile -userIds $userIds -certificate $cert -appId $appId -tenant $tenant
            }
            elseif ($requestType -eq "FreeText"){
                # Used in Search-O365
                for ($i=0; $i -lt $($freeTexts.Count); $i++){
                    $freeText = $freeTexts[$i]
                    "Collecting events for freeText $($i+1) (`"$freeText`") between $newStartHour - $newEndHour" | Write-Log -LogPath $logFile -LogLevel "Info"
                    $outputFile = $folderToProcess + "\UnifiedAuditLog_" + $tenant + "_" + $outputDate + "_" + $requestType + "_" + $actualDate + "_" + $i + ".json"
                    Get-LargeUnifiedAuditLog -startDate $newStartHour -endDate $newEndHour -sessionName $sessionName -freeText $freeText -outputFile $outputFile -logFile $logFile -requestType $requestType -certificate $cert -appId $appId -tenant $tenant
                }
            }
            elseif ($requestType -eq "IPAddresses"){
                # Used in Search-O365
                $outputFile = $folderToProcess + "\UnifiedAuditLog_" + $tenant + "_" + $outputDate + "_" + $requestType + "_" + $actualDate + ".json"
                Get-LargeUnifiedAuditLog -startDate $newStartHour -endDate $newEndHour -sessionName $sessionName -IPAddresses $IPAddresses -outputFile $outputFile -logFile $logFile -requestType $requestType -certificate $cert -appId $appId -tenant $tenant
            }
        }
    }

    $cert, $null, $null = Import-Certificate -certificatePath $certificatePath -logFile $logFile

    $totalTimeSpan = (New-TimeSpan -Start $startDate -End $endDate)

    if (($totalTimeSpan.Hours -eq 0) -and ($totalTimeSpan.Minutes -eq 0) -and ($totalTimeSpan.Seconds -eq 0)){
        $totalDays = $totalTimeSpan.days
        $totalLoops = $totalDays
    }
    else {
        $totalDays = $totalTimeSpan.days + 1
        $totalLoops = $totalTimeSpan.days
    }

    Get-RSJob | Remove-RSJob -Force

    "Checking the status of Unified Audit Log"| Write-Log -LogPath $logFile
    Connect-ExchangeOnlineApplication -logFile $logFile -certificate $cert -appId $appId -organization $tenant -commandNames "Get-AdminAuditLogConfig"
    try {
        $adminAuditLogConfig = Get-AdminAuditLogConfig
        $isIngestionEnabled = $adminAuditLogConfig.UnifiedAuditLogIngestionEnabled
        if (-not $isIngestionEnabled){
            Write-Error "Log ingestion is not enabled. This means that the unified audit log is disabled. This is not the default setting, please check https://learn.microsoft.com/en-us/purview/audit-log-enable-disable for more information"
            "Log ingestion is not enabled. This means that the unified audit log is disabled. This is not the default setting, please check https://learn.microsoft.com/en-us/purview/audit-log-enable-disable for more information" | Write-Log -LogPath $logFile -LogLevel "Error"
            $adminAuditLogConfig | ConvertTo-Json -Depth 99 | Write-Log -LogPath $logFile -LogLevel "Error"
        }
        else {
            $unifiedAuditLogFirstOptInDate = $adminAuditLogConfig.UnifiedAuditLogFirstOptInDate.ToString()
            "Unified Audit Log First Opt In Date : $unifiedAuditLogFirstOptInDate" | Write-Log -LogPath $logFile -LogLevel "Info"
        }
    }
    catch {
        $errormessage = $_.Exception.Message
        Write-Warning "Error while trying to execute Get-AdminAuditLogConfig : $errormessage. Continuing"
        "Error while trying to execute Get-AdminAuditLogConfig : $errormessage. Continuing" | Write-Log -LogPath $logFile -LogLevel "Warning"
    }

    "Checking permissions for app $($appId)"| Write-Log -LogPath $logFile
    Connect-ExchangeOnlineApplication -logFile $logFile -certificate $cert -appId $appId -organization $tenant
    try {
        $null = Search-UnifiedAuditLog -startDate (Get-Date).AddDays(-1) -endDate (Get-Date) -ResultSize 1
    }
    catch {
        $errormessage = $_.Exception.Message
        if ($errormessage -like "*The term 'Search-UnifiedAuditLog'*"){
            Write-Error "$appId does not have the required permissions to get Microsoft 365 Unified Audit Logs: does not have the 'View-Only Audit Logs' role on https://admin.exchange.microsoft.com/. Please delete and re-create the application. Exiting"
            "$appId does not have the required permissions to get Microsoft 365 Unified Audit Logs: does not have the 'View-Only Audit Logs' role on https://admin.exchange.microsoft.com/. Please delete and re-create the application. Exiting" | Write-Log -LogPath $logFile -LogLevel "Error"
            exit
        }
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
        $jobName = "UnifiedAuditLog_" + $dateToProcess

        Start-RSJob -Name $jobName -ScriptBlock $launchSearch -FunctionsToImport Connect-ExchangeOnlineApplication, Write-Log, Get-LargeUnifiedAuditLog, Get-MailboxAuditLog -ArgumentList $cert, $appId, $tenant, $newStartDate, $newEndDate, $requestType, $recordTypes, $operations, $freeTexts, $IPAddresses, $userIds, $currentPath

        $maxJobRunning = 1

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

function Get-O365Full {

    <#
    .SYNOPSIS
    The Get-O365Full function dumps in JSON files all or some specific record types from the Unified Audit Log for a specific time range.
    The list of record types can be found here: https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#enum-auditlogrecordtype---type-edmint32.
    Using the "-purview" switch, you can search using the Purview backend, instead of the Unified Audit Log.

    .EXAMPLE

    PS C:\>$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    PS C:\>$tenant = "example.onmicrosoft.com"
    PS C:\>$certificatePath = "./example.pfx"
    PS C:\>$endDate = Get-Date
    PS C:\>$startDate = $endDate.AddDays(-90)

    PS C:\>Get-O365Full -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath
    Dump all events from the Unified Audit Log for the last 90 days.

    PS C:\>Get-O365Full -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -recordTypes "AzureActiveDirectory","OneDrive"
    Dump all events related to Entra ID and OneDrive from the Unified Audit Log for the last 90 days.

    PS C:\>$startDate = $endDate.AddDays(-180)
    PS C:\>Get-O365Full -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -purview
    Dump all events from the Unified Audit Log for the last 180 days, using the Purview backend.
    #>

    param (
        [Parameter(Mandatory = $false)]
        [string[]]$recordTypes,
        [Parameter(Mandatory = $false)]
        [Switch]$purview = $false,
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
        [String]$logFile = "Get-O365Full.log"
    )

    if ($purview){
        if ($null -ne $recordTypes){
            Get-O365Purview -startDate $startDate -endDate $endDate -recordTypes $recordTypes -requestType "RecordTypes" -tenant $tenant -appId $appId -certificatePath $certificatePath -logFile $logFile
        }
        else {
            Get-O365Purview -startDate $startDate -endDate $endDate -requestType "Unfiltered" -tenant $tenant -appId $appId -certificatePath $certificatePath -logFile $logFile
        }
    }
    else {
        if ($null -ne $recordTypes){
            Get-O365 -startDate $startDate -endDate $endDate -recordTypes $recordTypes -requestType "RecordTypes" -tenant $tenant -appId $appId -certificatePath $certificatePath -logFile $logFile
        }
        else {
            Get-O365 -startDate $startDate -endDate $endDate -requestType "Unfiltered" -tenant $tenant -appId $appId -certificatePath $certificatePath -logFile $logFile
        }
    }
}

function Get-O365Light {

    <#
    .SYNOPSIS
    The Get-O365Light function dumps in JSON files a subset of events related to operations of interest from the Unified Audit Log for a specific time range.
    Using the "-purview" switch, you can search using the Purview backend, instead of the Unified Audit Log.
    Using the "-mailboxlogin" switch, you can add the "MailboxLogin" operations. If mailbox auditing is enabled, be aware that this can represent a lot of events.
    Using the "userLogin" switch, you can add the "UserLoggedIn" and "UserLoginFailed" operations. Be aware that this can represent a lot of events.

    .EXAMPLE

    PS C:\>$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    PS C:\>$tenant = "example.onmicrosoft.com"
    PS C:\>$certificatePath = "./example.pfx"
    PS C:\>$endDate = Get-Date
    PS C:\>$startDate = $endDate.AddDays(-90)

    PS C:\>Get-O365Light -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -operationsSet "all"
    Dump all events related to operations of interest from the Unified Audit Log for the last 90 days.

    PS C:\>Get-O365Light -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -operationsSet "allButAzureAD"
    Dump all but Entra ID events related to operations of interest from the Unified Audit Log for the last 90 days.

    PS C:\>Get-O365Light -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -operationsSet "ExchangeOnly" -mailboxLogin -userLogin
    Dump Exchange events related to operations of interest, mailbox login events and user login events from the Unified Audit Log for the last 90 days.

    PS C:\>Get-O365Light -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -operationsSet "ExchangeOnly"
    Dump Exchange events related to operations of interest from the Unified Audit Log for the last 90 days.

    PS C:\>Get-O365Light -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -operationsSet "OneDrive_Sharepoint_Teams_YammerOnly"
    Dump OneDrive, Sharepoint, Teams and Yammer events related to operations of interest from the Unified Audit Log for the last 90 days.

    PS C:\>Get-O365Light -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -operationsSet "AzureADOnly"
    Dump Entra ID events related to operations of interest from the Unified Audit Log for the last 90 days.

    PS C:\>Get-O365Light -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -operationsSet "SecurityAlertsOnly"
    Dump Security Alerts events related to operations of interest from the Unified Audit Log for the last 90 days.

    PS C:\>$startDate = $endDate.AddDays(-180)
    PS C:\>Get-O365Light -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -operationsSet "all" -purview
    Dump all events related to operations of interest from the Unified Audit Log for the last 180 days, using the Purview backend.
    #>

    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet("all","allButAzureAD","ExchangeOnly","OneDrive_Sharepoint_Teams_YammerOnly", "AzureADOnly", "SecurityAlertsOnly")]
        [String]$operationsSet = "all",
        [Parameter(Mandatory = $false)]
        [Switch]$mailboxLogin=$false,
        [Parameter(Mandatory = $false)]
        [Switch]$userLogin=$false,
        [Parameter(Mandatory = $false)]
        [Switch]$purview = $false,
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
        [String]$logFile = "Get-O365Light.log"
    )

    $OneDrive_Sharepoint_Teams_YammerOnly_operations = @(
        "AddedToGroup",
        "AnonymousLinkCreated",
        "AnonymousLinkUsed",
        "AppInstalled",
        "DeviceAccessPolicyChanged",
        "FileMalwareDetected",
        "GeoAdminAdded",
        "MemberRoleChanged",
        "NetworkAccessPolicyChanged",
        "NetworkSecurityConfigurationUpdated",
        "New-CSTeamsAppPermissionPolicy",
        "PermissionLevelModified",
        "Set-CSTeamsAppPermissionPolicy",
        "SharingInvitationAccepted",
        "SharingInvitationBlocked",
        "SharingPolicyChanged",
        "SiteCollectionAdminAdded",
        "SoftDeleteSettingsUpdated",
        "SupervisorAdminToggled",
        "TeamSettingChanged",
        "TeamsTenantSettingChanged",
        "UnmanagedSyncClientBlocked"
    )

    $AzureAD_operations = @(
        "Add application",
        "Add app role assignment grant to user",
        "Add app role assignment to service principal",
        "Add delegated permission grant",
        "Add delegation entry",
        "Add domain to company",
        "Add group",
        "Add member to group",
        "Add member to role",
        "Add OAuth2PermissionGrant",
        "Add partner to company",
        "Add service principal",
        "Add service principal credentials",
        "Add unverified domain",
        "Add verified domain",
        "Consent to application",
        "Delete group",
        "Disable Desktop Sso for a specific domain",
        "New-ConditionalAccessPolicy",
        "Register connector",
        "Remove delegation entry",
        "Remove member from group",
        "Remove member from role",
        "Remove service principal",
        "Remove service principal credentials",
        "Remove verified domain",
        "Set-AdminAuditLogConfig",
        "Set-ConditionalAccessPolicy",
        "Set delegation entry",
        "Set domain authentication",
        "Set federation settings on domain",
        "Update application",
        "Update application – Certificates and secrets management ",
        "Update application – Certificates and secrets management",
        "Update domain",
        "Update group",
        "Verify domain"
    )

    $Exchange_operations = @(
        "AddFolderPermissions",
        "Add-MailboxPermission",
        "Add-RecipientPermission",
        "Hard Delete user",
        "New-InboxRule",
        "New-TransportRule",
        "RemoveFolderPermissions",
        "Remove-MailboxPermission",
        "Remove-RecipientPermission",
        "SearchCreated",
        "SearchExported",
        "Set-CASMailbox",
        "Set-InboxRule",
        "Set-Mailbox",
        "Set-TransportRule",
        "UpdateInboxRules"
    )

    $securityAlerts_operations = @(
        "AlertEntityGenerated",
        "AlertTriggered"
    )

    $mailboxLogin_operation = @(
        "MailboxLogin"
    )

    $userLogin_operations = @(
        "UserLoggedIn",
        "UserLoginFailed"
    )

    $operationsToProcess = @()

    if ($mailboxLogin){
        Write-Warning "Retrieving MailboxLogin operations. If mailbox auditing is enabled, be aware that this can represent a lot of events."
        $confirmation = Read-Host "Continue ? [y/N]"
        if ($confirmation.ToUpper() -eq "Y"){
            "Retrieving MailboxLogin operations. If mailbox auditing is enabled, be aware that this can represent a lot of events." | Write-Log -LogPath $logFile -LogLevel "Warning"
            $operationsToProcess = $($operationsToProcess ; $mailboxLogin_operation)
        }
    }

    if ($userLogin){
        Write-Warning "Retrieving UserLoggedIn and UserLoggedInFailed operations. Be aware that this can represent a lot of events."
        $confirmation = Read-Host "Continue ? [y/N]"
        if ($confirmation.ToUpper() -eq "Y"){
            "Retrieving UserLoggedIn and UserLoggedInFailed operations. Be aware that this can represent a lot of events." | Write-Log -LogPath $logFile -LogLevel "Warning"
            $operationsToProcess = $($operationsToProcess ; $userLogin_operations)
        }
    }

    if ($operationsSet -eq "all"){
        $operationsToProcess = $($operationsToProcess ; $OneDrive_Sharepoint_Teams_YammerOnly_operations ; $AzureAD_operations ; $Exchange_operations ; $securityAlerts_operations)
        "Fetching all operations of interest, this is the default configuration" | Write-Log -LogPath $logFile
    }
    elseif ($operationsSet -eq "allButAzureAD"){
        $operationsToProcess = $($operationsToProcess ; $OneDrive_Sharepoint_Teams_YammerOnly_operations ; $Exchange_operations ; $securityAlerts_operations)
        "Fetching all operations of interest, except Entra ID related operations" | Write-Log -LogPath $logFile
    }
    elseif ($operationsSet -eq "ExchangeOnly"){
        $operationsToProcess = $($operationsToProcess ; $Exchange_operations)
        "Fetching only Exchange Online operations of interest" | Write-Log -LogPath $logFile
    }
    elseif ($operationsSet -eq "OneDrive_Sharepoint_Teams_YammerOnly"){
        $operationsToProcess = $($operationsToProcess ; $OneDrive_Sharepoint_Teams_YammerOnly_operations)
        "Fetching only OneDrive, SharePoint, Teams and Yammer operations of interest" | Write-Log -LogPath $logFile
    }
    elseif ($operationsSet -eq "SecurityAlertsOnly"){
        $operationsToProcess = $($operationsToProcess ; $securityAlerts_operations)
        "Fetching only Security Alerts operations of interest" | Write-Log -LogPath $logFile
    }
    elseif ($operationsSet -eq "AzureADOnly"){
        $operationsToProcess = $($operationsToProcess ; $AzureAD_operations)
        "Fetching only Entra ID operations of interest" | Write-Log -LogPath $logFile
    }

    if ($purview){
        Get-O365Purview -startDate $startDate -endDate $endDate -operations $operationsToProcess -requestType "Operations" -tenant $tenant -appId $appId -certificatePath $certificatePath -logFile $logFile
    }
    else {
        Get-O365 -startDate $startDate -endDate $endDate -operations $operationsToProcess -requestType "Operations" -tenant $tenant -appId $appId -certificatePath $certificatePath -logFile $logFile
    }

}

function Get-O365Defender {

    <#
    .SYNOPSIS
    The Get-O365Defender function dumps in JSON files events related to Microsoft Defender for Microsoft 365 in the Unified Audit Log for a specific time range. You need Defender for Microsoft 365 Plan 1 or 2, or Microsoft 365 A5/E5/F5/G5 Security to retrieve such logs.
    Using the "-purview" switch, you can search using the Purview backend, instead of the Unified Audit Log.

    .EXAMPLE

    PS C:\>$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    PS C:\>$tenant = "example.onmicrosoft.com"
    PS C:\>$certificatePath = "./example.pfx"
    PS C:\>$endDate = Get-Date
    PS C:\>$startDate = $endDate.AddDays(-90)

    PS C:\>Get-O365Defender -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath
    Dump all Microsoft Defender for Microsoft 365 events from the Unified Audit Log for the last 90 days.

    PS C:\>$startDate = $endDate.AddDays(-180)
    PS C:\>Get-O365Defender -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -purview
    Dump all Microsoft Defender for Microsoft 365 events from the Unified Audit Log for the last 180 days, using the Purview backend.
    #>

    param (
        [Parameter(Mandatory = $false)]
        [Switch]$purview = $false,
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
        [String]$logfile = "Get-O365Defender.log"
    )

    Write-Warning "You need Defender for Office 365 Plan 1 or 2, or Microsoft 365 A5/E5/F5/G5 Security to retrieve such logs"
    $confirmation = Read-Host "Continue ? [y/N]"
    if ($confirmation.ToUpper() -eq "Y"){
        $Defender_recordTypes = @(
            "AirAdminActionInvestigation",
            "AirInvestigation",
            "AirManualInvestigation",
            "Campaign",
            "MCASAlerts",
            "MSTIC",
            "ThreatFinder",
            "ThreatIntelligence",
            "ThreatIntelligenceAtpContent",
            "ThreatIntelligenceUrl",
            "WDATPAlerts"
        )
        if ($purview){
            Get-O365Purview -startDate $startDate -endDate $endDate -recordTypes $Defender_recordTypes -requestType "RecordTypes" -tenant $tenant -appId $appId -certificatePath $certificatePath -logFile $logFile
        }
        else {
            Get-O365 -startDate $startDate -endDate $endDate -recordTypes $Defender_recordTypes -requestType "RecordTypes" -tenant $tenant -appId $appId -certificatePath $certificatePath -logFile $logFile
        }
    }
}

function Search-O365 {

    <#
    .SYNOPSIS
    The Search-O365 function dumps in JSON files events related to specific free texts, IP addresses or users. Those events come from the Unified Audit Log and, when searching for users, the Mailbox Audit. The search is restrained to a specific time range.
    Using the "-purview" switch, you can search using the Purview backend, instead of the Unified Audit Log.

    .EXAMPLE

    PS C:\>$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    PS C:\>$tenant = "example.onmicrosoft.com"
    PS C:\>$certificatePath = "./example.pfx"
    PS C:\>$endDate = Get-Date
    PS C:\>$startDate = $endDate.AddDays(-90)

    PS C:\>Search-O365 -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -freeTexts "Python"
    PS C:\>Search-O365 -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -freeTexts "Python","Python3"
    Search for all events in the last 90 days which contain the string "Python" and "Python3"

    PS C:\>Search-O365 -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -IPAddresses "8.8.8.8"
    PS C:\>Search-O365 -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -IPAddresses "8.8.8.8","4.4.4.4"
    Search for all events in the last 90 days related to the activity of IP addresses "8.8.8.8" and "4.4.4.4"

    PS C:\>Search-O365 -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -userIds "user1@example.onmicrosoft.com"
    PS C:\>Search-O365 -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -userIds "user1@example.onmicrosoft.com","user2@example.onmicrosoft.com"
    Search for all events in the last 90 days related to the activity of users "user1@example.onmicrosoft.com" and "user2@example.onmicrosoft.com"

    PS C:\>$startDate = $endDate.AddDays(-180)
    PS C:\>Search-O365 -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -userIds "user1@example.onmicrosoft.com" -purview
    Search for all events in the last 180 days related to the activity of user "user1@example.onmicrosoft.com" using the Purview backend

    #>

    param (

        [Parameter(Mandatory = $false)]
        [string[]]$freeTexts,
        [Parameter(Mandatory = $false)]
        [string[]]$IPAddresses,
        [Parameter(Mandatory = $false)]
        [string[]]$userIds,
        [Parameter(Mandatory = $false)]
        [Switch]$purview = $false,
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
        [String]$logFile = "Search-O365.log"
    )

    if ($freeTexts){
        "Searching freeTexts $($freeTexts) in Unified Audit Log" | Write-Log -LogPath $logFile
        if ($purview){
            Get-O365Purview -startDate $startDate -endDate $endDate -freeTexts $freeTexts -requestType "FreeText" -tenant $tenant -appId $appId -certificatePath $certificatePath -logFile $logFile
        }
        else {
            Get-O365 -startDate $startDate -endDate $endDate -freeTexts $freeTexts -requestType "FreeText" -tenant $tenant -appId $appId -certificatePath $certificatePath -logFile $logFile
        }
    }
    if ($IPAddresses){
        "Searching IPAddresses $($IPAddresses) in Unified Audit Log" | Write-Log -LogPath $logFile
        if ($purview){
            Get-O365Purview -startDate $startDate -endDate $endDate -IPAddresses $IPAddresses -requestType "IPAddresses" -tenant $tenant -appId $appId -certificatePath $certificatePath -logFile $logFile
        }
        else {
            Get-O365 -startDate $startDate -endDate $endDate -IPAddresses $IPAddresses -requestType "IPAddresses" -tenant $tenant -appId $appId -certificatePath $certificatePath -logFile $logFile
        }
    }
    if ($userIds){
        "Searching userIds $($userIds) in Unified Audit Log and Mailbox Audit Log" | Write-Log -LogPath $logFile
        if ($purview){
            Get-O365Purview -startDate $startDate -endDate $endDate -userIds $userIds -requestType "UserIds" -tenant $tenant -appId $appId -certificatePath $certificatePath -logFile $logFile
        }
        else {
            Get-O365 -startDate $startDate -endDate $endDate -userIds $userIds -requestType "UserIds" -tenant $tenant -appId $appId -certificatePath $certificatePath -logFile $logFile
        }
    }
}