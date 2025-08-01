function Get-AADDevices {

    <#
    .SYNOPSIS
    The Get-AADDevices function dumps in JSON files Entra ID devices related events for a specific time range and tries to enrich the objects with the device configuration. If you want to limit the number of events considered by removing the "Update device" event, you can use the -filterUpdateDevice switch

    .EXAMPLE

    PS C:\>$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    PS C:\>$tenant = "example.onmicrosoft.com"
    PS C:\>$certificatePath = "./example.pfx"
    PS C:\>$endDate = Get-Date
    PS C:\>$startDate = $endDate.AddDays(-30)

    PS C:\>Get-AADDevices -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath

    Dump all Entra ID devices related events for the last 30 days.

    PS C:\>Get-AADDevices -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath -filterUpdateDevice

    Dump all Entra ID devices related events, excluding "Update device" events, for the last 30 days.
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
        [Switch]$filterUpdateDevice=$false,
        [Parameter(Mandatory = $false)]
        [String]$logFile = "Get-AADDevices.log"
    )

    $currentPath = (Get-Location).path

    $logFile = $currentPath + "\" + $logFile
    
    $cert, $null, $null = Import-Certificate -certificatePath $certificatePath -logFile $logFile

    $folderToProcess = $currentPath + '\azure_ad_devices'
    if ((Test-Path $folderToProcess) -eq $false){
        New-Item $folderToProcess -Type Directory | Out-Null
    }
    $outputFile = $folderToProcess + "\AADDevices_" + $tenant + ".json"
    
    $maxStartDate = (Get-Date).AddDays(-30)
    if ($startDate -lt $maxStartDate){
        Write-Warning "You can only get events in the last 30 days with the Audit Log. Setting startDate to $maxStartDate"
        "You can only get events in the last 30 days with the Audit Log. Setting startDate to $maxStartDate" | Write-Log -LogPath $logFile -LogLevel "Warning"
        if ($endDate -lt $maxStartDate){
            Write-Host "Incompatible endDate: $endDate. Exiting"
            "Incompatible endDate: $endDate. Exiting" | Write-Log -LogPath $logFile
            exit
        }
        $startDate = $maxStartDate
    }

    Connect-MicrosoftGraphApplication -certificate $cert -appId $appId -tenant $tenant -logFile $logFile

    # Check if Microsoft Entra ID P1 is enabled
    "Checking Microsoft Entra ID P1"| Write-Log -LogPath $logFile
    try {
        $null = Get-MgBetaAuditLogSignIn -Top 1 -All -ErrorAction Stop
    }
    catch {
        if ($_.ErrorDetails.Message -like "*RequestFromNonPremiumTenant*"){
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

    # Get device related events
    $auditStart = "{0:s}" -f $startDate + "Z"
    $auditEnd = "{0:s}" -f $endDate + "Z"
    if ($filterUpdateDevice -eq $true){
        "Getting all device related events via Audit Log (except 'Update device')" | Write-Log -LogPath $logFile
        $deviceEvents = Get-MgBetaAuditLogDirectoryAudit -All -Filter "activityDateTime ge $($auditStart) and activityDateTime lt $($auditEnd) and (activityDisplayName eq 'Add device' or activityDisplayName eq 'Device no longer compliant' or activityDisplayName eq 'Add registered users to device' or activityDisplayName eq 'Add registered owner to device' or activityDisplayName eq 'Delete device' or activityDisplayName eq 'Device no longer managed' or activityDisplayName eq 'Remove registered users from device' or activityDisplayName eq 'Remove registered owner from device')" -ErrorAction Stop
    }
    else {
        "Getting all device related events via Audit Log" | Write-Log -LogPath $logFile
        $deviceEvents = Get-MgBetaAuditLogDirectoryAudit -All -Filter "activityDateTime ge $($auditStart) and activityDateTime lt $($auditEnd) and (activityDisplayName eq 'Add device' or activityDisplayName eq 'Device no longer compliant' or activityDisplayName eq 'Add registered users to device' or activityDisplayName eq 'Add registered owner to device' or activityDisplayName eq 'Delete device' or activityDisplayName eq 'Device no longer managed' or activityDisplayName eq 'Remove registered users from device' or activityDisplayName eq 'Remove registered owner from device' or activityDisplayName eq 'Update device')" -ErrorAction Stop
    }
    if ($deviceEvents -ne $null){$deviceEvents = $deviceEvents.ToJsonString() | ConvertFrom-Json}

    # Get all devices
    "Getting all devices" | Write-Log -LogPath $logFile
    $allDevices = Get-MgDevice -All -ErrorAction Stop
    if ($allDevices -ne $null){$allDevices = $allDevices.ToJsonString() | ConvertFrom-Json}
    $devicesOutputFile = $folderToProcess + "\AADDevices_" + $tenant + "_devices_raw.json"
    $allDevices | ConvertTo-Json -Depth 99 | Out-File $devicesOutputFile -Encoding UTF8
    $countDevices = ($allDevices | Measure-Object).Count
    "Total number of devices in the tenant is $($countDevices)" | Write-Log -LogPath $logFile

    $enrichedDeviceEvents = @()
    $uniqueDevices = $deviceEvents | Select-Object -ExpandProperty targetResources | Group-Object -Property Id

    # Loop through Devices seen in Audit Log
    foreach ($uniqueDevice in $uniqueDevices){
        # Get Device object
        $deviceObject = $allDevices | Where-Object {$_.Id -eq $uniqueDevice.Name}
        $eventsPerDevice = $deviceEvents | Where-Object { $_.targetResources.Id -eq $uniqueDevice.Name}

        if ($deviceObject){
            "Get owners and users for $($uniqueDevice.Name) Device" | Write-Log -LogPath $logFile
            $deviceOwners = Get-MgDeviceRegisteredOwner -DeviceId $uniqueDevice.Name -All -ErrorAction Stop
            if ($deviceOwners -ne $null){$deviceOwners = $deviceOwners.ToJsonString() | ConvertFrom-Json}
            $owners = (($deviceOwners | Group-Object -Property UserPrincipalName).Name) -join ","
            $ownersLanguage = (($deviceOwners | Group-Object -Property PreferredLanguage).Name) -join ","

            $deviceUsers = Get-MgDeviceRegisteredUser -DeviceId $uniqueDevice.Name -All -ErrorAction Stop
            if ($deviceUsers -ne $null){$deviceUsers = $deviceUsers.ToJsonString() | ConvertFrom-Json}
            $users = (($deviceUsers | Group-Object -Property UserPrincipalName).Name) -join ","
            $usersLanguage = (($deviceUsers | Group-Object -Property PreferredLanguage).Name) -join ","

            if (-not ($null -eq $owners)){$eventsPerDevice | Add-Member -MemberType NoteProperty -Name "deviceOwners" -Value $owners -Force}
            if (-not ($null -eq $ownersLanguage)){$eventsPerDevice | Add-Member -MemberType NoteProperty -Name "deviceOwnersLanguage" -Value $ownersLanguage -Force}
            if (-not ($null -eq $users)){$eventsPerDevice | Add-Member -MemberType NoteProperty -Name "deviceUsers" -Value $users -Force}
            if (-not ($null -eq $usersLanguage)){$eventsPerDevice | Add-Member -MemberType NoteProperty -Name "deviceUsersLanguage" -Value $usersLanguage -Force}

            $deviceObject.PSObject.Properties | ForEach-Object {
                $newPropertyName = "device_$($_.Name)"
                if (-not ($eventsPerDevice.PSObject.Properties.Name -contains $newPropertyName)){
                    $eventsPerDevice | Add-Member -MemberType NoteProperty -Name $newPropertyName -Value $_.Value -Force
                } 
            }
        }
        else {
            "The device $($uniqueDevice.Name) does not exist in the tenant" | Write-Log -LogPath $logFile
        }
        $enrichedDeviceEvents += $eventsPerDevice
    }

    $nbEnrichedDeviceEvents = ($enrichedDeviceEvents | Measure-Object).Count

    "Dumping $($nbEnrichedDeviceEvents) enriched events to $($outputFile)" | Write-Log -LogPath $logFile

    $enrichedDeviceEvents | ConvertTo-Json -Depth 99 | Out-File $outputFile -Encoding UTF8
}
