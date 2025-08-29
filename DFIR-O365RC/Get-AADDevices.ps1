function Get-AADDevices {

    <#
    .SYNOPSIS
    The Get-AADDevices function dumps in JSON files Entra ID (enriched) devices. The objets are enriched with owners and users.

    .EXAMPLE

    PS C:\>$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    PS C:\>$tenant = "example.onmicrosoft.com"
    PS C:\>$certificatePath = "./example.pfx"

    PS C:\>Get-AADDevices -appId $appId -tenant $tenant -certificatePath $certificatePath

    Dump all Entra ID (enriched) devices.
    #>

    param (
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

    $folderToProcess = $currentPath + '\azure_ad_devices'
    if ((Test-Path $folderToProcess) -eq $false){
        New-Item $folderToProcess -Type Directory | Out-Null
    }
    $outputFile = $folderToProcess + "\AADDevices_" + $tenant + ".json"

    $cert, $null, $null = Import-Certificate -certificatePath $certificatePath -logFile $logFile
    Connect-MicrosoftGraphApplication -certificate $cert -appId $appId -tenant $tenant -logFile $logFile

    # Get all existing devices
    "Getting all existing devices" | Write-Log -LogPath $logFile
    $existingDevices = Get-MgDevice -All -ErrorAction Stop

    # Get all deleted devices
    "Getting all deleted devices" | Write-Log -LogPath $logFile
    $deletedDevices = Get-MgDirectoryDeletedItemAsDevice -All -ErrorAction Stop
    $deletedDevices | ForEach-Object {$_.Add("deleted", $true)}

    $allDevices = @($existingDevices) + @($deletedDevices)
    if ($null -ne $allDevices -and $allDevices.Count -ne 0){$allDevices = $allDevices.ToJsonString() | ConvertFrom-Json}
    $allDevicesOutputFile = $folderToProcess + "\AADDevices_" + $tenant + "_devices_raw.json"
    $allDevices | ConvertTo-Json -Depth 99 | Out-File $allDevicesOutputFile -Encoding UTF8
    "Got $($allDevices.Count) devices" | Write-Log -LogPath $logFile

    # Loop through Devices
    for ($i=0; $i -lt $allDevices.Length; $i += 1){
        $device = $allDevices[$i]
        if (-not $device.deleted){
            "Get owners for $($device.displayName) Device" | Write-Log -LogPath $logFile
            $deviceOwners = Get-MgDeviceRegisteredOwner -DeviceId $device.id -All -ErrorAction Stop
            if ($null -ne $deviceOwners){
                $deviceOwners = $deviceOwners.ToJsonString() | ConvertFrom-Json
                $allDevices[$i] | Add-Member -MemberType NoteProperty -Name "owners" -Value $deviceOwners -Force
            }

            "Get users for $($device.displayName) Device" | Write-Log -LogPath $logFile
            $deviceUsers = Get-MgDeviceRegisteredUser -DeviceId $device.id -All -ErrorAction Stop
            if ($null -ne $deviceUsers){
                $deviceUsers = $deviceUsers.ToJsonString() | ConvertFrom-Json
                $allDevices[$i] | Add-Member -MemberType NoteProperty -Name "users" -Value $deviceUsers -Force
            }
        }
    }
    $allDevices | ConvertTo-Json -Depth 99 | Out-File $outputFile -Encoding UTF8
}
