function Get-AADUsers {

    <#
    .SYNOPSIS
    The Get-AADUsers function dumps in JSON files Entra ID users and their authentication methods settings. If you want also want to collect the registered authentication methods for users, please add the "-authenticationMethods" switch.

    .EXAMPLE

    PS C:\>$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    PS C:\>$tenant = "example.onmicrosoft.com"
    PS C:\>$certificatePath = "./example.pfx"

    PS C:\>Get-AADUsers -appId $appId -tenant $tenant -certificatePath $certificatePath

    Dump all Entra ID users and their authentication methods settings.

    PS C:\>Get-AADUsers -appId $appId -tenant $tenant -certificatePath $certificatePath -authenticationMethods

    Dump all Entra ID users, their authentication methods settings as well as their registered authentication methods.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$certificatePath,
        [Parameter(Mandatory = $true)]
        [String]$appId,
        [Parameter(Mandatory = $true)]
        [String]$tenant,
        [Parameter(Mandatory = $false)]
        [Switch]$authenticationMethods=$false,
        [Parameter(Mandatory = $false)]
        [String]$logFile = "Get-AADUsers.log"
    )

    $currentPath = (Get-Location).path

    $logFile = $currentPath + "\" + $logFile
    
    $cert, $null, $null = Import-Certificate -certificatePath $certificatePath -logFile $logFile

    $folderToProcess = $currentPath + '\azure_ad_users'
    if ((Test-Path $folderToProcess) -eq $false){
        New-Item $folderToProcess -Type Directory | Out-Null
    }
    $outputFile = $folderToProcess + "\AADUsers_" + $tenant + ".json"
    Connect-MicrosoftGraphApplication -certificate $cert -appId $appId -tenant $tenant -logFile $logFile

    # Get all users
    "Getting all users" | Write-Log -LogPath $logFile
    $allUsers = Get-MgUser -All -ErrorAction Stop
    if ($null -ne $allUsers){$allUsers = $allUsers.ToJsonString() | ConvertFrom-Json}
    $usersOutputFile = $folderToProcess + "\AADUsers_" + $tenant + "_users_raw.json"
    $allUsers | ConvertTo-Json -Depth 99 | Out-File $usersOutputFile -Encoding UTF8
    $countUsers = ($allUsers | Measure-Object).Count
    "Total number of non-deleted users in the tenant is $($countUsers)" | Write-Log -LogPath $logFile

    # Get all deleted users
    "Getting all deleted users" | Write-Log -LogPath $logFile
    $deletedUsers = Get-MgDirectoryDeletedItemAsUser -All -ErrorAction Stop
    if ($null -ne $deletedUsers){$deletedUsers = $deletedUsers.ToJsonString() | ConvertFrom-Json}
    $deletedUsersOutputFile = $folderToProcess + "\AADUsers_" + $tenant + "_deleted_users_raw.json"
    $deletedUsers | ConvertTo-Json -Depth 99 | Out-File $deletedUsersOutputFile -Encoding UTF8

    # Get all users settings
    "Getting all users settings" | Write-Log -LogPath $logFile
    try {
        $allUsersSettings = Get-MgBetaReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop
        if ($null -ne $allUsersSettings){$allUsersSettings = $allUsersSettings.ToJsonString() | ConvertFrom-Json}
        $usersSettingsOutputFile = $folderToProcess + "\AADUsers_" + $tenant + "_users_settings_raw.json"
        $allUsersSettings | ConvertTo-Json -Depth 99 | Out-File $usersSettingsOutputFile -Encoding UTF8
    }
    catch {
        Write-Warning "Get-MgBetaReportAuthenticationMethodUserRegistrationDetail is a premium tenant feature. Please upgrade to Entra ID P1"
        "Get-MgBetaReportAuthenticationMethodUserRegistrationDetail is a premium tenant feature. Please upgrade to Entra ID P1" | Write-Log -LogPath $logFile -LogLevel "Warning"
        $allUsersSettings = $null
    }

    $enrichedUsersObject = @()

    # Loop through Users
    foreach ($user in $allUsers){
        # Check if user has associated authentication settings
        $userSettings = $allUsersSettings | Where-Object {$_.UserPrincipalName -eq $user.UserPrincipalName}

        if ($userSettings){
            $userSettings.PSObject.Properties | ForEach-Object {
                $newPropertyName = "user_authentication_settings_$($_.Name)"
                if (-not ($user.PSObject.Properties.Name -contains $newPropertyName)){
                    $user | Add-Member -MemberType NoteProperty -Name $newPropertyName -Value $_.Value -Force
                } 
            }
        }
        else {
            "The user $($user.UserPrincipalName) has no authentication settings" | Write-Log -LogPath $logFile
        }

        if ($authenticationMethods){
            "Getting $($user.UserPrincipalName) registered authentication methods" | Write-Log -LogPath $logFile
            # Check if user has registered authentication methods
            $registeredAuthenticationMethods = Get-MgBetaUserAuthenticationMethod -UserId $user.Id -All
            if ($registeredAuthenticationMethods){
                if ($null -ne $registeredAuthenticationMethods){$registeredAuthenticationMethods = $registeredAuthenticationMethods.ToJsonString() | ConvertFrom-Json}
                $registeredAuthenticationMethods.PSObject.Properties | ForEach-Object {
                    $newPropertyName = "user_registered_authentication_methods_$($_.Name)"
                    if (-not ($user.PSObject.Properties.Name -contains $newPropertyName)){
                        $user | Add-Member -MemberType NoteProperty -Name $newPropertyName -Value $_.Value -Force
                    } 
                }
            }
            else {
                "The user $($user.UserPrincipalName) has no registered authentication methods" | Write-Log -LogPath $logFile
            }
        }
        $enrichedUsersObject += $user
    }

    $nbEnrichedUsersObject = ($enrichedUsersObject | Measure-Object).Count

    "Dumping $($nbEnrichedUsersObject) enriched objects to $($outputFile)" | Write-Log -LogPath $logFile

    $enrichedUsersObject | ConvertTo-Json -Depth 99 | Out-File $outputFile -Encoding UTF8
}
