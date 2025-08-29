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
    
    $folderToProcess = $currentPath + '\azure_ad_users'
    if ((Test-Path $folderToProcess) -eq $false){
        New-Item $folderToProcess -Type Directory | Out-Null
    }
    $outputFile = $folderToProcess + "\AADUsers_" + $tenant + ".json"

    $cert, $null, $null = Import-Certificate -certificatePath $certificatePath -logFile $logFile
    Connect-MicrosoftGraphApplication -certificate $cert -appId $appId -tenant $tenant -logFile $logFile

    # Get all axisting users
    "Getting all existing users" | Write-Log -LogPath $logFile
    $existingUsers = Get-MgUser -All -ErrorAction Stop

    # Get all deleted users
    "Getting all deleted users" | Write-Log -LogPath $logFile
    $deletedUsers = Get-MgDirectoryDeletedItemAsUser -All -ErrorAction Stop
    $deletedUsers | ForEach-Object {$_.Add("deleted", $true)}

    $allUsers = @($existingUsers) + @($deletedUsers)
    if ($null -ne $allUsers -and $allUsers.Count -ne 0){$allUsers = $allUsers.ToJsonString() | ConvertFrom-Json}
    $allUsersOutputFile = $folderToProcess + "\AADUsers_" + $tenant + "_users_raw.json"
    $allUsers | ConvertTo-Json -Depth 99 | Out-File $allUsersOutputFile -Encoding UTF8
    "Got $($allUsers.Count) users" | Write-Log -LogPath $logFile

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
    for ($i=0; $i -lt $allUsers.Length; $i += 1){
        $user = $allUsers[$i]
        if (-not $user.deleted){
            # Check if user has associated authentication settings
            $userSettings = $allUsersSettings | Where-Object {$_.UserPrincipalName -eq $user.UserPrincipalName}
            if ($null -ne $userSettings){
                $allUsers[$i] | Add-Member -MemberType NoteProperty -Name "userAuthenticationSettings" -Value $userSettings -Force
            }
            else {
                "The user $($user.UserPrincipalName) has no authentication settings" | Write-Log -LogPath $logFile
            }

            if ($authenticationMethods){
                "Getting $($user.UserPrincipalName) registered authentication methods" | Write-Log -LogPath $logFile
                # Check if user has registered authentication methods
                $registeredAuthenticationMethods = Get-MgBetaUserAuthenticationMethod -UserId $user.Id -All
                if ($registeredAuthenticationMethods){
                    if ($null -ne $registeredAuthenticationMethods){
                        $registeredAuthenticationMethods = $registeredAuthenticationMethods.ToJsonString() | ConvertFrom-Json
                        $allUsers[$i] | Add-Member -MemberType NoteProperty -Name "userRegisteredAuthenticationMethods" -Value $registeredAuthenticationMethods -Force
                    }
                }
                else {
                    "The user $($user.UserPrincipalName) has no registered authentication methods" | Write-Log -LogPath $logFile
                }
            }
        }
    }
    $allUsers | ConvertTo-Json -Depth 99 | Out-File $outputFile -Encoding UTF8
}
