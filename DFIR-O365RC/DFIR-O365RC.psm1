function Write-Log {
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$message,
        [Parameter(Mandatory=$true)]
        [Alias("LogPath")]
        [String]$path,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warning","Info")]
        [Alias("LogLevel")]
        [String]$level="Info"
    )

    $logTime = "{0:yyyy-MM-dd} {0:HH:mm:ss}" -f (Get-Date) + ","

    switch ($level){
        "Error" {
            $levelText = "ERROR,"
        }
        "Warning" {
            $levelText = "WARNING,"
        }
        "Info" {
            $levelText = "INFO,"
        }
    }

    "$logTime $levelText $message" | Out-File -FilePath $path -Append -Encoding UTF8
}

function Import-Certificate {
    param (
        [Parameter(Mandatory = $true)]
        [String]$logFile,
        [Parameter(Mandatory = $true)]
        [String]$certificatePath
    )

    if (-not (Test-Path -Path $certificatePath)){
        Write-Error "The provided path for certificate: $certificatePath does not exist. Exiting"
        "The provided path for certificate: $certificatePath does not exist. Exiting" | Write-Log -LogPath $logFile -LogLevel "ERROR"
        exit
    }

    "Loading certificate $certificatePath" | Write-Log -LogPath $logFile
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificatePath)
        Write-Host "Loaded certificate $certificatePath with no password"
        "Loaded certificate $certificatePath with no password" | Write-Log -LogPath $logFile
        $emptySecurePassword = New-Object System.Security.SecureString
        return $cert, $false, $emptySecurePassword
    }
    catch {
        $errorMessage = $_.Exception.ToString()
        if ($errorMessage.Contains("password")){
            try {
                $certificatePassword = Read-Host -MaskInput "Please enter the password for the certificate $certificatePath"
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificatePath,$certificatePassword)
                $certificateSecurePassword = ConvertTo-SecureString -String $certificatePassword -AsPlainText -Force
                Write-Host "Loaded certificate $certificatePath with a password"
                "Loaded certificate $certificatePath with a password" | Write-Log -LogPath $logFile
                return $cert, $true, $certificateSecurePassword
            }
            catch {
                $errorMessage = $_.Exception.ToString()
                if ($errorMessage.Contains("password")){
                    Write-Error "Wrong password was provided for certificate $certificatePath. Exiting"
                    "Wrong password was provided for certificate $certificatePath. Exiting" | Write-Log -LogPath $logFile -LogLevel "ERROR"
                    exit
                }
                else {
                    Write-Error "Error while loading the certificate: $errorMessage. Exiting"
                    "Error while loading the certificate: $errorMessage. Exiting" | Write-Log -LogPath $logFile -LogLevel "ERROR"
                    exit
                }
            }
        }
        else {
            Write-Error "Error while loading the certificate: $errorMessage. Exiting"
            "Error while loading the certificate: $errorMessage. Exiting" | Write-Log -LogPath $logFile -LogLevel "ERROR"
            exit
        }
    }
}

function Connect-AzUser {
    param (
        [Parameter(Mandatory = $true)]
        [String]$logFile
    )

    $stopLoop = $false
    [Int]$retryCount = "0"

    try {
        $null = Disconnect-AzAccount -ErrorAction Stop
    }
    catch {
        
    }
    do {
        try {
            "Connecting to Azure" | Write-Log -LogPath $logFile
            Write-Warning "Please log in to Azure using a privileged account"
            $null = Connect-AzAccount -DeviceAuth -Confirm:$false -ErrorAction Stop
            "Successfully logged in to Azure" | Write-Log -LogPath $logFile
            $stopLoop = $true
        }
        catch {
            if ($retryCount -ge 3){
                Write-Error "Failed to log in to Azure $($retryCount + 1) times - aborting"
                "Failed to log in to Azure $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                $stopLoop = $true
            }
            else {
                $errorMessage = $_.Exception.Message
                Write-Warning "Failed to log in to Azure $($retryCount + 1) times - sleeping and retrying - $errorMessage"
                "Failed to log in to Azure $($retryCount + 1) times - sleeping and retrying - $errorMessage" | Write-Log -LogPath $logFile -LogLevel "Warning"
                Start-Sleep -Seconds (60 * ($retryCount + 1))
                $retryCount = $retryCount + 1
            }
        }
    } while ($stopLoop -eq $false)
}

function Connect-AzApplication {
    param (
        [Parameter(Mandatory = $true)]
        [String]$logFile,
        [Parameter(Mandatory = $true)]
        [String]$certificatePath,
        [Parameter(Mandatory = $true)]
        [SecureString]$certificateSecurePassword,
        [Parameter(Mandatory = $true)]
        [Bool]$needPassword,
        [Parameter(Mandatory = $true)]
        [String]$tenant,
        [Parameter(Mandatory = $true)]
        [String]$appId
    )

    $stopLoop = $false
    [Int]$retryCount = "0"
    do {
        try {
            try {
                $null = Disconnect-AzAccount -ErrorAction Stop
            }
            catch {
                
            }
            if ($needPassword){
                $null = Connect-AzAccount -CertificatePath $certificatePath -CertificatePassword $certificateSecurePassword -ServicePrincipal -Tenant $tenant -ApplicationId $appId -ErrorAction Stop
            }
            else {
                $null = Connect-AzAccount -CertificatePath $certificatePath -ServicePrincipal -Tenant $tenant -ApplicationId $appId -ErrorAction Stop
            }
            "Successfully logged in to Az using application $appId" | Write-Log -LogPath $logFile
            $stopLoop = $true
        }
        catch {
            if ($retryCount -ge 3){
                "Failed to log in to Az using application $appId $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                $stopLoop = $true
            }
            else {
                $errorMessage = $_.Exception.Message
                "Failed to log in to Az using application $appId $($retryCount + 1) times - sleeping and retrying - $($errorMessage)" | Write-Log -LogPath $logFile -LogLevel "Warning"
                Start-Sleep -Seconds (60 * ($retryCount + 1))
                $retryCount = $retryCount + 1
            }
        }
    } while ($stopLoop -eq $false)
}

function Connect-ExchangeOnlineUser {
    param (
        [Parameter(Mandatory = $true)]
        [String]$logFile
    )

    $stopLoop = $false
    [Int]$retryCount = "0"

    try {
        $null = Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
    }
    catch {
        
    }
    do {
        try {
            "Connecting to Exchange Online" | Write-Log -LogPath $logFile
            Write-Warning "Please log in to Exchange Online using a privileged account"
            Connect-ExchangeOnline -ErrorAction Stop -Device -ShowBanner:$false
            "Successfully logged in to Exchange Online" | Write-Log -LogPath $logFile
            $stopLoop = $true
        }
        catch {
            if ($retryCount -ge 3){
                Write-Error "Failed to log in to Exchange Online $($retryCount + 1) times - aborting"
                "Failed to log in to Exchange Online $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                $stopLoop = $true
            }
            else {
                $errorMessage = $_.Exception.Message
                Write-Warning "Failed to log in to Exchange Online $($retryCount + 1) times - sleeping and retrying - $errorMessage"
                "Failed to log in to Exchange Online $($retryCount + 1) times - sleeping and retrying - $errorMessage" | Write-Log -LogPath $logFile -LogLevel "Warning"
                Start-Sleep -Seconds (60 * ($retryCount + 1))
                $retryCount = $retryCount + 1
            }
        }
    } while ($stopLoop -eq $false)
}

function Connect-ExchangeOnlineApplication {

    param (
        [Parameter(Mandatory = $true)]
        [String]$logFile,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate,
        [Parameter(Mandatory = $true)]
        [String]$appId,
        [Parameter(Mandatory = $true)]
        [String]$organization,
        [Parameter(Mandatory = $false)]
        [Array]$commandNames = @("Search-UnifiedAuditLog","Search-MailboxAuditLog")
    )

    $stopLoop = $false
    [Int]$retryCount = "0"
    do {
        try {
            try {
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
            }
            catch {
                
            }
            Connect-ExchangeOnline -Certificate $certificate -AppID $appId -Organization $organization -CommandName $commandNames -ErrorAction Stop -ShowBanner:$false
            "Successfully logged in to Exchange Online using application $appId" | Write-Log -LogPath $logFile
            $stopLoop = $true
        }
        catch {
            if ($retryCount -ge 3){
                "Failed to log in to Exchange Online using application $appId $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                $stopLoop = $true
            }
            else {
                $errorMessage = $_.Exception.Message
                "Failed to log in to Exchange Online using application $appId $($retryCount + 1) times - sleeping and retrying - $($errorMessage)" | Write-Log -LogPath $logFile -LogLevel "Warning"
                if ($errorMessage -like "*No cmdlet assigned to the user have this feature enabled.*" -or $errorMessage -eq "UnAuthorized"){
                    $retryCount = 3
                }
                else {
                    Start-Sleep -Seconds (60 * ($retryCount + 1))
                }
                $retryCount = $retryCount + 1
            }
        }
    } while ($stopLoop -eq $false)
}

function Connect-MicrosoftGraphUser {
    param (
        [Parameter(Mandatory = $true)]
        [String]$logFile
    )

    $stopLoop = $false
    [Int]$retryCount = "0"
    try {
        $null = Disconnect-MgGraph -ErrorAction Stop
    }
    catch {
        
    }
    do {
        try {
            "Connecting to Entra ID" | Write-Log -LogPath $logFile
            Write-Warning "Please log in to Entra ID using a privileged account"
            Connect-MgGraph -NoWelcome -Scopes "Application.ReadWrite.All, Directory.Read.All, GroupMember.ReadWrite.All, RoleManagement.ReadWrite.Directory" -UseDeviceCode -ErrorAction Stop
            "Successfully logged in to Entra ID" | Write-Log -LogPath $logFile
            $stopLoop = $true
        }
        catch {
            if ($retryCount -ge 3){
                Write-Error "Failed to log in to Entra ID $($retryCount + 1) times - aborting"
                "Failed to log in to Entra ID $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                $stopLoop = $true
            }
            else {
                $errorMessage = $_.Exception.Message
                Write-Warning "Failed to log in to Entra ID $($retryCount + 1) times - sleeping and retrying - $errorMessage"
                "Failed to log in to Entra ID $($retryCount + 1) times - sleeping and retrying - $errorMessage" | Write-Log -LogPath $logFile -LogLevel "Warning"
                Start-Sleep -Seconds (60 * ($retryCount + 1))
                $retryCount = $retryCount + 1
            }
        }
    } while ($stopLoop -eq $false)
}

function Connect-MicrosoftGraphApplication {

    param (
        [Parameter(Mandatory = $true)]
        [String]$logFile,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate,
        [Parameter(Mandatory = $true)]
        [String]$appId,
        [Parameter(Mandatory = $true)]
        [String]$tenant
    )

    $stopLoop = $false
    [Int]$retryCount = "0"
    do {
        try {
            try {
                $null = Disconnect-MgGraph -ErrorAction Stop
            }
            catch {

            }
            Connect-MgGraph -Certificate $certificate -ClientId $appId -TenantId $tenant -NoWelcome -ErrorAction Stop
            "Successfully logged in to Microsoft Graph using application $appId" | Write-Log -LogPath $logFile
            $stopLoop = $true
        }
        catch {
            if ($retryCount -ge 3){
                "Failed to log in to Microsoft Graph using application $appId $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                $stopLoop = $true
            }
            else {
                $errorMessage = $_.Exception.Message
                "Failed to log in to Microsoft Graph using application $appId $($retryCount + 1) times - sleeping and retrying - $errorMessage" | Write-Log -LogPath $logFile -LogLevel "Warning"
                Start-Sleep -Seconds (60 * ($retryCount + 1))
                $retryCount = $retryCount + 1
            }
        }
    } while ($stopLoop -eq $false)
}

function Get-AzDevOpsRestAPIResponseUser {
    param
    (
        [Parameter(Mandatory = $true)]
        [String]$uri,
        [Parameter(Mandatory = $true)]
        [String]$logFile
    )
    try {
        $token = Get-AzAccessToken -ResourceUrl "499b84ac-1321-427f-aa17-267ca6975798" -AsSecureString:$false -ErrorAction Stop
    }
    catch {
        Connect-AzUser -logFile $logFile
        $token = Get-AzAccessToken -ResourceUrl "499b84ac-1321-427f-aa17-267ca6975798" -AsSecureString:$false -ErrorAction Stop
    }

    $APIresults = @()

    $stopLoop = $false
    [Int]$retryCount = "0"
    while ($stopLoop -eq $false){
        try {
            $data = Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.Token)"} -Uri $($uri) -Method GET -ContentType "application/json" -ResponseHeadersVariable responseHeaders -ErrorAction Stop
            $stopLoop = $true
        }
        catch {
            if ($retryCount -ge 10){
                Write-Error "Failed to dump events from Azure DevOps URI $($uri) $($retryCount + 1) times - aborting"
                "Failed to dump events from Azure DevOps URI $($uri) $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                $data = @()
                $stopLoop = $true
            }
            else {
                $errorCode = $_.Exception.Response.StatusCode.value__
                $errorMessage = $_.ErrorDetails.Message
                Write-Error "Failed to dump events from Azure DevOps URI $($uri) $($retryCount + 1) times - sleeping and retrying - ${errorCode}: ${errorMessage}"
                "Failed to dump events from Azure DevOps URI $($uri) $($retryCount + 1) times - sleeping and retrying - ${errorCode}: ${errorMessage}" | Write-Log -LogPath $logFile -LogLevel "Warning"
                if ($errorCode -eq "429"){
                    Start-Sleep -Seconds (15 * ($retryCount + 1))
                }
                elseif ($errorCode -eq "401" -or $errorCode -eq "403"){
                    $retryCount = 10
                }
                else {
                    Start-Sleep -Seconds 1
                }
                $retryCount = $retryCount + 1
            }
        }
    }
    if ($data){
        $APIresults += $data.value

        if ($null -ne $($responseHeaders."X-MS-ContinuationToken")){
            $stopLoop = $false
            [Int]$retryCount = "0"
            while ($stopLoop -eq $false -and $null -ne $($responseHeaders."X-MS-ContinuationToken")){
                try {
                    $continuationToken = $responseHeaders."X-MS-ContinuationToken"
                    if ($uri.contains("continuationToken=")){
                        $uri = ($uri -Split "continuationToken=")[0]
                        $uri = $uri.Substring(0, $uri.Length - 1)
                    }
                    if ($uri.contains("?")){
                        $uri += "&continuationToken=$continuationToken"
                    }
                    else {
                        $uri += "?continuationToken=$continuationToken"
                    }
                    $data = Invoke-RestMethod -Uri $uri -Headers @{Authorization = "Bearer $($token.Token)"} -Method GET -ContentType "application/json" -ResponseHeadersVariable responseHeaders -ErrorAction Stop
                    $APIresults += $data.value
                }
                catch {
                    if ($retryCount -ge 10){
                        Write-Error "Failed to dump events from Azure DevOps URI $($uri) $($retryCount + 1) times - aborting"
                        "Failed to dump events from Azure DevOps URI $($uri) $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                            $data = @()
                            $stopLoop = $true
                    }
                    else {
                        $errorCode = $_.Exception.Response.StatusCode.value__
                        $errorMessage = $_.ErrorDetails.Message
                        Write-Warning "Failed to dump events from Azure DevOps URI $($uri) $($retryCount + 1) times - sleeping and retrying - ${errorCode}: ${errorMessage}"
                        "Failed to dump events from Azure DevOps URI $($uri) $($retryCount + 1) times - sleeping and retrying - ${errorCode}: ${errorMessage}" | Write-Log -LogPath $logFile -LogLevel "Warning"
                        if ($token.ExpiresOn -le (Get-Date)){
                            Write-Warning "Token has expired, renewing"
                            "Token has expired, renewing" | Write-Log -LogPath $logFile -LogLevel "Warning"
                            try {
                                $token = Get-AzAccessToken -ResourceUrl "499b84ac-1321-427f-aa17-267ca6975798" -AsSecureString:$false -ErrorAction Stop
                            }
                            catch {
                                Connect-AzUser -logFile $logFile
                                $token = Get-AzAccessToken -ResourceUrl "499b84ac-1321-427f-aa17-267ca6975798" -AsSecureString:$false -ErrorAction Stop
                            }
                        }
                        else {
                            Start-Sleep -Seconds (5 * ($retryCount + 1))
                        }
                        $retryCount = $retryCount + 1
                    }
                }
            }
        }
    }
    else {
        Write-Host "No events to dump from Azure DevOps URI $($uri)"
        "No events to dump from Azure DevOps URI $($uri)" | Write-Log -LogPath $logFile
    }
    return $APIresults
}

function Get-AzDevOpsAuditLogs {
    param
    (
        [Parameter(Mandatory = $true)]
        [String]$certificatePath,
        [Parameter(Mandatory = $true)]
        [SecureString]$certificateSecurePassword,
        [Parameter(Mandatory = $true)]
        [Bool]$needPassword,
        [Parameter(Mandatory = $true)]
        [String]$tenant,
        [Parameter(Mandatory = $true)]
        [String]$appId,
        [Parameter(Mandatory = $true)]
        [String]$uri,
        [Parameter(Mandatory = $true)]
        [String]$logFile
    )
    try {
        $token = Get-AzAccessToken -ResourceUrl "499b84ac-1321-427f-aa17-267ca6975798" -AsSecureString:$false -ErrorAction Stop
    }
    catch {
        Connect-AzApplication -logFile $logFile -certificatePath $certificatePath -certificateSecurePassword $certificateSecurePassword -needPassword $needPassword -tenant $tenant -appId $appId
        $token = Get-AzAccessToken -ResourceUrl "499b84ac-1321-427f-aa17-267ca6975798" -AsSecureString:$false -ErrorAction Stop
    }

    $APIresults = @()

    $stopLoop = $false
    [Int]$retryCount = "0"
    while ($stopLoop -eq $false){
        try {
            $data = Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.Token)"} -Uri $($uri + "&batchSize=1") -Method GET -ContentType "application/json" -ErrorAction Stop
            $stopLoop = $true
        }
        catch {
            if ($retryCount -ge 10){
                "Failed to dump events from Azure DevOps URI $($uri) $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                $data = @()
                $stopLoop = $true
            }
            else {
                $errorCode = $_.Exception.Response.StatusCode.value__
                $errorMessage = $_.ErrorDetails.Message
                "Failed to dump events from Azure DevOps URI $($uri) $($retryCount + 1) times - sleeping and retrying - ${errorCode}: ${errorMessage}" | Write-Log -LogPath $logFile -LogLevel "Warning"
                if ($errorCode -eq "429"){
                    Start-Sleep -Seconds (15 * ($retryCount + 1))
                }
                elseif ($errorCode -eq "401" -or $errorCode -eq "403"){
                    $retryCount = 10
                }
                else {
                    Start-Sleep -Seconds 1
                }
                $retryCount = $retryCount + 1
            }
        }
    }
    if ($data){
        $APIresults += $data.decoratedAuditLogEntries
        
        if ($data.hasMore -eq $true){
            $stopLoop = $false
            [Int]$retryCount = "0"
            while ($stopLoop -eq $false -and $data.hasMore -eq $true){
                try {
                    $continuationToken = $data.continuationToken
                    if ($uri.contains("&continuationToken=")){
                        $uri = ($uri -Split "&continuationToken=")[0]
                    }
                    $uri += "&continuationToken=$continuationToken"
                    $data = Invoke-RestMethod -Uri $uri -Headers @{Authorization = "Bearer $($token.Token)"} -Method GET -ContentType "application/json" -ErrorAction Stop
                    $APIresults += $data.decoratedAuditLogEntries
                }
                catch {
                    if ($retryCount -ge 10){
                        "Failed to dump events from Azure DevOps URI $($uri) $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                        $data = @()
                        $stopLoop = $true
                    }
                    else {
                        $errorCode = $_.Exception.Response.StatusCode.value__
                        $errorMessage = $_.ErrorDetails.Message
                        "Failed to dump events from Azure DevOps URI $($uri) $($retryCount + 1) times - sleeping and retrying - ${errorCode}: ${errorMessage}" | Write-Log -LogPath $logFile -LogLevel "Warning"
                        if ($token.ExpiresOn -le (Get-Date)){
                            "Token has expired, renewing" | Write-Log -LogPath $logFile -LogLevel "Warning"
                            try {
                                $token = Get-AzAccessToken -ResourceUrl "499b84ac-1321-427f-aa17-267ca6975798" -AsSecureString:$false -ErrorAction Stop
                            }
                            catch {
                                Connect-AzApplication -logFile $logFile -certificatePath $certificatePath -certificateSecurePassword $certificateSecurePassword -needPassword $needPassword -tenant $tenant -appId $appId
                                $token = Get-AzAccessToken -ResourceUrl "499b84ac-1321-427f-aa17-267ca6975798" -AsSecureString:$false -ErrorAction Stop
                            }
                        }
                        else {
                            Start-Sleep -Seconds (5 * ($retryCount + 1))
                        }
                        $retryCount = $retryCount + 1
                    }
                }
            }
        }
    }
    else {
        "No events to dump from Azure DevOps URI $($uri)" | Write-Log -LogPath $logFile
    }
    return $APIresults
}

function Get-MgPurviewAuditLog {
    param
    (
        [String]$auditLogQueryId,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate,
        [Parameter(Mandatory = $true)]
        [String]$appId,
        [Parameter(Mandatory = $true)]
        [String]$tenant,
        [Parameter(Mandatory = $true)]
        [String]$logFile,
        [Parameter(Mandatory = $true)]
        [String]$outputFile
    )
    $uri = "https://graph.microsoft.com/beta/security/auditLog/queries/$auditLogQueryId/records"
    $dumpCount = 0

    $stopLoop = $false
    [Int]$retryCount = "0"
    "[" | Out-File $outputFile -Encoding UTF8 -Append
    while ($stopLoop -eq $false){
        try {
            $data = Invoke-MgGraphRequest -Method GET -Uri $uri
            $dumpCount = $dumpCount + $data["@odata.count"]
            "Dumped $($dumpCount) events" | Write-Log -LogPath $logFile -LogLevel "Info"
            if ($data["@odata.nextLink"] -eq $null){
                $stopLoop = $true
            }
            else {
                $uri = $data["@odata.nextLink"]
            }
        }
        catch {
            if ($retryCount -ge 10){
                "Failed to dump events from Microsoft Graph Purview $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                $data = @()
                $stopLoop = $true
            }
            else {
                $errorCode = $_.Exception.Response.StatusCode.value__
                $errorMessage = $_.ErrorDetails.Message
                "Failed to dump events from Microsoft Graph Purview $($retryCount + 1) times - sleeping and retrying - ${errorCode}: ${errorMessage}" | Write-Log -LogPath $logFile -LogLevel "Warning"
                if ($errorCode -eq "429"){
                    Start-Sleep -Seconds (15 * ($retryCount + 1))
                }
                elseif ($errorCode -eq "401" -or $errorCode -eq "403"){
                    $retryCount = 10
                    Connect-MicrosoftGraphApplication -certificate $certificate -appId $appId -tenant $tenant -logFile $logFile
                }
                else {
                    Start-Sleep -Seconds 1
                }
                $retryCount = $retryCount + 1
            }
        }
        if ($data.value -ne $null){
            $data.value.auditData | ConvertTo-Json -Depth 99 | Out-File $outputFile -Encoding UTF8 -Append
            if (-not $stopLoop){
                "," | Out-File $outputFile -Encoding UTF8 -Append
            }
        }
    }
    "]" | Out-File $outputFile -Encoding UTF8 -Append
}

function Get-LargeUnifiedAuditLog {
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Unfiltered","Operations","RecordTypes","FreeText","IPAddresses","UserIds")]
        [String]$requestType,
        [Parameter(Mandatory = $false)]
        [String]$freeText,
        [Parameter(Mandatory = $false)]
        [string[]]$IPAddresses,
        [Parameter(Mandatory = $false)]
        [string[]]$userIds,
        [Parameter(Mandatory = $false)]
        [string[]]$operations,
        [Parameter(Mandatory = $false)]
        [String]$recordTypes,
        [Parameter(Mandatory = $true)]
        [String]$sessionName,
        [Parameter(Mandatory = $true)]
        [DateTime]$startDate,
        [Parameter(Mandatory = $true)]
        [DateTime]$endDate,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate,
        [Parameter(Mandatory = $true)]
        [String]$appId,
        [Parameter(Mandatory = $true)]
        [String]$tenant,
        [Parameter(Mandatory = $true)]
        [String]$logFile,
        [Parameter(Mandatory = $true)]
        [String]$outputFile
    )

    "Collecting $requestType events for $startDate - $endDate" | Write-Log -LogPath $logFile -LogLevel "Info"
    [Int]$lastUnifiedAuditLogEntriesResultIndex = "0"
    do {
        $stopLoop = $false
        [Int]$retryCount = "0"
        do {
            try {
                # Using ReturnLargeSet to get back up to 50k events, 5k at a time
                if ($requestType -eq "Unfiltered"){
                    $unifiedAuditLogEntries = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -SessionId $sessionName -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction Stop                  
                }
				if ($requestType -eq "RecordTypes"){
                    $unifiedAuditLogEntries = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -RecordType $recordTypes -SessionId $sessionName -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction Stop
				}
				elseif ($requestType -eq "Operations"){
					$unifiedAuditLogEntries = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations $operations -SessionId $sessionName -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction Stop
				}
				elseif ($requestType -eq "FreeText"){
					$unifiedAuditLogEntries = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -FreeText $freeText -SessionId $sessionName -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction Stop
				}
				elseif ($requestType -eq "IPAddresses"){
					$unifiedAuditLogEntries = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -IPAddresses $IPAddresses -SessionId $sessionName -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction Stop
				}
				elseif ($requestType -eq "UserIds"){
					$unifiedAuditLogEntries = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -UserIds $userIds -SessionId $sessionName -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction Stop
				}

                if ($null -eq $unifiedAuditLogEntries){
                    if ($lastUnifiedAuditLogEntriesResultIndex -ne 0){
					    throw "We were supposed to have some events, but we got an empty result instead. This might be because of a server timeout"
                    }
                    else {
                        "0 $($requestType) events between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss} were found" -f ($startDate, $endDate) | Write-Log -LogPath $logFile -LogLevel "Warning"
                        $countUnifiedAuditLogEntries = 0
                        break
                    }
                }

                $countUnifiedAuditLogEntries = ($unifiedAuditLogEntries | Measure-Object).Count
                $unifiedAuditLogEntriesResultCount = ($unifiedAuditLogEntries | Select-Object -Property ResultCount -Unique).ResultCount
                $unifiedAuditLogEntriesResultIndex = $unifiedAuditLogEntries[-1].ResultIndex

                if (($unifiedAuditLogEntriesResultCount -eq 0) -or ($unifiedAuditLogEntriesResultIndex -eq -1)){
					throw "We were supposed to have some events, but we got a boggus result instead (ResultCount = 0 or ResultIndex = -1). This might be because of a server timeout"
                }
                elseif (($lastUnifiedAuditLogEntriesResultIndex + $countUnifiedAuditLogEntries) -ne $unifiedAuditLogEntriesResultIndex){
                    throw "We did not get the expected record index (lastIndex + actualCount != actualIndex). This might be because of a server timeout"
                }

                if ($lastUnifiedAuditLogEntriesResultIndex -eq 0 -and $unifiedAuditLogEntriesResultCount -gt 50000){
                    "More than 50000 $($requestType) events between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss} - some events will be missing" -f ($startDate, $endDate) | Write-Log -LogPath $logFile -LogLevel "Warning"
                }

				"Collected $($unifiedAuditLogEntriesResultIndex) events out of $($unifiedAuditLogEntriesResultCount) (+$($countUnifiedAuditLogEntries))" | Write-Log -LogPath $logFile -LogLevel "Info"
				$stopLoop = $true
            }
            catch {
                $lastUnifiedAuditLogEntriesResultIndex = 0
                $countUnifiedAuditLogEntries = 0
                $unifiedAuditLogEntries = @()
                if ($retryCount -ge 10){
                    "Failed to dump $($requestType) events $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                    $stopLoop = $true
                }
                else {
                    $errorMessage = $_.Exception.Message
                    "Failed to dump $($requestType) events $($retryCount + 1) times - deleting, reconnecting, sleeping and retrying for the time period $startDate - $endDate - $($errorMessage)" | Write-Log -LogPath $logFile -LogLevel "Warning"
                    $sessionName = $(New-Guid).Guid
                    if ((Test-Path $outputFile) -eq $true){
                        $null = Remove-Item $outputFile -Force -Confirm:$false
                    }
                    Start-Sleep -Seconds (60 * ($retryCount + 1))
                    Connect-ExchangeOnlineApplication -logFile $logFile -certificate $cert -appId $appId -organization $tenant
                    $retryCount = $retryCount + 1
                }
            }
        } while ($stopLoop -eq $false)

         # If count is 0, no events to process
        if ($countUnifiedAuditLogEntries -gt 0){
             # Dump data to json file
            $unifiedAuditLogEntries | Select-Object -ExpandProperty AuditData | Out-File $outputFile -Encoding UTF8 -Append
            $lastUnifiedAuditLogEntriesResultIndex += $countUnifiedAuditLogEntries
            if ($unifiedAuditLogEntriesResultIndex -ne 0 -and (($unifiedAuditLogEntriesResultIndex -eq $unifiedAuditLogEntriesResultCount) -or ($unifiedAuditLogEntriesResultIndex -eq 50000))){
                "Done collecting events for ${startDate} - ${endDate}: ${unifiedAuditLogEntriesResultIndex} events were collected out of $($unifiedAuditLogEntriesResultCount)" | Write-Log -LogPath $logFile -LogLevel "Info"
                $countUnifiedAuditLogEntries = 0
            }
        }
    } until ($countUnifiedAuditLogEntries -eq 0)
}

function Get-MicrosoftGraphLogs {
    param
    (
        [Parameter(Mandatory = $true)]
        [String]$type,
        [Parameter(Mandatory = $false)]
        [String]$tenantSize,
        [Parameter(Mandatory = $true)]
        [String]$dateStart,
        [Parameter(Mandatory = $true)]
        [String]$dateEnd,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate,
        [Parameter(Mandatory = $true)]
        [String]$appId,
        [Parameter(Mandatory = $true)]
        [String]$tenant,
        [Parameter(Mandatory = $true)]
        [String]$logFile
    )
    $stopLoop = $false
    [Int]$retryCount = "0"
    do {
        try {
            if ($type -eq "SignIns"){
                if ($tenantSize -eq "normal"){
                    $AzureADEvents = Get-MgBetaAuditLogSignIn -All -Filter "createdDateTime ge $($dateStart) and createdDateTime lt $($dateEnd)" -ErrorAction Stop
                }
                else {
                    $AzureADEvents = Get-MgBetaAuditLogSignIn -All -Filter "createdDateTime ge $($dateStart) and createdDateTime lt $($dateEnd) and status/errorCode eq 0 and (appId eq '00000002-0000-0ff1-ce00-000000000000' or appId eq '1b730954-1685-4b74-9bfd-dac224a7b894' or appId eq 'a0c73c16-a7e3-4564-9a95-2bdf47383716' or appId eq '00000003-0000-0ff1-ce00-000000000000' or appId eq '6eb59a73-39b2-4c23-a70f-e2e3ce8965b1' or appId eq 'cb1056e2-e479-49de-ae31-7812af012ed8' or appId eq '1950a258-227b-4e31-a9cf-717495945fc2' or appId eq 'fb78d390-0c51-40cd-8e17-fdbfab77341b' or appId eq '04b07795-8ddb-461a-bbee-02f9e1bf7b46')" -ErrorAction Stop
                }
            }
            elseif ($type -eq "AuditLogs"){
                    $AzureADEvents = Get-MgBetaAuditLogDirectoryAudit -All -Filter "activityDateTime ge $($dateStart) and activityDateTime lt $($dateEnd)" -ErrorAction Stop
            }
            $stopLoop = $true
        }
        catch {
            if ($retryCount -ge 10){
                "Failed to get $($type) logs $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                $AzureADEvents = $null
                $stopLoop = $true
            }
            else {
                $errorMessage = $_.Exception.Message
                if ($errorMessage -ne "Too many retries performed"){
                    Start-Sleep -Seconds (60 * ($retryCount + 1) + $(Get-Random -Minimum 1 -Maximum 60))
                }
                "Failed to get $($type) logs $($retryCount + 1) times - reconnecting and retrying - $($errorMessage)" | Write-Log -LogPath $logFile -LogLevel "Warning"
                Connect-MicrosoftGraphApplication -certificate $certificate -appId $appId -tenant $tenant -logFile $logFile
                $retryCount = $retryCount + 1
            }
        }
    } while ($stopLoop -eq $false)
    return $AzureADEvents
}

function Get-AzureRMActivityLog {
    param
    (
        [Parameter(Mandatory = $true)]
        [String]$dateStart,
        [Parameter(Mandatory = $true)]
        [String]$dateEnd,
        [Parameter(Mandatory = $true)]
        [String]$certificatePath,
        [Parameter(Mandatory = $true)]
        [SecureString]$certificateSecurePassword,
        [Parameter(Mandatory = $true)]
        [Bool]$needPassword,
        [Parameter(Mandatory = $true)]
        [String]$appId,
        [Parameter(Mandatory = $true)]
        [String]$tenant,
        [Parameter(Mandatory = $true)]
        [String]$logFile
    )
    $stopLoop = $false
    [Int]$retryCount = "0"
    do {
        try {
            $azureRMActivityEvents = Get-AzActivityLog -StartTime $dateStart -EndTime $dateEnd -DetailedOutput -ErrorAction Stop
            $stopLoop = $true
        }
        catch {
            if ($retryCount -ge 10){
                "Failed to get Azure Resource Manager activity logs $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                $azureRMActivityEvents = $null
                $stopLoop = $true
            }
            else {
                $errorMessage = $_.Exception.Message
                Start-Sleep -Seconds (60 * ($retryCount + 1) + $(Get-Random -Minimum 1 -Maximum 60))
                "Failed to get Azure Resource Manager activity logs $($retryCount + 1) times - reconnecting and retrying - $($errorMessage)" | Write-Log -LogPath $logFile -LogLevel "Warning"
                Connect-AzApplication -certificatePath $certificatePath -certificateSecurePassword $certificateSecurePassword -needPassword $needPassword -tenant $tenant -appId $appId -logFile $logFile
                $retryCount = $retryCount + 1
            }
        }
    } while ($stopLoop -eq $false)
    return $azureRMActivityEvents
}

function Get-UnifiedAuditLogPurview {
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Unfiltered","Operations","RecordTypes","FreeText","IPAddresses","UserIds")]
        [String]$requestType,
        [Parameter(Mandatory = $false)]
        [String]$freeText,
        [Parameter(Mandatory = $false)]
        [string[]]$IPAddresses,
        [Parameter(Mandatory = $false)]
        [string[]]$userIds,
        [Parameter(Mandatory = $false)]
        [string[]]$operations,
        [Parameter(Mandatory = $false)]
        [string[]]$recordTypes,
        [Parameter(Mandatory = $true)]
        [String]$sessionName,
        [Parameter(Mandatory = $true)]
        [DateTime]$startDate,
        [Parameter(Mandatory = $true)]
        [DateTime]$endDate,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate,
        [Parameter(Mandatory = $true)]
        [String]$appId,
        [Parameter(Mandatory = $true)]
        [String]$tenant,
        [Parameter(Mandatory = $true)]
        [String]$logFile,
        [Parameter(Mandatory = $true)]
        [String]$outputFile
    )
    $stopLoop = $false
    [Int]$retryCount = "0"
    "Collecting $requestType events for $startDate - $endDate" | Write-Log -LogPath $logFile -LogLevel "Info"
    do {
        try {
            if ($requestType -eq "Unfiltered"){
                $auditLogQuery = New-MgBetaSecurityAuditLogQuery -FilterStartDateTime $startDate -FilterEndDateTime $endDate -DisplayName $sessionName -ErrorAction Stop
            }
            if ($requestType -eq "RecordTypes"){
                $auditLogQuery = New-MgBetaSecurityAuditLogQuery -FilterStartDateTime $startDate -FilterEndDateTime $endDate -DisplayName $sessionName -RecordTypeFilters $recordTypes -ErrorAction Stop
            }
            elseif ($requestType -eq "Operations"){
                $auditLogQuery = New-MgBetaSecurityAuditLogQuery -FilterStartDateTime $startDate -FilterEndDateTime $endDate -DisplayName $sessionName -OperationFilters $operations -ErrorAction Stop
            }
            elseif ($requestType -eq "FreeText"){
                $auditLogQuery = New-MgBetaSecurityAuditLogQuery -FilterStartDateTime $startDate -FilterEndDateTime $endDate -DisplayName $sessionName -KeywordFilter $freeText -ErrorAction Stop
            }
            elseif ($requestType -eq "IPAddresses"){
                $auditLogQuery = New-MgBetaSecurityAuditLogQuery -FilterStartDateTime $startDate -FilterEndDateTime $endDate -DisplayName $sessionName -IPAddressFilters $IPAddresses -ErrorAction Stop
            }
            elseif ($requestType -eq "UserIds"){
                $auditLogQuery = New-MgBetaSecurityAuditLogQuery -FilterStartDateTime $startDate -FilterEndDateTime $endDate -DisplayName $sessionName -UserPrincipalNameFilters $userIds -ErrorAction Stop
            }
            $stopLoop = $true
        }
        catch {
            if ($retryCount -ge 10){
                "Failed to create a Purview query for $($requestType) events for $startDate - $endDate $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                $auditLogQuery = $null
                $stopLoop = $true
            }
            else {
                $errorMessage = $_.Exception.Message
                Start-Sleep -Seconds (60 * ($retryCount + 1) + $(Get-Random -Minimum 1 -Maximum 60))
                "Failed to create a Purview query for $($requestType) events for $startDate - $endDate $($retryCount + 1) times - reconnecting and retrying - $($errorMessage)" | Write-Log -LogPath $logFile -LogLevel "Warning"
                Connect-MicrosoftGraphApplication -certificate $certificate -appId $appId -tenant $tenant -logFile $logFile
                $retryCount = $retryCount + 1
            }
        }
    } while ($stopLoop -eq $false)

    if ($null -ne $auditLogQuery){
        $auditLogQueryId = $auditLogQuery.Id
        "Purview query for $($requestType) events for $startDate - $endDate was created with the Id $($auditLogQueryId)" | Write-Log -LogPath $logFile -LogLevel "Info"
        $stopLoop = $false
        while (-not $stopLoop){
            try {
                $status = (Get-MgBetaSecurityAuditLogQuery -AuditLogQueryId $auditLogQueryId -ErrorAction Stop).Status
            }
            catch {
                "Failed to get status for query $auditLogQueryId. Retrying" | Write-Log -LogPath $logFile -LogLevel "Warning"
                continue
            }
            "Audit Log Query $($auditLogQueryId) is in status `"$status`"" | Write-Log -LogPath $logFile
            if ($status -eq "succeeded"){
                $stopLoop = $true
            }
            if ($status -eq "failed" -or $status -eq "cancelled"){
                "Audit Log Query $auditLogQueryId has failed: `"$status`"" | Write-Log -LogPath $logFile -LogLevel "Error"
                $stopLoop = $true
            }
            Start-Sleep -Seconds 10
        }
        if ($status -eq "succeeded"){
            $stopLoop = $false
            [Int]$retryCount = "0"
            "Trying to get events for query $auditLogQueryId" | Write-Log -LogPath $logFile -LogLevel "Info"
            Get-MgPurviewAuditLog -auditLogQueryId $auditLogQueryId -certificate $certificate -appId $appId -tenant $tenant -logFile $logFile -outputFile $outputFile         
        }
    }
}

function Get-MailboxAuditLog {
    param
    (
        [Parameter(Mandatory = $true)]
        [String]$outputFileWithoutJson,
        [Parameter(Mandatory = $true)]
        [System.Array]$userIds,
        [Parameter(Mandatory = $true)]
        [DateTime]$startDate,
        [Parameter(Mandatory = $true)]
        [DateTime]$endDate,
        [Parameter(Mandatory = $true)]
        [String]$logFile,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate,
        [Parameter(Mandatory = $true)]
        [String]$appId,
        [Parameter(Mandatory = $true)]
        [String]$tenant
    )

    foreach ($userId in $userIds){
        $mailboxAuditLogEntries = @()
        $countMailboxAuditLogEntries = 0

        "Collecting MailboxAuditLog events for $startDate - $endDate for user $userId" | Write-Log -LogPath $logFile -LogLevel "Info"
        $outputFile = "$($outputFileWithoutJson)_$($userId).json"
        $stopLoop = $false
        [Int]$retryCount = "0"
        do {
            try {
                $mailboxAuditLogEntries = Search-MailboxAuditLog -StartDate $startDate -EndDate $endDate -Identity $userId -LogonTypes Admin,Delegate,Owner -IncludeInactiveMailbox -ShowDetails -ResultSize 250000 -ErrorAction Stop
                $countMailboxAuditLogEntries = ($mailboxAuditLogEntries | Measure-Object).Count
				$stopLoop = $true
            }
            catch {
				if ($_.ToString().contains("ManagementObjectNotFoundException") -or $_.ToString().contains("couldn't be found on")){
                    "$($userId) does not have a mailbox" | Write-Log -LogPath $logFile -LogLevel "Warning"
                    $countMailboxAuditLogEntries = 0
                    $stopLoop = $true
				}
                else {
                    if ($retryCount -ge 10){
                        "Failed to dump MailboxAuditLog for $($userId) $($retryCount + 1) times - aborting" | Write-Log -LogPath $logFile -LogLevel "Error"
                        $countMailboxAuditLogEntries = 0
                        $stopLoop = $true
                    }
                    else {
                        $errorMessage = $_.Exception.Message
                        "Failed to dump MailboxAuditLog for $($userId) $($retryCount + 1) times - reconnecting, sleeping and retrying - $($errorMessage)" | Write-Log -LogPath $logFile -LogLevel "Warning"
                        Connect-ExchangeOnlineApplication -logFile $logFile -certificate $cert -appId $appId -organization $tenant
                        Start-Sleep -Seconds (60 * ($retryCount + 1))
                        $retryCount = $retryCount + 1
                    }
                }
            }
        } while ($stopLoop -eq $false)

        if ($countMailboxAuditLogEntries -gt 250000){
            "More than 250000 events in one day, consider those events incomplete between $($startDate) and $($endDate) for $($userId)" | Write-Log -LogPath $logFile -LogLevel "Warning"
        }
        if ($countMailboxAuditLogEntries -gt 0){
            "Collected $countMailboxAuditLogEntries MailboxAuditLog events for $startDate - $endDate for user $userId" | Write-Log -LogPath $logFile -LogLevel "Info"
            $mailboxAuditLogEntries | ConvertTo-Json -Depth 99 | Out-File $outputFile -Encoding UTF8 -Append
            $mailboxAuditLogEntries = @()
            $countMailboxAuditLogEntries = 0
        }
        else {
            "0 MailboxAuditLog events between {0:yyyy-MM-dd} {0:HH:mm:ss} and {1:yyyy-MM-dd} {1:HH:mm:ss} were found for user $userId" -f ($startDate, $endDate) | Write-Log -LogPath $logFile -LogLevel "Warning"
        }
    }
}