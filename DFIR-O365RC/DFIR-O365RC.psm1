Function Write-Log {

    Param 
    ( 
        [Parameter(Mandatory=$true, 
        ValueFromPipeline = $true)] 
        [ValidateNotNullOrEmpty()] 
        [string]$Message, 
 
        [Parameter(Mandatory=$true)] 
        [Alias('LogPath')] 
        [string]$Path, 
         
        [Parameter(Mandatory=$false)] 
        [ValidateSet("Error","Warning","Info")] 
        [Alias('LogLevel')] 
        [string]$Level="Info" 

    ) 

    $logtime = "{0:yyyy-MM-dd} {0:HH:mm:ss}" -f (get-date) + ","

    switch ($Level) { 
        'Error' { 
            $LevelText = 'ERROR,' 
            } 
        'Warning' { 
            $LevelText = 'WARNING,' 
            } 
        'Info' { 
            $LevelText = 'INFO,' 
            } 
        }
     
    "$logtime $LevelText $Message" | Out-File -FilePath $Path -Append -Encoding UTF8
}

Function Get-OAuthToken {

    <#
    .SYNOPSIS
    The Get-OAuthToken function returns a MSAL token for a given Microsoft Cloud Service using the MSAL.PS module.

    .EXAMPLE
    --- Prompts connexion for Microsoft Graph Service and returns token ---
    Get-OAuthToken -Service MSGraph -silent $false


    #>

    param (
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("EXO","MSGraph","AzRM","AzDevOps")]
        [string]$Service,
        [Parameter(Mandatory = $false, ParameterSetName="silent")]
        [boolean]$silent=$false,
        [Parameter(Mandatory = $false, ParameterSetName="DeviceCode")]
        [boolean]$DeviceCode=$false,
        [Parameter(Mandatory = $false)]
        [string]$LoginHint,
        [Parameter(Mandatory = $false)]
        [string]$Logfile
    )

    switch ($Service) {
        exo {
            # EXO Powershell Client ID
            $clientId = "a0c73c16-a7e3-4564-9a95-2bdf47383716" 
            $scope = "https://outlook.office365.com/.default"
            $redirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
        }
        MSGraph {
            # Azure AD PowerShell Client ID
            $clientId = "1b730954-1685-4b74-9bfd-dac224a7b894"
            $scope = "https://graph.microsoft.com/.default"
            $redirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    
        }
        AzRM
            {
            # AZ PowerShell Client ID
            $clientid = "1950a258-227b-4e31-a9cf-717495945fc2"
            $scope = "https://management.azure.com/.default"
            $redirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"   
            }
        AzDevOps
            {
            # AZ PowerShell Client ID
            $clientid = "1950a258-227b-4e31-a9cf-717495945fc2"
            $scope = "499b84ac-1321-427f-aa17-267ca6975798/user_impersonation"
            $redirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"       
            }
        Default { Write-Error "Service Not Implemented" -ErrorAction Stop }
    }


    $Stoploop = $false
    [int]$Retrycount = "0"
    do {
        try {
        if($silent)
            {$app = Get-MsalClientApplication | Where-Object{$_.ClientId -eq $clientId}
            if($app)
                {
                if($logfile){"Asking Oauth silent token renewal for $($Service)" | Write-Log -LogPath $logfile}    
                $token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes $scope -ErrorAction Stop
                }
            else{
                Write-Error "Silent token renewal asked but no token cache available for the given application ID"
                if($logfile){"Silent token renewal asked for $($Service) but no token cache available for the given application ID" | Write-Log -LogPath $logfile -LogLevel "Error"}
                }
            }
        else {
            if($logfile){"Asking Oauth token for $($Service)" | Write-Log -LogPath $logfile} 
            if($DeviceCode -eq $true)
            {
            $token = Get-MsalToken -ClientId $clientId -Interactive -Scope $scope -DeviceCode
            }
            else
                {
                if($PSVersionTable.PSEdition -eq "Desktop") 
                    {
                    $token = Get-MsalToken -ClientId $clientId -Interactive -Scope $scope -RedirectUri $redirectUri 
                    }
                elseif($PSVersionTable.PSEdition -eq "Core")
                    {
                    $token = Get-MsalToken -ClientId $clientId -Interactive -Scope $scope -DeviceCode   
                    }
                }
            }                          
        $Stoploop = $true
            }
        catch {
            if ($Retrycount -gt 3){
                $Stoploop = $true
                $ErrorMessage = $_.Exception.Message
                $FailedItem = $_.Exception.ItemName
                Write-Error "Failed to get Oauth token after 4 retries"
                if($logfile){"Failed to get Oauth token for $($Service) service after 4 retries: Item $($FailedItem) Error message $($ErrorMessage)" | Write-Log -LogPath $logfile -LogLevel "Error"}
                }
            else {
                Start-Sleep -Seconds 2
                $Retrycount = $Retrycount + 1
                $ErrorMessage = $_.Exception.Message
                $FailedItem = $_.Exception.ItemName
                Write-Warning -Message "Failed to get Oauth Token, retrying..."
                if($logfile){"Failed to get Oauth token for $($Service) service: Item $($FailedItem) Error message $($ErrorMessage)" | Write-Log -LogPath $logfile -LogLevel "Warning"}
                }
            }
        }
        While ($Stoploop -eq $false)
    

    $toklifetime =  (New-TimeSpan -Start (get-date) -End (get-date $token.ExpiresOn.LocalDateTime)).Minutes  
    if($toklifetime -ge 59)
    {
    
        if($logfile){"New Oauth token for $($Service) service acquired" | Write-Log -LogPath $logfile}  
    }  
    return $token
}

Function Get-RestAPIResponse {
    param 
    (
        [Parameter(Mandatory = $true)]
        [string]$uri,
        [Parameter(Mandatory = $true)]   
        [System.Object]$app,
        [Parameter(Mandatory = $true)]
        [string]$user,
        [Parameter(Mandatory = $true)]
        [ValidateSet("MSGraph","AzRM","AzDevOps")]
        [string]$RESTAPIService,
        [Parameter(Mandatory = $true)]
        [string]$Logfile
    )
    if($RESTAPIService -eq "MSGraph")
        {$token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes "https://graph.microsoft.com/.default"}
    elseif($RESTAPIService -eq "AzRM")
        {$token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes "https://management.azure.com/.default"}
    else
        {$token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes "499b84ac-1321-427f-aa17-267ca6975798/user_impersonation"}
    $APIresults = @()

    $Stoploop = $false
    [int]$Retrycount = "0"
    do {
        try {

        $Data = Invoke-RestMethod -Headers @{Authorization = "Bearer $($token.AccessToken)"} -Uri $Uri -Method Get -ContentType "application/json" -ErrorAction Stop
        $Stoploop = $true
            }
        catch {
            if ($Retrycount -gt 9){
                "Failed to dump from $($RESTAPIService) uri $($uri) records $($Retrycount) times - aborting" | Write-Log -LogPath $logfile -LogLevel "Error"
                $Data = @()  
                $Stoploop = $true
                }
            else {
                $errorcode = $_.Exception.Response.StatusCode.value__
                $errormessage = $_.ErrorDetails.Message
                "Failed to dump from $($RESTAPIService) uri $($uri) - sleeping and retrying  - $($errorcode) : $($errormessage)" | Write-Log -LogPath $logfile -LogLevel "Warning"
                
                If ($errorcode -eq "429") {
                    Start-Sleep -Seconds (5 * ($Retrycount + 1))
                }
                Elseif ($errorcode -eq "403") {
                    $Retrycount = 9
                }
                Else {
                    Start-Sleep -Seconds 1
                }
                $Retrycount = $Retrycount + 1
                }
            }
        }
        While ($Stoploop -eq $false)

        if($Data)
        {   if($RESTAPIService -eq "AzDevOps"){$APIresults+=$Data.decoratedAuditLogEntries} 
            else{$APIresults+=$Data.Value}
            while(($null -ne $Data."@odata.nextLink") -or  ($null -ne $Data.nextLink) -or ($Data.hasMore -eq $true)) {        
            $Stoploop = $false
             [int]$Retrycount = "0"
              do {
                   try {
                    if($RESTAPIService -eq "MSGraph")
                        {
                        $Data = Invoke-RestMethod -Uri $Data."@odata.nextLink" -Headers @{Authorization = "Bearer $($token.AccessToken)"} -Method Get -ContentType "application/json" -ErrorAction Stop
                        }
                    elseif($RESTAPIService -eq "AzRM") {
                        $Data = Invoke-RestMethod -Uri $Data.nextLink -Headers @{Authorization = "Bearer $($token.AccessToken)"} -Method Get -ContentType "application/json" -ErrorAction Stop
                        }
                    else{
                        $urisuite = (($uri -split "startTime")[0]) + "continuationToken=$($Data.continuationToken)&api-version=6.0-preview.1"
                        $Data = Invoke-RestMethod -Uri $urisuite -Headers @{Authorization = "Bearer $($token.AccessToken)"} -Method Get -ContentType "application/json" -ErrorAction Stop
                        }
                    if($RESTAPIService -eq "AzDevOps"){$APIresults+=$Data.decoratedAuditLogEntries} 
                    else{$APIresults+=$Data.Value}
                    $Stoploop = $true
                     }
                catch {
                    if ($Retrycount -gt 3){
                        "Failed to dump from $($RESTAPIService) uri $($uri) records 3 times - aborting" | Write-Log -LogPath $logfile -LogLevel "Error"
                         $Data = @()  
                         $Stoploop = $true
                    }
                     else {
                        $errormessage = $_.Exception.Message
                        "Failed to dump from $($RESTAPIService) uri $($uri) - sleeping and retrying  - $($errormessage)" | Write-Log -LogPath $logfile -LogLevel "Warning"   
                        Start-Sleep -Seconds 1
                        if($token.ExpiresOn -le (get-date))
                            {
                            "Token has expired renewing $($RESTAPIService) token" | Write-Log -LogPath $logfile -LogLevel "Warning"  
                            if($RESTAPIService -eq "MSGraph")
                            {$token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes "https://graph.microsoft.com/.default"}
                        elseif($RESTAPIService -eq "AzRM")
                            {$token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes "https://management.azure.com/.default"}
                        else
                            {$token = Get-MsalToken -Silent -PublicClientApplication $app -LoginHint $user -Scopes "499b84ac-1321-427f-aa17-267ca6975798/user_impersonation"}
                            }
                        $Retrycount = $Retrycount + 1
                        }
                    }  
                } While ($Stoploop -eq $false)   
            }
        }    
        else
        {"No event to process for uri $($uri)"  | Write-Log -LogPath $logfile  }    
    return $APIresults
}

function Connect-EXOPsearchUnified
{

param (
        
        [Parameter(Mandatory = $true)]   
        [System.Object]$token,
        [Parameter(Mandatory = $true)]   
        [string]$sessionName,
        [Parameter(Mandatory = $true)]
        [string]$Logfile,
        [Parameter(Mandatory = $false)]
        [array]$commandNames = "Search-UnifiedAuditLog"
    )

    
    $UserId = ($token.Account.Username).tostring()
    $Stoploop = $false
    [int]$Retrycount = "0"
    do {
        try {
        Connect-ExchangeOnline -AccessToken $token.AccessToken -UserPrincipalName $UserId -CommandName $commandNames -ErrorAction Stop
        "EXO session $($sessionName) successfully created" | Write-Log -LogPath $logfile                           
        $Stoploop = $true
            }
        catch {
            if ($Retrycount -gt 3){
                "Failed to create EXO session $($sessionName) $($Retrycount) times - aborting" | Write-Log -LogPath $logfile -LogLevel "Error"  
                $Stoploop = $true
                }
            else
                {
                $errormessage = $_.Exception.Message
                "Failed to create EXO session $($sessionName) - sleeping and retrying  - $($errormessage)" | Write-Log -LogPath $logfile -LogLevel "Warning"   
                if ($errormessage -like "*No cmdlet assigned to the user have this feature enabled.*") {
                    $Retrycount = 3
                }
                else {  
                    Start-Sleep -Seconds (60 * ($Retrycount + 1))
                }
                $Retrycount = $Retrycount + 1                  
                }
            }
        }
        While ($Stoploop -eq $false)
}


Function Get-LargeUnifiedAuditLog {
    param 
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Operations","Records","freetext","IPAddresses","UserIds")]
        [string]$requesttype,
        [Parameter(Mandatory = $true)]
        [string]$sessionName,
        [Parameter(Mandatory = $true)]
        [string]$outputfile,
        [Parameter(Mandatory = $false)]
        [string]$recordtype,
        [Parameter(Mandatory = $false)]
        [string]$searchstring,
        [Parameter(Mandatory = $false)]
        [System.Array]$searchtable,
        [Parameter(Mandatory = $false)]
        [array]$operations,
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,
        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,
        [Parameter(Mandatory = $true)]
        [string]$Logfile
    )
    $j = 0 
    Do {

        $Stoploop = $false
        [int]$Retrycount = "0"
        do {
            try {
            # Using ReturnLargeSet to get back up to 50k records, 5k at a time
				if($requesttype -eq "Records")
				{
					$o = Search-UnifiedAuditLog -StartDate $startdate -EndDate $enddate -RecordType $recordtype -SessionId $sessionName -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction Stop
					$n = ($o | measure-object).count
					$f = (($o | Select-Object -Property ResultCount -Unique).ResultCount -eq 0) -or (($o | Select-Object -Property ResultIndex -Unique).ResultIndex -eq -1)
				}
				elseif($requesttype -eq "Operations")
				{
					$o = Search-UnifiedAuditLog -StartDate $startdate -EndDate $enddate -Operations $operations -SessionId $sessionName -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction Stop                        
					$n = ($o | measure-object).count
					$f = (($o | Select-Object -Property ResultCount -Unique).ResultCount -eq 0) -or (($o | Select-Object -Property ResultIndex -Unique).ResultIndex -eq -1)
				}
				elseif($requesttype -eq "freetext")
				{
					$o = Search-UnifiedAuditLog -StartDate $startdate -EndDate $enddate -FreeText $searchstring -SessionId $sessionName -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction Stop                        
					$n = ($o | measure-object).count
					$f = (($o | Select-Object -Property ResultCount -Unique).ResultCount -eq 0) -or (($o | Select-Object -Property ResultIndex -Unique).ResultIndex -eq -1)
				}
				elseif($requesttype -eq "IPAddresses")
				{
					$o = Search-UnifiedAuditLog -StartDate $startdate -EndDate $enddate -IPAddresses $searchstring -SessionId $sessionName -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction Stop                        
					$n = ($o | measure-object).count
					$f = (($o | Select-Object -Property ResultCount -Unique).ResultCount -eq 0) -or (($o | Select-Object -Property ResultIndex -Unique).ResultIndex -eq -1)
				}
				elseif($requesttype -eq "UserIds")
				{
					$o = Search-UnifiedAuditLog -StartDate $startdate -EndDate $enddate -UserIds $searchtable -SessionId $sessionName -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction Stop                        
					$n = ($o | measure-object).count
					$f = (($o | Select-Object -Property ResultCount -Unique).ResultCount -eq 0) -or (($o | Select-Object -Property ResultIndex -Unique).ResultIndex -eq -1)
				}
				"Got $($n) records" | Write-Log -LogPath $logfile -LogLevel "Info"                      
				if ($f){
					Start-Sleep -Seconds 300
					throw "Error. Internal timeout"
				}
				$Stoploop = $true
            }
            catch {
                if ($Retrycount -gt 3){
                    "Failed to dump $($recordtype) records 4 times - aborting" | Write-Log -LogPath $logfile -LogLevel "Error"
                    $o = @()  
                    $n = 0
                    $Stoploop = $true
                    }
                else {
                    $errormessage = $_.Exception.Message
                    "Failed to dump $($recordtype) records - sleeping and retrying  - $($errormessage)" | Write-Log -LogPath $logfile -LogLevel "Warning"   
                    Start-Sleep -Seconds 1
                    $Retrycount = $Retrycount + 1
                    }
                }
            }
            While ($Stoploop -eq $false)
         # If count is 0, no records to process
        if ($n -gt 0) 
            {
             # Dump data to json file
            $o | Select-Object -ExpandProperty AuditData | out-file $outputfile -encoding UTF8 -append
            if ($n -lt 5000) {
                $o = @()
                $n = 0
             } 
             else {
            $j++
            }
        }
    } Until ($n -eq 0)
}

Function Get-MailboxAuditLog {
    param 
    (
        [Parameter(Mandatory = $true)]
        [string]$outputfile,
        [Parameter(Mandatory = $true)]
        [System.Array]$UserIds,
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,
        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,
        [Parameter(Mandatory = $true)]
        [string]$logfile
    )

    foreach ($userId in $UserIds)
    {
        $Stoploop = $false
        [int]$Retrycount = "0"
        do {
            try {
                $o = Search-MailboxAuditLog -StartDate $startdate -EndDate $enddate -Identity $userId -LogonTypes Admin,Delegate,Owner -IncludeInactiveMailbox -ShowDetails -ResultSize 250000 -ErrorAction Stop                        
                $n = ($o | measure-object).count
				"Got $($n) records" | Write-Log -LogPath $logfile -LogLevel "Info"
				$Stoploop = $true
            }
            catch {
				if ($_.CategoryInfo.Reason -eq "ManagementObjectNotFoundException") {
                    "$($userId) does not have a mailbox" | Write-Log -LogPath $logfile -LogLevel "Warning"
                    $o = @()
                    $n = 0
                    $Stoploop = $true
				}
                else
                {
                    if ($Retrycount -gt 3){
                        "Failed to dump MailboxAuditLog for $($userId) 4 times - aborting" | Write-Log -LogPath $logfile -LogLevel "Error"
                        $o = @()
                        $n = 0
                        $Stoploop = $true
                    }
                    else {
                        $errormessage = $_.Exception.Message
                        "Failed to dump MailboxAuditLog for $($userId) - sleeping and retrying  - $($errormessage)" | Write-Log -LogPath $logfile -LogLevel "Warning"   
                        Start-Sleep -Seconds 1
                        $Retrycount = $Retrycount + 1
                    }
                }
            }
        } While ($Stoploop -eq $false)
        if ($n -eq 250000){
            "More than 250000 events in one day, consider logs incomplete between $($startdate) and $($enddate) for $($userId)" | Write-Log -LogPath $logfile -LogLevel "Warning"
        }
        if ($n -gt 0){
            $o | ConvertTo-Json -Depth 99 | out-file $outputfile -encoding UTF8 -append
            $o = @()
            $n = 0
        }
    }
}