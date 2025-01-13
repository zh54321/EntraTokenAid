<#
    .Synopsis
    Pure PowerShell Entra OAuth authentication to get access and refresh tokens.

    .Description
    EntraTokenAid is a PowerShell module to simplify OAuth workflows with Microsoft Entra ID, to get the access and refresh token for different APIs using different clients.
    Accessing cleartext access and refresh tokens for various MS APIs (e.g., MS Graph) is often a requirement during engagements and research, especially using pre-consented clients (e.g., AzureCLI) to avoid additional consent prompts. Tokens are needed not only for manual enumeration via APIs but also for tools like AzureHound or GraphRunner, which require a valid refresh token. 
    With more customers starting to block the Device Code Flow, alternative authentication methods for obtaining cleartext refresh tokens are becoming increasingly important. While using AzureCLI modules is a common solution, its installation may not always be feasible—especially on customer systems. Other alternatives like roadtx require Python, which might not be ideal in customer environments.
    This tool should bridges this gap with a lightweight, standalone PowerShell solution that works even on the customers Windows systems.

    Features:
    - No dependencies: A pure PowerShell single-file module that works on Windows systems (tested in PS 5&7).
    - Interactive Authentication: Supports both OAuth Auth Code Flow and Device Code Flow.
    - Flexible Refresh: Obtain access tokens for any API and client using refresh tokens.
    - CAE Support: By default, requests CAE (Continuous Access Evaluation) capable access tokens, valid for 24 hours.
    - JWT Parsing: Automatically decodes access tokens to display details (e.g., scope, tenant, IP, authentication methods).
    - Avoiding Consent: By default, the tool uses the Azure CLI client ID, enabling many MS Graph API actions without additional consent due to pre-consented permissions.
    - Parameters: A wide range of parameters allow you to customize the tool's behavior, such as enabling features like PKCE, CAE, and more, providing greater control during usage.
    - Automation-Friendly: Enables automated OAuth Auth Code Flow tests by disabling user interaction, with the gathered tokens and claims exported to a CSV file.
    - Support of the parameters BrkClientId, RedirectUri and Origin. In combination with a refresh token from the Azure Portal, this allows to get tokens from applications with interesting pre consented scopes on the MS Graph API.

    .LINK
    https://github.com/zh54321/EntraTokenAid
#>


function Invoke-Auth {
    <#
    .SYNOPSIS
    Performs OAuth 2.0 authentication using the Authorization Code Flow for Microsoft Entra ID.

    .DESCRIPTION
    The `Invoke-Auth` function facilitates OAuth 2.0 Authorization Code Flow to get access and refresh tokens. It supports flexible configuration options, including scope, tenant, and client ID customization. The function can optionally output tokens, parse JWTs, or suppress PKCE, use CAE, and other standard authentication features. 
    This function is particularly useful for penetration testers and security researchers who need cleartext access/refresh tokens to interact with Microsoft APIs like Microsoft Graph.

    .PARAMETER Port
    Specifies the local port number for the redirection URI used during the authorization process. 
    Default: 13824

    .PARAMETER ClientID
    Specifies the client ID of the application being authenticated. 
    Default: `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Microsoft Azure CLI)

    .PARAMETER Scope
    Specifies the API permissions (scopes) to request during authentication. Multiple scopes should be space-separated.
    Default: `default offline_access`

    .PARAMETER Api
    Specifies the target API for the authentication request. Typically, this is the Microsoft Graph API.
    Default: `graph.microsoft.com`

    .PARAMETER HttpTimeout
    Specifies the time in seconds the http should listenting for requests.
    Useful for automated testing in combination with -DisablePrompt.
    Default: `180`

    .PARAMETER Tenant
    Specifies the tenant to authenticate against. Options include:
    - `organizations` (for multi-tenant apps)
    - A specific tenant ID
    Default: `organizations`

    .PARAMETER TokenOut
    Outputs the access and refresh tokens to the console upon successful authentication.

    .PARAMETER DisableJwtParsing
    Disables parsing of the JWT access token. When set, the token is returned as-is without any additional information.

    .PARAMETER DisablePrompt
    Prevents user selection in the browser during authentication (silent authentication).

    .PARAMETER DisablePKCE
    Disables the use of Proof Key for Code Exchange (PKCE) during authentication.

    .PARAMETER RedirectURL
    Custom redirect URL.
    Default: `http://localhost:%PORT%`

    .PARAMETER DisableCAE
    Disables Continuous Access Evaluation (CAE), which is used to revoke tokens in real-time based on certain security events.
    Access token are shorter lived when CAE is not used.

    .PARAMETER Reporting
    Enables additional logging to a CSV.

    .EXAMPLE
    Invoke-Auth

    Performs the defualt authentication for Microsoft Graph with client id of Azure CLI.

    .EXAMPLE
    Invoke-Auth -ClientID "04b07795-8ddb-461a-bbee-02f9e1bf7b46" -Scope "User.Read" -Api "graph.microsoft.com"

    Performs authentication for Microsoft Graph with the specified client ID and scope.

    .EXAMPLE
    Invoke-Auth -Api "management.azure.com"

    Performs authentication for Azure ARM

    .EXAMPLE
    Invoke-Auth -Tenant 9f412d6a-ae60-43fb-9765-32e31a6XXXXX"

    Performs authentication on a specific tenant

    .EXAMPLE
    Invoke-Auth -DisablePKCE -$DisableCAE

    Disable the usage of PKCE and do not request CAE.
    #>
    param (
        [Parameter(Mandatory=$false)][int]$Port = 13824,
        [Parameter(Mandatory=$false)][int]$HttpTimeout = 180,
        [Parameter(Mandatory=$false)][string]$ClientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        [Parameter(Mandatory=$false)][string]$Scope = "default offline_access",
        [Parameter(Mandatory=$false)][string]$Api = "graph.microsoft.com",
        [Parameter(Mandatory=$false)][string]$Tenant = "organizations",
        [Parameter(Mandatory=$false)][string]$RedirectURL = "http://localhost:$($Port)",
        [Parameter(Mandatory=$false)][switch]$TokenOut,
        [Parameter(Mandatory=$false)][switch]$DisableJwtParsing = $false,
        [Parameter(Mandatory=$false)][switch]$DisablePrompt = $false,
        [Parameter(Mandatory=$false)][switch]$DisablePKCE = $false,
        [Parameter(Mandatory=$false)][switch]$DisableCAE = $false,
        [Parameter(Mandatory=$false)][switch]$Reporting = $false
    )

    $AuthError = $false
    # Http Server
    $HttpListener = [System.Net.HttpListener]::new() 
    $HttpListener.Prefixes.Add("http://localhost:$Port/")
    Try {
        $HttpListener.Start()
    } Catch {
        $HttpStartError = $_
        if ($HttpStartError -match "because it conflicts with an existing registration on the machine") {
            Write-Host "[!] The port $Port is already blocked by another process."
            Write-Host "[!] Close the other process or use -port to define another port."
        } else {
            write-host "[!] ERROR: $HttpStartError"
        }
    }
        
    if ($HttpListener.IsListening) {
        write-host "[+] HTTP server running on http://localhost:$Port/"
        write-host "[i] Listening for OAuth callback for $HttpTimeout s (HttpTimeout value) "
        write-host "[i] Press Ctrl+C to stop manually."

        # Variable to control the server loop
        $KeepRunning = $true

        # Runspace for the HTTP server
        $Runspace = [runspacefactory]::CreateRunspace()
        $Runspace.Open()

        # Shared object for communication
        $RequestQueue = [System.Collections.Concurrent.ConcurrentQueue[PSObject]]::new()

        # Script block for the HTTP server loop
        $ScriptBlock = {
            param(
                    $HttpListener,
                    [ref]$KeepRunning,
                    $RequestQueue
                )

            #Outer while loop to keep the server running in case of errors
            while ($KeepRunning.Value -and $HttpListener.IsListening) {
                try {
                    while ($KeepRunning.Value -and $HttpListener.IsListening) {

                        $Context = $HttpListener.GetContext()

                        # Retrieve request information and share with main script
                        $Request = $Context.Request
                        $RequestQueue.Enqueue($Request)

                        # Response handeling in case there is a code parameter
                        if ($Request.HttpMethod -eq 'GET' -and $Request.QueryString -match "\bcode\b") {
                            [string]$HtmlContent = "
                            <!DOCTYPE html>
                                <head>
                                    <title>OAuth Code Received</title>
                                        <style>
                                            body { font-family: monospace; background: #1b1b3a; color: #a0b0d0; margin: 0; display: flex; justify-content: center; align-items: center; height: 100vh; }
                                            .container { background: #2a2a50; padding: 20px; border-radius: 8px; width: 400px; box-shadow: 0 0 15px rgba(160,176,208,0.3); }
                                            .field { margin: 12px 0; }
                                            .label { font-weight: bold; font-size: 18px; color:rgb(224, 219, 218); }
                                        </style>
                                </head>
                                <body>
                                    <div class='container'><div class='field'><span class='label'>Received an OAuth Authorization Code<br>You can now close this tab.</span></div></div>
                                </body>
                            </html>
                            "
                            #Response to the HTTP request
                            $Response = $Context.Response
                            $ResponseOutput = [System.Text.Encoding]::UTF8.GetBytes($HtmlContent)
                            $Response.OutputStream.Write($ResponseOutput, 0, $ResponseOutput.Length)
                            $Response.OutputStream.Close()

                        } else {
                            [string]$HtmlContent = "<!DOCTYPE html>Nothing to see here.</html>"
                            $Response = $Context.Response
                            $Response.StatusCode = "404"
                            $ResponseOutput = [System.Text.Encoding]::UTF8.GetBytes($HtmlContent)
                            $Response.OutputStream.Write($ResponseOutput, 0, $ResponseOutput.Length)
                            $Response.OutputStream.Close()
                        }

                    }
                } catch {
                    # Share error data
                    $RequestQueue.Enqueue($_)
                }
            }
        }


        #Construct Scope
        $ApiScopeUrl = "https://$Api/.$Scope"

        #Generate State
        $State = [Convert]::ToBase64String((1..12 | ForEach-Object { [byte](Get-Random -Minimum 0 -Maximum 256) })).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Define the URL
        $Url = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/authorize?response_type=code&client_id=$ClientID&redirect_uri=$RedirectURL&state=$State&scope=$ApiScopeUrl&client_info=1"

        #Check if account prompt should be disabled
        if (-not $DisablePrompt) {
            $Url += "&prompt=select_account"
        }

        #Check if PKCE should not be used
        if (-not $DisablePKCE) {
            $PKCE = -join ((48..57) + (65..90) + (97..122) + 45, 46, 95, 126 | Get-Random -Count (Get-Random -Minimum 43 -Maximum 129) | ForEach-Object {[char]$_})
            $Url += "&code_challenge=$PKCE&code_challenge_method=plain"
        }

        #Check if CAE is wanted
        if (-not $DisableCAE) {
            $Url += '&claims={%22access_token%22:%20{%22xms_cc%22:%20{%22values%22:%20[%22CP1%22]}}}'
        }

        # Create a PS instance and assign the script block to it
        $PSInstance = [powershell]::Create()
        $PSInstance.AddScript($ScriptBlock).AddArgument($HttpListener).AddArgument([ref]$KeepRunning).AddArgument($RequestQueue) | Out-Null
        $PSInstance.Runspace = $Runspace
        $PSInstance.BeginInvoke() | Out-Null

        # Main loop to process output from the shared queue
        $StartTime = [datetime]::Now
        $Proceed = $true
        # Start auth flow in Browser
        Start-Process $Url

        #Main Flow which process the received web request
        try {
            while ($Proceed) {
                Start-Sleep -Milliseconds 500
    
                # Check if the runtime exceeds the timeout (if set)
                if ($HttpTimeout -gt 0 -and ([datetime]::Now - $StartTime).TotalSeconds -ge $HttpTimeout) {
                    Write-Host "[!] Runtime limit reached. Stopping the server..."
                    $AuthError = $true
                    $Proceed = $false

                    #Create Error Object to use in reporting
                    $ErrorDetails = [PSCustomObject]@{
                        ClientID    = $ClientID
                        ErrorLong   = "Timeout limit reached"
                    }
                    break
                }
    
                # Process output from the shared queue
                $Request = $null
                while ($RequestQueue.TryDequeue([ref]$Request) -and $Proceed) {

                    #Null check to avoid the script crashing
                    if ($Request.HttpMethod -eq 'GET' -and $Request.QueryString -match "\bcode\b") {

                        write-host "[+] Got OAuth callback request containing CODE"

                        $RawUrl =  $($Request.RawUrl)
    
                        #Get content of the GET parameters
                        $QueryString = $RawUrl  -replace '^.*\?', ''
                        $Params = $QueryString -split '&'
                        $QueryParams = @{}
    
                        # Iterate over each parameter and split into key-value pairs
                        foreach ($Param in $Params) {
                            $Key, $Value = $Param -split '=', 2
                            $QueryParams[$Key] = $Value
                        }
                        $Code = $QueryParams["code"]
                        $StateResponse = $QueryParams["state"]
                        
                        if ($StateResponse -ne $State) {
                            write-host "[!] Error: Wrong state reveived from IDP. Aborting..."
                            write-host "[!] Error: Received $StateResponse but exepected $State"
                            $AuthError = $true
                            $Proceed = $false
                            $ErrorDetails = [PSCustomObject]@{
                                ClientID    = $ClientID
                                ErrorLong   = "Wrong state reveived from IDP"
                            }
                            break
                        }
    
                        write-host "[*] Calling the token endpoint"
    
                        #Define headers (emulate Azure CLI)
                        $Headers = @{
                            "User-Agent" = "python-requests/2.32.3"
                            "X-Client-Sku" = "MSAL.Python"
                            "X-Client-Ver" = "1.31.0"
                            "X-Client-Os" = "win32"
                        }
    
                        #Define Body
                        $Body = @{
                            grant_type   = "authorization_code"
                            client_id    = "$ClientID"
                            scope        = $ApiScopeUrl
                            code         = $Code
                            redirect_uri = "http://localhost:$Port/"
                            client_info  = 1
                        }
    
                        #Add PKCE if not disabled
                        if (-not $DisablePKCE) {
                            $Body.Add("code_verifier", $PKCE)
                        }
    
                        #Check if CAE is deactivated
                        if (-not $DisableCAE) {
                            $Body.Add("claims", '{"access_token": {"xms_cc": {"values": ["CP1"]}}}')
                        }
    
                        Try {
                            # Call the token endpoint to get the tokens
                            $tokens = Invoke-RestMethod 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token' -Method POST -Body $Body -Headers $Headers
                        } Catch {
                            #Error Handling for initial request
                            $TokenRequestError = $_ | ConvertFrom-Json
                            if ($TokenRequestError.error -eq "invalid_grant") {
                                Write-Host "[!] The authorization code or PKCE code verifier is invalid or has expired. Aborting..."
                            } elseif ($TokenRequestError.error -eq "invalid_request") {
                                Write-Host "[!] Protocol error, such as a missing required parameter. Aborting..."
    
                            } elseif ($TokenRequestError.error -eq "unauthorized_client") {
                                Write-Host "[!] The authenticated client isn't authorized to use this authorization grant type.. Aborting..."
    
                            } elseif ($TokenRequestError.error -eq "invalid_resource") {
                                Write-Host "[!] The target resource is invalid because it doesn't exist, Microsoft Entra ID can't find it, or it's not correctly configured. Aborting..."
    
                            } elseif ($TokenRequestError.error -eq "consent_required") {
                                Write-Host "[!] The request requires user consent.. Aborting..."
    
                            } elseif ($TokenRequestError.error -eq "invalid_scope") {
                                Write-Host "[!] The scope requested by the app is invalid... Aborting..."
    
                            } else {
                                Write-Host "[!] Unknown error: Aborting...."
                                Write-Host "[!] Error: $($TokenRequestError.error)"
                                Write-Host "[!] Error Description: $($TokenRequestError.error_description)"
                            }

                            #Create Error Object to use in reporting
                            $ErrorDetails = [PSCustomObject]@{
                                ClientID    = $ClientID
                                ErrorLong   = $($TokenRequestError.error_description)
                            }
                            $AuthError = $true
                            $Proceed = $false
                            break
                        }
    
                        #Check if answer contains tokens
                        if ($tokens.access_token -and $tokens.refresh_token) {
                            Write-Host "[+] Got an access token and a refresh token"
    
                            $tokens | Add-Member -NotePropertyName Expiration_time -NotePropertyValue (Get-Date).AddSeconds($tokens.expires_in)
    
                            if (-not $DisableJwtParsing) {
                                #Parse JWT
                                Try {
                                    # Parse the token
                                    $JWT = Invoke-ParseJwt -jwt $tokens.access_token
                                } Catch {
                                    $JwtParseError = $_ 
                                    Write-Host "[!] JWT Parse error: $($JwtParseError)"
                                    Write-Host "[!] Aborting...."

                                    #Create Error Object to use in reporting
                                    $ErrorDetails = [PSCustomObject]@{
                                        ClientID    = $ClientID
                                        ErrorLong   = $JwtParseError
                                    }

                                    $AuthError = $true
                                    $Proceed = $false
                                    break
                                }
    
                                #Add additonal infos to token object
                                $tokens | Add-Member -NotePropertyName scp -NotePropertyValue $JWT.scp
                                $tokens | Add-Member -NotePropertyName tenant -NotePropertyValue $JWT.tid
                                $tokens | Add-Member -NotePropertyName user -NotePropertyValue $JWT.upn
                                $tokens | Add-Member -NotePropertyName client_app -NotePropertyValue $JWT.app_displayname
                                $tokens | Add-Member -NotePropertyName client_app_id -NotePropertyValue $ClientID
                                $tokens | Add-Member -NotePropertyName auth_methods -NotePropertyValue $JWT.amr
                                $tokens | Add-Member -NotePropertyName ip -NotePropertyValue $JWT.ipaddr
                                $tokens | Add-Member -NotePropertyName uti -NotePropertyValue $JWT.uti
                                $tokens | Add-Member -NotePropertyName audience -NotePropertyValue $JWT.aud
                                $tokens | Add-Member -NotePropertyName api -NotePropertyValue ($JWT.aud -replace '^https?://', '' -replace '/$', '')
                                if ($null -ne $JWT.xms_cc) {
                                    $tokens | Add-Member -NotePropertyName xms_cc -NotePropertyValue $JWT.xms_cc
                                    $xms_cc = $true
                                } else {
                                    $xms_cc = $false
                                }
                                Write-Host "[i] Audience: $($JWT.aud) / Expires at: $($tokens.expiration_time)"
                            } else {
                                Write-Host "[i] Expires at: $($tokens.expiration_time)"
                            }
                            
                            $AuthError = $false
                            $Proceed = $false

                        } else {
                            Write-Host "[!] Error: Something went wrong. The answer from the token endpoint do not contains tokens"
                            $AuthError = $true
                            $Proceed = $false
                            #Create Error Object to use in reporting
                            $ErrorDetails = [PSCustomObject]@{
                                ClientID    = $ClientID
                                ErrorLong   = "The answer from the token endpoint do not contains tokens."
                            }
                            break
                        }
    
    


                    } elseif ($Request.HttpMethod -eq 'GET' -and $($Request.QueryString) -match "\berror\b") {
                        write-host "[!] Got OAuth callback request containing an ERROR"
                        $QueryString = $($Request.QueryString)
                        $RawUrl =  $($Request.RawUrl)
    
                        #Get content of the GET parameters
                        $QueryString = $RawUrl  -replace '^.*\?', ''
                        $Params = $QueryString -split '&'
                        $QueryParams = @{}
    
                        # Iterate over each parameter and split into key-value pairs
                        foreach ($Param in $Params) {
                            $Key, $Value = $Param -split '=', 2
                            $QueryParams[$Key] = $Value
                        }
    
                        #Define errors
                        $ErrorShort = $QueryParams["error"]
                        $ErrorDescription = [System.Web.HttpUtility]::UrlDecode($QueryParams["error_description"]) 
                        $MoreInfo = [System.Web.HttpUtility]::UrlDecode($QueryParams["error_uri"]) 
    
                        write-host "[!] Error in OAuth Callback: $ErrorShort"
                        write-host "[!] Description: $ErrorDescription"
                        write-host "[!] More info: $MoreInfo"

                        #Handle errors
                        $AuthError = $true
                        $Proceed = $false

                        #Create Error Object to use in reporting
                        $ErrorDetails = [PSCustomObject]@{
                            ClientID    = $ClientID
                            ErrorLong   = $MoreInfo
                        }

                        break

                    } elseif ($null -ne $Request -and $Request -is [System.Net.HttpListenerRequest]) {
                        Write-Host "[*] Got request without OAuth Code: $($Request.HttpMethod) $($Request.RawUrl))"
                    } else {
                        Write-Host "[!] Request caused an error: $Request"
                    }
                    
                }
            }
    
        } finally {
            #Cleaning up
            Write-Host "[*] Stopping the server..."
            $KeepRunning = $false
            Start-Sleep -Milliseconds 500 # Allow the loop in the runspace to complete
            $HttpListener.Stop()
            $PSInstance.Stop()
            $PSInstance.Dispose()
            $Runspace.Close()
            $Runspace.Dispose()
            Write-Host "[*] Server stopped."
        }

        if (-Not $AuthError) {
            #Print token info if switch is used
            if ($TokenOut) {
                invoke-PrintTokenInfo -jwt $tokens -NotParsed $DisableJwtParsing
            }
            
            #Check if report file should be written
            if ($Reporting) {
                Invoke-Reporting -jwt $tokens -OutputFile "Auth_report.csv"
            }

        } else {
            if ($Reporting) {
                Invoke-Reporting -ErrorDetails $ErrorDetails -OutputFile "Auth_report_error.csv"
            }
        }

        Return $tokens

    } else {
        write-host "[!] Error starting the HTTP Server!"
    }
}




function Invoke-Refresh {
    <#
    .SYNOPSIS
    Uses a refresh token to obtain a new access token, optionally for the same or a different API, or client.

    .DESCRIPTION
    `Invoke-Refresh` allows users to exchange an existing refresh token for a new access token. 
    It supports scenarios such as refreshing tokens for a different client or API, changing scopes, 
    or simply renewing tokens before expiration.

    .PARAMETER RefreshToken
    Specifies the refresh token to be exchanged for a new access token. This is a required parameter.

    .PARAMETER ClientID
    Specifies the client ID of the application. Defaults to  
    (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) Azure CLI.

    .PARAMETER Scope
    Defines the access scope requested in the new token. Defaults to `default offline_access`. 

    .PARAMETER Api
    The base URL of the API for which the new access token is required. Defaults to `graph.microsoft.com`.

    .PARAMETER UserAgent
    Specifies the user agent string to be used in the HTTP requests. This can be customized to mimic specific browser or application behavior.
    Default: `python-requests/2.32.3`

    .PARAMETER Tenant
    Specifies the target tenant id for authentication. Defaults to `organizations` for multi-tenant scenarios.

    .PARAMETER TokenOut
    If specified, the function outputs the access token in the console.

    .PARAMETER DisableJwtParsing
    Disables the automatic parsing of the access token's JWT payload. 

    .PARAMETER DisableCAE
    Disables Continuous Access Evaluation (CAE) features when requesting the new token.

    .PARAMETER BrkClientId
    Specifiy the brk_client_id parameter.

    .PARAMETER RedirectUri
    Specifiy the redirect_uri parameter.

    .PARAMETER Origin
    Define Origin Header to be used in the HTTP request.

    .PARAMETER Reporting
    Enables logging (CSV) the details of the refresh operation for later analysis. 

    .EXAMPLE
    # Example 1: Refresh an access token for the default client and API
    Invoke-Refresh -RefreshToken $tokens.refresh_token

    # Example 2: Refresh an access token for a custom client, scope, and tenant
    Invoke-Refresh -ClientID "your-client-id" -Scope "custom_scope offline_access" -Api "custom.api.endpoint" -RefreshToken "sample_refresh_token"

    .NOTES
    - The function can handle both same-client and cross-client token refreshes (FOCI).
    - Ensure that the refresh token provided has the necessary permissions for the requested client, scope, or API.

    #>
    param (
        [Parameter(Mandatory=$true)][string]$RefreshToken,
        [Parameter(Mandatory=$false)][string]$ClientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        [Parameter(Mandatory=$false)][string]$Scope = "default offline_access",
        [Parameter(Mandatory=$false)][string]$Api = "graph.microsoft.com",
        [Parameter(Mandatory=$false)][string]$Tenant = "common",
        [Parameter(Mandatory=$false)][switch]$TokenOut,
        [Parameter(Mandatory=$false)][string]$UserAgent = "python-requests/2.32.3",
        [Parameter(Mandatory=$false)][switch]$DisableJwtParsing = $false,
        [Parameter(Mandatory=$false)][switch]$DisableCAE = $false,
        [Parameter(Mandatory=$false)][switch]$Reporting = $false,
        [Parameter(Mandatory=$false)][string]$Origin,
        [Parameter(Mandatory=$false)][string]$BrkClientId,
        [Parameter(Mandatory=$false)][string]$RedirectUri
    )

    #Define headers (Emulat Azure CLI)
    $Headers = @{
        "User-Agent" = $UserAgent
        "X-Client-Sku" = "MSAL.Python"
        "X-Client-Ver" = "1.31.0"
        "X-Client-Os" = "win32"
        "Origin" = $Origin
    }

    #Construct Scope
    $ApiScopeUrl = "https://$Api/.$Scope"

    #Define Body (Emulat Azure CLI)
    $Body = @{
        grant_type    = "refresh_token"
        client_id     = $ClientID
        scope  = $ApiScopeUrl
        refresh_token = $RefreshToken
    }

    #Check if CAE is wanted
    if (-not $DisableCAE) {
        $Body.Add("claims", '{"access_token": {"xms_cc": {"values": ["CP1"]}}}')
    }

    #Check if brk_client_id is wanted
    if (-not [string]::IsNullOrEmpty($BrkClientId)) {
        $Body.Add("brk_client_id", $BrkClientId)
    }
    
    #Check if redirect uri is wanted
    if (-not [string]::IsNullOrEmpty($RedirectUri)) {
        $Body.Add("redirect_uri", $RedirectUri)
    }    

    Write-Host "[*] Sending request to token endpoint"
    # Call the token endpoint to get the tokens
    $Proceed = $true

    #Try to get the tokens
    Try {
        $tokens = Invoke-RestMethod "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -Method POST -Body $Body -Headers $Headers
    } Catch {
        Write-Host "[!] Request Error:"
        $RequestError = $_ 
        $ParsedError = $null

        # Check if $RequestError is valid JSON
        if ($RequestError -and ($ParsedError = $RequestError | ConvertFrom-Json -ErrorAction SilentlyContinue)) {
            # Check if the parsed JSON contains the expected properties
            if ($ParsedError.PSObject.Properties["error"] -and $ParsedError.PSObject.Properties["error_description"]) {
                $ErrorShort = $ParsedError.error
                $ErrorLong = $ParsedError.error_description
                Write-Host "[!] Error: $ErrorShort"
                Write-Host "[!] Error Description: $ErrorLong"

                if ($Reporting) {
                    $ErrorDetails = [PSCustomObject]@{
                        ClientID    = $ClientID
                        ErrorLong   = $ErrorLong
                    }
                    Invoke-Reporting -ErrorDetails $ErrorDetails -OutputFile "Refresh_errors.csv"
                }

            } else {
                Write-Host "[!] Unknown error: $RequestError"
            }
        }
        Write-Host "[!] Aborting...."
        $Proceed = $false
    }

    #Check if answer contains tokens
    if ($tokens.access_token -and $tokens.refresh_token -and $Proceed) {
        Write-Host "[+] Got an access token and a refresh token"
        $tokens | Add-Member -NotePropertyName Expiration_time -NotePropertyValue (Get-Date).AddSeconds($tokens.expires_in)
    

        if (-not $DisableJwtParsing) {

            #Try to Parse the JWT
            Try {
                $JWT = Invoke-ParseJwt -jwt $tokens.access_token
            } Catch {
                
                $JwtParseError = $_ 
                Write-Host "[!] JWT Parse error: $($JwtParseError)"
                Write-Host "[!] Aborting...."
                break
            }

            #Add additonal infos to token object
            $tokens | Add-Member -NotePropertyName scp -NotePropertyValue $JWT.scp
            $tokens | Add-Member -NotePropertyName tenant -NotePropertyValue $JWT.tid
            $tokens | Add-Member -NotePropertyName user -NotePropertyValue $JWT.upn
            $tokens | Add-Member -NotePropertyName client_app -NotePropertyValue $JWT.app_displayname
            $tokens | Add-Member -NotePropertyName client_app_id -NotePropertyValue $ClientID
            $tokens | Add-Member -NotePropertyName auth_methods -NotePropertyValue $JWT.amr
            $tokens | Add-Member -NotePropertyName ip -NotePropertyValue $JWT.ipaddr
            $tokens | Add-Member -NotePropertyName audience -NotePropertyValue $JWT.aud
            $tokens | Add-Member -NotePropertyName api -NotePropertyValue ($JWT.aud -replace '^https?://', '' -replace '/$', '')
            if ($null -ne $JWT.xms_cc) {
                $tokens | Add-Member -NotePropertyName xms_cc -NotePropertyValue $JWT.xms_cc
            }
            Write-Host "[i] Audience: $($JWT.aud) / Expires at: $($tokens.expiration_time)"
        } else {
            Write-Host "[i] Expires at: $($tokens.expiration_time)"
        }
        
        #Print token info if switch is used
        if ($TokenOut) {
            invoke-PrintTokenInfo -jwt $tokens -NotParsed $DisableJwtParsing
        }

        #Check if report file should be written
        if ($Reporting) {
            Invoke-Reporting -jwt $tokens -OutputFile "Refresh_report.csv"
        }
        Return $tokens
    } elseif($Proceed) {
        Write-Host "[!] The answer obtained from the token endpoint do not contains tokens"
    }
    
}

function Invoke-DeviceCodeFlow {
    <#
        .SYNOPSIS
        Performs OAuth 2.0 authentication using the Device Code Flow.

        .DESCRIPTION
        The `Invoke-DeviceCodeFlow` function facilitates OAuth 2.0 authentication using the Device Code Flow. 
        This flow is ideal for scenarios where interactive login via a browser is required, but the client application runs in an environment where a browser is not readily available (e.g., CLI or limited UI environments). 
        The function automatically starts a browser session to complete authentication and copies the user code to the clipboard for convenience. Upon successful authentication, the function retrieves access and refresh tokens.

        .PARAMETER ClientID
        Specifies the client ID of the application being authenticated. 
        Default: `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Microsoft Azure CLI)

        .PARAMETER Api
        Specifies the target API for the authentication request.
        Default: `graph.microsoft.com`
        
        .PARAMETER DisableJwtParsing
        Disables parsing of the JWT access token. When set, the token is returned as-is without any additional information.

        .PARAMETER DisableBrowserStart
        Disables the automatic start of the browser.

        .PARAMETER TokenOut
        Outputs the access and refresh tokens to the console upon successful authentication.

        .PARAMETER UserAgent
        Specifies the user agent string to be used in the HTTP requests. This can be customized to mimic specific browser or application behavior.
        Default: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36`

        .PARAMETER Tenant
        Specifies the tenant to authenticate against. Options include:
        - `organizations` (for multi-tenant apps)
        - A specific tenant ID
        - `common` (for both personal and organizational accounts)
        - `consumers` (for personal accounts only).
        Default: `organizations`

        .PARAMETER Reporting
        Enables logging (CSV) the details of the refresh operation for later analysis. 

        .EXAMPLE
        Invoke-DeviceCodeFlow

        Performs device code flow authentication with the default settings (Microsoft Graph + Azure CLI).

        .EXAMPLE
        Invoke-DeviceCodeFlow -ClientID "your-client-id" -Api "management.azure.com"

        Performs device code flow authentication for Azure ARM with the specified client ID.

        .EXAMPLE
        Invoke-DeviceCodeFlow -TokenOut

        Performs authentication and outputs the access and refresh tokens to the console.
    #>
    param (
        [Parameter(Mandatory=$false)][string]$ClientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        [Parameter(Mandatory=$false)][string]$APi = "graph.microsoft.com",
        [Parameter(Mandatory=$false)][switch]$TokenOut,
        [Parameter(Mandatory=$false)][switch]$DisableJwtParsing = $false,
        [Parameter(Mandatory=$false)][switch]$DisableBrowserStart = $false,
        [Parameter(Mandatory=$false)][string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        [Parameter(Mandatory=$false)][string]$Tenant = "organizations",
        [Parameter(Mandatory=$false)][switch]$Reporting = $false
    )

    $Proceed = $true
    $Resource = "https://$API"
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Body = @{
        client_id   = $ClientID
        resource    = $Resource
    }
    write-host "[*] Starting Device Code Flow: API $Resource / Client id: $ClientID"

    # Call the token endpoint to get the tokens
    Try {
        $DeviceCodeDetails = Invoke-RestMethod "https://login.microsoftonline.com/$Tenant/oauth2/devicecode?api-version=1.0" -Method POST -Body $Body -Headers $Headers
    } Catch {
        $InitialError = $_ | ConvertFrom-Json  
        Write-Host "[!] Aborting...."
        Write-Host "[!] Error: $($InitialError.error)"
        Write-Host "[!] Error Description: $($InitialError.error_description)"
        if ($Reporting) {
            $ErrorDetails = [PSCustomObject]@{
                ClientID    = $ClientID
                ErrorLong   = $PollingError.error_description
            }
            Invoke-Reporting -ErrorDetails $ErrorDetails -OutputFile "DeviceCode_errors.csv"
        }
        $Proceed = $false
    }
    
    if ($Proceed) {
        Set-Clipboard $DeviceCodeDetails.user_code
        write-host "[i] User code: $($DeviceCodeDetails.user_code). Copied to clipboard..."

        #Check if browser should be started automatically
        if (-not $DisableBrowserStart) {
            write-host "[*] Opening browser"
            Start-Process $DeviceCodeDetails.verification_url
        } else {
            write-host "[i] Automatic Browser start disabled"
            write-host "[i] Use the code at: $($DeviceCodeDetails.verification_url)"
        }

        $Body = @{
            client_id   = $ClientID
            grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
            code        =  $DeviceCodeDetails.device_code
        }

        $Counter = 0
        $MaxAttempts = 200
        Start-Sleep 5
        while ($Counter -lt $MaxAttempts) {
            $Counter++
            Try {
                $TokensDeviceCode = Invoke-RestMethod 'https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0' -Method POST -Body $Body -Headers $Headers
            } Catch {
                $PollingError = $_ | ConvertFrom-Json
                if ($PollingError.error -eq "authorization_pending") {
                    Write-Host "[*] Authentication is pending. Continue polling ($Counter/$MaxAttempts)..."
                } elseif ($PollingError.error -eq "code_expired") {
                    Write-Host "[!] Verification code expired. Aborting...."
                    break
                } else {
                    Write-Host "[!] Unknown error: Aborting...."
                    Write-Host "[!] Error: $($PollingError.error)"
                    Write-Host "[!] Error Description: $($PollingError.error_description)"
                    if ($Reporting) {
                        $ErrorDetails = [PSCustomObject]@{
                            ClientID    = $ClientID
                            ErrorLong   = $PollingError.error_description
                        }
                        Invoke-Reporting -ErrorDetails $ErrorDetails -OutputFile "DeviceCode_errors.csv"
                    }
                    break
                }
                Start-Sleep 3
            }
            if ($TokensDeviceCode.access_token -and $TokensDeviceCode.refresh_token) {
                Write-Host "[+] Got an access token and a refresh token"
                $TokensDeviceCode | Add-Member -NotePropertyName Expiration_time -NotePropertyValue (Get-Date).AddSeconds($tokens.expires_in)

                if (-not $DisableJwtParsing) {
                    #Parse JWT
                    Try {
                        # Parse the token
                        $JWT = Invoke-ParseJwt -jwt $TokensDeviceCode.access_token
                    } Catch {
                        $JwtParseError = $_ 
                        Write-Host "[!] JWT Parse error: $($JwtParseError)"
                        Write-Host "[!] Aborting...."
                        break
                    }
            
                    #Add additonal infos to token object
                    $TokensDeviceCode | Add-Member -NotePropertyName scp -NotePropertyValue $JWT.scp
                    $TokensDeviceCode | Add-Member -NotePropertyName tenant -NotePropertyValue $JWT.tid
                    $TokensDeviceCode | Add-Member -NotePropertyName user -NotePropertyValue $JWT.upn
                    $TokensDeviceCode | Add-Member -NotePropertyName client_app -NotePropertyValue $JWT.app_displayname
                    $TokensDeviceCode | Add-Member -NotePropertyName client_app_id -NotePropertyValue $ClientID
                    $TokensDeviceCode | Add-Member -NotePropertyName auth_methods -NotePropertyValue $JWT.amr
                    $TokensDeviceCode | Add-Member -NotePropertyName ip -NotePropertyValue $JWT.ipaddr
                    $TokensDeviceCode | Add-Member -NotePropertyName audience -NotePropertyValue $JWT.aud
                    $TokensDeviceCode | Add-Member -NotePropertyName api -NotePropertyValue ($JWT.aud -replace '^https?://', '' -replace '/$', '')
                    if ($null -ne $JWT.xms_cc) {
                        $TokensDeviceCode | Add-Member -NotePropertyName xms_cc -NotePropertyValue $JWT.xms_cc
                    }
                    Write-Host "[i] Audience: $($JWT.aud) / Expires at: $($tokens.expiration_time)"
                } else {
                    Write-Host "[i] Expires at: $($tokens.expiration_time)"
                }
                
                
                #Print token info if switch is used
                if ($TokenOut) {
                    invoke-PrintTokenInfo -jwt $TokensDeviceCode -NotParsed $DisableJwtParsing
                }

                #Check if report file should be written
                if ($Reporting) {
                    Invoke-Reporting -jwt $TokensDeviceCode -OutputFile "DeviceCode_report.csv"
                }
                break
            }
        }
        if ($Counter -eq $MaxAttempts) {
            Write-Host "[i] Max polling attempts reached. Aborting..."
        }
        Return $TokensDeviceCode
    }
}

function Invoke-ClientCredential {
    <#
        .SYNOPSIS
        Performs OAuth 2.0 authentication using the Client Credential  Flow.

        .DESCRIPTION
        The `Invoke-ClientCredential` function implements the OAuth 2.0 Client Credentials Flow. 
        It retrieves an access token for the specified API and supports additional features like JWT parsing, custom reporting, and secure handling of client secrets.

        .PARAMETER ClientId
        Specifies the client ID of the application being authenticated. This parameter is mandatory.

        .PARAMETER ClientSecret
        Specifies the client secret of the application being authenticated. If not provided, the function prompts for secure input during execution.
        
        .PARAMETER Api
        Specifies the target API for the authentication request.
        Default: `graph.microsoft.com`

        .PARAMETER Scope
        Specifies the API permissions (scopes) to request during authentication. Multiple scopes should be space-separated.
        Default: `default`
        
        .PARAMETER DisableJwtParsing
        Disables parsing of the JWT access token. When set, the token is returned as-is without any additional information.

        .PARAMETER TokenOut
        Outputs the access to the console upon successful authentication.

        .PARAMETER UserAgent
        Specifies the user agent string to be used in the HTTP requests. This can be customized to mimic specific browser or application behavior.
        Default: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36`

        .PARAMETER TenantId
        Specifies the tenant ID for authentication. This parameter is mandatory.

        .PARAMETER Reporting
        Enables logging (CSV) the details of the refresh operation for later analysis. 

        .EXAMPLE
        Invoke-ClientCredential -ClientId "your-client-id" -ClientSecret "your-client-secret" -TenantId "your-tenant-id"

        Authenticates with the specified client ID and secret, targeting the default Microsoft Graph API.

        .EXAMPLE
        Invoke-ClientCredential -ClientId "your-client-id" -ClientSecret "your-client-secret" -TenantId "your-tenant-id" -Api "management.azure.com"

        Authenticates with the specified client credentials and retrieves a token for the Azure Management API.

        .EXAMPLE
        Invoke-ClientCredential -ClientId "your-client-id" -TenantId "your-tenant-id" -Reporting

        Prompts for the client secret securely, authenticates, and logs detailed results to a CSV file.

        .NOTES
        Ensure the client application has the appropriate permissions for the specified API and scope in Azure AD.
        
    #>
    param (
        [Parameter(Mandatory=$true)][string]$ClientId,
        [Parameter(Mandatory=$false)][string]$ClientSecret,
        [Parameter(Mandatory=$false)][string]$Api = "graph.microsoft.com",
        [Parameter(Mandatory=$false)][string]$Scope = "default",
        [Parameter(Mandatory=$false)][switch]$TokenOut,
        [Parameter(Mandatory=$false)][switch]$DisableJwtParsing = $false,
        [Parameter(Mandatory=$false)][string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        [Parameter(Mandatory=$true)][string]$TenantId,
        [Parameter(Mandatory=$false)][switch]$Reporting = $false
    )

    $Proceed = $true
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    
    #Prompt for client credential if not defined
    if (-not $ClientSecret) {
        $ClientSecretSecure = Read-Host -Prompt "Enter the client secret" -AsSecureString
        if ($ClientSecretSecure -is [System.Security.SecureString]) {
            Write-Host "Variable is a SecureString."
        } else {
            Write-Host "Variable is NOT a SecureString. Check your input."
        }
        $ClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecretSecure)
        )
    }

    #Construct Scope
    $ApiScopeUrl = "https://$Api/.$Scope"
        
     # Get Access Token 
    $tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" 
    $body = @{
         'scope'     = $ApiScopeUrl
         'client_id'      = $ClientId 
         'client_secret' = $ClientSecret
         'grant_type' = 'client_credentials' 
    }

    write-host "[*] Starting Client Credential flow: API $Api / Client id: $ClientID"
    Try {
        $TokensClientCredential = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body -Headers $Headers
    } Catch {
        $InitialError = $_ | ConvertFrom-Json  
        Write-Host "[!] Aborting...."
        Write-Host "[!] Error: $($InitialError.error)"
        Write-Host "[!] Error Description: $($InitialError.error_description)"
        if ($Reporting) {
            $ErrorDetails = [PSCustomObject]@{
                ClientID    = $ClientID
                ErrorLong   = $PollingError.error_description
            }
            Invoke-Reporting -ErrorDetails $ErrorDetails -OutputFile "ClientCredential_errors.csv"
        }
        $Proceed = $false
    }

    if ($Proceed) {
        if ($TokensClientCredential.access_token) {
            Write-Host "[+] Got an access token"
            $TokensClientCredential | Add-Member -NotePropertyName Expiration_time -NotePropertyValue (Get-Date).AddSeconds($tokens.expires_in)

            if (-not $DisableJwtParsing) {
                #Parse JWT
                Try {
                    # Parse the token
                    $JWT = Invoke-ParseJwt -jwt $TokensClientCredential.access_token
                } Catch {
                    $JwtParseError = $_ 
                    Write-Host "[!] JWT Parse error: $($JwtParseError)"
                    Write-Host "[!] Aborting...."
                    break
                }

                #Add additonal infos to token object
                $TokensClientCredential | Add-Member -NotePropertyName client_app_id -NotePropertyValue $JWT.appid
                if ($JWT.app_displayname) {$TokensClientCredential | Add-Member -NotePropertyName client_app -NotePropertyValue $JWT.app_displayname}
                $TokensClientCredential | Add-Member -NotePropertyName sp_object_id -NotePropertyValue $JWT.oid
                if ($JWT.roles) {$TokensClientCredential | Add-Member -NotePropertyName roles -NotePropertyValue $JWT.roles}
                $TokensClientCredential | Add-Member -NotePropertyName tenant -NotePropertyValue $JWT.tid
                $TokensClientCredential | Add-Member -NotePropertyName audience -NotePropertyValue $JWT.aud
                Write-Host "[i] Audience: $($JWT.aud) / Expires at: $($TokensClientCredential.expiration_time)"
            } else {
                Write-Host "[i] Expires at: $($TokensClientCredential.expiration_time)"
            }
            
            
            #Print token info if switch is used
            if ($TokenOut) {
                invoke-PrintTokenInfo -jwt $TokensClientCredential -NotParsed $DisableJwtParsing
            }

            #Check if report file should be written
            if ($Reporting) {
                Invoke-Reporting -jwt $TokensClientCredential -OutputFile "ClientCredential_report.csv"
            }

        }
    }

    Return $TokensClientCredential 
}

function Invoke-ParseJwt {
    <#
        .SYNOPSIS
        Parses the body of a JWT and returns the decoded contents as a PowerShell object.

        .DESCRIPTION
        The `Invoke-ParseJwt` function parses a JSON Web Token (JWT) and decodes its payload (body). 
        This is useful for analyzing token claims, scopes, expiration, and other metadata embedded in the JWT.

        .PARAMETER Jwt
        Specifies the JSON Web Token (JWT) to be parsed. The token must be provided as a string in standard JWT format: `header.payload.signature`.

        .EXAMPLE
        Invoke-ParseJwt -Jwt "eyJh..."

        Parses the provided JWT and returns its decoded payload as a PowerShell object.

        .EXAMPLE
        Invoke-ParseJwt -Jwt $tokens.access_token

        Parses the provided JWT and returns its decoded payload as a PowerShell object.

        .NOTES
        - The function validates the token structure by checking for a valid format (`header.payload.signature`) and Base64URL encoding.
        - Invalid tokens will generate an error.
    #>

    [cmdletbinding()]
    param([Parameter(Mandatory=$true)][string]$jwt)
 
    #JWT verification
    if (!$jwt.Contains(".") -or !$jwt.StartsWith("eyJ")) { 
        if ($jwt.StartsWith("1.")) {
            Write-Error "Invalid token! The refresh token can not be parsed since it is encrypted." -ErrorAction Stop
        } else {
            Write-Error "Invalid token!" -ErrorAction Stop 
        }
    }

    #Process Token Body
    $TokenBody = $jwt.Split(".")[1].Replace('-', '+').Replace('_', '/')
    
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($TokenBody.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $TokenBody += "=" }

    #Convert to Byte array and to string array
    $tokenByteArray = [System.Convert]::FromBase64String($TokenBody)
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)

    #Convert from JSON to PS Object
    $TokenObject = $tokenArray | ConvertFrom-Json

    return $TokenObject
}

function Invoke-PrintTokenInfo {
    <#
    .SYNOPSIS
    Displays detailed token information in a formatted output to console.

    .DESCRIPTION
    The `Invoke-PrintTokenInfo` function is an internal utility designed to display claims and metadata from a JSON Web Token (JWT) in a readable, formatted manner. Depending on whether the token has been pre-parsed, it extracts and shows specific details.

    .PARAMETER JWT
    Specifies the JSON Web Token (JWT) object containing the metadata to display. 

    .PARAMETER NotParsed
    Indicates whether the JWT has not been pre-parsed. If set to `$true`, the function displays a reduced set of token details, assuming minimal processing has occurred.

    .EXAMPLE
    Invoke-PrintTokenInfo -JWT $ParsedJwt -NotParsed $false

    Displays detailed claims and metadata from a parsed JWT.

    .EXAMPLE
    Invoke-PrintTokenInfo -JWT $RawJwtObject -NotParsed $true

    Displays basic details from an unparsed JWT, focusing on available high-level information.

    .NOTES
    - This is an internal function and is not exported.
    - The function relies on the structure of the `$JWT` object. If specific properties are missing, the function may produce incomplete output.
    #>
    param (
        [Parameter(Mandatory=$true)][PSObject]$JWT,
        [Parameter(Mandatory=$true)][bool]$NotParsed
    )

    write-host ""
    write-host "**********************************************************************"
    write-host ""
    Write-Host "Token Information"
    Write-Host "===================="

    if (-not $NotParsed) {
        Write-Host "Audience: $($JWT.audience)"
        if ($JWT.scp) { Write-Host "Scope: $($JWT.scp)"}
        Write-Host "Client: $($JWT.client_app)"
        if ($JWT.auth_methods) { Write-Host "Auth Methods: $($JWT.auth_methods)"}
        Write-Host "CAE (xms_cc): $($JWT.xms_cc)"
        Write-Host "Tenant: $($JWT.tenant)"
        if ($JWT.user) { Write-Host "User: $($JWT.user)"}
        if ($JWT.ip) {Write-Host "IP: $($JWT.ip)"}
        if ($JWT.sp_object_id) {Write-Host "SP Object ID: $($JWT.sp_object_id)"}
        if ($JWT.client_app_id) {Write-Host "Client App ID: $($JWT.client_app_id)"}
        if ($JWT.roles) {Write-Host "Roles: $($JWT.roles)"}
    } else {
        Write-Host "Scope: $($JWT.scope)"
    } 

    if ($JWT.foci) {Write-Host "Foci: $($JWT.foci)"} else {Write-Host "Foci: 0" }
    if ($JWT.xms_cc) {Write-Host "CAE (xms_cc): $($JWT.xms_cc)"} else {Write-Host "CAE (xms_cc): 0" }
    Write-Host "Expires In: $($JWT.expires_in) seconds"
    Write-Host "Expiration Time: $($JWT.expiration_time)"
    Write-Host ""

    # Display full access and refresh tokens with clear delimiters
    Write-Host "Access Token:"
    Write-Host "==========================================================="
    Write-Host $JWT.access_token
    Write-Host "==========================================================="
    Write-Host ""
    if ($JWT.refresh_token) {
        Write-Host "Refresh Token:"
        Write-Host "==========================================================="
        Write-Host $JWT.refresh_token
        Write-Host "==========================================================="
        write-host ""
    }
    write-host "**********************************************************************"
    write-host ""
}


function Invoke-Reporting {
    <#
        .SYNOPSIS
        Logs JWT information to a CSV file for internal analysis and comparison during mass testing.

        .DESCRIPTION
        The `Invoke-Reporting` function is an internal utility designed to log selected claims and metadata from a JSON Web Token (JWT) to a CSV file. 
        It is particularly useful for analyzing multiple tokens.
        This function intended for internal use by other functions or scripts within the module.
        If the specified CSV file does not exist, the function creates it with headers. If the file exists, the new data is appended without rewriting the headers.

        .PARAMETER JWT
        Specifies the JSON Web Token (JWT) object to be logged. The token object should include the relevant claims and properties (e.g., audience, scope, client_app).

        .PARAMETER ErrorDetails
        Specifies ErrorObject object to be logged. The token object should include the properties (e.g., ClientID, ErrorLong).

        .PARAMETER OutputFile
        Specifies the path to the CSV file where the token information will be logged. If the file does not exist, it will be created. If the file exists, new entries will be appended.

        .EXAMPLE
        Invoke-Reporting -JWT $jwtObject -OutputFile "jwt_log.csv"

        Logs a JWT's details to the specified CSV file.

        .NOTES
        - This is an internal function and is not exported via `Export-ModuleMember`.
        - The function selects specific fields from the JWT object, including `audience`, `scp`, `client_app`, `expires_in`, and others. Custom fields, such as `AuthMethods` and `xms_cc`, are joined into a single string for better readability in the CSV.
    #>
    param (
        [Parameter(Mandatory=$false)][PSObject]$JWT,
        [Parameter(Mandatory=$false)][PSObject]$ErrorDetails,
        [Parameter(Mandatory=$true)][String]$OutputFile
    )

    if ($null -ne $JWT) {
        #Add timestamp
        $JWT | Add-Member -MemberType NoteProperty -Name "timestamp" -Value (Get-Date).ToString("o")
        $SelectedInfo = $JWT | select-object timestamp,audience,scp,client_app,client_app_id,@{Name = "foci"; Expression = { if ($null -eq $_.foci) { 0 } else { $_.foci } } },expires_in,ext_expires_in,Expiration_time,refresh_in,@{Name = "AuthMethods"; Expression = { ($_.auth_methods -join ", ") } },@{Name = "xms_cc"; Expression = { ($_.xms_cc -join ", ") } },access_token,refresh_token
    } elseif ($null -ne $ErrorDetails) {
        #Add timestamp
        $ErrorDetails | Add-Member -MemberType NoteProperty -Name "timestamp" -Value (Get-Date).ToString("o")
        $SelectedInfo = $ErrorDetails  | select-object timestamp,ClientID,ErrorLong
    }
    

    # Write to CSV with or without headers
    if (-Not (Test-Path -Path $OutputFile)) {
        # File doesn't exist: write with headers
        $SelectedInfo | Export-Csv -Path $OutputFile -NoTypeInformation
    } else {
        # File exists: append without headers
        $SelectedInfo | Export-Csv -Path $OutputFile -NoTypeInformation -Append
    }

}

Export-ModuleMember -Function Invoke-Auth,Invoke-Refresh,Invoke-DeviceCodeFlow,Invoke-ParseJwt,Show-ModuleHelp,Invoke-ClientCredential


function Show-ModuleBanner {
    $banner = @'
    ______      __            ______      __              ___    _     __
   / ____/___  / /__________ /_  __/___  / /_____  ____  /   |  (_)___/ /
  / __/ / __ \/ __/ ___/ __ `// / / __ \/ //_/ _ \/ __ \/ /| | / / __  / 
 / /___/ / / / /_/ /  / /_/ // / / /_/ / ,< /  __/ / / / ___ |/ / /_/ /  
/_____/_/ /_/\__/_/   \__,_//_/  \____/_/|_|\___/_/ /_/_/  |_/_/\__,_/                                                                

'@
    # Show Banner with color
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ''
    # Now showing Available Commands with different colors for emphasis
    Write-Host 'Available Commands:' -ForegroundColor Green
    Write-Host ''
    Write-Host '$tokens = Invoke-Auth                                         ' -ForegroundColor Yellow
    Write-Host 'Interactive OAuth Code Flow / Defaults to MS Graph API & Azure CLI as client' -ForegroundColor White
    Write-Host ''
    Write-Host '$tokens = Invoke-DeviceCodeFlow                               ' -ForegroundColor Yellow
    Write-Host 'DeviceCode Flow / Defaults to MS Graph API & Azure CLI as client' -ForegroundColor White
    Write-Host ''
    Write-Host '$tokens = Invoke-Refresh -RefreshToken $tokens.refresh_token   ' -ForegroundColor Yellow
    Write-Host 'Get a new Access Token / Defaults to MS Graph API & Azure CLI as client' -ForegroundColor White
    Write-Host ''
    Write-Host '$tokens = Invoke-ClientCredential -ClientId $YourClientId -TenantId $YourTenantId -ClientSecret $YourCLientSecret  ' -ForegroundColor Yellow
    Write-Host 'Authenticate as service principal / Defaults to MS Graph API' -ForegroundColor White
    Write-Host ''
    Write-Host 'Invoke-ParseJwt -JWT $tokens.access_token            ' -ForegroundColor Yellow
    Write-Host 'Parses the JWT' -ForegroundColor White
    Write-Host ''
}

# Show Banner
Show-ModuleBanner