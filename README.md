# EntraTokenAid

EntraTokenAid is a PowerShell module to simplify OAuth workflows with Microsoft Entra ID, to get the access and refresh token for different APIs using different clients.

Accessing cleartext access and refresh tokens for various MS APIs (e.g., MS Graph) is often a requirement during engagements and research, especially using pre-consented clients (e.g., AzureCLI) to avoid additional consent prompts. Tokens are needed not only for manual enumeration via APIs but also for tools like AzureHound or GraphRunner, which require a valid refresh token. 

With more customers starting to block the Device Code Flow, alternative authentication methods for obtaining cleartext refresh tokens are becoming increasingly important. While using AzureCLI modules is a common solution, its installation may not always be feasible—especially on customer systems. Other alternatives like roadtx require Python, which might not be ideal in customer environments.

This tool should bridges this gap with a lightweight, standalone PowerShell solution that works even on the customers Windows systems.



---

## Features

- **No dependencies**: A pure PowerShell single-file module that works on Windows systems (tested in PS 5&7) and on Linux.
- **Interactive Authentication**: Supports both OAuth Auth Code Flow and Device Code Flow.
- **Flexible Refresh**: Obtain access tokens for any API and client using refresh tokens.
- **CAE Support**: By default, requests CAE (Continuous Access Evaluation) capable access tokens, valid for 24 hours.
- **JWT Parsing**: Automatically decodes access tokens to display details (e.g., scope, tenant, IP, authentication methods).
- **Avoiding Consent**: By default, the tool uses the Azure CLI client ID, enabling many MS Graph API actions without additional consent due to pre-consented permissions.
- **Parameters**: A wide range of parameters allow you to customize the tool's behavior, such as enabling features like PKCE, CAE, and more, providing greater control during usage.
- **Automation-Friendly**: Enables automated OAuth Auth Code Flow tests by disabling user selection, with the gathered tokens and claims exported to a CSV file.
---

## Images
Performing an authentication and showing the gathered tokens and other useful information:

![alt text](images/tokens_console.png "Title")

Using the obtained refresh token to get new tokens on another API and using another client (Azure PowerShell):

![alt text](images/tokens_refresh.png "Title")

---
## Installation

1. Clone the repository:
    ```powershell
   git clone https://github.com/zh54321/EntraTokenAid.git
   ```
2. Import the module before usage:
   ```powershell
   Import-Module ./EntraTokenAid/EntraTokenAid.psm1
   ```

---

## Getting Started

The module includes the following commands:

| Command                   | Description                                                      |Default behavior|
|---------------------------|------------------------------------------------------------------|----|
| `Invoke-Auth`             | Perform authentication (auth code flow) and retrieve tokens.          |API: MS Graph / Client: Azure CLI / CAE: Yes|
| `Invoke-DeviceCodeFlow`   | Authenticate via the device code flow.|API: MS Graph / Client: Azure CLI|
| `Invoke-ClientCredential` | Authenticate using the client credential flow.                      |API: MS Graph|
| `Invoke-Refresh`          | Get a new access token using the refresh token. |API: MS Graph / Client: Azure CLI|
| `Invoke-ParseJwt`         | Decode a JWT and display its body properties.                      |-|

---

## Module Functions

### `Invoke-Auth`

Performs OAuth authentication using the authorization code flow.
By default, tokens from the MS Graph API are requested using Azure CLI as the client.

#### Parameters
All parameters are optional.

| Parameter            | Description                                                                 | Default Value                                     |
|----------------------|-----------------------------------------------------------------------------|---------------------------------------------------|
| **ClientID**         | Specifies the client ID for authentication.                                 | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI)|
| **Scope**            | Scopes (space sperated) to be requested.                                    | `default offline_access`                          |
| **Api**              | API for which the access token is needed.                                   | `graph.microsoft.com`                             |
| **Tenant**           | Specific tenant id.                                                         | `organizations`                                   |
| **Port**             | Local port to listen on for the OAuth callback.                             | `13824`                                           |
| **TokenOut**         | If provided, outputs the raw token to console.                              | `false`                                           |
| **RedirectURL**      | URL for the OAuth redirect.                                                 | `http://localhost:%PORT%`                         |
| **DisableJwtParsing**| Skips the parsing of the JWT.                                               | `false`                                           |
| **DisablePrompt**    | Suppresses interactive user selection. Used logged-in user directly         | `false`                                           |
| **HttpTimeout**      | Time in seconds the HTTP Server waiting for OAuth callback.                 | `60`                                              |
| **DisablePKCE**      | Disables the PKCE usage.                                                    | `false`                                           |
| **DisableCAE**       | Disables Continuous Access Evaluation (CAE) support.                        | `false`                                           |
| **Reporting**        | If provided, enables detailed token logging to csv.                         | `false`                                           |  


#### Examples
Perform authentication and retrieve tokens with default options (MS Graph API / Azure CLI as the client):
```powershell
$Tokens = Invoke-Auth
```

Authenticate on Azure ARM API:
```powershell
$Tokens = Invoke-Auth -API "management.azure.com"
```

Authenticate with a custom client ID and scope:
```powershell
$Tokens = Invoke-Auth -ClientID "your-client-id" -Scope "offline_access Mail.Read"
```

Connect to Microsoft Graph API:
```powershell
Connect-MgGraph -AccessToken ($Tokens.access_token | ConvertTo-SecureString -AsPlainText -Force)
```

Authenticate and use with [AzureHound](https://github.com/BloodHoundAD/AzureHound):
```powershell
$Tokens = Invoke-Auth
.\azurehound.exe --refresh-token $Tokens.refresh_token list --tenant $Tokens.tenant -o output-all.json
```
Authenticate and use with [GraphRunner](https://github.com/dafthack/GraphRunner):
```powershell
$tokens = Invoke-Auth
Invoke-GraphRecon -Tokens $tokens -PermissionEnum
```
Authenticate on Azure Resource Manager as Azure Powershell, refresh to Office API as Microsoft Office:
```powershell
$tokens = invoke-auth -ClientID 1950a258-227b-4e31-a9cf-717495945fc2 -api management.azure.com
$tokensOffice = invoke-refresh -RefreshToken $tokens.refresh_token -ClientID d3590ed6-52b3-4102-aeff-aad2292ab01c -api manage.office.com
```

Perform automated testing by disabling user selection (the already logged-in user in the browser will be used), activating reporting, setting the HTTP timeout, and looping through a list of client IDs:
```powershell
# Define the array of GUIDs
$guids = @(
    "1950a258-227b-4e31-a9cf-717495945fc2",
    "7ae974c5-1af7-4923-af3a-fb1fd14dcb7e",
    "5572c4c0-d078-44ce-b81c-6cbf8d3ed39e"
)

# Loop through each GUID in the array
foreach ($guid in $guids) {
    Invoke-Auth -ClientID $guid -DisablePrompt -Reporting -HttpTimeout 5
}
```

---

### `Invoke-DeviceCodeFlow`

Authenticate using the device code flow. The browser opens automatically, and the required code is copied to the clipboard.

#### Parameters
All parameters are optional.
| Parameter              | Description                                                                 | Default Value                                     |
|----------------------  |-----------------------------------------------------------------------------|---------------------------------------------------|
| **ClientID**           | Specifies the clientID for authentication.                                  | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI)|
| **Api**                | API for which the access token is needed.                                   | `graph.microsoft.com`                             |
| **UserAgent**          | User agent used. | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari 537`|  
| **Tenant**             | Specific tenant id.                                                         | `organizations`                                   |
| **TokenOut**           | If provided, outputs the raw token to console.                              | `false`                                           |
| **DisableJwtParsing**  | Skips the parsing of the JWT.                                               | `false`                                           |
| **DisableBrowserStart**| Disables the automatic start of the browser.                                | `false`                                           |
| **Reporting**          | If provided, enables detailed token logging to csv.                         | `false`                                           |  


#### Example

Simpy start of the device code flow with default options.
```powershell
Invoke-DeviceCodeFlow
```
Get tokens for the AzureARM API
```powershell
Invoke-DeviceCodeFlow -API management.azure.com
```
Authenticate using the device code flow specifiy the client id and api
```powershell
$Token = Invoke-DeviceCodeFlow -ClientID "your-client-id" -Api "graph.microsoft.com"
```
Connect to MS Graph API:
```powershell
Connect-MgGraph -AccessToken ($Tokens.access_token | ConvertTo-SecureString -AsPlainText -Force)
```

Authenticate and use with [AzureHound](https://github.com/BloodHoundAD/AzureHound):
```powershell
$Tokens = Invoke-DeviceCodeFlow
.\azurehound.exe --refresh-token $Tokens.refresh_token list --tenant $Tokens.tenant -o output-all.json
```

---

### `Invoke-ClientCredential`

Authenticate using the client credential flow. Currently, only client secrets are supported.

#### Parameters
All parameters are optional.
| Parameter              | Description                                                                 | Default Value                                     |
|----------------------  |-----------------------------------------------------------------------------|---------------------------------------------------|
| **ClientID**           | Specifies the clientID for authentication.                                  | -|
| **ClientSecret**       | Client secret of the application (secure prompt if empty).                         | -|
| **Tenant**             | Specific tenant id.                                                         | `-`                                   |
| **Api**                | API for which the access token is needed.                                   | `graph.microsoft.com`                             |
| **Scope**              | Scopes (space sperated) to be requested.                                    | `default`                          |
| **UserAgent**          | User agent used. | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari 537`|  
| **TokenOut**           | If provided, outputs the raw token to console.                              | `false`                                           |
| **DisableJwtParsing**  | Skips the parsing of the JWT.                                               | `false`                                           |
| **Reporting**          | If provided, enables detailed token logging to csv.                         | `false`                                           |  


#### Example

Authenticates with the specified client ID and secret, targeting the default Microsoft Graph API.
```powershell
Invoke-ClientCredential -ClientId "your-client-id" -ClientSecret "your-client-secret" -TenantId "your-tenant-id"
```
Authenticates with the specified client credentials and retrieves a token for the Azure Management API.
```powershell
Invoke-ClientCredential -ClientId "your-client-id" -ClientSecret "your-client-secret" -TenantId "your-tenant-id" -Api "management.azure.com"
```
Prompts for the client secret securely, authenticates, and logs detailed results to a CSV file.
```powershell
Invoke-ClientCredential -ClientId "your-client-id" -TenantId "your-tenant-id" -Reporting
```
Connect to MS Graph API:
```powershell
Connect-MgGraph -AccessToken ($Tokens.access_token | ConvertTo-SecureString -AsPlainText -Force)
```

---

### `Invoke-Refresh`

Uses a refresh token to obtain a new access token, optionally for the same or a different API or client (for FOCI tokens).
Supports `brk_client_id`, `redirect_uri`, and `origin`. In combination with a refresh token from the Azure Portal, this allows retrieving MS Graph tokens using `ADIbizaUX` or `Microsoft_Azure_PIMCommon` as client. With the token, it is possible to for example read eligible role assignments (pre-consented scopes on MS Graph).

#### Parameters

| Parameter            | Description                                                                 | Default Value                                     |
|----------------------|-----------------------------------------------------------------------------|---------------------------------------------------|
| **RefreshToken**     | Refresh token to used (MANDETORY).                                          | -                                                 |
| **ClientID**         | Specifies the client ID for authentication.                                 | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI)|
| **Scope**            | Scopes (space sperated) to be requested.                                    | `default offline_access`                          |
| **Api**              | API for which the access token is needed.                                   | `graph.microsoft.com`                             |
| **UserAgent**        | User agent used.                                                            | `python-requests/2.32.3`                          |  
| **Tenant**           | Specific tenant id.                                                         | `organizations`                                   |
| **TokenOut**         | If provided, outputs the raw token to console.                              | `false`                                           |
| **DisableJwtParsing**| Skips the parsing of the JWT.                                               | `false`                                           |
| **DisableCAE**       | Disables Continuous Access Evaluation (CAE) support.                        | `false`                                           |
| **BrkClientId**      | Define brk_client_id.                                                       | `-`                                               |
| **RedirectUri**      | Define redirect_uri.                                                        | `-`                                               |
| **Origin**           | Define Origin Header.                                                       | `-`                                               |
| **Reporting**        | If provided, enables detailed token logging to csv.                         | `false`                                           |  

#### Example
Reuse the refresh token to get new tokens:
```powershell
Invoke-Refresh -RefreshToken $Tokens.refresh_token
```

Refresh tokens using the same client ID, API, and scopes as before:
```powershell
Invoke-Refresh -RefreshToken $Tokens.refresh_token -Scope $Tokens.scp -Api $Tokens.api
```

Refresh to a specific API (e.g., Azure Resource Manager):
```powershell
Invoke-Refresh -RefreshToken $Tokens.refresh_token -Api management.azure.com
```

Refresh to ADIbizaUX client using the ```broker client id``` of the Azure portal (to use pre-consented permission)*:
```powershell
$refresh_token = "1.Aa4...." #Add refresh token from the Azure portal
Invoke-Refresh -RefreshToken $refresh_token -clientid 74658136-14ec-4630-ad9b-26e160ff0fc6 -api graph.microsoft.com -BrkClientId c44b4083-3bb0-49c1-b47d-974e53cbdf3c -RedirectUri "brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://entra.microsoft.com" -Origin "https://entra.microsoft.com"
```
Note: this requires a valid refresh token from the Azure portal scoped to `https://management.core.windows.net//` (Auth on the Azure Portal and search in the DEV tools for this string).
<details>
<summary>Pre-consented permissions of ADIbizaUX on the MS Graph API</summary>

- AccessReview.ReadWrite.All
- Application.Read.All
- AuditLog.Read.All
- ChangeManagement.Read.All
- ConsentRequest.Create
- ConsentRequest.Read
- ConsentRequest.ReadApprove.All
- ConsentRequest.ReadWrite.All
- CustomSecAttributeAssignment.Read.All
- CustomSecAttributeAuditLogs.Read.All
- Device-OrganizationalUnit.ReadWrite.All
- Directory.AccessAsUser.All
- Directory.Read.All
- Directory.ReadWrite.All
- Directory.Write.Restricted
- DirectoryRecommendations.Read.All
- DirectoryRecommendations.ReadWrite.All
- Domain.ReadWrite.All
- email
- EntitlementManagement.Read.All
- Group.ReadWrite.All
- HealthMonitoringAlert.ReadWrite.All
- HealthMonitoringAlertConfig.ReadWrite.All
- IdentityProvider.ReadWrite.All
- IdentityRiskEvent.ReadWrite.All
- IdentityRiskyServicePrincipal.ReadWrite.All
- IdentityRiskyUser.ReadWrite.All
- IdentityUserFlow.Read.All
- LifecycleWorkflows.ReadWrite.All
- OnPremDirectorySynchronization.Read.All
- openid
- OrganizationalUnit.ReadWrite.All
- Policy.Read.All
- Policy.Read.IdentityProtection
- Policy.ReadWrite.AuthenticationFlows
- Policy.ReadWrite.AuthenticationMethod
- Policy.ReadWrite.Authorization
- Policy.ReadWrite.ConditionalAccess
- Policy.ReadWrite.ExternalIdentities
- Policy.ReadWrite.IdentityProtection
- Policy.ReadWrite.MobilityManagement
- profile
- Reports.Read.All
- RoleManagement.ReadWrite.Directory
- SecurityEvents.ReadWrite.All
- TrustFrameworkKeySet.Read.All
- User.Export.All
- User.ReadWrite.All
- UserAuthenticationMethod.ReadWrite.All
- User-OrganizationalUnit.ReadWrite.All
</details>


---

### `Invoke-ParseJwt`

Decodes and analyzes a JWT, extracting and displaying its claims.
The function is used automatically by other functions but can also be used manually.

#### Parameters

| Parameter   | Description                                                        | Default Value                                     |
|-------------|--------------------------------------------------------------------|---------------------------------------------------|
| **JWT**     | The JWT to decode (MANDETORY).                                     | -                                                 |

#### Example
Parse a JWT and display its claims:
```powershell
Invoke-ParseJwt -JWT $Tokens.access_token
```

---


## Internal Functions

The following functions are for internal use and are not exported by the module:

- `Invoke-PrintTokenInfo` Formats and displays JWT information in console.
- `Invoke-Reporting` Logs information to a CSV file for later analysis or comparison.

## Security Warning

It is **discouraged** to pass sensitive information, such as **Access Tokens** or especially **Refresh Tokens**, directly in the command line. 


Command-line arguments are stored by default in the PowerShell history file in your profile, events, or security monitoring tools.
Attackers which gain access to those files may abuse credentials like long-lived refresh tokens

### Recommendations:
- **Use variables** to store sensitive information in your script instead of passing it directly in the command line.
  - Example:
  ```powershell
  #Store the tokens in a variable
  $Tokens = invoke-auth

  #Work with the variable instead the token itself:
  Invoke-Refresh -RefreshToken $Tokens.refresh_token
  Invoke-ParseJwt -Jwt $Tokens.access_token
  ```

- **Clear your PowerShell history** after use to ensure sensitive data is at least not retained in the PS history files (all 3 commands):
  ```powershell
  Clear-History
  [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
  set-content -Path (Get-PSReadLineOption).HistorySavePath -value ' '
   ```

## Credits

This module includes a JWT parsing method that was initially adapted from the following blog post:

- [Decode JWT Access and ID Tokens via PowerShell](https://www.michev.info/blog/post/2140/decode-jwt-access-and-id-tokens-via-powershell) by [Michev](https://www.michev.info)

## Changelog

### 2025-01-13
#### Added
- Invoke-ClientCredential: Client credentials flow (atm. only by using credentials)

#### Changed
- Invoke Auth: Major overhault of the local HTTP Server:
  - Can now stopped using Ctrl +C.
  - Better HTTP server error handling for improved stability
  - Improved stability

#### Fixed
- Invoke Auth: CAE issue when using Firefox

#### Removed
- Invoke Auth: Token details are not displayed in HTML anymore (because of HTTP-Server changes).


### 2024-12-30
#### Added
- Invoke Auth: New redirect parameter
- Invoke Auth: Better HTTP server error handling

### 2024-12-18
#### Added

- Refresh Auth: New User Agent parameter
- Refresh Auth: New parameters BrkClientId, RedirectUri and Origin. In combination with a refresh token from the Azure Portal, this allows to get tokens from applications with interesting pre consented scopes on the MS Graph API.
- Refresh Auth: Failed authentications are now logged as well to the CSV file (switch `-Reporting`)
- Device Code Flow: Failed authentications are now logged as well to the CSV file (switch `-Reporting`)


### 2024-12-09

#### Fixed
- Fixed an issue with static RT parameter (Invoke-Refresh)


### 2024-11-25

- Initial release
