
#region Invoke-AzResourceGraphCheck
function Invoke-AzResourceGraphCheck {
    [CmdletBinding()]
    param (
        $CheckList,
        $CheckListId,
        $DebugMode = $false
    )
    $Query = $CheckList | Where-Object { $_.guid -eq $CheckListId } | Select-Object -ExpandProperty graph

    if ($DebugMode) {
        Write-Host "Running query '$Query'`n"
    }

    Search-AzGraph $Query | Select-Object -ExpandProperty Data | Where-Object { $_.compliant -eq 0 } | Select-Object -ExpandProperty id
}
#endregion

#region Get-GroupMember
function Get-GroupMember {
    [CmdletBinding()]
    param (
        [array]$DirectoryObjectByIds
    )
    $params = @{
        ids   = $DirectoryObjectByIds
        types = @(
            "user"
            "group"
        )
    }

    if ($null -eq $DirectoryObjectByIds -or $DirectoryObjectByIds.Count -eq 0) {
        return $()
    }

    $DirectoryObject = Get-MgDirectoryObjectById -BodyParameter $params

    $DirectoryObject | ForEach-Object {
        $ObjectType = $_.AdditionalProperties.'@odata.type'
        if ($ObjectType -eq '#microsoft.graph.group') {
            Get-GroupMember -DirectoryObjectByIds (Get-MgGroupMember -GroupId $_.Id | Select-Object -ExpandProperty Id)
        }
        if ($ObjectType -eq '#microsoft.graph.user') {
            $_
        }
    }
}
#endregion

#region Get-EntraIdRoleAssignment
function Get-EntraIdRoleAssignment {
    [CmdletBinding()]
    param (
        [string]$RoleName = $null,
        [switch]$ExcludeEligebleRoles
    )

    if ([string]::IsNullOrEmpty($RoleName)) {
        throw "Must supply a rolename"
    }

    [array]$Assigned = @()
    [array]$Eligeble = @()

    # Get the role definition id
    $DirectoryRoleDefinitionId = Get-MgBetaRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$RoleName'" -Property "id" | Select-Object -ExpandProperty Id

    # only get those that are assigned
    $Filter = "roleDefinitionId eq '$DirectoryRoleDefinitionId' and AssignmentType eq 'Assigned'"
    [array]$AssignedPrincipals = Get-MgBetaRoleManagementDirectoryRoleAssignmentScheduleInstance -Filter $Filter | Select-Object -ExpandProperty PrincipalId
    Write-Verbose "Found $($AssignedPrincipals.Count) assigned principals"
    # recursively get group members
    $Assigned = Get-GroupMember -DirectoryObjectByIds $AssignedPrincipals | Sort-Object -Unique -Property Id
    Write-Verbose "Found $($Assigned.Count) assigned user principals"
    if (-not $ExcludeEligebleRoles.IsPresent) {
        $Filter = "roleDefinitionId eq '$DirectoryRoleDefinitionId'"
        # get principals that are eligble for the role
        [array]$EligeblePrincipals = Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance -Filter $Filter | Select-Object -ExpandProperty PrincipalId
        Write-Verbose "Found $($EligeblePrincipals.Count) eligeble principals"
        # recursively get group members
        [array]$Eligeble = Get-GroupMember -DirectoryObjectByIds $EligeblePrincipals
        Write-Verbose "Found $($Assigned.Count) eligeble user principals"
    }
    # sort unique to remove duplicates (eligble and assigned)
    $Assigned + $Eligeble | Sort-Object -Unique -Property Id
}
#endregion

#region Get-PrivilegedAdministratorRoleAssignment
function Get-PrivilegedAdministratorRoleAssignment {
    [CmdletBinding()]
    param (
        $TenantId,
        $SubscriptionId, # TODO: only using in set-azcontext
        $ManagementGroupId
    )

    function Get-GroupMember {
        [CmdletBinding()]
        param (
            [array]$DirectoryObjectByIds
        )
        $params = @{
            ids   = $DirectoryObjectByIds
            types = @(
                "user"
                "group"
            )
        }

        if ($null -eq $DirectoryObjectByIds -or $DirectoryObjectByIds.Count -eq 0) {
            return $()
        }

        $DirectoryObject = Get-MgDirectoryObjectById -BodyParameter $params

        $DirectoryObject | ForEach-Object {
            $ObjectType = $_.AdditionalProperties.'@odata.type'
            if ($ObjectType -eq '#microsoft.graph.group') {
                Get-GroupMember -DirectoryObjectByIds (Get-MgGroupMember -GroupId $_.Id | Select-Object -ExpandProperty Id)
            }
            if ($ObjectType -eq '#microsoft.graph.user') {
                $_
            }
        }  
    }

    # NOTE: Highly recommend to always use latest version of Microsoft.Graph modules, and uninstall old versions
    $RequiredModules = 'Az.ResourceGraph', 'Microsoft.Graph.Groups', 'Microsoft.Graph.Users', 'Microsoft.Graph.Authentication'
    $null = Import-Module -Name $RequiredModules -ErrorAction Stop
    
    try {
        $null = Set-AzContext -TenantId $TenantId -SubscriptionId $SubscriptionId -ErrorAction Stop -WarningAction Stop
    }
    catch {
        $null = Connect-AzAccount -TenantId $TenantId -SubscriptionId $SubscriptionId -UseDeviceAuthentication
    }

    <# we need to input options and set authorizationScopeFilter to AtScopeAboveAndBelow to get inherited permissions
    this means we cannot use search-azgraph
    #>

    function Get-PrivilegedUser {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [ValidateSet('Owner', 'Contributor', 'User Access Administrator')]
            $Role,
            [Parameter(Mandatory)]
            [System.Security.SecureString]
            $Token,
            [Parameter(Mandatory)]
            $ManagementGroupId
        )
        $PrivilegedRoles = @{
            'Owner'                     = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
            'Contributor'               = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
            'User Access Administrator' = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
        }
        $RoleDefId = $PrivilegedRoles[$Role]
        $Query = @"
        authorizationResources
        | where type == 'microsoft.authorization/roleassignments'
        | extend prop = properties
        | extend roleDefinitionIdFull = tostring(properties.roleDefinitionId)
        | extend roleDefinitionIdsplit = split(roleDefinitionIdFull,'/')
        | extend roleDefinitionId = tostring(roleDefinitionIdsplit[(4)])
        | extend roleAssignmentPrincipalType = properties.principalType
        | extend roleAssignmentDescription = properties.description
        | extend roleAssignmentPrincipalId = properties.principalId
        | extend roleAssignmentCreatedOn = properties.createdOn
        | extend roleAssignmentUpdatedOn = properties.updatedOn
        | extend roleAssignmentUpdatedById = properties.updatedBy
        | extend roleAssignmentCreatedById = properties.createdBy
        | extend roleAssignmentScope = properties.scope
        | project roleDefinitionId,roleAssignmentPrincipalType,roleAssignmentPrincipalId,roleAssignmentCreatedOn,roleAssignmentUpdatedOn,roleAssignmentUpdatedById,roleAssignmentCreatedById,roleAssignmentScope
        | where roleDefinitionId == '$RoleDefId'
"@

        $Body = ConvertTo-Json @{
            managementGroups = @($ManagementGroupId)
            query            = $Query
            options          = @{
                autorizationScopeFilter = "AtScopeAboveAndBelow"
            }
        }
        $Uri = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'
        $Headers = @{
        }
        Write-Verbose "Sending query:`n$Query"
        $Response = Invoke-RestMethod -Method Post -Uri $Uri -Body $Body -Headers $Headers -Authentication Bearer -Token $Token -ContentType 'application/json'
        $PrivilegedRBAC = $Response.data  #Search-AzGraph -Query $Query -ManagementGroup $ManagementGroupId -debug
    
        [array]$Groups = ($PrivilegedRBAC | Where-Object { $_.roleAssignmentPrincipalType -eq 'Group' }).roleAssignmentPrincipalId | Sort-Object -Unique
        if ($Groups.Count -gt 0) {
            $Filter = "Id in ($(($Groups | ForEach-Object { "'$_'" }) -join ','))"
            $Groups = Get-MgGroup -Filter $Filter
        }
        [array]$GroupMembers = Get-GroupMember -DirectoryObjectByIds $Groups.Id | Select-Object -ExpandProperty Id

        [array]$Users = $GroupMembers + ($PrivilegedRBAC | Where-Object { $_.roleAssignmentPrincipalType -eq 'User' }).roleAssignmentPrincipalId | Sort-Object -Unique
        if ($Users.Count -gt 0) {
            # TODO: chunks of 15 as this is the max allowed
            $Users = $Users | Select-Object -First 15
            $Filter = "Id in ($(($Users | ForEach-Object { "'$_'" }) -join ','))"
            $Users = Get-MgUser -Filter $Filter
            $Users | ForEach-Object {
                # $UserId = $_.Id
                $_ | Add-Member -MemberType NoteProperty -Name Role -Value $Role -PassThru -Force
            } |  Select-Object -Property DisplayName, Role
        }
    }

    # this will check if already connected, so we can run this multiple times
    Connect-MgGraph -TenantId $TenantId -UseDeviceCode -Scopes 'User.Read.All', 'Group.Read.All'
    # $Token = ConvertTo-SecureString -String (Get-AzAccessToken -TenantId $TenantId).Token -Force -AsPlainText
    $Token = Get-AzAccessToken -TenantId $TenantId -AsSecureString | Select-Object -ExpandProperty Token
    $GetPrivilegedUsersParams = @{Token = $Token; ManagementGroupId = $ManagementGroupId }
    Write-Host "Privileged role assignments at '$ManagementGroupId'"
    
    Get-PrivilegedUser -Role 'Owner' @GetPrivilegedUsersParams
    
    Get-PrivilegedUser -Role 'Contributor' @GetPrivilegedUsersParams
    
    Get-PrivilegedUser -Role 'User Access Administrator' @GetPrivilegedUsersParams
}
#endregion

#region Measure-IpAddressCount
function Measure-IpAddressCount {
    [CmdletBinding()]
    param (
        $StartIpAddress,
        $EndIpAddress
    )
    $Ip_Adresa_Od = $StartIpAddress -split "\."
    $Ip_Adresa_Do = $EndIpAddress -split "\."

    #change endianness
    [array]::Reverse($Ip_Adresa_Od)
    [array]::Reverse($Ip_Adresa_Do)

    #convert octets to integer
    $start = [bitconverter]::ToUInt32([byte[]]$Ip_Adresa_Od, 0)
    $end = [bitconverter]::ToUInt32([byte[]]$Ip_Adresa_Do, 0)

    # if they are the same, return 1
    return [System.Math]::Max($end - $start, 1)
}
# Measure-IpAddressCount -StartIpAddress '192.168.1.0' -EndIpAddress '192.168.2.0'
# Measure-IpAddressCount -StartIpAddress '0.0.0.0' -EndIpAddress '255.255.255.255'
#endregion

#region ConvertTo-Markdown
# NOTE: this has trouble with properties that are null or empty strings. It will mess with the order of the columns
# from https://www.powershellgallery.com/packages/PSMarkdown/1.1
<#
.Synopsis
   Converts a PowerShell object to a Markdown table.
.Description
   The ConvertTo-Markdown function converts a Powershell Object to a Markdown formatted table
.EXAMPLE
   Get-Process | Where-Object {$_.mainWindowTitle} | Select-Object ID, Name, Path, Company | ConvertTo-Markdown
 
   This command gets all the processes that have a main window title, and it displays them in a Markdown table format with the process ID, Name, Path and Company.
.EXAMPLE
   ConvertTo-Markdown (Get-Date)
 
   This command converts a date object to Markdown table format
.EXAMPLE
   Get-Alias | Select Name, DisplayName | ConvertTo-Markdown
 
   This command displays the name and displayname of all the aliases for the current session in Markdown table format
#>
Function ConvertTo-Markdown {
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [PSObject[]]$InputObject
    )

    Begin {
        $items = @()
        $columns = [ordered]@{}
    }

    Process {
        ForEach ($item in $InputObject) {
            $items += $item

            $item.PSObject.Properties | ForEach-Object {
                if ($null -ne $_.Value) {
                    if (-not $columns.Contains($_.Name) -or $columns[$_.Name] -lt $_.Value.ToString().Length) {
                        $columns[$_.Name] = $_.Value.ToString().Length
                    }
                }
            }
        }
    }

    End {
        ForEach ($key in $($columns.Keys)) {
            $columns[$key] = [Math]::Max($columns[$key], $key.Length)
        }

        $header = @()
        ForEach ($key in $columns.Keys) {
            $header += ('{0,-' + $columns[$key] + '}') -f $key
        }
        $header -join ' | '

        $separator = @()
        ForEach ($key in $columns.Keys) {
            $separator += '-' * $columns[$key]
        }
        $separator -join ' | '

        ForEach ($item in $items) {
            $values = @()
            ForEach ($key in $columns.Keys) {
                $values += ('{0,-' + $columns[$key] + '}') -f $item.($key)
            }
            $values -join ' | '
        }
    }
}
#endregion

#region Get-DeviceCodeAuthenticationToken
## get token for main.iam.ad.ext.azure.com
## https://rozemuller.com/use-internal-azure-api-in-automation/
function Get-DeviceCodeAuthenticationToken {
    [CmdletBinding()]
    param (
        $tenantId
    )

    #NOTE: we may be able to just use Get-AzAccessToken -Resource "https://main.iam.ad.ext.azure.com/"

    <# Stopped using this API?
    AADSTS500011: The resource principal named https://main.iam.ad.ext.azure.com/ was not found in the tenant named <TENANT>. This can happen if the application has not been installed by the administrator of the tenant or consented to by any user in the tenant. You might have sent your authentication request to the wrong tenant.
    #>

    $clientId = "1950a258-227b-4e31-a9cf-717495945fc2" # This is de Microsoft Azure Powershell application
    $resource = "https://main.iam.ad.ext.azure.com/"
    $tokenRequest = $null

    # Send the request to receive a device authentication URL
    $codeRequest = Invoke-RestMethod -Method POST -UseBasicParsing -Uri "https://login.microsoftonline.com/$tenantId/oauth2/devicecode" -Body "resource=$resource&client_id=$clientId" -Verbose:$false
    Write-Host "`n$($codeRequest.message)"
    Read-Host "Press enter to continue (in VS Code enter something random, then enter)"

    # Create the body for the token request, where the device code from the previous request will be used in the call
    $tokenBody = @{
        grant_type = "urn:ietf:params:oauth:grant-type:device_code"
        code       = $codeRequest.device_code
        client_id  = $clientId
    }

    # Get OAuth Token
    while ([string]::IsNullOrEmpty($tokenRequest.access_token)) {
        # Write-Verbose "`$tokenRequest is empty"
        $tokenRequest = try {
            Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tenantId/oauth2/token" -Body $tokenBody -Verbose:$false -ErrorAction Stop
        }
        catch {
            $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json
            Write-Verbose $errorMessage
            # If not waiting for auth, throw error
            if ($errorMessage.error -ne "authorization_pending") {
                throw "Authorization is pending."
            }
            else {
                Write-Host "Waiting for device code authentication..."
                Start-Sleep -Seconds 10
            }
        }
    }

    # Printing the relevant information for tracability of the token and code
    # Write-Output $($tokenRequest | Select-Object -Property token_type, scope, resource, access_token, refresh_token, id_token)
    $refreshToken = $tokenRequest.refresh_token

    try {
        $response = (Invoke-RestMethod "https://login.windows.net/$tenantId/oauth2/token" -Method POST -Body "resource=74658136-14ec-4630-ad9b-26e160ff0fc6&grant_type=refresh_token&refresh_token=$refreshToken&client_id=$clientId&scope=openid" -ErrorAction Stop -Verbose:$false)
    }
    catch {
        throw $_
    }
    $response.access_token
}
#endregion

#region Get-EntraIDApplicationInsight
function Get-EntraIDApplicationInsight {
    [CmdletBinding()]
    param (
        $appId,
        $Token
    )

    # start and end is in Unix time
    $Date = Get-Date
    $end = [int](Get-Date $Date -UFormat %s) * 1000
    $Date = $Date.AddDays(-30) # does not look like we can go further back than 30 days here
    $start = [int](Get-Date $Date -UFormat %s) * 1000

    # Microsoft Graph PowerShell | Usage & insights
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $Uri = "https://main.iam.ad.ext.azure.com/api/ApplicationInsights/EnterpriseAppSignIns?appId=$appId&start=$Start&end=$End"
    $Headers = @{
        "x-ms-client-session-id" = [GUID]::NewGuid().Guid
        "x-ms-client-request-id" = [GUID]::NewGuid().Guid
        "x-ms-command-name"      = "ApplicationManagement - GetEnterpriseAppSignInInsights"
        "Accept-Language"        = "en"
        "Authorization"          = "Bearer $Token"
        "x-ms-effective-locale"  = "en.en-gb"
        "Accept"                 = "*/*"
    }
    $Response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -WebSession $session -Headers $Headers -ContentType "application/json"
    $response.Content | Convertfrom-Json

    <# looks like we get back data for each day
for errorNo 0 the activityCount is the number of signins in the last x days

if erroNo is not 0 then it lists signin failures and a reason
#>
}
#endregion

#region Initialize-Notebook
function Initialize-Notebook {
    [CmdletBinding()]
    param (
        $TenantId = $Global:TenantId,
        $Scopes = @("Directory.AccessAsUser.All", "Policy.Read.All", "RoleManagement.Read.Directory", "RoleManagementAlert.Read.Directory", "AccessReview.Read.All", "Application.Read.All", "Directory.Read.All", "AuditLog.Read.All", "CrossTenantInformation.ReadBasic.All"),
        [SecureString]$AccessToken = $null
    )

    # these scopes are added automatically. To avoid a difference when comparing scopes we add them now
    $Scopes = $Scopes + @('profile', 'openid', 'User.Read', 'email') | Sort-Object -Unique
    $TenantId = $Global:TenantId = if ($null -eq $TenantId) { Read-Host -Prompt "Enter tenant ID" } else { $TenantId }

    # TODO: write a warning if any scope is a write scope

    # connect once for all necessary scopes for this notebook - these are delegated permissions so we cannot do something the authenticated user could not already do!
    # This means that 'Microsoft Graph Command Line Tools' must be approved by a Global Administrator
    # use Get-MgContext to check if we need to connect again
    $MgContext = Get-MgContext
    $NotConnected = $null -ne $AccessToken -or $null -eq $MgContext -or $MgContext.TenantId -ne $TenantId -or $null -ne (Compare-Object -ReferenceObject $MgContext.Scopes -DifferenceObject $Scopes)
    if ($NotConnected) {
        if ($null -ne $AccessToken) {
            Write-Verbose "Connecting to tenant '$TenantId' using provided access token"
            # cannot define scopes when using access token
            $null = Connect-MgGraph -AccessToken $AccessToken -ErrorAction Stop -NoWelcome
        }
        else {
            Write-Verbose "Connecting to tenant '$TenantId' with the following scope: $Scopes"
            $null = Connect-MgGraph -Scopes $Scopes -TenantId $TenantId -ContextScope Process -ErrorAction Stop -NoWelcome
        }
    }
    else {
        Write-Verbose "Already connected to tenant '$TenantId' with the following scope: $($MgContext.Scopes)"
    }

    Write-Verbose "Connected to tenant '$TenantId'"
    $null = Set-AzContext -TenantId $TenantId -ErrorAction Stop -WarningAction SilentlyContinue
}
#endregion

<#
.SYNOPSIS
Creates a new multi-tenant application in the specified tenant.

.DESCRIPTION
Creates a new multi-tenant application in the specified tenant. The application will have the application permissions to conduct the Entra ID Security Assessment.

.PARAMETER TenantId
Specifies the tenant ID of the tenant to create the application in.

.PARAMETER AppDisplayName
The display name of the application. Default is "Entra ID Security Assessment"

.EXAMPLE
New-MultiTenantApplication -TenantId 'abcdefg-8c5e-4a10-a32e-523da88a4c99'

.NOTES
General notes
#>
function New-MultiTenantApplication {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        $TenantId,
        $AppDisplayName = "Entra ID Security Assessment"
    )
    Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All" -TenantId $TenantId -NoWelcome

    $apiPermission = @{
        "resourceAppId"  = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
        "resourceAccess" = @(
            @{
                "id"   = "d07a8cc0-3d51-4b77-b3b0-32704d1f69fa" # AccessReview.Read.All
                "type" = "Role"
            }
            @{
                "id"   = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30" # Application.Read.All
                "type" = "Role"
            }
            @{
                "id"   = "b0afded3-3588-46d8-8b3d-9842eff778da" # AuditLog.Read.All
                "type" = "Role"
            }
            @{
                "id"   = "cac88765-0581-4025-9725-5ebc13f729ee" # CrossTenantInformation.ReadBasic.All
                "type" = "Role"
            }
            @{
                "id"   = "7ab1d382-f21e-4acd-a863-ba3e13f7da61" # Directory.Read.All
                "type" = "Role"
            }
            @{
                "id"   = "246dd0d5-5bd0-4def-940b-0421030a5b68" # Policy.Read.All
                "type" = "Role"
            }
            @{
                "id"   = "d5fe8ce8-684c-4c83-a52c-46e882ce4be1" # RoleAssignmentSchedule.Read.Directory
                "type" = "Role"
            }
            @{
                "id"   = "ff278e11-4a33-4d0c-83d2-d01dc58929a5" # RoleEligibilitySchedule.Read.Directory
                "type" = "Role"
            }
            @{
                "id"   = "c7fbd983-d9aa-4fa7-84b8-17382c103bc4" # RoleManagement.Read.All
                "type" = "Role"
            }
            @{
                "id"   = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c" # RoleManagement.Read.Directory
                "type" = "Role"
            }
            @{
                "id"   = "ef31918f-2d50-4755-8943-b8638c0a077e" # RoleManagementAlert.Read.Directory
                "type" = "Role"
            }
            @{
                "id"   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d" # User.Read
                "type" = "Scope"
            }
        )
    }
    # allows the app to redirect to portal.azure.com after consent is granted
    $Web = @{
        "RedirectUris" = @("https://portal.azure.com/")
    }
    $app = New-MgApplication -DisplayName $AppDisplayName -SignInAudience "AzureADMultipleOrgs" -RequiredResourceAccess @($apiPermission) -Web $Web
    $null = New-MgServicePrincipal -AppId $app.AppId
    #return the Application (client) ID
    $app.AppId
}

<#
functions used in the identity notebook.
#>

#region Get-UserState
function Get-UserState {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost,
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $TotalUsers = (Get-MgUser -All -Property Id).Count
    $Filter = "accountEnabled eq false"
    $DisabledUsers = (Get-MgUser -All -Property Id -Filter $Filter).Count
    $Filter = "userType eq 'Guest'"
    $GuestUsers = (Get-MgUser -All -Property Id -Filter $Filter).Count
    $DeletedUsers = (Get-MgBetaDirectoryDeletedItemAsUser -All).Count

    if ($OutputToHost.IsPresent) {
        Write-Host "Total users: $TotalUsers"
        Write-Host "Disabled users: $DisabledUsers"
        Write-Host "Guest users: $GuestUsers"
        Write-Host "Deleted users: $DeletedUsers"
    }
    else {
        # return an object
        $Output = [pscustomobject] @{
            TotalUsers    = $TotalUsers
            DisabledUsers = $DisabledUsers
            GuestUsers    = $GuestUsers
            DeletedUsers  = $DeletedUsers
        }
        if ($OutputMarkdown.IsPresent) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
    }
}
#endregion

#region Get-DisabledUser
function Get-DisabledUser {
    [CmdletBinding()]
    param (
        [switch]$IncludeLicenseDetails,
        [switch]$IncludeGroupMemberships,
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $Filter = "accountEnabled eq false and userType eq 'Member'"
    $DisabledUsers = Get-MgUser -All -Filter $Filter -ErrorAction Stop
    Write-Verbose "Found $($DisabledUsers.Count) disabled users"
    
    $Output = $DisabledUsers | ForEach-Object {
        $UserId = $_.Id
        $UserDisplayName = $_.DisplayName
        $User = [PSCustomObject][Ordered]@{ User = $UserDisplayName; }
        if ($IncludeGroupMemberships.IsPresent) {
            $UserMemberOf = (Get-MgUserMemberOf -UserId $UserId -All)
    
            if ($null -ne $UserMemberOf) {
                [string]$Groups = ($UserMemberOf | Where-Object { $_.AdditionalProperties."@odata.type" -eq '#microsoft.graph.group' }).AdditionalProperties.displayName -join ','
                [string]$Roles = ($UserMemberOf | Where-Object { $_.AdditionalProperties."@odata.type" -ne '#microsoft.graph.group' }).AdditionalProperties.displayName -join ','
                # avoid listing too many groups as it messes with the table width
                $Groups = $Groups[0..128] -join ""
                $User = $User | Add-Member -MemberType NoteProperty -Name Groups -Value $Groups -PassThru
                if (-not [string]::IsNullOrEmpty($Roles)) {
                    $User = $User | Add-Member -MemberType NoteProperty -Name Roles -Value $Roles -PassThru
                }
            }
        }

        if ($IncludeLicenseDetails.IsPresent) {
            $SkuPartNumber = (Get-MgUserLicenseDetail -UserId $UserId -Property SkuPartNumber).SkuPartNumber
        
            if ($null -ne $SkuPartNumber) {
                $User = $User | Add-Member -MemberType NoteProperty -Name Sku -Value $SkuPartNumber -PassThru
                # [PSCustomObject][Ordered]@{ User = $_.DisplayName; Sku = $SkuPartNumber }
            }
        }
        $User
    }
    if ($OutputMarkdown.IsPresent) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }       
}
#endregion

#region Get-GlobalAdminstrator
function Get-GlobalAdminstrator {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown,
        [switch]$OutputToHost
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $Setting = Get-EntraIdRoleAssignment -RoleName "Global Administrator"
    $Compliant = $Setting.Count -lt 5

    if ($OutputToHost.IsPresent) {
        if ($Compliant) {
            Write-Host "Compliant to control; there are $($Setting.Count) Global Administrators (Assigned and Eligible)" -ForegroundColor Green
        }
        else {
            Write-Host "Not compliant to control; there are $($Setting.Count) Global Administrators (Assigned and Eligible)" -ForegroundColor Red
        }
    }

    $Output = $Setting | Select-Object -Property Id, @{ Name = 'Display Name'; Expression = { $_.AdditionalProperties.displayName } }, @{ Name = 'User Principal Name'; Expression = { $_.AdditionalProperties.userPrincipalName } }

    if ($OutputMarkdown.IsPresent) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
}
#endregion

#region Get-SynchronizedAccount
function Get-SynchronizedAccount {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown,
        [switch]$ShowProgress
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $PrivilegedRolesList = @('62e90394-69f5-4237-9190-012177145e10', '194ae4cb-b126-40b2-bd5b-6091b380977d', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', '29232cdf-9323-42fd-ade2-1d097af3e4de', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', '729827e3-9c14-49f7-bb1b-9608f156bbb8', 'b0f54661-2d74-4c50-afa3-1ec803f12efe', 'fe930be7-5e62-47db-91af-98c3a49a38b1', 'c4e39bd9-1100-46d3-8c65-fb160da0071f', '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', '158c047a-c907-4556-b7ef-446551a6b5f7', '966707d0-3269-4727-9be2-8c3a10f19b9d', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', 'e8611ab8-c189-46e8-94e1-60213ab1f814')

    # check if there is any synchronized accounts at all
    $SynchronizedAccounts = Get-MgUser -Filter "onPremisesSyncEnabled eq true" -All # TODO: test and only return the count
    if ($SynchronizedAccounts.Count -eq 0) {
        return
    }

    $i = 0
    $UsersWithPrivilegedRoles = $PrivilegedRolesList | ForEach-Object {    
        $RoleName = Get-MgBetaRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_ -Property "DisplayName" | Select-Object -ExpandProperty DisplayName
        $i += 1
        if ($ShowProgress.IsPresent) {
            [int]$p = 100 * [float]$i / [float]($PrivilegedRolesList.Count)
            Write-Progress -Activity "Getting users with the role '$RoleName'" -PercentComplete $p -Status "$p% Complete"
        }
        Get-EntraIdRoleAssignment -RoleName $RoleName | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name 'Role' -Value $RoleName -PassThru -Force }
    }

    $Output = $UsersWithPrivilegedRoles | ForEach-Object {
        $UserWithPrivilegedRole = $_
        Get-MgUser -UserId $UserWithPrivilegedRole.Id -Property onPremisesSyncEnabled, DisplayName, AccountEnabled -ErrorAction SilentlyContinue | Select-Object -Property DisplayName, AccountEnabled, onPremisesSyncEnabled, @{ Name = 'Role'; Expression = { $UserWithPrivilegedRole.Role } }
    } | Where-Object { $_.OnPremisesSyncEnabled -and $_.AccountEnabled } | Select-Object -Property @{ Name = 'Display Name'; Expression = { $_.DisplayName } }, Role

    if ($OutputMarkdown.IsPresent) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
}
#endregion

#region Get-GroupsWithRoleAssignment
function Get-GroupsWithRoleAssignment {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $RoleName = "Global Administrator"

    # Get the directory role id for $RoleName
    $DirectoryRoleId = Get-MgDirectoryRole -Filter "DisplayName eq '$RoleName'" | Select-Object -ExpandProperty Id
    # Get currently assigned
    $null = Get-MgDirectoryRoleMember -DirectoryRoleId $DirectoryRoleId | Select-Object -ExpandProperty Id

    # TODO: $Assigned includes eligeble that have activated the role, but does not provide any details. we need to kow the 'state' and if it is activated we can disregard

    # Get the role definition id for $RoleName
    $DirectoryRoleDefinitionId = Get-MgBetaRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$RoleName'" -Property "id" | Select-Object -ExpandProperty Id
    # get principals that are eligble for GA
    $EligeblePrincipals = Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance -Filter "roleDefinitionId eq '$DirectoryRoleDefinitionId'" | Select-Object -ExpandProperty PrincipalId

    $DirectoryObjectByIds = $EligeblePrincipals # + $Assigned

    $params = @{
        ids   = $DirectoryObjectByIds
        types = @(
            "user"
            "group"
        )
    }

    if ($params.ids.Count -gt 0) {
        $DirectoryObject = Get-MgDirectoryObjectById -BodyParameter $params

        $DirectoryObject | Select-Object Id, @{ Name = 'displayName'; Expression = { $_.AdditionalProperties.displayName } }, @{ Name = 'type'; Expression = { $_.AdditionalProperties.'@odata.type'.split('.') | Select-Object -Last 1 } }
    }

    if ($OutputMarkdown.IsPresent) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
}
#endregion

#region Get-PimAlert
function Get-PimAlert {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $GovernanceRoleManagementAlerts = Get-MgBetaIdentityGovernanceRoleManagementAlert -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole' and isActive eq true" -ExpandProperty "alertDefinition,alertConfiguration,alertIncidents"

    $Output = $GovernanceRoleManagementAlerts | Select-Object -Property @{ Name = 'Alert'; Expression = { $_.alertDefinition.displayName } }, @{ Name = 'Incident Count'; Expression = { $_.IncidentCount } }

    if ($OutputMarkdown.IsPresent) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
}
#endregion

#region Get-PimAlertAffectedPrincipal
function Get-PimAlertAffectedPrincipal {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $GovernanceRoleManagementAlerts = Get-MgBetaIdentityGovernanceRoleManagementAlert -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole' and isActive eq true" -ExpandProperty "alertDefinition,alertConfiguration,alertIncidents"

    $Output = $GovernanceRoleManagementAlerts.alertIncidents.AdditionalProperties | Where-Object { $_.assigneeUserPrincipalName } | ForEach-Object {
        $_ | Select-Object -Property @{ Name = 'User'; Expression = { "$($_.assigneeDisplayName) ($($_.assigneeUserPrincipalName))" } }, @{ Name = 'Role'; Expression = { $_.roleDisplayName } }
    }

    if ($OutputMarkdown.IsPresent) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
}
#endregion

#region Get-RecurringAccessReview
function Get-RecurringAccessReview {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $AccessReviewDefinitions = Get-MgBetaIdentityGovernanceAccessReviewDefinition

    $Output = [pscustomobject] @{"Access review definitions" = $(($AccessReviewDefinitions | Measure-Object).Count) }
    if ($OutputMarkdown.IsPresent) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
}
#endregion

#region Get-AppOwnersChangeGroupMembership
function Test-AppOwnersChangeGroupMembership {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    #get the graph id
    $Graph = Get-MgBetaServicePrincipal -filter "appId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction Stop
    #get the permission IDs
    $group_permissions = $Graph | Select-Object -ExpandProperty approles | Select-Object * | Where-Object { $_.value -in ("GroupMember.ReadWrite.All", "Group.ReadWrite.All") }


    $Output = Get-MgBetaServicePrincipalAppRoleAssignedTo -ServicePrincipalId $graph.id -All | `
        Where-Object { $_.AppRoleId -in ($group_permissions.id) } | Select-Object PrincipalDisplayName, PrincipalId -Unique | ForEach-Object {
        Get-MgBetaServicePrincipal -serviceprincipalid $_.PrincipalId -ExpandProperty owners | ForEach-Object {
            $app = $null; $app = $_
            $app | Select-Object appid, displayname, PublisherName, @{N = "via"; Expression = { "AppRoleAssignment" } }
            ($app.owners).id | Select-Object @{N = "appid"; Expression = { $app.appid } }, `
            @{N = "DisplayName"; Expression = { (Get-MgBetaDirectoryObjectById -Ids $_ | Select-Object -ExpandProperty AdditionalProperties | ConvertTo-Json | ConvertFrom-Json).displayname } }, `
            @{N = "PublisherName"; Expression = { $app.PublisherName } }, @{N = "via"; Expression = { "Owner of $($app.displayname)" } }
            (Get-MgBetaApplication -filter "appId eq '$($_.appid)'" -ExpandProperty owners | `
                Select-Object -expandproperty owners).id | Select-Object @{N = "appid"; Expression = { $app.appid } }, `
            @{N = "DisplayName"; Expression = { (Get-MgBetaDirectoryObjectById -Ids $_ | Select-Object -ExpandProperty AdditionalProperties | ConvertTo-Json | ConvertFrom-Json).displayname } }, `
            @{N = "PublisherName"; Expression = { $app.PublisherName } }, @{N = "via"; Expression = { "Owner of $($app.displayname)" } }
        }
    } | Select-Object DisplayName, via -Unique

    # Roles that have GroupMember.ReadWrite.All or Group.ReadWrite.All
    $roles = '810a2642-a034-447f-a5e8-41beaa378541', ',11451d60-acb2-45eb-a7d6-43d0f0125c13', '45d8d3c5-c802-45c6-b32a-1d70b5e1e86e', `
        '744ec460-397e-42ad-a462-8b3f9747a02c', 'b5a8dcf3-09d5-43a9-a639-8e29ef291470', 'fdd7a751-b60b-444a-984c-02652fe8fa1c', `
        '69091246-20e8-4a56-aa4d-066075b2a7a8', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', '29232cdf-9323-42fd-ade2-1d097af3e4de', `
        '9360feb5-f418-4baa-8175-e2a00bac4301', 'fe930be7-5e62-47db-91af-98c3a49a38b1', '62e90394-69f5-4237-9190-012177145e10'

    $Output += Get-MgBetaDirectoryRole -all | Where-Object { $_.RoleTemplateId -in $roles } -pv role | ForEach-Object {
        Get-MgBetaDirectoryRoleMember -DirectoryRoleId $_.Id | ForEach-Object { $_ | Select-Object -expandproperty AdditionalProperties | `
                ConvertTo-Json -Depth 5 | ConvertFrom-Json }  | Select-Object displayName, @{N = "via"; Expression = { "Role Member of $($role.displayname)" } }
    } | Select-Object DisplayName, via -Unique

    $Output = $Output | Select-Object -Property @{ Name = 'Display Name'; Expression = { $_.DisplayName } }, via

    # TODO: column order is reversed
    if ($OutputMarkdown.IsPresent) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
    #$Output[0].PSObject.Properties
}
#endregion

#region Test-StandingAccess
function Test-StandingAccess {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown,
        [switch]$ShowProgress
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    # get permanent assignments of privileged Entra ID roles

    $PrivilegedRolesList = @('62e90394-69f5-4237-9190-012177145e10', '194ae4cb-b126-40b2-bd5b-6091b380977d', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', '29232cdf-9323-42fd-ade2-1d097af3e4de', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', '729827e3-9c14-49f7-bb1b-9608f156bbb8', 'b0f54661-2d74-4c50-afa3-1ec803f12efe', 'fe930be7-5e62-47db-91af-98c3a49a38b1', 'c4e39bd9-1100-46d3-8c65-fb160da0071f', '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', '158c047a-c907-4556-b7ef-446551a6b5f7', '966707d0-3269-4727-9be2-8c3a10f19b9d', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', 'e8611ab8-c189-46e8-94e1-60213ab1f814')

    $i = 0
    $Output = $PrivilegedRolesList | ForEach-Object {    
        $RoleName = Get-MgBetaRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_ -Property "DisplayName" | Select-Object -ExpandProperty DisplayName
        $i += 1
        if ($ShowProgress.IsPresent) {
            [int]$p = 100 * [float]$i / [float]($PrivilegedRolesList.Count)
            Write-Progress -Activity "Getting users with the role '$RoleName'" -PercentComplete $p -Status "$p% Complete"
        }
        Get-EntraIdRoleAssignment -RoleName $RoleName -ExcludeEligebleRoles | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name 'Role' -Value $RoleName -PassThru -Force }
    } | Select-Object -Property Role, @{Name = 'DisplayName'; Expression = { $_.AdditionalProperties.displayName } }, @{Name = 'UserPrincipalName'; Expression = { $_.AdditionalProperties.userPrincipalName } }

    if ($OutputMarkdown.IsPresent) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }

    # get permanent assignments of privileged Azure RBAC roles
}
#endregion

#region Test-GuestInviteSetting
function Test-GuestInviteSetting {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost,
        [switch]$ShowExplanation,
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $AuthorizationPolicy = Get-MgPolicyAuthorizationPolicy

    $Setting = $AuthorizationPolicy.AllowInvitesFrom
    $Compliant = $Setting -in 'adminsAndGuestInviters', 'none'

    if ($ShowExplanation.IsPresent) {
        Write-Host "Compliant External Collaboration Settings: Guest invite settings set to 'Only users assigned to specific admin roles can invite guest users' or 'No one in the organization can invite guest users including admins (most restrictive)'"
    }

    if ($OutputToHost.IsPresent) {
        if ($Compliant) {
            Write-Host "Compliant to control, setting is $($Setting)" -ForegroundColor Green
        }
        else {
            Write-Host "Not compliant to control, setting is $($Setting)" -ForegroundColor Red
        }
    }
    if ($OutputMarkdown.IsPresent) {
        # return an object
        $Output = [pscustomobject] @{
            "Guest invite settings" = $Setting
        }
        $Output | ConvertTo-Markdown
    }
}
#endregion

#region Test-GuestUserAccessRestriction
function Test-GuestUserAccessRestriction {
    [CmdletBinding()]
    param (
        [switch]$ShowExplanation
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $Explanation = @"
Compliant External Collaboration Settings: Guest user access set to 'Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)'
"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }
    Write-Warning "Work in progress - not yet implemented"; return
    # TODO: does not say anything about guest user access....

    # $ExternalIdentityPolicy = Get-MgBetaPolicyExternalIdentityPolicy #-ExpandProperty "AdditionalProperties"

    # $ExternalIdentityPolicy | fl *
    # $ExternalIdentityPolicy.AdditionalProperties | fl *
}
#endregion

#region Test-UsersCanRegisterApplication
function Test-UsersCanRegisterApplication {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost,
        [switch]$ShowExplanation,
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $Explanation = @"
Users can register applications should be set to `No`.

Users should not be allowed to register applications. Use specific roles such as `Application Developer`.    
"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }
    $AuthorizationPolicy = Get-MgPolicyAuthorizationPolicy -Property "DefaultUserRolePermissions"

    $Setting = $AuthorizationPolicy.DefaultUserRolePermissions.AllowedToCreateApps
    $Compliant = $Setting -eq $false

    if ($OutputToHost.IsPresent) {
        if ($Compliant) {
            Write-Host "Compliant to control; users are not allowed to create applications" -ForegroundColor Green
        }
        else {
            Write-Host "Not compliant to control; users are allowed to create applications" -ForegroundColor Red
        }
    }
    if ($OutputMarkdown.IsPresent) {
        # return an object
        $Output = [pscustomobject] @{
            "Users are allowed to create applications" = $Compliant ? "No" : "Yes"
        }
        $Output | ConvertTo-Markdown
    }
}
#endregion

#region Test-AuthenticationMethod
function Test-AuthenticationMethod {
    [CmdletBinding()]
    param (
        [switch]$ShowExplanation
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $Explanation = @"
    
"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }

    $Response = Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/policies/authenticationmethodspolicy" -ErrorAction Stop
    $policyMigrationState = $Response | Select-Object -ExpandProperty policyMigrationState
    # possible options??? preMigration, migrationInProgress, migrationComplete
    if ($policyMigrationState -eq 'migrationComplete') {
        Write-Host "Authentcation medthod policy migration already completed!"
        return
    }
    Write-Host "Authentcation method policy migration status is '$policyMigrationState'"
    
    # look up the state of authentication methods
    $authenticationMethodConfigurations = $Response | Select-Object -ExpandProperty authenticationMethodConfigurations | Where-Object { $_.state -eq "enabled" }
    Write-Host "$($authenticationMethodConfigurations.Count) authentication methods are enabled: $(($authenticationMethodConfigurations | Select-Object -ExpandProperty id) -join ',')"
    
    # get methods from SSPR
    # azure portal uses
    # https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=false
    # looks like there is no MG API for this - makes sense when moving to use authentication method policies
    # $Token = ConvertTo-SecureString -Force -AsPlainText (Get-AzAccessToken -TenantId $TenantId -ResourceUrl "https://main.iam.ad.ext.azure.com" | Select-Object -ExpandProperty Token)
    # $Uri = 'https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=false'
    # token does not work for this endpoint. inspecting a working token the audience and appid is a guid
    
    # get methods from old MFA portal
    
    # compare with what is enabled
}
#endregion

#region Test-VerifiedDomain
function Test-VerifiedDomain {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost,
        [switch]$ShowExplanation,
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $Explanation = @"
Check that only validated customer domains are registered in the tenant.
"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }
    $Domains = Get-MgBetaDomain

    $UnverifiedDomains = $Domains | Where-Object { -not $_.IsVerified }

    $Compliant = $UnverifiedDomains.Count -eq 0

    if ($OutputToHost.IsPresent) {
        if ($Compliant) {
            Write-Host "Compliant to control; All ($($Domains.Count)) domains are verified" -ForegroundColor Green
        }
        else {
            Write-Host "Not compliant to control; There are unverified domains registered: $($UnverifiedDomains | Select-Object -ExpandProperty Id)" -ForegroundColor Red
        }
    }
    if ($OutputMarkdown.IsPresent) {
        # return an object
        $Output = [pscustomobject] @{
            "Unverified domains registered" = $Compliant ? "0" : ($UnverifiedDomains | Select-Object -ExpandProperty Id)
        }
        $Output | ConvertTo-Markdown
    }
}
#endregion

#region Test-UserConsentForApp
function Test-UserConsentForApp {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost,
        [switch]$ShowExplanation,
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $Explanation = @"
Users should only be allowed to consent to apps from verified publishers or not consent at all. Allowing users to consent to any application is a security risk.
"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }

    $PolicyAuthorization = Get-MgPolicyAuthorizationPolicy #-ExpandProperty defaultUserRolePermissions
    $permissionGrantPoliciesAssigned = $PolicyAuthorization.DefaultUserRolePermissions.permissionGrantPoliciesAssigned

    $Setting = $permissionGrantPoliciesAssigned
    $Compliant = $Setting[0] -ne "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"

    if ($OutputToHost.IsPresent) {
        if ($Compliant) {
            Write-Host "Compliant to control; users are only allowed to consent to apps from verified publishers or not consent at all." -ForegroundColor Green
        }
        else {
            Write-Host "Not compliant to control; users are allowed to consent to all applications." -ForegroundColor Red
        }
    }
    if ($OutputMarkdown.IsPresent) {
        # return an object
        $Output = [pscustomobject] @{
            "Users are allowed to consent to all applications" = $Compliant ? "No" : "Yes"
        }
        $Output | ConvertTo-Markdown
    }
}
#endregion

#region Test-GroupOwnerConsent
function Test-GroupOwnerConsent {
    [CmdletBinding()]
    param (
        [switch]$ShowExplanation
    )
    $Explanation = @"
TODO
"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }
    # TODO https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent-groups?tabs=azure-portal&pivots=ms-powershell
}
#endregion

#region Find-OwnersFirstPartyMicrosoftApplication
function Find-OwnersFirstPartyMicrosoftApplication {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost,
        [switch]$ShowExplanation,
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $Explanation = @"
Owners of builtin applications can be exploited, see https://dirkjanm.io/azure-ad-privilege-escalation-application-admin/
"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }
    $Output = Get-MgBetaServicePrincipal -all -ExpandProperty owners | `
        # looking for first-party Microsoft applications with owners
        # TODO: convert to filter
    Where-Object { $_.PublisherName -like "*Microsoft*" -or !($_.PublisherName -eq "Microsoft Accounts") -and $_.AppOwnerOrganizationId -eq 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' } | `
        Where-Object { $_.owners -like "*" } | Select-Object appid, displayname, PublisherName, owners # TODO: look up owner
    if ($OutputToHost.IsPresent) {
    }
    if ($OutputMarkdown.IsPresent) {
        $Output | ConvertTo-Markdown
    }
    # TODO: can we look for anyone who persisted access through one of these? 
}
#endregion

#region Find-ApplicationsWithApplicationPermissionsAndOwner
function Find-ApplicationsWithApplicationPermissionsAndOwner {
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [switch]$OutputMarkdown,
        [switch]$ShowExplanation
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $Explanation = @"

"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }

    $MgGraphPermissionIds = Find-MgGraphPermission -All -PermissionType Application | Select-Object -ExpandProperty Id
    $Applications = Get-MgBetaApplication -All -ExpandProperty Owners | Where-Object {
        $RequiredResourceAccess = $_.RequiredResourceAccess
        $ResourceAppId = $RequiredResourceAccess.ResourceAppId
        $ResourceAccessIds = $RequiredResourceAccess.ResourceAccess.Id
        $ResourceAppId -eq '00000003-0000-0000-c000-000000000000' -and $_.Owners.Count -gt 0 -and ($ResourceAccessIds | Where-Object { $_ -In $MgGraphPermissionIds }).Count -gt 0
    }
    
    if ($Applications.Count -eq 0) {
        "Found no applications with Owners"
        return
    }
    
    $Owners = Get-MgDirectoryObjectById -ErrorAction SilentlyContinue -Ids ($Applications | ForEach-Object {
            $_.Owners.Id
        } | Sort-Object -Unique)
    
    # need these in a specific order for Markdown output, ConvertTo-Markdown still outputs in different order
    $Output = $Applications | ForEach-Object {
        $App = $_
        $OwnerIds = $App.Owners.Id
        [PSCustomObject][Ordered]@{
            DisplayName = $App.DisplayName
            AppId       = $App.AppId
            Owners      = ($OwnerIds | ForEach-Object { $Id = $_; $Owners | Where-Object { $_.Id -eq $Id } }).AdditionalProperties.userPrincipalName -join ','
        }
    }
    
    if ($OutputMarkdown.IsPresent) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
}
#endregion

$LowPermissions = @('14dad69e-099b-42c9-810b-d002981feec1', 'e1fe6dd8-ba31-4d61-89e7-88639da4683d', '64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0', '7427e0e9-2fba-42fe-b0c0-848c9e6a8182', '37f7f235-527c-4136-accd-4a02d197296e')

#region Show-LowRiskApplicationPermission
function Show-LowRiskApplicationPermission {
    [CmdletBinding()]
    param (
        [switch]$ShowExplanation,
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $Explanation = @"
These permissions are considered low risk
"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }
    
    $Output = Find-MgGraphPermission -All | Where-Object { $_.Id -in $LowPermissions } # uncomment to list low-risk permissions

    if ($OutputMarkdown.IsPresent) {
        $Output | ConvertTo-Markdown
    }
    else {
        $Output | Format-Table -AutoSize
    }
}
#endregion

#region Find-ApplicationsNonLowRiskPermissionsAndOwner
function Find-ApplicationsNonLowRiskPermissionsAndOwner {
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [switch]$ShowExplanation,
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $Explanation = @"
Look for applications with owners and any resource access that we do not consider low-risk. 
"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }
    
    # filter out some of the classical delegated low-risk permissions    
($LowPermissions | ForEach-Object { Find-MgGraphPermission $_ }).Name
    $Applications = Get-MgBetaApplication -All -ExpandProperty Owners | Where-Object {
        $RequiredResourceAccess = $_.RequiredResourceAccess
        $ResourceAppId = $RequiredResourceAccess.ResourceAppId
        $ResourceAccessIds = $RequiredResourceAccess.ResourceAccess.Id
        $HasOwners = $_.Owners.Count -gt 0
        $HasOnlyWindowsAzureActiveDirectoryUserRead = $ResourceAppId -eq '00000002-0000-0000-c000-000000000000' -and '311a71cc-e848-46a1-bdf8-97ff7156d8e6' -in $ResourceAccessIds -and $ResourceAccessIds.Count -eq 1
        $OnlyLowPermissions = $ResourceAppId -eq '00000003-0000-0000-c000-000000000000' -and ($ResourceAccessIds | Where-Object { $_ -notin $LowPermissions }).Count -eq 0
        # Application has owners, has API permissions and those permission are not only low-risk permissions
        $HasOwners -and $null -ne $_.RequiredResourceAccess -and -not $OnlyLowPermissions -and $ResourceAccessIds.Count -gt 0 -and -not $HasOnlyWindowsAzureActiveDirectoryUserRead
    }

    if ($Applications.Count -eq 0) {
        "Found no applications with Owners and above low-risk permissions"
        return
    }

    $Owners = Get-MgDirectoryObjectById -Ids ($Applications | ForEach-Object {
            $_.Owners.Id
        } | Sort-Object -Unique)

    # need these in a specific order for Markdown output, ConvertTo-Markdown still outputs in different order
    $Output = $Applications | ForEach-Object {
        $App = $_
        $OwnerIds = $App.Owners.Id    
        $ResourceAccessTypes = $App.RequiredResourceAccess.ResourceAccess.type
        [PSCustomObject][Ordered]@{
            DisplayName         = $App.DisplayName
            AppId               = $App.AppId
            Owners              = ($OwnerIds | ForEach-Object { $Id = $_; $Owners | Where-Object { $_.Id -eq $Id } }).AdditionalProperties.userPrincipalName -join ','
            ResourceAccessTypes = ($ResourceAccessTypes | Sort-Object -Unique) -join ','
        }
    }

    # TODO: pretty print headers

    if ($OutputMarkdown) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
}
#endregion

#region Get-EntraIdPrivilegedAppRoleAssignment
############################################################################################################
#                                                                                                          #
#  Powershell script showcasing how to fetch and report on all app role assignments for Microsoft Graph    #
#  and Azure AD Graph. Requires Microsoft Graph Powershell SDK v2, but the script can be altered to also   #
#  work in v1 if replacing beta-cmdlets.                                                                   #
#                                                                                                          #
#  The script only requires read-access and a few Graph scopes in Entra ID.                                #
#                                                                                                          #
#  Please read the blogpost first:                                                                         #
#  https://learningbydoing.cloud/blog/audit-ms-graph-app-role-assignments/                                 #
#                                                                                                          #
############################################################################################################

### Start of script

# asp@apento.com - making into function

function Get-EntraIdPrivilegedAppRoleAssignment {
    [CmdletBinding()]
    param (
        
    )

    #region: Script Configuration

    # The tier 0 app roles below are typically what can be abused to become Global Admin.
    # NOTE: Organizations should do their own investigations and include any app roles to regard as sensitive, and which tier to assign them.
    $appRoleTiers = @{
        'Application.ReadWrite.All'          = 'Tier 0' # SP can add credentials to other high-privileged apps, and then sign-in as the high-privileged app
        'AppRoleAssignment.ReadWrite.All'    = 'Tier 0' # SP can add any app role assignments to any resource, including MS Graph
        'Directory.ReadWrite.All'            = 'Tier 0' # SP can read and write all objects in the directory, including adding credentials to other high-privileged apps
        'RoleManagement.ReadWrite.Directory' = 'Tier 0' # SP can grant any role to any principal, including Global Admin
    }

    #endregion: Script Configuration

    # Connect to Microsoft Graph - assuming this has already been done
    # Connect-MgGraph -Scopes "Application.Read.All", "AuditLog.Read.All", "CrossTenantInformation.ReadBasic.All"

    # Get Microsoft Graph SPN, appRoles, appRolesAssignedTo and generate hashtable for quick lookups
    $servicePrincipalMsGraph = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"
    [array] $msGraphAppRoles = $servicePrincipalMsGraph.AppRoles
    [array] $msGraphAppRolesAssignedTo = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $servicePrincipalMsGraph.Id -All
    $msGraphAppRolesHashTableId = $msGraphAppRoles | Group-Object -Property Id -AsHashTable

    # Get Azure AD Graph SPN, appRoles, appRolesAssignedTo and generate hashtable for quick lookups
    $servicePrincipalAadGraph = Get-MgServicePrincipal -Filter "AppId eq '00000002-0000-0000-c000-000000000000'"
    [array] $aadGraphAppRoles = $servicePrincipalAadGraph.AppRoles
    [array] $aadGraphAppRolesAssignedTo = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $servicePrincipalAadGraph.Id -All
    $aadGraphAppRolesHashTableId = $aadGraphAppRoles | Group-Object -Property Id -AsHashTable

    # Join appRolesAssignedTo entries for AAD / MS Graph
    $joinedAppRolesAssignedTo = @(
        $msGraphAppRolesAssignedTo
        $aadGraphAppRolesAssignedTo
    )

    # Process each appRolesAssignedTo for AAD / MS Graph
    $progressCounter = 0
    $cacheAppOwnerOrganizations = @()
    $cacheServicePrincipalObjects = @()
    $cacheServicePrincipalSigninActivities = @()
    $cacheServicePrincipalsWithoutSigninActivities = @()
    [array] $msGraphAppRoleAssignedToReport = $joinedAppRolesAssignedTo | ForEach-Object {
        $progressCounter++
        $currentAppRoleAssignedTo = $_
        Write-Verbose "Processing appRole # $progressCounter of $($joinedAppRolesAssignedTo.count)"

        # Lookup appRole for MS Graph
        $currentAppRole = $msGraphAppRolesHashTableId["$($currentAppRoleAssignedTo.AppRoleId)"]
        if ($null -eq $currentAppRole) {
            # Lookup appRole for AAD Graph
            $currentAppRole = $aadGraphAppRolesHashTableId["$($currentAppRoleAssignedTo.AppRoleId)"]
        }
    
        # Lookup servicePrincipal object - check cache
        $currentServicePrincipalObject = $null
        if ($cacheServicePrincipalObjects.Id -contains $currentAppRoleAssignedTo.PrincipalId) {
            $currentServicePrincipalObject = $cacheServicePrincipalObjects | Where-Object { $_.Id -eq $currentAppRoleAssignedTo.PrincipalId }
        } 

        else {
            # Retrieve servicePrincipalObject from MS Graph
            $currentServicePrincipalObject = Get-MgServicePrincipal -ServicePrincipalId $currentAppRoleAssignedTo.PrincipalId
            $cacheServicePrincipalObjects += $currentServicePrincipalObject
            Write-Verbose "Added servicePrincipal object to cache: $($currentServicePrincipalObject.displayName)"
        }

        # Lookup app owner organization
        $currentAppOwnerOrgObject = $null
        if ($null -ne $currentServicePrincipalObject.AppOwnerOrganizationId) {
            # Check if app owner organization is in cache
            if ($cacheAppOwnerOrganizations.tenantId -contains $currentServicePrincipalObject.AppOwnerOrganizationId) {
                $currentAppOwnerOrgObject = $cacheAppOwnerOrganizations | Where-Object { $_.tenantId -eq $currentServicePrincipalObject.AppOwnerOrganizationId }
            } 

            else {
                # Retrieve app owner organization from MS Graph
                $currentAppOwnerOrgObject = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='$($currentServicePrincipalObject.AppOwnerOrganizationId)')"
                $cacheAppOwnerOrganizations += $currentAppOwnerOrgObject
                Write-Verbose "Added app owner organization tenant to cache: $($currentAppOwnerOrgObject.displayName)"
            }
        }

        # Lookup servicePrincipal sign-in activity if not already in no-signin-activity list
        $currentSpSigninActivity = $null
        if ($currentServicePrincipalObject.AppId -notin $cacheServicePrincipalsWithoutSigninActivities) {
            if ($cacheServicePrincipalSigninActivities.AppId -contains $currentServicePrincipalObject.AppId) {
                $currentSpSigninActivity = $cacheServicePrincipalSigninActivities | Where-Object { $_.AppId -eq $currentServicePrincipalObject.AppId }
            } 

            else {
                # Retrieve servicePrincipal sign-in activity from MS Graph
                $currentSpSigninActivity = Get-MgBetaReportServicePrincipalSignInActivity -Filter "AppId eq '$($currentServicePrincipalObject.AppId)'"
            
                # If sign-in activity was found, add it to the cache - else add appId to no-signin-activity list
                if ($currentSpSigninActivity) {
                    $cacheServicePrincipalSigninActivities += $currentSpSigninActivity
                    Write-Verbose "Found servicePrincipal sign-in activity and added it to cache: $($currentServicePrincipalObject.displayName)"
                }

                else {
                    $cacheServicePrincipalsWithoutSigninActivities += $currentServicePrincipalObject.AppId
                    Write-Verbose "Did not find servicePrincipal sign-in activity: $($currentServicePrincipalObject.displayName)"
                }
            }
        }

        # Create reporting object
        [PSCustomObject][Ordered]@{
            AppRoleTier                                     = $appRoleTiers["$($currentAppRole.Value)"]
            ServicePrincipalDisplayName                     = $currentServicePrincipalObject.DisplayName
            ServicePrincipalId                              = $currentServicePrincipalObject.Id
            ServicePrincipalType                            = $currentServicePrincipalObject.ServicePrincipalType
            ServicePrincipalEnabled                         = $currentServicePrincipalObject.AccountEnabled
            AppId                                           = $currentServicePrincipalObject.AppId
            AppSignInAudience                               = $currentServicePrincipalObject.SignInAudience
            AppOwnerOrganizationTenantId                    = $currentServicePrincipalObject.AppOwnerOrganizationId
            AppOwnerOrganizationTenantName                  = $currentAppOwnerOrgObject.DisplayName
            AppOwnerOrganizationTenantDomain                = $currentAppOwnerOrgObject.DefaultDomainName
            Resource                                        = $currentAppRoleAssignedTo.ResourceDisplayName
            AppRole                                         = $currentAppRole.Value
            AppRoleAssignedDate                             = $(if ($currentAppRoleAssignedTo.CreatedDateTime) { (Get-Date $currentAppRoleAssignedTo.CreatedDateTime -Format 'yyyy-MM-dd') })
            AppRoleName                                     = $currentAppRole.DisplayName
            AppRoleDescription                              = $currentAppRole.Description
            LastSignInActivity                              = $currentSpSigninActivity.LastSignInActivity.LastSignInDateTime
            DelegatedClientSignInActivity                   = $currentSpSigninActivity.DelegatedClientSignInActivity.LastSignInDateTime
            DelegatedResourceSignInActivity                 = $currentSpSigninActivity.DelegatedResourceSignInActivity.LastSignInDateTime
            ApplicationAuthenticationClientSignInActivity   = $currentSpSigninActivity.ApplicationAuthenticationClientSignInActivity.LastSignInDateTime
            ApplicationAuthenticationResourceSignInActivity = $currentSpSigninActivity.ApplicationAuthenticationResourceSignInActivity.LastSignInDateTime
        }
    }

    $msGraphAppRoleAssignedToReport
}
#endregion

#region Get-PrivilegedAppRoleAssignment
function Get-PrivilegedAppRoleAssignment {
    [CmdletBinding()]
    param (
        [switch]$ShowExplanation,
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $Explanation = @"

"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }
    $Output = Get-EntraIdPrivilegedAppRoleAssignment -ErrorAction SilentlyContinue -Verbose:$false
    # lots of properties. We need to reduce to make it fit in Markdown
    if ($OutputMarkdown.IsPresent) { $Output | Select-Object -Property @{ Name = 'Tier 0'; Expression = { $_.AppRoleTier -like "*Tier 0*" ? "Y" : "N" } }, @{ Name = 'AppRole'; Expression = { "$($_.AppRole) ($($_.AppRoleName))" } }, LastSignInActivity, ServicePrincipalDisplayName | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
}
#endregion

#region Test-ConditionalAccessPolicy
function Test-ConditionalAccessPolicy {
    param (
        [switch]$OutputMarkdown,
        [switch]$OutputToHost,
        [parameter(ParameterSetName = "BlockLegacyProtocols")][switch]$BlockLegacyProtocols,
        [parameter(ParameterSetName = "MfaAdministrators")][switch]$MfaAdministrators,
        [parameter(ParameterSetName = "MfaAzureManagement")][switch]$MfaAzureManagement,
        [parameter(ParameterSetName = "RestrictedLocations")][switch]$RestrictedLocations,
        [parameter(ParameterSetName = "DeviceCompliance")][switch]$DeviceCompliance
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $CompliantText = ''
    $NonCompliantText = 'No valid CA Policy found'
    $Output = [pscustomobject] @{}
    ## BLOCK LEGACY PROTOCOLS ##
    if ($BlockLegacyProtocols.IsPresent) {
        # we are looking for a policy that is enabled, the control is block, includes all users, and condition is legacy clients
        $Filter = "state eq 'enabled' and grantControls/builtInControls/all(i:i eq 'block') and conditions/users/includeUsers/all(i:i eq 'All') and conditions/clientAppTypes/all(i:i eq 'exchangeActiveSync' or i eq 'other')"
        # need to use the beta API as v1.0 does not include policies made from templates
        $BlockLegacyProtocolPolicy = Get-MgBetaIdentityConditionalAccessPolicy -Filter $Filter

        # $BlockLegacyProtocolPolicy | Select-Object -Property DisplayName, Id

        $ExcludeUsers = $BlockLegacyProtocolPolicy.Conditions.Users.ExcludeUsers
        # $ExcludeGroups = $BlockLegacyProtocolPolicy.Conditions.Users.ExcludeGroups
        # $ExcludeGuestsOrExternalUsers = $BlockLegacyProtocolPolicy.Conditions.Users.ExcludeGuestsOrExternalUsers

        # TODO:
        # $ExcludeGroups
        # $ExcludeGuestsOrExternalUsers

        $Compliant = $null -ne $BlockLegacyProtocolPolicy -and $BlockLegacyProtocolPolicy.Count -gt 0
        $CompliantText = 'CA Policy found blocking legacy protocols'
        $NonCompliantText = 'No valid CA Policy found blocking legacy protocols'
    } # end if ($BlockLegacyProtocols.IsPresent)

    ## MFA FOR ADMINISTRATORS ##
    if ($MfaAdministrators.IsPresent) {
        # we are looking for a policy that is enabled, the control is MFA or authentication strenght, includes specific roles, and includes all applications
        $PrivilegedRolesList = "('62e90394-69f5-4237-9190-012177145e10','194ae4cb-b126-40b2-bd5b-6091b380977d','f28a1f50-f6e7-4571-818b-6a12f2af6b6c','29232cdf-9323-42fd-ade2-1d097af3e4de','b1be1c3e-b65d-4f19-8427-f6fa0d97feb9','729827e3-9c14-49f7-bb1b-9608f156bbb8','b0f54661-2d74-4c50-afa3-1ec803f12efe','fe930be7-5e62-47db-91af-98c3a49a38b1','c4e39bd9-1100-46d3-8c65-fb160da0071f','9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3','158c047a-c907-4556-b7ef-446551a6b5f7','966707d0-3269-4727-9be2-8c3a10f19b9d','7be44c8a-adaf-4e2a-84d6-ab2649e08a13','e8611ab8-c189-46e8-94e1-60213ab1f814')"
        # cannot filter on authenticationStrength: Invalid $filter: navigation property 'authenticationStrength' not found on type 'microsoft.graph.conditionalAccessPolicy'.
        # we will do this when checking if the policy is compliant
        $Filter = "state eq 'enabled' and conditions/applications/includeApplications/all(i:i eq 'All') and conditions/users/includeRoles/`$count gt 0 and conditions/users/includeRoles/all(i:i in $PrivilegedRolesList)" # and (grantControls/builtInControls/all(i:i eq 'mfa') or grantControls/authenticationStrength ne null)
        # need to use the beta API as v1.0 does not include policies made from templates
        $RequireMfaAdminsPolicy = Get-MgBetaIdentityConditionalAccessPolicy -Filter $Filter

        # $RequireMfaAdminsPolicy | Select-Object -Property DisplayName, Id

        $ExcludeUsers = $RequireMfaAdminsPolicy.Conditions.Users.ExcludeUsers
        # $ExcludeGroups = $RequireMfaAdminsPolicy.Conditions.Users.ExcludeGroups
        # $ExcludeGuestsOrExternalUsers = $RequireMfaAdminsPolicy.Conditions.Users.ExcludeGuestsOrExternalUsers

        # TODO:
        # $ExcludeGroups
        # $ExcludeGuestsOrExternalUsers

        if ($RequireMfaAdminsPolicy.Count -gt 1) {
            # $Compliant will become $false as we expect a single policy
            Write-Warning "Found multiple matching CA policies:`n$($RequireMfaAdminsPolicy.DisplayName -join ',')"
        }
        $Compliant = $null -ne $RequireMfaAdminsPolicy -and $RequireMfaAdminsPolicy.Count -eq 1 -and ('mfa' -in $RequireMfaAdminsPolicy.GrantControls.builtInControls -or $RequireMfaAdminsPolicy.GrantControls.authenticationStrength.requirementsSatisfied -eq 'mfa')
        $CompliantText = 'CA Policy found that requires administrators to use MFA or better'
        $NonCompliantText = 'No valid CA Policy found targeting Azure administrators'
    } # end if ($MfaAdministrators.IsPresent)

    ## ## MFA FOR AZURE MANAGEMENT ##
    if ($MfaAzureManagement.IsPresent) {
        # we are looking for a policy that is enabled, the control is MFA or authentication strenght, targeting application "Microsoft Azure Management"
        # cannot filter on authenticationStrength: Invalid $filter: navigation property 'authenticationStrength' not found on type 'microsoft.graph.conditionalAccessPolicy'.
        # we will do this when checking if the policy is compliant
        $Filter = "state eq 'enabled' and conditions/applications/includeApplications/all(i:i eq '797f4846-ba00-4fd7-ba43-dac1f8f63013') and conditions/users/includeRoles/`$count gt 0 and conditions/users/includeUsers/all(i:i eq 'All')" # and (grantControls/builtInControls/all(i:i eq 'mfa') or grantControls/authenticationStrength ne null)
        # need to use the beta API as v1.0 does not include policies made from templates
        $RequireMfaAdminsPolicy = Get-MgBetaIdentityConditionalAccessPolicy -Filter $Filter

        # $RequireMfaAdminsPolicy | Select-Object -Property DisplayName, Id

        $ExcludeUsers = $RequireMfaAdminsPolicy.Conditions.Users.ExcludeUsers
        # $ExcludeGroups = $RequireMfaAdminsPolicy.Conditions.Users.ExcludeGroups
        # $ExcludeGuestsOrExternalUsers = $RequireMfaAdminsPolicy.Conditions.Users.ExcludeGuestsOrExternalUsers

        # TODO:
        # $ExcludeGroups
        # $ExcludeGuestsOrExternalUsers

        if ($RequireMfaAdminsPolicy.Count -gt 1) {
            # $Compliant will become $false as we expect a single policy
            Write-Warning "Found multiple matching CA policies"
        }
        $Compliant = $null -ne $RequireMfaAdminsPolicy -and $RequireMfaAdminsPolicy.Count -eq 1 -and ('mfa' -in $RequireMfaAdminsPolicy.GrantControls.builtInControls -or $RequireMfaAdminsPolicy.GrantControls.authenticationStrength.requirementsSatisfied -eq 'mfa')
        $CompliantText = 'CA Policy found that requires MFA or better to use "Microsoft Azure Management"'
    }

    ## RESTRICTED LOCATIONS ##
    if ($RestrictedLocations.IsPresent) {
        # check if any named locations exist
        $NamedLocation = Get-MgBetaIdentityConditionalAccessNamedLocation

        $Compliant = $null -ne $NamedLocation -and $NamedLocation.Count -gt 0
        $CompliantText = "$($NamedLocation.Count) Named Locations are defined"
        $NonCompliantText = 'No Named Locations are defined'

        # we can look for policies that excludes locations under conditions but exclude those that block access
        $Filter = "state eq 'enabled' and conditions/locations/excludeLocations/all(i:i ne null) and grantControls/builtInControls/all(i:i ne 'block')"
        # need to use the beta API as v1.0 does not include policies made from templates
        $PoliciesLocationExclusion = Get-MgBetaIdentityConditionalAccessPolicy -Filter $Filter

        if ($PoliciesLocationExclusion.Count -gt 0) {
            Write-Warning "$($PoliciesLocationExclusion.Count) policies has location exclusions:"
            $Output = $PoliciesLocationExclusion | Select-Object -Property DisplayName, Id
        }
    }

    ## DEVICE COMPLIANCE ##
    if ($DeviceCompliance.IsPresent) {
        # we are looking for a policy that is enabled, the control is require device to be marked as compliant
        $Filter = "state eq 'enabled' and grantControls/builtInControls/`$count gt 0 and grantControls/builtInControls/all(i:i eq 'compliantDevice')"
        # need to use the beta API as v1.0 does not include policies made from templates
        $CompliantDevicePolicy = Get-MgBetaIdentityConditionalAccessPolicy -Filter $Filter

        # $CompliantDevicePolicy | Select-Object -Property DisplayName, Id

        $ExcludeUsers = $CompliantDevicePolicy.Conditions.Users.ExcludeUsers
        # $ExcludeGroups = $CompliantDevicePolicy.Conditions.Users.ExcludeGroups
        # $ExcludeGuestsOrExternalUsers = $CompliantDevicePolicy.Conditions.Users.ExcludeGuestsOrExternalUsers

        # TODO:
        # $ExcludeGroups
        # $ExcludeGuestsOrExternalUsers

        $Compliant = $null -ne $CompliantDevicePolicy -and $CompliantDevicePolicy.Count -gt 0
        $CompliantText = "CA Policy found that requires devices to be marked as compliant:`n$($CompliantDevicePolicy.DisplayName -join ',')"
    }

    # Output for use in markdown
    $Output = [pscustomobject] @{
        "Policy compliance" = $Compliant ? $CompliantText : $NonCompliantText
    }

    if ($OutputToHost.IsPresent) {
        if ($Compliant) {
            Write-Host "Compliant to control; $CompliantText" -ForegroundColor Green
            # only makes sense to show if the policy is compliant
            $ExcludeUsers | Where-Object { $null -ne $_ } | ForEach-Object {
                $ExcludedUser = Get-MgUser -Filter "id eq '$_'"
                Write-Host "Excluded user: $($ExcludedUser.DisplayName) ($($ExcludedUser.UserPrincipalName))"
            }        
        }
        else {
            Write-Host "Not compliant to control; $NonCompliantText" -ForegroundColor Red
        }
    }
    if ($OutputMarkdown.IsPresent) { 
        $Output | ConvertTo-Markdown 
        # only makes sense to show excluded users if the policy is compliant
        if ($Compliant) {
            $ExcludeUsers | Where-Object { $null -ne $_ } | ForEach-Object {
                $ExcludedUser = Get-MgUser -Filter "id eq '$_'"
                [pscustomobject] @{
                    "Excluded user" = "$($ExcludedUser.DisplayName) ($($ExcludedUser.UserPrincipalName))"
                }
            } | ConvertTo-Markdown      
        }
    }
    else { $Output | Format-Table -AutoSize }
}
#endregion

#region Test-ProtectedAction
function Test-ProtectedAction {
    [CmdletBinding()]
    param (
        [switch]$ShowExplanation
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $Explanation = @"

"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }

    # look for protected actions with an authentication context
    # Get-MgBetaRoleManagementDirectoryResourceNamespaceResourceAction seems broken. what is UnifiedRbacResourceNamespaceId
    $Response = Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/roleManagement/directory/resourceNamespaces/microsoft.directory/resourceActions?`$filter=isAuthenticationContextSettable eq true and authenticationContextId ne null&`$select=id,name,description,actionVerb,isEnabledForCustomRole,isAuthenticationContextSettable,authenticationContextId&`$top=500" -ErrorAction Stop
    # first we check if any protected actions are defined at all
    $ProtectedActions = $Response.value
    if ($ProtectedActions.Count -eq 0) {
        Write-Warning "No protected actions defined"
        return
    }
    # get all possible protected actions
    $Response = Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/roleManagement/directory/resourceNamespaces/microsoft.directory/resourceActions?`$filter=isAuthenticationContextSettable eq true&`$select=id" -ErrorAction Stop
    Write-Host "$($ProtectedActions.Count) of $($Response.value.Count) protected actions are associated with an authentication context"

    $authenticationContextIds = ($ProtectedActions | Select-Object -ExpandProperty authenticationContextId) | Sort-Object -Unique
    # next we find if these are in use in any CA Policy
    $FilterArray = ($authenticationContextIds | ForEach-Object { "'$_'" }) -join ','
    $Filter = "state eq 'enabled' and grantControls/builtInControls/`$count gt 0 and conditions/applications/includeAuthenticationContextClassReferences/`$count gt 0 and conditions/applications/includeAuthenticationContextClassReferences/all(i:i in ($FilterArray))" 
    # need to use the beta API as v1.0 does not include policies made from templates
    $CompliantDevicePolicy = Get-MgBetaIdentityConditionalAccessPolicy -Filter $Filter
    if ($CompliantDevicePolicy.Count -eq 0) {
        Write-Warning "No CA policy uses the authentication context associated with a protected action"
    }
    else {
        # TODO: specify which action is protected by which policy. Most likely that they are all protected by a single policy, so not that important.
        Write-Host "Protected actions: $(($ProtectedActions | Select-Object -ExpandProperty description) -join ',') are protected by CA policies: $(($CompliantDevicePolicy | Select-Object -ExpandProperty DisplayName) -join ',')"
    }    
}
#endregion

#region Test-EntraIdDiagnosticSetting
<#
run either of these using an account that has enabled "Access management for Azure resources" in Entra ID properties (requires Global Administrator)
easiest way to do this is to run it from a cloud shell

New-AzRoleAssignment -ObjectId "<enterprise application object id>" -Scope "/providers/Microsoft.aadiam" -RoleDefinitionName 'Contributor' -ObjectType 'ServicePrincipal'
az role assignment create --assignee-principal-type  ServicePrincipal --assignee-object-id '<enterprise application object id>' --scope "/providers/Microsoft.aadiam" --role 'b24988ac-6180-42a0-ab88-20f7382dd24c'
#>
function Test-EntraIdDiagnosticSetting {
    [CmdletBinding()]
    param (
        [switch]$ShowExplanation,
        [switch]$OutputMarkdown
    )
    Write-Verbose "Running command: $($MyInvocation.MyCommand)"

    $Explanation = @"
Entra ID should export diagnostic logs to a Log Analytics workspace. This is a best practice to ensure that you can monitor and alert on the logs.
"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }

    # Retrieve all diagnostic settings from Entra ID #

    # looks to be no builtin cmdlet for this, so we need to use the REST API

    # Generate an access token for the management API
    $accessToken = (Get-AzAccessToken -ResourceUrl "https://management.azure.com" -TenantId $Global:TenantId -AsSecureString -WarningAction SilentlyContinue).Token
    
    # $accessToken = (Get-AzAccessToken -ResourceUrl "https://management.azure.com" -TenantId '690e25b4-8c5e-4a10-a32e-523da88a4c99' -AsSecureString -WarningAction SilentlyContinue).Token

    # Set the API endpoint 
    $apiEndpoint = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview"
    
    # Set the headers for the API call
    $headers = @{
        "Authorization" = "Bearer $(ConvertFrom-SecureString $accessToken -AsPlainText)"
        "Content-Type" = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $apiEndpoint -Headers $headers -Method Get -ErrorAction Stop        
    }
    catch {
        Write-Warning "Failed to retrieve diagnostic settings from Entra ID. Be sure to have granted the necessary permissions to the service principal"
    }

    $diagnosticSettings = $response.value
    foreach ($diagnosticSetting in $diagnosticSettings) {        
        $properties = ($diagnosticSetting | Select-Object -Property name, properties).properties
        $logs = $properties.logs
        $Output = [PSCustomObject][Ordered]@{
            "Diagnostics settings name"         = $diagnosticSetting.name
            "Exporting to workspace" = $null -ne $properties.workspaceId
            "Exporting audit logs" = $logs | Where-Object { $_.category -eq 'AuditLogs' } | Select-Object -ExpandProperty enabled
            "Exporting Signin logs" = $logs | Where-Object { $_.category -eq 'SignInLogs' } | Select-Object -ExpandProperty enabled
        }

        if ($OutputMarkdown) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
    }
}
#endregion

#region Write-EntraIdAssessment
<#
This is the pure powershell based Entra ID assessment. It will strongly correlate to the experience in entra-id.ipynb (Notebook)
#>
function Write-EntraIdAssessment {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$OutputFolder = ".\",
        [SecureString]$AccessToken = $null,
        [string]$StorageAccountName = $null,
        [string]$StorageAccountTenantId = $null,
        [string]$ContainerName = "entra-id"
    )

    Initialize-Notebook -TenantId $TenantId -AccessToken $AccessToken   

    #region Markdown here-string
    $Markdown = @"
# Entra ID Review for tenant $TenantId

## Users

### User States

Count the total number of users, disabled users, deleted users, and guest users.

$((Get-UserState -OutputMarkdown) -join "`n")

### Disabled Users

Find disabled users with group memberships or roles or licenses assigned.

Disabled users should not have roles or licenses assigned, and group memberships should at least be reviewed. 

$((Get-DisabledUser -IncludeLicenseDetails -OutputMarkdown) -join "`n")

$((Get-DisabledUser -IncludeGroupMemberships -OutputMarkdown) -join "`n")

## Privileged Administration

### Limit the number of Global Administrators to less than 5

*Severity*: High

*Guid*: 9e6efe9d-f28f-463b-9bff-b5080173e9fe

[Entra ID best practice](https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices#5-limit-the-number-of-global-administrators-to-less-than-5)

*As a best practice, Microsoft recommends that you assign the Global Administrator role to fewer than five people in your organization...*

Global Administrators:

$((Get-GlobalAdminstrator -OutputMarkdown) -join "`n")

### Synchronized accounts

*Severity*: High

*Guid*: 87791be1-1eb0-48ed-8003-ad9bcf241b99

Do not synchronize accounts with the highest privilege access to on-premises resources as you synchronize your enterprise identity systems with cloud directories.

If below list any users then `onPremisesSyncEnabled` is true (and their account is enabled). Those should have the role removed, and a cloud-only user created as a replacement.

[Entra ID best practice](https://learn.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices#centralize-identity-management)

*Do not synchronize accounts to Azure AD that have high privileges in your existing Active Directory instance...*

$((Get-SynchronizedAccount -OutputMarkdown) -join "`n")

### Use groups for Entra ID role assignments

*Work in Progress*

For now we can check the *Membership* column in [Privileged Identity Management | Azure AD roles](https://portal.azure.com/?feature.msaljs=true#view/Microsoft_Azure_PIMCommon/ResourceMenuBlade/~/members/resourceId//resourceType/tenant/provider/aadroles)

*Severity*: High

*Guid*: e0d968d3-87f6-41fb-a4f9-d852f1673f4c

[Best Practice: Use groups for Microsoft Entra role assignments and delegate the role assignment](https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices#7-use-groups-for-microsoft-entra-role-assignments-and-delegate-the-role-assignment)

*If you have an external governance system that takes advantage of groups, then you should consider assigning roles to Microsoft Entra groups, instead of individual users....*

<!-- Get-GroupsWithRoleAssignment -OutputMarkdown # WiP -->

### PIM Alerts

*Severity*: High

*Guid*: N/A

There should be no active alerts in PIM. If below identifies any active alerts go to [PIM alerts](https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ResourceMenuBlade/~/Alerts/resourceId//resourceType/tenant/provider/aadroles) for further details.

$((Get-PimAlert -OutputMarkdown) -join "`n")

We can also list affected principals. Note that in some cases there is no direct principal, ex. for the alert `NoMfaOnRoleActivationAlert`

$((Get-PimAlertAffectedPrincipal -OutputMarkdown) -join "`n")

### Recurring access reviews

*Severity*: High

*Guid*: eae64d01-0d3a-4ae1-a89d-cc1c2ad3888f

Configure recurring access reviews to revoke unneeded permissions over time.

[Best Practice: Configure recurring access reviews to revoke unneeded permissions over time](https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices#4-configure-recurring-access-reviews-to-revoke-unneeded-permissions-over-time)

If there are no access review definitions then there are no recurring access reviews.

$((Get-RecurringAccessReview -OutputMarkdown) -join "`n")

### Access Reviews: Enabled for all groups

*Severity*: Medium

*Guid*: e6b4bed3-d5f3-4547-a134-7dc56028a71f

[Plan a Microsoft Entra access reviews deployment](https://learn.microsoft.com/en-us/azure/active-directory/governance/deploy-access-reviews)

<!-- no code yet -->

### Apps and Owners Can Change All Group Membership

*Work in Progress*

Chad Cox: Group Membership changes to all groups, this script list every role and member (not pim eligible) with this capability , every application with the permission, and every owner of the application. Some of the permissions are to unified and some are to security. either way can you imagine if someone granted access to a group that gave them all kinds of access to teams sites or access to other cloud resources.

https://www.linkedin.com/posts/chad-cox-194bb560_entraid-aad-azuread-activity-7093368251329495040-Ff9T

https://github.com/chadmcox/Azure_Active_Directory/blob/master/Applications/get-AppsandOwnersCanChangeAllGroupMembership.ps1

TODO: does not show the display name for Owners of relevant apps

$((Test-AppOwnersChangeGroupMembership -OutputMarkdown) -join "`n")

### Avoid standing access for user accounts and permissions

*Work in Progress*

[MCSB: PA-2: Avoid standing access for user accounts and permissions](https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-2-avoid-standing-access-for-user-accounts-and-permissions)

$((Test-StandingAccess -OutputMarkdown) -join "`n")

## External Identities

### Guest invite settings

*Severity*: High

*Guid*: be64dd7d-f2e8-4bbb-a468-155abc9164e9

External Collaboration Settings: Guest invite settings set to `'Only users assigned to specific admin roles can invite guest users'` or `'No one in the organization can invite guest users including admins (most restrictive)'`

$((Test-GuestInviteSetting -OutputMarkdown) -join "`n")

### Guest user access restrictions

*Work in Progress*

*Severity*: High

*Guid*: 459c373e-7ed7-4162-9b37-5a917ecbe48f

External Collaboration Settings: Guest user access set to `'Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)'`

<!-- code is work in progress -->

## User Setting

### User role permissions (Application registration)

*Severity*: High

*Guid*: a2cf2149-d013-4a92-9ce5-74dccbd8ac2a

Users can register applications should be set to `No`.

Users should not be allowed to register applications. Use specific roles such as `Application Developer`.

$((Test-UsersCanRegisterApplication -OutputMarkdown) -join "`n")

### Authentication Methods

*Work in Progress*

Check if authentication method policies are enabled or not

check if migration has already been done, and if not, can we check if the methods in the different places are enabled in the policy

<!-- code is work in progress -->

## Custom Domains

### Verified Domains

*Severity*: High

*Guid*: bade4aad-1e8c-439e-a946-667313c00567

Only validated customer domains are registered

$((Test-VerifiedDomain -OutputMarkdown) -join "`n")

## Enterprise Applications

### User consent for apps

*Severity*: Medium

*Guid*: 459c373e-7ed7-4162-9b37-5a917ecbe48f

Consent & Permissions: Allow user consent for apps from verified publishers

[Configure how users consent to applications](https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?pivots=ms-graph)

$((Test-UserConsentForApp -OutputMarkdown) -join "`n")

###  Group Owner Consent

*Work in Progress*

*Severity*: Medium

*Guid*: 909aed8c-44cf-43b2-a381-8bafa2cf2149

Consent & Permissions: Allow group owner consent for selected group owners 

[Configure group owner consent to applications](https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent-groups?tabs=azure-portal)

<!-- code is work in progress -->

###  Application Owners

*Severity*: High

*Guid*: N/A

MITRE ATT&CK tactics: [Persistence](https://attack.mitre.org/tactics/TA0003/), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)

Credit: [Chad Cox](https://github.com/chadmcox) / [Applications/get-BuiltinAPPOwners.ps1](https://github.com/chadmcox/Azure_Active_Directory/blob/master/Applications/get-BuiltinAPPOwners.ps1)

Read here how these can be exploited: [Azure AD privilege escalation - Taking over default application permissions as Application Admin](https://dirkjanm.io/azure-ad-privilege-escalation-application-admin/) - Note that the Owner of the service principal can exploit this in the same way, hence why we look for owners.

Below code snippets look for various applications that are at an increased risk from having owners. 

$((Find-OwnersFirstPartyMicrosoftApplication -OutputMarkdown) -join "`n")

Look for applications with application permission in Microsoft Graph and 1 or more owners assigned. Application permissions are often medium-high risk permissions.

$((Find-ApplicationsWithApplicationPermissionsAndOwner -OutputMarkdown) -join "`n")

Look for applications with owners and any resource access that we do not consider low-risk. The applications listed below is worth looking into.

These permissions are considered low risk:

$((Show-LowRiskApplicationPermission -OutputMarkdown) -join "`n")

Look for applications with owners and any resource access that we do not consider low-risk. 

$((Find-ApplicationsNonLowRiskPermissionsAndOwner -OutputMarkdown) -join "`n")

### Applications with privileged app role assignments

All credit goes to [What's lurking in your Microsoft Graph app role assignments?](https://learningbydoing.cloud/blog/audit-ms-graph-app-role-assignments/)

$((Get-PrivilegedAppRoleAssignment -OutputMarkdown) -join "`n")

## Conditional Access Policies

### Block Legacy Protocols

*Severity*: High

*Guid*: 9e6efe9d-f28f-463b-9bff-b5080173e9fe

[Common Conditional Access policy: Block legacy authentication](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-block-legacy)

This policy, along with policies that enforce MFA are the most important to have. Legacy authentication will de-facto bypass MFA.

Below looks for a conditional access policy that blocks legacy protocols and also outputs users excluded.

$((Test-ConditionalAccessPolicy -BlockLegacyProtocols -OutputMarkdown) -join "`n")

## Require MFA for Administrators

*Severity*: High

*Guid*: fe1bd15d-d2f0-4d5e-972d-41e3611cc57b

[Common Conditional Access policy: Require MFA for administrators](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-admin-mfa)

Below looks for a conditional access policy that matches the policy template `"Require multifactor authentication for admins"`

$((Test-ConditionalAccessPolicy -MfaAdministrators -OutputMarkdown) -join "`n")

## Require MFA for Azure Management

*Severity*: High

*Guid*: 4a4b1410-d439-4589-ac22-89b3d6b57cfc

[Common Conditional Access policy: Require MFA for Azure management](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-azure-management)

Below looks for a conditional access policy that matches the policy template `"Require multifactor authentication for Azure management"`

$((Test-ConditionalAccessPolicy -MfaAzureManagement -OutputMarkdown) -join "`n")

## Restricted Locations

*Severity*: Medium

*Guid*: 079b588d-efc4-4972-ac3c-d21bf77036e5

[Using the location condition in a Conditional Access policy](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/location-condition)

Named locations can be used in numerous different way. A bad way to use them is to exclude from ex. enforcing MFA when coming from a `"trusted location"`. This does not conform to a `zero trust strategy`.

$((Test-ConditionalAccessPolicy -RestrictedLocations -OutputMarkdown) -join "`n")

## Require devices to be marked as compliant

*Severity*: High

*Guid*: 7ae9eab4-0fd3-4290-998b-c178bdc5a06c

[Require device to be marked as compliant](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-grant#require-device-to-be-marked-as-compliant)

Requiring devices to be marked as compliant in CA policy grants can be a powerful way of ensuring that connections are made from devices that are managed by the organization. With sufficiently strict device configurations enforced, this can be combined with MFA, or just a standalone grant.

$((Test-ConditionalAccessPolicy -DeviceCompliance -OutputMarkdown) -join "`n")

## Protected Actions

Use [Protected Actions](https://learn.microsoft.com/en-us/azure/active-directory/roles/protected-actions-overview) to enforce strong authentcation and other strict grant controls when performing highly privileged actions, like `Delete conditional access policies`.

$((Test-ProtectedAction) -join "`n")

## Entra ID Diagnostic Settings

Entra ID should export diagnostic logs to a Log Analytics workspace. This is a best practice to ensure that you can monitor and alert on the logs.

The most important logs to export are audit and signin logs. These should be considered bare minimum, but only export logs that you will use.

Below does not reflect logs exported to Event hub (common for SIEM) or storage account (common for long-term storage).

$((Test-EntraIdDiagnosticSetting -OutputMarkdown) -join "`n")
"@
    #endregion

    $FileName = "entra-id-$TenantId.md"
    $FilePath = "$OutputFolder\$FileName"
    $Markdown | Out-File -FilePath $FilePath
    Write-Verbose "Saved to $FilePath"

    # upload to Azure Blob Storage
    if ($null -ne $StorageAccountName -and $null -ne $StorageAccountTenantId) {
        # Blob name is the same as the file name
        $BlobName = $FileName
        Write-Verbose "Uploading to Azure Blob Storage: $StorageAccountName/$ContainerName/$BlobName"
        # switch to the storage account tenant
        $null = Set-AzContext -TenantId $StorageAccountTenantId
        # create storage context with OAuth (Microsoft Entra ID) Authentication
        $StorageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount -ErrorAction Stop
        # create container if not exist
        $Container = Get-AzStorageContainer -Name $ContainerName -Context $StorageContext -ErrorAction SilentlyContinue
        if ($null -eq $Container) {
            $Container = New-AzStorageContainer -Name $ContainerName -Context $StorageContext
        }
        # upload file
        $null = Set-AzStorageBlobContent -Container $ContainerName -File $FilePath -Blob $BlobName -Context $StorageContext -Force -ErrorAction Stop
        Write-Verbose "Uploaded to Azure Blob Storage!"
    }
}
#endregion