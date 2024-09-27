
Import-Module "$PSScriptRoot\identity.psm1"

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

#region Get-GroupMembers
function Get-GroupMembers {
    [CmdletBinding()]
    param (
        [array]$DirectoryObjectByIds,
        $DebugMode = $false
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
            Get-GroupMembers -DirectoryObjectByIds (Get-MgGroupMember -GroupId $_.Id | Select-Object -ExpandProperty Id)
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
    $Assigned = Get-GroupMembers -DirectoryObjectByIds $AssignedPrincipals | Sort-Object -Unique -Property Id
    Write-Verbose "Found $($Assigned.Count) assigned user principals"
    if (-not $ExcludeEligebleRoles.IsPresent) {
        $Filter = "roleDefinitionId eq '$DirectoryRoleDefinitionId'"
        # get principals that are eligble for the role
        [array]$EligeblePrincipals = Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance -Filter $Filter | Select-Object -ExpandProperty PrincipalId
        Write-Verbose "Found $($EligeblePrincipals.Count) eligeble principals"
        # recursively get group members
        [array]$Eligeble = Get-GroupMembers -DirectoryObjectByIds $EligeblePrincipals
        Write-Verbose "Found $($Assigned.Count) eligeble user principals"
    }
    # sort unique to remove duplicates (eligble and assigned)
    $Assigned + $Eligeble | Sort-Object -Unique -Property Id
}
#endregion

#region Get-PrivilegedAdministratorRoleAssignments
function Get-PrivilegedAdministratorRoleAssignments {
    [CmdletBinding()]
    param (
        $TenantId,
        $SubscriptionId, # TODO: only using in set-azcontext
        $ManagementGroupId
    )
    
    function Get-GroupMembers {
        [CmdletBinding()]
        param (
            [array]$DirectoryObjectByIds,
            $DebugMode = $false
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
                Get-GroupMembers -DirectoryObjectByIds (Get-MgGroupMember -GroupId $_.Id | Select-Object -ExpandProperty Id)
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
    
    function Get-PrivilegedUsers {
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
        [array]$GroupMembers = Get-GroupMembers -DirectoryObjectByIds $Groups.Id | Select-Object -ExpandProperty Id
    
        [array]$Users = $GroupMembers + ($PrivilegedRBAC | Where-Object { $_.roleAssignmentPrincipalType -eq 'User' }).roleAssignmentPrincipalId | Sort-Object -Unique
        if ($Users.Count -gt 0) {
            # TODO: chunks of 15 as this is the max allowed
            $Users = $Users | Select-Object -First 15
            $Filter = "Id in ($(($Users | ForEach-Object { "'$_'" }) -join ','))"
            $Users = Get-MgUser -Filter $Filter
            $Users | ForEach-Object {
                $UserId = $_.Id
                $_ | Add-Member -MemberType NoteProperty -Name Role -Value $Role -PassThru -Force
            } |  Select-Object -Property DisplayName, Role
        }
    }
    
    # this will check if already connected, so we can run this multiple times
    Connect-MgGraph -TenantId $TenantId -UseDeviceCode -Scopes 'User.Read.All', 'Group.Read.All'
    $Token = ConvertTo-SecureString -String (Get-AzAccessToken -TenantId $TenantId).Token -Force -AsPlainText
    $GetPrivilegedUsersParams = @{Token = $Token; ManagementGroupId = $ManagementGroupId }
    Write-Host "Privileged role assignments at '$ManagementGroupId'"
    
    Get-PrivilegedUsers -Role 'Owner' @GetPrivilegedUsersParams
    
    Get-PrivilegedUsers -Role 'Contributor' @GetPrivilegedUsersParams
    
    Get-PrivilegedUsers -Role 'User Access Administrator' @GetPrivilegedUsersParams
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

            $item.PSObject.Properties | % {
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

#region Get-EntraIDApplicationInsights
function Get-EntraIDApplicationInsights {
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
        $Scopes = @("Directory.AccessAsUser.All", "Policy.Read.All", "RoleManagement.Read.Directory", "RoleManagementAlert.Read.Directory", "AccessReview.Read.All", "Application.Read.All", "Directory.Read.All", "AuditLog.Read.All", "CrossTenantInformation.ReadBasic.All")
    )
    
    # these scopes are added automatically. To avoid a difference when comparing scopes we add them now
    $Scopes = $Scopes + @('profile','openid','User.Read','email') | Sort-Object -Unique
    $TenantId = $Global:TenantId = if($null -eq $TenantId){ Read-Host -Prompt "Enter tenant ID" } else { $TenantId }

    # TODO: write a warning if any scope is a write scope

    # connect once for all necessary scopes for this notebook - these are delegated permissions so we cannot do something the authenticated user could not already do!
    # This means that 'Microsoft Graph Command Line Tools' must be approved by a Global Administrator
    # use Get-MgContext to check if we need to connect again
    $MgContext = Get-MgContext
    $AlreadyConnected = $null -eq $MgContext -or $MgContext.TenantId -ne $TenantId -or $null -ne (Compare-Object -ReferenceObject $MgContext.Scopes -DifferenceObject $Scopes)
    if ($AlreadyConnected) {
        $null = Connect-MgGraph -Scopes $Scopes -TenantId $TenantId -ContextScope Process -ErrorAction Stop -NoWelcome
    }
    else {
        Write-Verbose "Already connected to tenant '$TenantId' with the following scope: $($MgContext.Scopes)"
    }

    Write-Host "Connected to tenant '$TenantId' with the following scope: $Scopes"
    $null = Set-AzContext -TenantId $TenantId -ErrorAction Stop -WarningAction SilentlyContinue
}
#endregion