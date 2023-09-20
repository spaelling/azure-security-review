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

function Get-EntraIdRoleAssignment {
    [CmdletBinding()]
    param (
        [string]$RoleName = $null,
        [switch]$ExcludeEligebleRoles
    )

    if ([string]::IsNullOrEmpty($RoleName)) {
        throw "Must supply a rolename"
    }

    # Get the role definition id
    $DirectoryRoleDefinitionId = Get-MgBetaRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$RoleName'" -Property "id" | Select-Object -ExpandProperty Id
    
    # only get those that are assigned
    $Filter = "roleDefinitionId eq '$DirectoryRoleDefinitionId' and AssignmentType eq 'Assigned'"
    [array]$AssignedPrincipals = Get-MgBetaRoleManagementDirectoryRoleAssignmentScheduleInstance -Filter $Filter | Select-Object -ExpandProperty PrincipalId
    # recursively get group members
    $Assigned = Get-GroupMembers -DirectoryObjectByIds $AssignedPrincipals | Sort-Object -Unique -Property Id
    if (-not $ExcludeEligebleRoles.IsPresent) {
        $Filter = "roleDefinitionId eq '$DirectoryRoleDefinitionId'"
        # get principals that are eligble for the role
        [array]$EligeblePrincipals = Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance -Filter $Filter | Select-Object -ExpandProperty PrincipalId
        # recursively get group members
        [array]$Eligeble = Get-GroupMembers -DirectoryObjectByIds $EligeblePrincipals
    }
    # sort unique to remove duplicates (eligble and assigned)
    $Assigned + $Eligeble | Sort-Object -Unique -Property Id
}

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
