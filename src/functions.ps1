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
        [string]$RoleName = $null
        # [string]$DirectoryRoleDefinitionId = $null
    )

    if ([string]::IsNullOrEmpty($RoleName)) {
        throw "Must supply a rolename"
    }

    # Get the directory role id
    # NOTE: The role must be activated in tenant for a successful response.
    $DirectoryRoleId = Get-MgDirectoryRole -Filter "DisplayName eq '$RoleName'" | Select-Object -ExpandProperty Id
    Write-Verbose "`$DirectoryRoleId = $DirectoryRoleId"
    # Get currently assigned
    $Assigned = $()
    if ($null -ne $DirectoryRoleId) {
        [array]$Assigned = Get-MgDirectoryRoleMember -DirectoryRoleId $DirectoryRoleId  
    }

    # Get the role definition id
    $DirectoryRoleDefinitionId = Get-MgBetaRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$RoleName'" -Property "id" | Select-Object -ExpandProperty Id
    
    # get principals that are eligble for the role
    [array]$EligeblePrincipals = Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance -Filter "roleDefinitionId eq '$DirectoryRoleDefinitionId'" | Select-Object -ExpandProperty PrincipalId
    # recursively get group members
    [array]$Eligeble = Get-GroupMembers -DirectoryObjectByIds $EligeblePrincipals
    # sort unique to remove duplicates (eligble and assigned)
    $Assigned + $Eligeble | Sort-Object -Unique -Property Id
}