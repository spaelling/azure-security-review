<#
functions used in the identity notebook.
#>

#region Get-UserStates
function Get-UserStates {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost
    )

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
        @{
            TotalUsers    = $TotalUsers
            DisabledUsers = $DisabledUsers
            GuestUsers    = $GuestUsers
            DeletedUsers  = $DeletedUsers
        }
    }
}
#endregion

#region Get-DisabledUsers
function Get-DisabledUsers {
    [CmdletBinding()]
    param (
        [switch]$IncludeLicenseDetails,
        [switch]$IncludeGroupMemberships,
        [switch]$OutputMarkdown
    )

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

#region Get-GlobalAdminstrators
function Get-GlobalAdminstrators {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown,
        [switch]$OutputToHost
    )
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

    Write-Host "`nGlobal Administrators:`n"
    $Output = $Setting | Select-Object -Property Id, @{ Name = 'Display Name'; Expression = { $_.AdditionalProperties.displayName } }, @{ Name = 'User Principal Name'; Expression = { $_.AdditionalProperties.userPrincipalName } }

    if ($OutputMarkdown.IsPresent) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
}
#endregion

#region Get-SynchronizedAccounts
function Get-SynchronizedAccounts {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown,
        [switch]$ShowProgress
    )
    $PrivilegedRolesList = @('62e90394-69f5-4237-9190-012177145e10', '194ae4cb-b126-40b2-bd5b-6091b380977d', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', '29232cdf-9323-42fd-ade2-1d097af3e4de', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', '729827e3-9c14-49f7-bb1b-9608f156bbb8', 'b0f54661-2d74-4c50-afa3-1ec803f12efe', 'fe930be7-5e62-47db-91af-98c3a49a38b1', 'c4e39bd9-1100-46d3-8c65-fb160da0071f', '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', '158c047a-c907-4556-b7ef-446551a6b5f7', '966707d0-3269-4727-9be2-8c3a10f19b9d', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', 'e8611ab8-c189-46e8-94e1-60213ab1f814')

    # TODO: check if there is any synchronized accounts at all

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

#region Get-GroupsWithRoleAssignments
function Get-GroupsWithRoleAssignments {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown
    )
    $RoleName = "Global Administrator"

    # Get the directory role id for $RoleName
    $DirectoryRoleId = Get-MgDirectoryRole -Filter "DisplayName eq '$RoleName'" | Select-Object -ExpandProperty Id
    # Get currently assigned
    $Assigned = Get-MgDirectoryRoleMember -DirectoryRoleId $DirectoryRoleId | Select-Object -ExpandProperty Id

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

#region Get-PimAlerts
function Get-PimAlerts {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown
    )
    $GovernanceRoleManagementAlerts = Get-MgBetaIdentityGovernanceRoleManagementAlert -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole' and isActive eq true" -ExpandProperty "alertDefinition,alertConfiguration,alertIncidents"

    $Output = $GovernanceRoleManagementAlerts | Select-Object -Property @{ Name = 'Alert'; Expression = { $_.alertDefinition.displayName } }, @{ Name = 'Incident Count'; Expression = { $_.IncidentCount } }

    if ($OutputMarkdown.IsPresent) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
}
#endregion

#region Get-PimAlertAffectedPrincipals
function Get-PimAlertAffectedPrincipals {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown
    )
    $GovernanceRoleManagementAlerts = Get-MgBetaIdentityGovernanceRoleManagementAlert -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole' and isActive eq true" -ExpandProperty "alertDefinition,alertConfiguration,alertIncidents"

    $Output = $GovernanceRoleManagementAlerts.alertIncidents.AdditionalProperties | Where-Object { $_.assigneeUserPrincipalName } | ForEach-Object {
        $_ | Select-Object -Property @{ Name = 'User'; Expression = { "$($_.assigneeDisplayName) ($($_.assigneeUserPrincipalName))" } }, @{ Name = 'Role'; Expression = { $_.roleDisplayName } }
    }

    if ($OutputMarkdown.IsPresent) { $Output | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
}
#endregion

#region Get-RecurringAccessReviews
function Get-RecurringAccessReviews {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown
    )
    $AccessReviewDefinitions = Get-MgBetaIdentityGovernanceAccessReviewDefinition

    Write-Host "Access review definitions: $(($AccessReviewDefinitions | Measure-Object).Count)"
}
#endregion

#region Get-AppOwnersChangeGroupMembership
function Test-AppOwnersChangeGroupMembership {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown
    )
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
        Get-MgBetaDirectoryRoleMember -DirectoryRoleId $_.Id | ForEach-Object { $_ | select -expandproperty AdditionalProperties | `
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
    # get permanent assignments of privileged Entra ID roles

    $PrivilegedRolesList = @('62e90394-69f5-4237-9190-012177145e10', '194ae4cb-b126-40b2-bd5b-6091b380977d', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', '29232cdf-9323-42fd-ade2-1d097af3e4de', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', '729827e3-9c14-49f7-bb1b-9608f156bbb8', 'b0f54661-2d74-4c50-afa3-1ec803f12efe', 'fe930be7-5e62-47db-91af-98c3a49a38b1', 'c4e39bd9-1100-46d3-8c65-fb160da0071f', '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', '158c047a-c907-4556-b7ef-446551a6b5f7', '966707d0-3269-4727-9be2-8c3a10f19b9d', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', 'e8611ab8-c189-46e8-94e1-60213ab1f814')
    . "..\src\functions.ps1"

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

#region Test-GuestInviteSettings
function Test-GuestInviteSettings {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost,
        [switch]$ShowExplanation
    )
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
}
#endregion

#region Test-GuestUserAccessRestrictions
function Test-GuestUserAccessRestrictions {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost,
        [switch]$ShowExplanation
    )
    $Explanation = @"
Compliant External Collaboration Settings: Guest user access set to 'Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)'
"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }
    Write-Warning "Work in progress - not yet implemented"; return
    # TODO: does not say anything about guest user access....

    $ExternalIdentityPolicy = Get-MgBetaPolicyExternalIdentityPolicy #-ExpandProperty "AdditionalProperties"

    # $ExternalIdentityPolicy | fl *
    # $ExternalIdentityPolicy.AdditionalProperties | fl *
}
#endregion

#region Test-UsersCanRegisterApplications
function Test-UsersCanRegisterApplications {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost,
        [switch]$ShowExplanation
    )
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
}
#endregion

#region Test-AuthenticationMethods
function Test-AuthenticationMethods {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost,
        [switch]$ShowExplanation
    )
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
    $Uri = 'https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=false'
    # token does not work for this endpoint. inspecting a working token the audience and appid is a guid
    
    # get methods from old MFA portal
    
    # compare with what is enabled
}
#endregion

#region Test-VerifiedDomains
function Test-VerifiedDomains {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost,
        [switch]$ShowExplanation
    )
    $Explanation = @"
Check that only validated customer domains are registered in the tenant.
"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }
    $Domains = Get-MgBetaDomain

    $UnverifiedDomains = $Domains | Where-Object { -not $_.IsVerified }

    $Setting = $UnverifiedDomains
    $Compliant = $Setting.Count -eq 0

    if ($OutputToHost.IsPresent) {
        if ($Compliant) {
            Write-Host "Compliant to control; All ($($Domains.Count)) domains are verified" -ForegroundColor Green
        }
        else {
            Write-Host "Not compliant to control; There are unverified domains registered: $($Setting | Select-Object -ExpandProperty Id)" -ForegroundColor Red
        }
    }
}
#endregion

#region Test-UserConsentForApps
function Test-UserConsentForApps {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost,
        [switch]$ShowExplanation
    )
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
}
#endregion

#region Test-GroupOwnerConsent
function Test-GroupOwnerConsent {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost,
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

#region Find-OwnersFirstPartyMicrosoftApplications
function Find-OwnersFirstPartyMicrosoftApplications {
    [CmdletBinding()]
    param (
        [switch]$OutputToHost,
        [switch]$ShowExplanation
    )
    $Explanation = @"
Owners of builtin applications can be exploited, see https://dirkjanm.io/azure-ad-privilege-escalation-application-admin/
"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }
    Get-MgBetaServicePrincipal -all -ExpandProperty owners | `
        # looking for first-party Microsoft applications with owners
        # TODO: convert to filter
    Where-Object { $_.PublisherName -like "*Microsoft*" -or !($_.PublisherName -eq "Microsoft Accounts") -and $_.AppOwnerOrganizationId -eq 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' } | `
        Where-Object { $_.owners -like "*" } | Select-Object appid, displayname, PublisherName, owners # TODO: look up owner

    # TODO: can we look for anyone who persisted access through one of these? 
}
#endregion

#region Find-ApplicationsWithApplicationPermissionsAndOwner
function Find-ApplicationsWithApplicationPermissionsAndOwner {
    [CmdletBinding()]
    param (
        [switch]$OutputMarkdown,
        [switch]$ShowExplanation
    )
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
        Write-Host "Found no applications with Owners" -ForegroundColor Green
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

#region Show-LowRiskApplicationPermissions
function Show-LowRiskApplicationPermissions {
    [CmdletBinding()]
    param (
        [switch]$ShowExplanation
    )
    $Explanation = @"
These permissions are considered low risk
"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }
    
    Find-MgGraphPermission -All | Where-Object { $_.Id -in $LowPermissions } # uncomment to list low-risk permissions
}
#endregion

#region Find-ApplicationsNonLowRiskPermissionsAndOwners
function Find-ApplicationsNonLowRiskPermissionsAndOwners {
    [CmdletBinding()]
    param (
        [switch]$ShowExplanation,
        [switch]$OutputMarkdown
    )
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
        Write-Host "Found no applications with Owners and above low-risk permissions" -ForegroundColor Green
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

#region Get-EntraIdPrivilegedAppRoleAssignments
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

function Get-EntraIdPrivilegedAppRoleAssignments {
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

#region Get-PrivilegedAppRoleAssignments
function Get-PrivilegedAppRoleAssignments {
    [CmdletBinding()]
    param (
        [switch]$ShowExplanation,
        [switch]$OutputMarkdown
    )
    $Explanation = @"

"@
    if ($ShowExplanation.IsPresent) {
        Write-Host $Explanation
    }
    $Output = Get-EntraIdPrivilegedAppRoleAssignments -ErrorAction Stop
    # lots of properties. We need to reduce to make it fit in Markdown
    if ($OutputMarkdown.IsPresent) { $Output | Select-Object -Property @{ Name = 'Tier 0'; Expression = { $_.AppRoleTier -like "*Tier 0*" ? "Y" : "N" } }, @{ Name = 'AppRole'; Expression = { "$($_.AppRole) ($($_.AppRoleName))" } }, LastSignInActivity, ServicePrincipalDisplayName | ConvertTo-Markdown } else { $Output | Format-Table -AutoSize }
}
#endregion

#region Test-ConditionalAccessPolicy
function Test-ConditionalAccessPolicy {
    param (
        [parameter(ParameterSetName = "BlockLegacyProtocols")][switch]$BlockLegacyProtocols,
        [parameter(ParameterSetName = "MfaAdministrators")][switch]$MfaAdministrators,
        [parameter(ParameterSetName = "MfaAzureManagement")][switch]$MfaAzureManagement
    )

    $CompliantText = ''
    $NonCompliantText = 'No valid CA Policy found'
    ## BLOCK LEGACY PROTOCOLS ##
    if ($BlockLegacyProtocols.IsPresent) {
        # we are looking for a policy that is enabled, the control is block, includes all users, and condition is legacy clients
        $Filter = "state eq 'enabled' and grantControls/builtInControls/all(i:i eq 'block') and conditions/users/includeUsers/all(i:i eq 'All') and conditions/clientAppTypes/all(i:i eq 'exchangeActiveSync' or i eq 'other')"
        # need to use the beta API as v1.0 does not include policies made from templates
        $BlockLegacyProtocolPolicy = Get-MgBetaIdentityConditionalAccessPolicy -Filter $Filter

        # $BlockLegacyProtocolPolicy | Select-Object -Property DisplayName, Id

        $ExcludeUsers = $BlockLegacyProtocolPolicy.Conditions.Users.ExcludeUsers
        $ExcludeGroups = $BlockLegacyProtocolPolicy.Conditions.Users.ExcludeGroups
        $ExcludeGuestsOrExternalUsers = $BlockLegacyProtocolPolicy.Conditions.Users.ExcludeGuestsOrExternalUsers

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
        $ExcludeGroups = $RequireMfaAdminsPolicy.Conditions.Users.ExcludeGroups
        $ExcludeGuestsOrExternalUsers = $RequireMfaAdminsPolicy.Conditions.Users.ExcludeGuestsOrExternalUsers

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
        $ExcludeGroups = $RequireMfaAdminsPolicy.Conditions.Users.ExcludeGroups
        $ExcludeGuestsOrExternalUsers = $RequireMfaAdminsPolicy.Conditions.Users.ExcludeGuestsOrExternalUsers

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
#endregion

<#
. "..\src\functions.ps1"
#>