<# This is the pure powershell based Entra ID assessment. It will strongly correlate to the experience in entra-id.ipynb (Notebook)
#>

Remove-Module -Name azure-security-review -Force -ErrorAction SilentlyContinue
Import-Module ".\modules\azure-security-review.psm1"

$TenantId = "1b775964-7849-4f1a-8052-60b8e5c59b96"

Initialize-Notebook -TenantId $TenantId

$Markdown = @"
# Entra ID Review for tenant $TenantId

## Users

### User States

Count the total number of users, disabled users, deleted users, and guest users.

$((Get-UserStates -OutputMarkdown) -join "`n")

### Disabled Users

Find disabled users with group memberships or roles or licenses assigned.

Disabled users should not have roles or licenses assigned, and group memberships should at least be reviewed. 

$((Get-DisabledUsers -IncludeLicenseDetails -OutputMarkdown) -join "`n")

$((Get-DisabledUsers -IncludeGroupMemberships -OutputMarkdown) -join "`n")

## Privileged Administration

### Limit the number of Global Administrators to less than 5

*Severity*: High

*Guid*: 9e6efe9d-f28f-463b-9bff-b5080173e9fe

[Entra ID best practice](https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices#5-limit-the-number-of-global-administrators-to-less-than-5)

*As a best practice, Microsoft recommends that you assign the Global Administrator role to fewer than five people in your organization...*

Global Administrators:

$((Get-GlobalAdminstrators -OutputMarkdown) -join "`n")

### Synchronized accounts

*Severity*: High

*Guid*: 87791be1-1eb0-48ed-8003-ad9bcf241b99

Do not synchronize accounts with the highest privilege access to on-premises resources as you synchronize your enterprise identity systems with cloud directories.

If below list any users then `onPremisesSyncEnabled` is true (and their account is enabled). Those should have the role removed, and a cloud-only user created as a replacement.

[Entra ID best practice](https://learn.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices#centralize-identity-management)

*Do not synchronize accounts to Azure AD that have high privileges in your existing Active Directory instance...*

$((Get-SynchronizedAccounts -OutputMarkdown) -join "`n")

### Use groups for Entra ID role assignments

*Work in Progress*

For now we can check the *Membership* column in [Privileged Identity Management | Azure AD roles](https://portal.azure.com/?feature.msaljs=true#view/Microsoft_Azure_PIMCommon/ResourceMenuBlade/~/members/resourceId//resourceType/tenant/provider/aadroles)

*Severity*: High

*Guid*: e0d968d3-87f6-41fb-a4f9-d852f1673f4c

[Best Practice: Use groups for Microsoft Entra role assignments and delegate the role assignment](https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices#7-use-groups-for-microsoft-entra-role-assignments-and-delegate-the-role-assignment)

*If you have an external governance system that takes advantage of groups, then you should consider assigning roles to Microsoft Entra groups, instead of individual users....*

<!-- Get-GroupsWithRoleAssignments -OutputMarkdown # WiP -->

### PIM Alerts

*Severity*: High

*Guid*: N/A

There should be no active alerts in PIM. If below identifies any active alerts go to [PIM alerts](https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ResourceMenuBlade/~/Alerts/resourceId//resourceType/tenant/provider/aadroles) for further details.

$((Get-PimAlerts -OutputMarkdown) -join "`n")

We can also list affected principals. Note that in some cases there is no direct principal, ex. for the alert `NoMfaOnRoleActivationAlert`

$((Get-PimAlertAffectedPrincipals -OutputMarkdown) -join "`n")

### Recurring access reviews

*Severity*: High

*Guid*: eae64d01-0d3a-4ae1-a89d-cc1c2ad3888f

Configure recurring access reviews to revoke unneeded permissions over time.

[Best Practice: Configure recurring access reviews to revoke unneeded permissions over time](https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices#4-configure-recurring-access-reviews-to-revoke-unneeded-permissions-over-time)

If there are no access review definitions then there are no recurring access reviews.

$((Get-RecurringAccessReviews -OutputMarkdown) -join "`n")

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

$((Test-GuestInviteSettings -OutputMarkdown) -join "`n")

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

$((Test-UsersCanRegisterApplications -OutputMarkdown) -join "`n")

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

$((Test-VerifiedDomains -OutputMarkdown) -join "`n")

## Enterprise Applications

### User consent for apps

*Severity*: Medium

*Guid*: 459c373e-7ed7-4162-9b37-5a917ecbe48f

Consent & Permissions: Allow user consent for apps from verified publishers

[Configure how users consent to applications](https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?pivots=ms-graph)

$((Test-UserConsentForApps -OutputMarkdown) -join "`n")

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

$((Find-OwnersFirstPartyMicrosoftApplications -OutputMarkdown) -join "`n")

Look for applications with application permission in Microsoft Graph and 1 or more owners assigned. Application permissions are often medium-high risk permissions.

$((Find-ApplicationsWithApplicationPermissionsAndOwner -OutputMarkdown) -join "`n")

Look for applications with owners and any resource access that we do not consider low-risk. The applications listed below is worth looking into.

These permissions are considered low risk:

$((Show-LowRiskApplicationPermissions -OutputMarkdown) -join "`n")

Look for applications with owners and any resource access that we do not consider low-risk. 

$((Find-ApplicationsNonLowRiskPermissionsAndOwners -OutputMarkdown) -join "`n")

### Applications with privileged app role assignments

All credit goes to [What's lurking in your Microsoft Graph app role assignments?](https://learningbydoing.cloud/blog/audit-ms-graph-app-role-assignments/)

$((Get-PrivilegedAppRoleAssignments -OutputMarkdown) -join "`n")

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

$((Test-ProtectedActions) -join "`n")
"@

$Markdown | Out-File -FilePath "entra-id.md"