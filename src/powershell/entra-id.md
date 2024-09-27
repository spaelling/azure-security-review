# Entra ID Review for tenant 1b775964-7849-4f1a-8052-60b8e5c59b96

## Users

### User States

Count the total number of users, disabled users, deleted users, and guest users.

TotalUsers | DisabledUsers | GuestUsers | DeletedUsers
---------- | ------------- | ---------- | ------------
36         | 1             | 1          | 10          

### Disabled Users

Find disabled users with group memberships or roles or licenses assigned.

Disabled users should not have roles or licenses assigned, and group memberships should at least be reviewed. 

User        | Sku            
----------- | ---------------
Adele Vance | Microsoft_Teams_EEA_New

User        | Groups                                                                                                                           
----------- | ---------------------------------------------------------------------------------------------------------------------------------
Adele Vance | Contoso,Sales and Marketing,Leadership,Mark 8 Project Team,Retail,Contoso Team,Digital Initiative Public Relations,U.S. Sales,sg-

## Privileged Administration

### Limit the number of Global Administrators to less than 5

*Severity*: High

*Guid*: 9e6efe9d-f28f-463b-9bff-b5080173e9fe

[Entra ID best practice](https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices#5-limit-the-number-of-global-administrators-to-less-than-5)

*As a best practice, Microsoft recommends that you assign the Global Administrator role to fewer than five people in your organization...*

Global Administrators:

Id                                   | Display Name              | User Principal Name                              
------------------------------------ | ------------------------- | -------------------------------------------------
0be62ebe-2c9f-495f-96fe-7bf55b38f82f | Nestor Wilke              | NestorW@M365x53531719.OnMicrosoft.com            
4b7132e7-7c7a-4194-a6f2-0f01deb4c512 | Microsoft Service Account | ms-serviceaccount@M365x53531719.OnMicrosoft.com  
62e3caad-18b1-42f4-b137-5b859866e0d6 | Anders Spælling           | asp_apento.com#EXT#@M365x53531719.onmicrosoft.com
65cfef21-f882-40a8-acc4-e00eeb156088 | MOD Administrator         | admin@M365x53531719.onmicrosoft.com              
888ec1ea-0bbd-4b56-8fdd-619ccb204681 | Isaiah Langer             | IsaiahL@M365x53531719.OnMicrosoft.com            
952bcf88-96f1-4f5c-ad27-0f6fe1e0c41e | Allan Deyoung             | AllanD@M365x53531719.OnMicrosoft.com             
a9202440-969a-45d3-9829-7217021c4e6c | Megan Bowen               | MeganB@M365x53531719.OnMicrosoft.com             
d07fef1b-338d-4b3e-8bf5-8541378813c1 | Lidia Holloway            | LidiaH@M365x53531719.OnMicrosoft.com             

### Synchronized accounts

*Severity*: High

*Guid*: 87791be1-1eb0-48ed-8003-ad9bcf241b99

Do not synchronize accounts with the highest privilege access to on-premises resources as you synchronize your enterprise identity systems with cloud directories.

If below list any users then onPremisesSyncEnabled is true (and their account is enabled). Those should have the role removed, and a cloud-only user created as a replacement.

[Entra ID best practice](https://learn.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices#centralize-identity-management)

*Do not synchronize accounts to Azure AD that have high privileges in your existing Active Directory instance...*



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

Alert                                    | Incident Count
---------------------------------------- | --------------
There are too many global administrators | 8             

We can also list affected principals. Note that in some cases there is no direct principal, ex. for the alert NoMfaOnRoleActivationAlert

User                                                                       
---------------------------------------------------------------------------
Lidia Holloway (LidiaH@M365x53531719.OnMicrosoft.com)                      
MOD Administrator (admin@M365x53531719.onmicrosoft.com)                    
Megan Bowen (MeganB@M365x53531719.OnMicrosoft.com)                         
Allan Deyoung (AllanD@M365x53531719.OnMicrosoft.com)                       
Anders Spælling (asp_apento.com#EXT#@M365x53531719.onmicrosoft.com)        
Nestor Wilke (NestorW@M365x53531719.OnMicrosoft.com)                       
Microsoft Service Account (ms-serviceaccount@M365x53531719.OnMicrosoft.com)
Isaiah Langer (IsaiahL@M365x53531719.OnMicrosoft.com)                      

### Recurring access reviews

*Severity*: High

*Guid*: eae64d01-0d3a-4ae1-a89d-cc1c2ad3888f

Configure recurring access reviews to revoke unneeded permissions over time.

[Best Practice: Configure recurring access reviews to revoke unneeded permissions over time](https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices#4-configure-recurring-access-reviews-to-revoke-unneeded-permissions-over-time)

If there are no access review definitions then there are no recurring access reviews.

Access review definitions
-------------------------
0                        

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

Display Name              | via                                  
------------------------- | -------------------------------------
EXO_App2                  | Role Member of Exchange Administrator
MOD Administrator         | Role Member of Global Administrator  
ProvisioningHealth        | Role Member of Global Administrator  
Microsoft Service Account | Role Member of Global Administrator  
Allan Deyoung             | Role Member of Global Administrator  
Nestor Wilke              | Role Member of Global Administrator  
Isaiah Langer             | Role Member of Global Administrator  
Megan Bowen               | Role Member of Global Administrator  
Lidia Holloway            | Role Member of Global Administrator  
Anders Spælling           | Role Member of Global Administrator  

### Avoid standing access for user accounts and permissions

*Work in Progress*

[MCSB: PA-2: Avoid standing access for user accounts and permissions](https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-2-avoid-standing-access-for-user-accounts-and-permissions)

Role                 | DisplayName               | UserPrincipalName                                
-------------------- | ------------------------- | -------------------------------------------------
Global Administrator | Nestor Wilke              | NestorW@M365x53531719.OnMicrosoft.com            
Global Administrator | Microsoft Service Account | ms-serviceaccount@M365x53531719.OnMicrosoft.com  
Global Administrator | Anders Spælling           | asp_apento.com#EXT#@M365x53531719.onmicrosoft.com
Global Administrator | MOD Administrator         | admin@M365x53531719.onmicrosoft.com              
Global Administrator | Isaiah Langer             | IsaiahL@M365x53531719.OnMicrosoft.com            
Global Administrator | Allan Deyoung             | AllanD@M365x53531719.OnMicrosoft.com             
Global Administrator | Megan Bowen               | MeganB@M365x53531719.OnMicrosoft.com             
Global Administrator | Lidia Holloway            | LidiaH@M365x53531719.OnMicrosoft.com             

## External Identities

### Guest invite settings

*Severity*: High

*Guid*: be64dd7d-f2e8-4bbb-a468-155abc9164e9

External Collaboration Settings: Guest invite settings set to 'Only users assigned to specific admin roles can invite guest users' or 'No one in the organization can invite guest users including admins (most restrictive)'

Guest invite settings
---------------------
everyone             

### Guest user access restrictions

*Work in Progress*

*Severity*: High

*Guid*: 459c373e-7ed7-4162-9b37-5a917ecbe48f

External Collaboration Settings: Guest user access set to 'Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)'

<!-- code is work in progress -->

## User Setting

### User role permissions (Application registration)

*Severity*: High

*Guid*: a2cf2149-d013-4a92-9ce5-74dccbd8ac2a

Users can register applications should be set to No.

Users should not be allowed to register applications. Use specific roles such as Application Developer.

Users are allowed to create applications
----------------------------------------
Yes                                     

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

Unverified domains registered
-----------------------------
0                            

## Enterprise Applications

### User consent for apps

*Severity*: Medium

*Guid*: 459c373e-7ed7-4162-9b37-5a917ecbe48f

Consent & Permissions: Allow user consent for apps from verified publishers

[Configure how users consent to applications](https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?pivots=ms-graph)

Users are allowed to consent to all applications
------------------------------------------------
Yes                                             

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

AppId                                | DisplayName            | PublisherName      | Owners                                                                 
------------------------------------ | ---------------------- | ------------------ | -----------------------------------------------------------------------
797f4846-ba00-4fd7-ba43-dac1f8f63013 | Azure Resource Manager | Microsoft Services | Microsoft.Graph.Beta.PowerShell.Models.MicrosoftGraphDirectoryObject   

Look for applications with application permission in Microsoft Graph and 1 or more owners assigned. Application permissions are often medium-high risk permissions.

Found no applications with Owners

Look for applications with owners and any resource access that we do not consider low-risk. The applications listed below is worth looking into.

These permissions are considered low risk:

Id                                   | PermissionType | Consent | Name           | Description                                                                                                                                                           
------------------------------------ | -------------- | ------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------
64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0 | Delegated      | User    | email          | Allows the app to read your primary email address                                                                                                                     
7427e0e9-2fba-42fe-b0c0-848c9e6a8182 | Delegated      | User    | offline_access | Allows the app to see and update the data you gave it access to, even when you are not currently using the app. This does not give the app any additional permissions.
37f7f235-527c-4136-accd-4a02d197296e | Delegated      | User    | openid         | Allows you to sign in to the app with your work or school account and allows the app to read your basic profile information.                                          
14dad69e-099b-42c9-810b-d002981feec1 | Delegated      | User    | profile        | Allows the app to see your basic profile (e.g., name, picture, user name, email address)                                                                              
e1fe6dd8-ba31-4d61-89e7-88639da4683d | Delegated      | User    | User.Read      | Allows you to sign in to the app with your organizational account and let the app read your profile. It also allows the app to read basic company information.        

Look for applications with owners and any resource access that we do not consider low-risk. 


Found no applications with Owners and above low-risk permissions

### Applications with privileged app role assignments

All credit goes to [What's lurking in your Microsoft Graph app role assignments?](https://learningbydoing.cloud/blog/audit-ms-graph-app-role-assignments/)

Tier 0 | AppRole                                                                                                         | LastSignInActivity   | ServicePrincipalDisplayName         
------ | --------------------------------------------------------------------------------------------------------------- | -------------------- | ------------------------------------
N      | Policy.ReadWrite.ConditionalAccess (Read and write your organization's conditional access policies)             | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
N      | Policy.ReadWrite.AuthenticationMethod (Read and write all authentication method policies )                      | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
N      | Mail.ReadWrite (Read and write mail in all mailboxes)                                                           | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
N      | User.ReadWrite.All (Read and write all users' full profiles)                                                    | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
N      | RoleManagement.Read.Directory (Read all directory RBAC settings)                                                | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
Y      | Directory.ReadWrite.All (Read and write directory data)                                                         | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
N      | User.EnableDisableAccount.All (Enable and disable user accounts)                                                | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
N      | Directory.Read.All (Read directory data)                                                                        | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
N      | User.Read.All (Read all users' full profiles)                                                                   | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
N      |  ()                                                                                                             | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
N      | Mail.Send (Send mail as any user)                                                                               | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
N      | User.ManageIdentities.All (Manage all users' identities)                                                        | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
Y      | RoleManagement.ReadWrite.Directory (Read and write all directory RBAC settings)                                 | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
N      | AuditLog.Read.All (Read all audit log data)                                                                     | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
N      | Policy.Read.All (Read your organization's policies)                                                             | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
N      | CloudPC.ReadWrite.All (Read and write Cloud PCs)                                                                | 9/26/2024 6:49:24 AM | ProvisioningHealth                  
N      | User.ReadWrite.All (Read and write all users' full profiles)                                                    | 9/19/2024 3:59:57 AM | MOD Demo Platform UnifiedApiConsumer
N      | EduRoster.ReadWrite.All (Read and write the organization's roster)                                              | 9/19/2024 3:59:57 AM | MOD Demo Platform UnifiedApiConsumer
N      | User.Read.All (Read all users' full profiles)                                                                   | 9/19/2024 3:59:57 AM | MOD Demo Platform UnifiedApiConsumer
N      | DeviceManagementServiceConfig.ReadWrite.All (Read and write Microsoft Intune configuration)                     | 9/19/2024 3:59:57 AM | MOD Demo Platform UnifiedApiConsumer
N      | MailboxSettings.ReadWrite (Read and write all user mailbox settings)                                            | 9/19/2024 3:59:57 AM | MOD Demo Platform UnifiedApiConsumer
N      | DeviceManagementConfiguration.ReadWrite.All (Read and write Microsoft Intune device configuration and policies) | 9/19/2024 3:59:57 AM | MOD Demo Platform UnifiedApiConsumer
N      | CloudPC.ReadWrite.All (Read and write Cloud PCs)                                                                | 9/19/2024 3:59:57 AM | MOD Demo Platform UnifiedApiConsumer
N      |  ()                                                                                                             |                      |                                     

## Conditional Access Policies

### Block Legacy Protocols

*Severity*: High

*Guid*: 9e6efe9d-f28f-463b-9bff-b5080173e9fe

[Common Conditional Access policy: Block legacy authentication](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-block-legacy)

This policy, along with policies that enforce MFA are the most important to have. Legacy authentication will de-facto bypass MFA.

Below looks for a conditional access policy that blocks legacy protocols and also outputs users excluded.

Policy compliance                                 
--------------------------------------------------
No valid CA Policy found blocking legacy protocols

## Require MFA for Administrators

*Severity*: High

*Guid*: fe1bd15d-d2f0-4d5e-972d-41e3611cc57b

[Common Conditional Access policy: Require MFA for administrators](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-admin-mfa)

Below looks for a conditional access policy that matches the policy template "Require multifactor authentication for admins"

Policy compliance                                      
-------------------------------------------------------
No valid CA Policy found targeting Azure administrators

## Require MFA for Azure Management

*Severity*: High

*Guid*: 4a4b1410-d439-4589-ac22-89b3d6b57cfc

[Common Conditional Access policy: Require MFA for Azure management](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-azure-management)

Below looks for a conditional access policy that matches the policy template "Require multifactor authentication for Azure management"

Policy compliance       
------------------------
No valid CA Policy found

## Restricted Locations

*Severity*: Medium

*Guid*: 079b588d-efc4-4972-ac3c-d21bf77036e5

[Using the location condition in a Conditional Access policy](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/location-condition)

Named locations can be used in numerous different way. A bad way to use them is to exclude from ex. enforcing MFA when coming from a "trusted location". This does not conform to a zero trust strategy.

Policy compliance            
-----------------------------
5 Named Locations are defined



## Require devices to be marked as compliant

*Severity*: High

*Guid*: 7ae9eab4-0fd3-4290-998b-c178bdc5a06c

[Require device to be marked as compliant](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-grant#require-device-to-be-marked-as-compliant)

Requiring devices to be marked as compliant in CA policy grants can be a powerful way of ensuring that connections are made from devices that are managed by the organization. With sufficiently strict device configurations enforced, this can be combined with MFA, or just a standalone grant.

Policy compliance       
------------------------
No valid CA Policy found

## Protected Actions

Use [Protected Actions](https://learn.microsoft.com/en-us/azure/active-directory/roles/protected-actions-overview) to enforce strong authentcation and other strict grant controls when performing highly privileged actions, like Delete conditional access policies.


