# Azure Security Review

A *notebook* (using Polyglot) that codifies the [Azure Security Review Checklist](https://github.com/Azure/review-checklists) and other general security recommendations, like [Microsoft Security Benchmarks](https://learn.microsoft.com/en-us/security/benchmark/azure/overview). It will also include best practices and *well architected* recommendations.

The notebook approach allows for use of many different languages and frameworks. We can use Microsoft Graph to gain insights into Entra ID (Azure AD), and we can use Azure Resource Graph combined with Azure Powershell or Az cli. But C#, Python, Javascript, etc. is also viable options.

Combined with Markdown, this allows for verbosity to a level that is hard to beat with any other tooling, and insights gained literally with the click of a button.

## Notes

These are the controls/checks that are implemented, planned, or work in progress.

- Entra ID (Azure AD) [identity.ipynb](./notebooks/identity.ipynb)
  - Privileged administration
    - Limit the number of Global Administrators to less than 5
    - Synchronized accounts
    - Use groups for Azure AD role assignments (Work in Progress)
    - PIM Alerts
    - Recurring access reviews
    - Access Reviews: Enabled for all groups
    - Apps and Owners Can Change All Group Membership (Work in Progress)
    - Avoid standing access for user accounts and permissions (Work in Progress)
  - External Identities
    - Guest Invite Settings
    - Guest User Access Restrictions (Work in Progress)
  - User Setting
    - User role permissions (Application registration)
    - Authentication Methods
  - Custom Domains
    - Verified Domains
  - Enterprise Applications
    - User Consent for Apps
    - Group Owner Consent (Work in Progress)
    - Application Owners
    - Applications with privileged app role assignments (Work in Progress)
  - Conditional Access Policies
    - Block Legacy Protocols
    - Require MFA for Administrators
    - Require MFA for Azure Management
    - Restricted Locations
    - Require devices to be marked as compliant
    - Protected Actions
  - Password Reset
    - Self-service password reset policy requirement (Work in Progress)
    - Re-confirm authentication information (Work in Progress)
    - Number of methods required to reset password (Work in Progress)
- Azure Infrastructure
  - Network [network.ipynb](./notebooks/network.ipynb)
    - Subnets should have an NSG associated
    - NSG Deny All Rule
    - Open Management Ports
    - NSG Flow Logs
  - App Services [app_services.ipynb](./notebooks/app_services.ipynb)
    - Use HTTPS Only
    - Set minimum TLS policy to 1.2
    - Turn off remote debugging
  - Role Based Access Control (RBAC)
    - Privileged Administrator Role Assignments (planned)

Check out the [Demo](#demo) section for examples.

## Prerequisites

- VSCode
- Python Extension
- Polyglot Extension
- Anaconda 3

```powershell
# Install Anaconda 3 using ex. Chocolatey

# from an elevated command prompt
choco install anaconda3
# go drink a coffee - this takes a while
```

We need to make sure a few prequisite modules are installed

- Az (Azure Powershell)
- Az.ResourceGraph
- Microsoft.Graph

Note that `Microsoft.Graph` is a collection of many modules.

If there are multiple of the same modules listed using below code, then you have Microsoft.Graph modules installed in multiple places and possibly multiple different versions.

I would suggest completely uninstalling and then install the necessary modules. Also beware if you are installing to PowerShell Desktop or Core, check `$PSVersionTable`.

```powershell
$MGModuleNames = 'Microsoft.Graph.Identity.DirectoryManagement', 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Groups', 'Microsoft.Graph.DirectoryObjects', 'Microsoft.Graph.Users', 'Microsoft.Graph.Applications'
$MGModuleNames | % {Install-Module -Name $_ -Scope AllUsers -Force -Verbose}
# beta modules
$MGModuleNames = 'Microsoft.Graph.Beta.Identity.SignIns', 'Microsoft.Graph.Beta.Identity.Governance', 'Microsoft.Graph.Beta.Applications', 'Microsoft.Graph.Beta.Identity.DirectoryManagement'
$MGModuleNames | % {Install-Module -Name $_ -Scope AllUsers -Force -Verbose -AllowClobber}
```

Note that this installation takes a while to complete.

You can list the modules, versions and their install location using

```powershell
Get-Module -ListAvailable | Where-Object {$_.Name -like "Microsoft.Graph*"}
```

Beware of having multiple versions or differing versions installed. You can encounter this error `Assembly with same name is already loaded` if two different modules are loading two different assemblies with the same name but different versions. Avoid this by always using the latest version.

Update all MG modules using

```powershell
Get-Module -ListAvailable | Where-Object {$_.Name -like "*Microsoft.Graph.*"} | Update-Module -Force
```

Alternative is to use `MicrosoftGraphPS`

```powershell
Install-Module -Name MicrosoftGraphPS
# and run
Manage-Version-Microsoft.Graph -CleanupOldMicrosoftGraphVersions
```

We will also be using a community module:

```powershell
Install-Module -Name AzResourceGraphPS
```

and for PS Core only users we need `Out-GridView` (Windows GUI elements not available in PS Core)

```powershell
Install-Module Microsoft.PowerShell.ConsoleGuiTools
# And set the alias - note this is just for the session.
Set-Alias -Name Out-GridView -Value Out-ConsoleGridview
```

## Azure Policies

This notebook is not a replacement for Azure Policies. Many of the checks done here is much better to do using Azure Policies (if possible), as these continously evaluate, and can also enforce specific settings.

## Demo

[Limit the number of Global Administrators to less than 5](/notebooks/media/Limit%20the%20number%20of%20Global%20Administrators%20to%20less%20than%205.mov)

https://github.com/spaelling/azure-security-review/assets/871412/41c6ea70-57cd-44c9-b0a2-61d8e3107fed

[PIM Alerts](/notebooks/media/PIM%20alerts.mov)

https://github.com/spaelling/azure-security-review/assets/871412/12db37a9-18aa-4f7e-ad4a-9732f1959761

[User consent for apps](/notebooks/media/user%20consent%20for%20apps.mov)

https://github.com/spaelling/azure-security-review/assets/871412/f60e87de-98b5-4152-adf1-7e3962969853

[Application owners](/notebooks/media/application%20owners.mov)

https://github.com/spaelling/azure-security-review/assets/871412/cc9db762-f164-4945-8732-ff9e9193a350

[Block Legacy Protocols](/notebooks/media/block%20legacy%20protocols.mov)

https://github.com/spaelling/azure-security-review/assets/871412/69ff9d19-edc0-4b58-951d-a565da418ae3

[Subnets should have an NSG associated](/notebooks/media/Subnets%20should%20have%20an%20NSG%20associated.mov)

https://github.com/spaelling/azure-security-review/assets/871412/e4261ba9-7f7b-4e3f-9d5c-2de49033a2b5

[Open Management Ports](/notebooks/media/Open%20Management%20Ports.mov)

https://github.com/spaelling/azure-security-review/assets/871412/036c614e-bfe1-4b32-a84c-a69d2f517c09

