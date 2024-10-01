<# This is the pure powershell based Entra ID assessment. It will strongly correlate to the experience in entra-id.ipynb (Notebook)

Note that the tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license for part of the assessment to work.

# run below if changes has been made to the module
Remove-Module -Name PSAzureSecurityAssessment -Force -ErrorAction SilentlyContinue
#>

param(
    $TranscriptPath = "./transcripts",
    $OutputFolder = "./entraid_assessments",
    $TenantIds= @("1b775964-7849-4f1a-8052-60b8e5c59b96"),
    $StorageAccountName = 'sa6a6e37fa52624205977',
    $StorageAccountTenantId = '690e25b4-8c5e-4a10-a32e-523da88a4c99',
    $ApplicationId = '449b684c-9946-4eea-94f8-32003fbb0391', # multi tenant app: Entra ID Security Assessment in tenant 690e25b4-8c5e-4a10-a32e-523da88a4c99
    [switch]$InstallMicrosoftGraphModules
)

if (-not (Test-Path -Path $TranscriptPath)) {
    $null = New-Item -Path $TranscriptPath -ItemType Directory
}
$TranscriptPath = (Resolve-Path $TranscriptPath).Path

$TranscriptPath = $TranscriptPath + "/" + (Get-Date -Format "yyyy_MM_dd_hh_mm") + ".log"
Start-Transcript -Path $TranscriptPath

# install powershell module PSAzureSecurityAssessment if not already installed
# check latest version of PSAzureSecurityAssessment
$PSAzureSecurityAssessmentLatestVersion = Find-Module -Name PSAzureSecurityAssessment -Repository PSGallery -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version
$InstalledLatestVersion = $null -ne (Get-Module -ListAvailable -Name PSAzureSecurityAssessment -ErrorAction SilentlyContinue | Where-Object { $_.Version -eq $PSAzureSecurityAssessmentLatestVersion })
if (-not $InstalledLatestVersion) {
    Install-Module -Name PSAzureSecurityAssessment -Force -AllowClobber -Scope CurrentUser
}

$null = Import-Module -Name PSAzureSecurityAssessment -ErrorAction Stop -Force
# $null = Import-Module ./src/powershell/modules/PSAzureSecurityAssessment/PSAzureSecurityAssessment.psd1 -Force

# install Microsoft Graph modules
if($InstallMicrosoftGraphModules.IsPresent)
{
    $MGModuleNames = 'Microsoft.Graph.Identity.DirectoryManagement', 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Groups', 'Microsoft.Graph.DirectoryObjects', 'Microsoft.Graph.Users', 'Microsoft.Graph.Applications'
    $MGModuleNames | % {Install-Module -Name $_ -Scope CurrentUser -Force}
    # beta modules
    $MGModuleNames = 'Microsoft.Graph.Beta.Identity.SignIns', 'Microsoft.Graph.Beta.Identity.Governance', 'Microsoft.Graph.Beta.Applications', 'Microsoft.Graph.Beta.Identity.DirectoryManagement', 'Microsoft.Graph.Beta.DirectoryObjects', 'Microsoft.Graph.Beta.Reports'
    $MGModuleNames | % {Install-Module -Name $_ -Scope CurrentUser -Force -AllowClobber}
}

<#
$SecurePassword = Read-Host -Promt "Enter client secret for $ApplicationId" -AsSecureString
#>

# consent must be granted ONCE per tenant
Write-Host "paste this into a browser (once) to consent and add to tenant:`n"
foreach ($TenantId in $TenantIds) {
    # paste into browser and consent. the app will appear in the tenant's enterprise applications
    "https://login.microsoftonline.com/$TenantId/oauth2/authorize?response_type=code&client_id=$ApplicationId&redirect_uri=https://portal.azure.com/`n"
}

$OutputFolder = $OutputFolder + "/$(Get-Date -Format "yyyy_MM_dd_hh_mm")"
if (-not (Test-Path -Path $OutputFolder)) {
    $null = New-Item -Path $OutputFolder -ItemType Directory
}
$OutputFolder = (Resolve-Path $OutputFolder).Path

# TODO: run commands asynchronously so that we can generate the markdown output much faster - may hit some rate limiting?
$TenantId = $TenantIds[0]
foreach ($TenantId in $TenantIds) {
    <# must authenticate using a service principal that has the following application permissions "RoleEligibilitySchedule.Read.Directory", "RoleAssignmentSchedule.Read.Directory", "Directory.AccessAsUser.All", "Policy.Read.All", "RoleManagement.Read.Directory", "RoleManagementAlert.Read.Directory", "AccessReview.Read.All", "Application.Read.All", "Directory.Read.All", "AuditLog.Read.All", "CrossTenantInformation.ReadBasic.All"
    for the entra id diagnostic settings run either of these using an account that has enabled "Access management for Azure resources" in Entra ID properties (requires Global Administrator)
    easiest way to do this is to run it from a cloud shell

    New-AzRoleAssignment -ObjectId "<enterprise application object id>" -Scope "/providers/Microsoft.aadiam" -RoleDefinitionName 'Contributor' -ObjectType 'ServicePrincipal'
    az role assignment create --assignee-principal-type  ServicePrincipal --assignee-object-id '<enterprise application object id>' --scope "/providers/Microsoft.aadiam" --role 'b24988ac-6180-42a0-ab88-20f7382dd24c'
    #>
    if($null -ne $ApplicationId)
    {
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecurePassword
        $null = Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $Credential -ErrorAction Stop
    }
    $AccessToken = Get-AzAccessToken -TenantId $TenantId -ResourceTypeName MSGraph -AsSecureString -WarningAction SilentlyContinue | Select-Object -ExpandProperty Token
    Write-Host "Starting assessment for tenant $TenantId"
    Write-EntraIdAssessment -TenantId $TenantId -AccessToken $AccessToken -OutputFolder $OutputFolder -StorageAccountName $StorageAccountName -StorageAccountTenantId $StorageAccountTenantId -Verbose -ErrorAction Stop
}
# 
Stop-Transcript