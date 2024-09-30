<# This is the pure powershell based Entra ID assessment. It will strongly correlate to the experience in entra-id.ipynb (Notebook)

Note that the tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license for part of the assessment to work.

# run below if changes has been made to the module
Remove-Module -Name azure-security-review -Force -ErrorAction SilentlyContinue
#>

$TranscriptPath = "..\..\entraid_assessments\" + (Get-Date -Format "yyyy_MM_dd_hh_mm") + ".log"
Start-Transcript -Path $TranscriptPath -Append

Import-Module ".\modules\azure-security-review.psm1" -Force

# define which tenants to assess
$TenantIds = @("1b775964-7849-4f1a-8052-60b8e5c59b96") # demo tenant, faxmeinthecloud

# consent must be granted ONCE per tenant
Write-Host "paste this into a browser (once) to consent and add to tenant:`n`n"
foreach ($TenantId in $TenantIds) {
    # paste into browser and consent. the app will appear in the tenant's enterprise applications
    "https://login.microsoftonline.com/$TenantId/oauth2/authorize?response_type=code&client_id=0614bbae-3283-41e4-b3ac-3946fdcab533&redirect_uri=https://portal.azure.com/`n`n"
}

$ApplicationId = '0614bbae-3283-41e4-b3ac-3946fdcab533' # multi tenant app: Entra ID Security Assessment in tenant 690e25b4-8c5e-4a10-a32e-523da88a4c99
<#
$SecurePassword = Read-Host -Promt "Enter client secret for $ApplicationId" -AsSecureString
#>
$OutputFolder = "..\..\entraid_assessments\$(Get-Date -Format "yyyy_MM_dd_hh_mm")"
if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory
}
$OutputFolder = (Resolve-Path $OutputFolder).Path
$OutputFolder
# TODO: run commands asynchronously so that we can generate the markdown output much faster - may hit some rate limiting?
foreach ($TenantId in $TenantIds) {
    # must authenticate using a service principal that has the following application permissions "RoleEligibilitySchedule.Read.Directory", "RoleAssignmentSchedule.Read.Directory", "Directory.AccessAsUser.All", "Policy.Read.All", "RoleManagement.Read.Directory", "RoleManagementAlert.Read.Directory", "AccessReview.Read.All", "Application.Read.All", "Directory.Read.All", "AuditLog.Read.All", "CrossTenantInformation.ReadBasic.All"
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecurePassword
    $null = Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $Credential
    $AccessToken = Get-AzAccessToken -ResourceTypeName MSGraph -AsSecureString -WarningAction SilentlyContinue | Select-Object -ExpandProperty Token
    Write-Host "Starting assessment for tenant $TenantId"
    Write-EntraIdAssessment -TenantId $TenantId -AccessToken $AccessToken -OutputFolder $OutputFolder -Verbose -ErrorAction Stop
}

<#
https://login.microsoftonline.com/1b775964-7849-4f1a-8052-60b8e5c59b96/oauth2/authorize?response_type=code&client_id=0614bbae-3283-41e4-b3ac-3946fdcab533&redirect_uri=https://portal.azure.com/
#>

Stop-Transcript