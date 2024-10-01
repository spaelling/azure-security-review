$NuGetApiKey = Read-Host -Promt "Enter NuGet API key" -AsSecureString

# run this from the powershell folder

Test-ModuleManifest -Path ".\modules\PSAzureSecurityAssessment\PSAzureSecurityAssessment.psd1"

Publish-Module -Path ".\modules\PSAzureSecurityAssessment" -NuGetApiKey (ConvertFrom-SecureString $NuGetApiKey -AsPlainText)