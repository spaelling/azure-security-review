$NuGetApiKey = Read-Host -Promt "Enter NuGet API key" -AsSecureString

# run this from the powershell modules folder

# region run script analyzer
Import-Module -Name PSScriptAnalyzer -ErrorAction Stop

Invoke-ScriptAnalyzer -Path "PSAzureSecurityAssessment\PSAzureSecurityAssessment.psm1" -ExcludeRule PSAvoidTrailingWhitespace
# endregion

Test-ModuleManifest -Path ".\PSAzureSecurityAssessment\PSAzureSecurityAssessment.psd1"

Publish-Module -Path ".\PSAzureSecurityAssessment" -NuGetApiKey (ConvertFrom-SecureString $NuGetApiKey -AsPlainText)