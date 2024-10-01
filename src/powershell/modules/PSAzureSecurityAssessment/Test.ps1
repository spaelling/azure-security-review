Import-Module -Name PSScriptAnalyzer -ErrorAction Stop

Clear-Host; Invoke-ScriptAnalyzer -Path ".\PSAzureSecurityAssessment.psm1" -ExcludeRule PSAvoidTrailingWhitespace