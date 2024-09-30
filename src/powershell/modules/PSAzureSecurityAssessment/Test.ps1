Import-Module -Name PSScriptAnalyzer

Clear-Host; Invoke-ScriptAnalyzer -Path .\src\powershell\modules\PSAzureSecurityAssessment\PSAzureSecurityAssessment.psm1 -ExcludeRule PSAvoidTrailingWhitespace