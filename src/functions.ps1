function Invoke-AzResourceGraphCheck {
    [CmdletBinding()]
    param (
        $CheckList,
        $CheckListId,
        $DebugMode = $false
    )
    $Query = $CheckList | Where-Object { $_.guid -eq $CheckListId } | Select-Object -ExpandProperty graph

    if ($DebugMode) {
        Write-Host "Running query '$Query'`n"
    }
    
    Search-AzGraph $Query | Select-Object -ExpandProperty Data | Where-Object { $_.compliant -eq 0 } | Select-Object -ExpandProperty id    
}

function Get-GroupMembers {
    [CmdletBinding()]
    param (
        $DirectoryObjectByIds,
        $DebugMode = $false
    )
    $params = @{
        ids   = $DirectoryObjectByIds
        types = @(
            "user"
            "group"
        )
    }

    $DirectoryObject = Get-MgDirectoryObjectById -BodyParameter $params

    $DirectoryObject | ForEach-Object {
        $ObjectType = $_.AdditionalProperties.'@odata.type'
        if ($ObjectType -eq '#microsoft.graph.group') {
            Get-GroupMembers -DirectoryObjectByIds (Get-MgGroupMember -GroupId $_.Id | Select-Object -ExpandProperty Id)
        }
        if ($ObjectType -eq '#microsoft.graph.user') {
            $_ 
        }
    }  
}