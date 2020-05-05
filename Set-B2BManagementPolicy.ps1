# .SYNOPSIS
#   Helps admin to update the B2BManagementPolicy for Allow/Block domain list for inviting external Users.
#   Powershell must be connected to target tenant before running this script (using Connect-AzureAD cmdlet).
#
# .DESCRIPTION
#
#   Operations available:
#   - Query policy
#   - Backup existing policy
#   - Remove existing policy
#   - Update/Append allowed domain list
#   - Update/Append blocked domain list
#   Prerequisites
#   - Sufficient AAD role to modify B2BManagement policy in target tenant
#   - AzureAD or AzureADPreview PowerShell module available
#   - Powershell must be connected to target tenant before running this script (using Connect-AzureAD cmdlet)
#
# .PARAMETER Update
#    Parameter to update allow or block domain list.
#
# .PARAMETER Append
#    Parameter to append domains to an existing allow or block domain list.
#
# .PARAMETER AllowList
#    Parameter to specify list of allowed domains as defined array of strings, e.g. @('domain1.com','domain2.com')
#
# .PARAMETER AllowListFile
#    Parameter to specify input file with allow domain list (single domain per line).
#
# .PARAMETER BlockList
#    Parameter to specify list of blocked domains as defined array of strings, e.g. @('domain1.com','domain2.com')
#
# .PARAMETER BlockListFile
#    Parameter to specify input file with block domain list (single domain per line).
#
# .PARAMETER Remove
#    Switch parameter to delete the existing policy.
#
# .PARAMETER QueryPolicy
#    Switch parameter to query the existing policy.
#
# .PARAMETER Backup
#    Switch parameter to backup existing domains.
#
# .Example
#	Set-B2BManagementPolicy.ps1 -Update -AllowList @("contoso.com", "fabrikam.com")
#
# .Example
#	Set-B2BManagementPolicy.ps1 -Update -AllowListFile .\AllowListFile.txt
#
# .Example
#	Set-B2BManagementPolicy.ps1 -Update -BlockList @("fabrikam.com", "contoso.com")
#
# .Example
#	Set-B2BManagementPolicy.ps1 -Update -BlockListFile .\BlockListFile.txt
#
# .Example
#	Set-B2BManagementPolicy.ps1 -Append -AllowList @("contoso.com", "fabrikam.com")
#
# .Example
#	Set-B2BManagementPolicy.ps1 -Append -AllowListFile .\NewAllowListFile.txt
#
# .Example
#	Set-B2BManagementPolicy.ps1 -Append -BlockList @("fabrikam.com", "contoso.com")
#
# .Example
#	Set-B2BManagementPolicy.ps1 -Append -BlockListFile .\NewBlockListFile.txt
#
# .Example
#	Set-B2BManagementPolicy.ps1 -Append -BlockList @("fabrikam.com")
#
# .Example
#	Set-B2BManagementPolicy.ps1 -Remove
#
# .Example
#	Set-B2BManagementPolicy.ps1 -QueryPolicy
#
# .Example
#	Set-B2BManagementPolicy.ps1 -Backup

Param(
    # Build ParameterSetNames to allow below invocations
    # Set-B2BManagementPolicy.ps1 -Update -AllowList <String[]>
    # Set-B2BManagementPolicy.ps1 -Update -BlockList <String[]>
    # Set-B2BManagementPolicy.ps1 -Update -AllowListFile <file name>
    # Set-B2BManagementPolicy.ps1 -Update -BlockListFile <file name>
    # Set-B2BManagementPolicy.ps1 -Append -BlockListFile <file name>
    # Set-B2BManagementPolicy.ps1 -Append -AllowListFile <file name>
    # Set-B2BManagementPolicy.ps1 -Append -AllowList <String[]>
    # Set-B2BManagementPolicy.ps1 -Append -BlockList <String[]>
    # Set-B2BManagementPolicy.ps1 -Remove
    # Set-B2BManagementPolicy.ps1 -QueryPolicy
    # Set-B2BManagementPolicy.ps1 -Backup
    # Set-B2BManagementPolicy.ps1 -Help

    [cmdletbinding(DefaultParameterSetName = "ExistingPolicySet")] # defaults to QueryPolicy if no parameters set

    [Parameter(Mandatory = $true, ParameterSetName = "Update+BlockListFile")]
    [Parameter(Mandatory = $true, ParameterSetName = "Update+AllowListFile")]
    [Parameter(Mandatory = $true, ParameterSetName = "Update+BlockList")]
    [Parameter(Mandatory = $true, ParameterSetName = "Update+AllowList")]
    [Switch] $Update,

    [Parameter(Mandatory = $true, ParameterSetName = "Append+BlockList")]
    [Parameter(Mandatory = $true, ParameterSetName = "Append+AllowList")]
    [Parameter(Mandatory = $true, ParameterSetName = "Append+AllowListFile")]
    [Parameter(Mandatory = $true, ParameterSetName = "Append+BlockListFile")]
    [Switch] $Append,

    [Parameter(Mandatory = $true, ParameterSetName = "Append+BlockList")]
    [Parameter(Mandatory = $true, ParameterSetName = "Update+BlockList")]
    [String[]] $BlockList,

    [Parameter(Mandatory = $true, ParameterSetName = "Append+AllowList")]
    [Parameter(Mandatory = $true, ParameterSetName = "Update+AllowList")]
    [String[]] $AllowList,

    [Parameter(Mandatory = $true, ParameterSetName = "Append+BlockListFile")]
    [Parameter(Mandatory = $true, ParameterSetName = "Update+BlockListFile")]
    [String[]] $BlockListFile,

    [Parameter(Mandatory = $true, ParameterSetName = "Append+AllowListFile")]
    [Parameter(Mandatory = $true, ParameterSetName = "Update+AllowListFile")]
    [String[]] $AllowListFile,

    [Parameter(Mandatory = $true, ParameterSetName = "ClearPolicySet")]
    [switch] $Remove,

    [Parameter(Mandatory = $false, ParameterSetName = "ExistingPolicySet")]
    [switch] $QueryPolicy,

    [Parameter(Mandatory = $true, ParameterSetName = "BackupPolicySet")]
    [switch] $Backup,

    [Parameter(Mandatory = $true, ParameterSetName = "HelpPolicySet")]
    [switch] $Help
)

# ###################################################################################################
# Declare global variables
# ###################################################################################################

# Name of the target policy - default B2BManagementPolicy
[string]$global:strPolicyName = "B2BManagementPolicy"

# When listing current domains definition, stop after 10
# Inform to dump data to file for further
[int16]$global:intDisplayLimit = 10

# Warning limit for policy size (KB)
[int16]$global:policySizeLowerLimit = 24

# Error limit for policy size (KB)
[int16]$global:policySizeUpperLimit = 25
[string]$global:policySizeUpperLimitStr = $policySizeUpperLimit.ToString(".0000")

# ###################################################################################################
# Function definitions
# ###################################################################################################

# Gets Json for the policy with given Allowed and Blocked Domain List
function GetJSONForAllowBlockDomainPolicy([string[]] $AllowDomains = @(), [string[]] $BlockedDomains = @()) {
    # Remove any duplicate domains from Allowed or Blocked domains specified.
    $AllowDomains = $AllowDomains | Select-Object -uniq
    $BlockedDomains = $BlockedDomains | Select-Object -uniq

    return @{B2BManagementPolicy = @{InvitationsAllowedAndBlockedDomainsPolicy = @{AllowedDomains = @($AllowDomains); BlockedDomains = @($BlockedDomains) } } } | ConvertTo-Json -Depth 3 -Compress
}

# Converts Json to Object since ConvertFrom-Json does not support the depth parameter.
function GetObjectFromJson([string] $JsonString) {
    ConvertFrom-Json -InputObject $JsonString |
    ForEach-Object {
        foreach ($property in ($_ | Get-Member -MemberType NoteProperty)) {
            $_.$($property.Name) | Add-Member -MemberType NoteProperty -Name 'Name' -Value $property.Name -PassThru
        }
    }
}

# Gets the existing policy if it exists
function GetExistingPolicy([String] $policyStringName) {
    $currentpolicy = Get-AzureADPolicy -All $true| Where-Object { $_.Type -eq "$policyStringName" } | Select-Object -First 1
    return $currentpolicy;
} # end function GetExistingPolicy()

# Save Allowed and Blocked Domain List for the given policy
function SaveAllowBlockedList([String] $defString) {
    $policyObj = GetObjectFromJson $defString;
    $TenantName = (Get-AzureADTenantDetail).DisplayName
    $TenantName = $TenantName.Replace(" ", "")
    $DateTimeStamp = Get-Date -F yyyyMMddHHmmss


    $BlockedDomainsFile = "$TenantName-$DateTimeStamp-BlockedDomains.txt"
    $AllowedDomainsFile = "$TenantName-$DateTimeStamp-AllowedDomains.txt"

    If ($policyObj.InvitationsAllowedAndBlockedDomainsPolicy.BlockedDomains) {
        ($policyObj.InvitationsAllowedAndBlockedDomainsPolicy | Select-Object -ExpandProperty BlockedDomains | out-string).trim() | Out-File $BlockedDomainsFile
        Write-Host "`nBlocked domains list saved to $BlockedDomainsFile"
    }
    else {
        Write-Host "`nBlocked domains not defined, nothing to backup."
    }

    If ($policyObj.InvitationsAllowedAndBlockedDomainsPolicy.AllowedDomains) {
        ($policyObj.InvitationsAllowedAndBlockedDomainsPolicy | Select-Object -ExpandProperty AllowedDomains | out-string).trim() | Out-File $AllowedDomainsFile
        Write-Host "Allowed domains list saved to $AllowedDomainsFile`n"
    }
    else {
        Write-Host "Allowed domains not defined, nothing to backup.`n"
    }

} # end function SaveAllowBlockedList()

# Print Allowed and Blocked Domain List for the given policy
function PrintAllowBlockedList([String] $defString) {
    $policyObj = GetObjectFromJson $defString;

    $countAllowed = $policyObj.InvitationsAllowedAndBlockedDomainsPolicy.AllowedDomains.count
    Write-Host "`nAllowed Domains [$countAllowed]:`n" -ForegroundColor Green
    $i = 0
    ForEach ($domain in $policyObj.InvitationsAllowedAndBlockedDomainsPolicy.AllowedDomains) {
        $i++
        Write-Host "`t$i.`t$domain"
        if ($i -ge $intDisplayLimit) {
            Write-Host "`n   (Limited display to first $intDisplayLimit domains. Please use -Backup switch to output full list to file.)`n"
            Break;
        }
    }

    $countBlocked = $policyObj.InvitationsAllowedAndBlockedDomainsPolicy.BlockedDomains.count
    Write-Host "`nBlocked Domains [$countBlocked]:`n" -ForegroundColor Red
    $i = 0
    ForEach ($domain in $policyObj.InvitationsAllowedAndBlockedDomainsPolicy.BlockedDomains) {
        $i++
        Write-Host "`t$i.`t$domain"
        if ($i -ge $intDisplayLimit) {
            Write-Host "`n   (Limited display to first $intDisplayLimit domains. Please use -Backup switch to output full list to file.)`n"
            Break;
        }
    }

    # Print policy settings
    If ($countAllowed -eq 0 -and $countBlocked -eq 0) {
        Write-Host "`nCurrent policy settings : 'Allow invitations to be sent to any domain (most inclusive)'`n" -ForegroundColor Yellow
    }
    ElseIf ($countAllowed -eq 0 -and $countBlocked -gt 0) {
        Write-Host "`nCurrent policy settings : 'Deny invitations to the specified domains'`n" -ForegroundColor Yellow
    }
    ElseIf ($countBlocked -eq 0 -and $countAllowed -gt 0) {
        Write-Host "`nCurrent policy settings : 'Allow invitations only to the specified domains (most restrictive)'`n" -ForegroundColor Yellow
    }
    Else {
        Write-Host "`nCurrent policy settings : <UNKNOWN>" -ForegroundColor Yellow
    }
} # end function PrintAllowBlockedList()

# Gets AllowDomainList from the existing policy
function GetExistingAllowedDomainList() {
    $policy = GetExistingPolicy $strPolicyName

    if ($null -ne $policy) {
        $policyObject = GetObjectFromJson $policy.Definition[0];

        if ($null -ne $policyObject.InvitationsAllowedAndBlockedDomainsPolicy -and $null -ne $policyObject.InvitationsAllowedAndBlockedDomainsPolicy.AllowedDomains) {
            return $policyObject.InvitationsAllowedAndBlockedDomainsPolicy.AllowedDomains;
        }
    }
    return $null
} # end function GetExistingAllowedDomainList()

# Gets BlockDomainList from the existing policy
function GetExistingBlockedDomainList() {
    $policy = GetExistingPolicy $strPolicyName

    if ($null -ne $policy) {
        $policyObject = GetObjectFromJson $policy.Definition[0];

        if ($null -ne $policyObject.InvitationsAllowedAndBlockedDomainsPolicy -and $null -ne $policyObject.InvitationsAllowedAndBlockedDomainsPolicy.BlockedDomains) {
            return $policyObject.InvitationsAllowedAndBlockedDomainsPolicy.BlockedDomains;
        }
    }
    return $null
} # end function GetExistingBlockedDomainList()

# ###################################################################################################
# Main Script which sets the Allow/Block domain list policy
# according to the parameters specified by the user.
# ###################################################################################################

# Verify if connection to target tenant established

if (!($help)) { # If -help not used, verify connection to tenant
    try
    { $var = Get-AzureADTenantDetail }

    catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException]
    { Write-Host "`nYou're not connected. Connect to target tenant first with Connect-AzureAD()`n" -ForegroundColor Red; Exit }

    $currentpolicy = GetExistingPolicy $strPolicyName

    # Verify if policy exists
    $policyExist = ($null -ne $currentpolicy)
}
# Go thru all ParameterSetName scenarios
switch ($PSCmdlet.ParameterSetName) {

    # UPDATE scenarios
    "Update+BlockList" {
        Write-Host "`nSetting BlockDomainsList for B2BManagementPolicy (UPDATE)";
        $policyValue = GetJSONForAllowBlockDomainPolicy -BlockedDomains $BlockList
        break;
    }
    "Update+AllowList" {
        Write-Host "`nSetting AllowedDomainList for B2BManagementPolicy (UPDATE)";
        $policyValue = GetJSONForAllowBlockDomainPolicy -AllowDomains $AllowList
        break;
    }
    "Update+BlockListFile" {
        Write-Host "`nSetting BlockDomainsList for B2BManagementPolicy (UPDATE from file)";
        [array]$tempBlock = Get-Content $BlockListFile
        $policyValue = GetJSONForAllowBlockDomainPolicy -BlockedDomains $tempBlock
        break;
    }
    "Update+AllowListFile" {
        Write-Host "`nSetting AllowDomainsList for B2BManagementPolicy (UPDATE from file)";
        [array]$tempAllow = Get-Content $AllowListFile
        $policyValue = GetJSONForAllowBlockDomainPolicy -AllowDomains $tempAllow
        break;
    }

    # APPEND scenarios
    "Append+BlockList" {
        $ExistingBlockList = GetExistingBlockedDomainList

        if ($null -ne $ExistingBlockList) {
            Write-Host "`nSetting BlockDomainList for B2BManagementPolicy (APPEND).`n"
            $BlockList = $BlockList + $ExistingBlockList
        }
        else {
            Write-Host "`nExisting BlockDomainList is empty. Adding the domain list specified.`n"
        }
        $policyValue = GetJSONForAllowBlockDomainPolicy -BlockedDomains $BlockList
        break;
    }
    "Append+AllowList" {
        $ExistingAllowList = GetExistingAllowedDomainList

        if ($null -ne $ExistingAllowList) {
            Write-Host "`nSetting AllowDomainList for B2BManagementPolicy (APPEND).`n"
            $AllowList = $AllowList + $ExistingAllowList
        }
        else {
            Write-Host "`nExisting AllowDomainList List is empty. Adding the domain list specified.`n"
        }
        $policyValue = GetJSONForAllowBlockDomainPolicy -AllowDomains $AllowList
        break;
    }
    "Append+BlockListFile" {
        $ExistingBlockList = GetExistingBlockedDomainList
        [array]$tempBlock = Get-Content $BlockListFile

        if ($null -ne $ExistingBlockList) {
            Write-Host "`nSetting BlockDomainList for B2BManagementPolicy (APPEND from file).`n"
            $BlockList = $tempBlock + $ExistingBlockList
        }
        else {
            Write-Host "`nExisting BlockDomainList is empty. Adding the domain list specified.`n"
            $BlockList = $tempBlock
        }
        $policyValue = GetJSONForAllowBlockDomainPolicy -BlockedDomains $BlockList
        break;
    }

    "Append+AllowListFile" {
        $ExistingAllowList = GetExistingAllowedDomainList
        [array]$tempAllow = Get-Content $AllowListFile

        if ($null -ne $ExistingAllowList) {
            Write-Host "`nSetting AllowDomainList for B2BManagementPolicy (APPEND from file).`n"
            $AllowList = $tempAllow + $ExistingAllowList
        }
        else {
            Write-Host "`nExisting AllowDomainList List is empty. Adding the domain list specified.`n"
            $AllowList = $tempAllow
        }
        $policyValue = GetJSONForAllowBlockDomainPolicy -AllowDomains $AllowList
        break;
    }

    # Remove policy scenario
    "ClearPolicySet" {
        if ($policyExist -eq $true) {
            Write-Host "`nRemoved $strPolicyName Policy.`n";
            Remove-AzureADPolicy -Id $currentpolicy.Id | Out-Null
        }
        else {
            Write-Host "`nNo $strPolicyName policy to Remove.`n"
        }
        Exit
    }

    # Query existing policy scenario
    "ExistingPolicySet" {
        if ($null -ne $currentpolicy) {
            Write-Information "Current $strPolicyName definition:`n"
            PrintAllowBlockedList $currentpolicy.Definition[0];
        }
        else {
            Write-Host "`nNo $strPolicyName defined.`n" -ForegroundColor Red
        }
        Exit
    }

    # Backup policy scenario
    "BackupPolicySet" {
        if ($null -ne $currentpolicy) {
            SaveAllowBlockedList $currentpolicy.Definition[0];
        }
        else {
            Write-Host "`nNo $strPolicyName defined.`n" -ForegroundColor Red
        }
        Exit
    }

    # Display help
    "HelpPolicySet" {
        Get-Help $MyInvocation.MyCommand.Definition
        Exit
    }
}

if ($policyExist -and $null -ne $policyValue) {
    Write-Host "*** Details for the Existing Policy in Azure AD: "
    PrintAllowBlockedList $currentpolicy.Definition[0];

    Write-Host "`n***New Policy Changes:"
    PrintAllowBlockedList $policyValue;

    $title = "**************** [ Policy Change ] ***************";
    $message = "Do you want to continue changing existing policy ?";
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "Y"
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "N"

    # Count policy size + display info|warning|error message depends on policy size
    $policySize = [System.Text.Encoding]::ASCII.GetByteCount($policyValue)
    $policySizeKB = $policySize / 1KB
    $policySizeKBstr = $policySizeKB.ToString(".0000")
    $policySizeUpperLimitStr = $policySizeUpperLimit.ToString(".0000")

    if ($policySizeKB -gt $policySizeLowerLimit -and $policySizeKB -lt $policySizeUpperLimit) {
        Write-Host "   Info `t- Requested policy definition size: $policySizeKBstr KB"
        Write-Host "Warning `t- Requested policy size close to $policySizeUpperLimitStr KB" -ForegroundColor Yellow
    }
    elseif ($policySizeKB -gt $policySizeUpperLimit ) {
        Write-Host "   Info `t- Requested policy definition size: $policySizeKBstr KB"
        Write-Host "  Error `t- Requested policy size above $policySizeUpperLimitStr KB" -ForegroundColor Red
        Write-Host "        `t- You may contine script execution, but it is expected that policy change will fail." -ForegroundColor Red
    }
    else {
        Write-Host "   Info `t- Requested policy definition size: $policySizeKBstr KB"
    }

    # Display Y/N dialog for policy change
    [System.Management.Automation.Host.ChoiceDescription[]]$options = $no, $yes;
    $confirmation = $host.ui.PromptForChoice($title, $message, $options, 0);

    # Stop script execution if answer = N
    if ($confirmation -eq 0) {
        Exit
    }

    # Try to modify policy
    Try {
        Set-AzureADPolicy -Definition $policyValue -Id $currentpolicy.Id
        Write-Host "`nExecuting policy change...SUCCESS !"
    }
    Catch {
        Write-Host "`nExecuting policy change...FAILED !" -ForegroundColor Red
    }
}
else {
    # policy do not exist - create new one upon first append/update execution

    # Count policy size + display info|warning|error message depends on policy size
    $policySize = [System.Text.Encoding]::ASCII.GetByteCount($policyValue)
    $policySizeKB = $policySize / 1KB
    $policySizeKBstr = $policySizeKB.ToString(".0000")

    if ($policySizeKB -gt $policySizeLowerLimit -and $policySizeKB -lt $policySizeUpperLimit) {
        Write-Host "   Info `t- Requested policy definition size: $policySizeKBstr KB"
        Write-Host "Warning `t- Requested policy size close to $policySizeUpperLimitStr KB" -ForegroundColor Yellow
    }
    elseif ($policySizeKB -gt $policySizeUpperLimit ) {
        Write-Host "   Info `t- Requested policy definition size: $policySizeKBstr KB"
        Write-Host "  Error `t- Requested policy size above $policySizeUpperLimitStr KB" -ForegroundColor Red
    }
    else {
        Write-Host "   Info `t- Requested policy definition size: $policySizeKBstr KB"
    }

    Try {
        New-AzureADPolicy   -Definition $policyValue `
            -DisplayName $strPolicyName `
            -Type B2BManagementPolicy `
            -IsOrganizationDefault $true `
            -InformationAction Ignore | Out-Null
        Write-Host "`nExecuting policy change...SUCCESS !"
    }
    catch {
        Write-Host "`nExecuting policy change...FAILED !`n" -ForegroundColor Red
        Exit
    }
}

Write-Output "`nUpdated / New / Modified $strPolicyName Policy: "
$currentPolicy = GetExistingPolicy $strPolicyName
PrintAllowBlockedList $currentpolicy.Definition[0];

Exit