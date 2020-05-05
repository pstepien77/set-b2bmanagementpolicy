# set-b2bmanagementpolicy
 Azure - Manage B2B Management Policy settings with PowerShell

Helps admin to update the Azure B2BManagementPolicy for Allow/Block domain list for inviting external Users.
Powershell must be connected to target tenant before running this script (using Connect-AzureAD cmdlet).

Operations available:
- Query policy
- Backup existing policy
- Remove existing policy
- Update/Append allowed domain list
- Update/Append blocked domain list

Prerequisites
- Sufficient AAD role to modify B2BManagement policy in target tenant
- AzureAD or AzureADPreview PowerShell module available
- Powershell must be connected to target tenant before running this script (using Connect-AzureAD cmdlet)

Please refer to implementation.pdf for full details.
