```html
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

Table of contents

1 Introduction ......................................................................... 2 
1.1 Executive summary .................................................................. 2 
1.2 External collaboration settings .................................................... 2 
1.3 Scope .............................................................................. 2 
1.4 Collaboration restriction settings ................................................. 2 
1.5 Collaboration restriction settings – important considerations ...................... 3 
2 Set the allow or deny list policy in the portal ...................................... 4 
2.1 Add a deny list .................................................................... 4 
2.2 Add an allow list .................................................................. 5 
2.3 Switch from allow to deny list and vice versa ...................................... 6 
3 Set the allow or deny list policy using PowerShell ................................... 7 
3.1 Set-B2BManagementPolicy.ps1 script description ..................................... 7 
3.1.1 Prerequisites .................................................................... 7 
3.1.2 Script parameters ................................................................ 7 
3.2 Set-B2BManagementPolicy.ps1 script usage ........................................... 9 
3.2.1 Query policy ..................................................................... 10 
3.2.2 Backup existing policy ........................................................... 10 
3.2.3 Remove existing policy ........................................................... 11 
3.2.4 Update allowed/blocked domain list ............................................... 12 
3.2.5 Update allowed/blocked domain list from file...................................... 13 
3.2.6 Append allowed/blocked domain list ............................................... 14 
3.2.7 Append allowed/blocked domain list from file ..................................... 15 
3.3 Common patterns .................................................................... 16 
3.3.1 Modify default policy for the first time ......................................... 16 
3.3.2 Modify existing policy (replace all data) ........................................ 16 
3.3.3 Modify existing policy (remove unwanted data) .................................... 16 
3.3.4 Modify existing policy (append new data) ......................................... 16 
3.4 Policy definition limits ........................................................... 17 
3.4.1 Warning .......................................................................... 17 
3.4.2 Error ............................................................................ 18 

Please refer to implementation.pdf for full details.
```
