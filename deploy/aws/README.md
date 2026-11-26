# AWS example: one host for the Momus Compose stack

`scanner-host.yaml` is a CloudFormation template for one EC2 instance that runs this project's Compose stack (`compose.yaml`: the scanner, the brain, and, if you use it, the seeder). It is an example to read and adapt, not a managed service.

`test_template.py` and `cfn-lint` check it statically (see "Checks" below). Two values are not confirmed by the AWS documentation and are marked below; check them before you deploy.

## What it creates

| Resource | Why |
|---|---|
| A VPC with one public subnet, an internet gateway, and a route table | The host's own network. Instances get no public address at launch. |
| A security group with **no inbound rule** and all outbound traffic allowed | The scanner reaches public targets; nothing can connect in. |
| An Elastic IP associated with the instance | A static outbound address, so the people who own the targets can recognize the scan. |
| One EC2 instance (default `t4g.large`, arm64) from Canonical's Ubuntu Server 24.04 LTS image, through a public Systems Manager parameter | The host. The scanner is a container, so the host needs no security distribution. |
| An encrypted gp3 root volume (default 60 GiB, 30 to 1024) | Docker's data: images, the scan data, and the app database volumes. |
| Instance metadata: IMDSv2 required, hop limit 2 | See "Instance metadata" below. |
| An instance role with `AmazonSSMManagedInstanceCore` | Session Manager access. No key pair, no SSH. This template does not install the Session Manager agent: the AWS documentation says it is "likely" already installed on Ubuntu Server 24.04 LTS images. If the instance never appears in Session Manager, check that first, because there is no other way in. |
| Optional, off by default: one policy each for the seeder (assume one role; Route 53 listing) and for the brain's analyst (Bedrock) | See "Optional permissions". |
| A Data Lifecycle Manager policy (daily snapshots of the volumes of instances tagged `Backup=scan`, 7 kept) and its role | Backups. |
| A CloudWatch alarm on `StatusCheckFailed` (two 5-minute periods; missing data counts as failing), with an SNS topic and an optional email subscription, or an existing topic | To hear when the host is down. |

User data installs Docker and the Compose plugin from Ubuntu's own archive (`docker.io`, `docker-compose-v2`, and `docker-buildx`, Docker's build component, for `docker compose build`) and nothing else. It clones no repository and starts nothing: the steps after connecting are below.

The template creates no S3 bucket and grants no S3 permission: nothing in this project uses object storage.

## Costs to think about

No prices here; check the AWS pricing pages for your region.
- **The instance**, by the hour, while it runs (stopping it stops this charge, not the others).
- **The Elastic IP.** AWS charges by the hour for each public IPv4 address, in use or idle (Amazon VPC pricing page).
- **The root volume** (gp3, by the GiB-month) and **the snapshots** (by the GiB-month of changed data; seven daily ones are kept).
- Small: the CloudWatch alarm and SNS email. Data transfer out of AWS (scan traffic and image downloads), and, if you turn it on, Amazon Bedrock usage by the analyst.

## Before you deploy: two values to check

The AWS documentation does not confirm these two values:
1. **The image parameter path** `/aws/service/canonical/ubuntu/server/24.04/stable/current/<arm64|amd64>/hvm/ebs-gp3/ami-id`. The AWS documentation lists `canonical` among the publishers of public parameters, but does not show this path; the path follows Canonical's naming. Check that it resolves in your region (a read-only call):
   ```
   aws ssm get-parameters --names /aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id --query 'Parameters[0].Value' --output text
   ```
2. **The root device name** `/dev/sda1`. The AWS documentation says the root device is "/dev/sda1 or /dev/xvda", depending on the image. With the image id from step 1:
   ```
   aws ec2 describe-images --image-ids <image id> --query 'Images[0].RootDeviceName' --output text
   ```
   If it prints `/dev/xvda`, deploy with `RootDeviceName=/dev/xvda` (the parameter allows only these two names). A wrong value would attach the encrypted volume as a second disk and leave the root at the image's own size and encryption.

## Deploy

You need the AWS CLI with credentials for the target account, and the Session Manager plugin for the CLI (required to start sessions). From the repository root:

```
aws cloudformation deploy \
  --stack-name momus \
  --template-file deploy/aws/scanner-host.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides AlarmEmail=you@example.com
```

`CAPABILITY_IAM` is needed because the template creates IAM roles, an instance profile, and policies. The CloudFormation documentation requires `CAPABILITY_NAMED_IAM` instead for "IAM resources with custom names" without defining the term. No role or instance profile here sets a name; if the deploy fails with `InsufficientCapabilities`, use `CAPABILITY_NAMED_IAM`.

Other parameters: `InstanceType` (`t4g.large` with the default arm64 image; for x86, for example `InstanceType=t3.large` with `ImageParameter=/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id`), `VolumeGb`, `VpcCidr` (default `172.24.96.0/24`), `ExistingAlarmTopicArn` (when it is set, the stack creates no topic and `AlarmEmail` is not used), and the optional permissions below. Every free-text parameter has an allowed pattern, so a typing error is refused before anything is created. Confirm the SNS email subscription when it arrives.

The instance id and the static outbound address:

```
aws cloudformation describe-stacks --stack-name momus --query 'Stacks[0].Outputs' --output table
```

## Connect

A shell on the host (Session Manager; no SSH, no inbound rule):

```
aws ssm start-session --target <instance id>
```

The web UI, forwarded to your own machine at `127.0.0.1:8080` (the brain publishes port 8080 on the host's loopback address only):

```
aws ssm start-session --target <instance id> \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8080"],"localPortNumber":["8080"]}'
```

Then open `http://127.0.0.1:8080` locally. Keep that command running while you use the UI.

## After connecting (once)

User data has installed Docker and Compose (its log: `/var/log/momus-userdata.log`). In the shell session:

1. Put a copy of this project on the host, for example `sudo apt-get install -y git` and `git clone <your copy of the repository> momus`, or copy a release archive. Review what you copy: this template does not fetch it for you.
2. `cd momus`, then optionally create `.env` from `.env.example` (the brain's settings) and `seed.env` (the seeder's settings, the `SEED_*` variables in `.env.example`).
3. `sudo docker compose up -d --build` (builds the scanner image from the official Kali image, and the brain image, on this host).
4. `sudo docker compose logs brain` shows the one-time bootstrap token; open the UI through the port forward and create the first admin account.

## Instance metadata: hop limit 2, and what it means

The metadata service requires IMDSv2 tokens. The hop limit is **2**, not 1, so that a container on this host can obtain the instance role's credentials: the brain, when the analyst uses Amazon Bedrock with the instance role, and the seeder, when it reads Route 53 with the instance role.

**Consequence, plainly:** every container on this host that has a network can reach the instance metadata service and obtain the instance role's credentials, **except the scanner**. That includes the brain, the seeder, and any other container you run on this host. (The developer `jobctl` service has no network at all.) Give the instance role only the optional permissions you use; by default it has Session Manager only.

The scanner cannot reach it. Its egress firewall rejects the IPv4 link-local range `169.254.0.0/16`, which holds `169.254.169.254`, and every non-global IPv6 destination, which includes `fd00:ec2::/32`, before any scan tool runs. At every start it tries to connect to the metadata address and refuses to start unless that attempt fails (the firewall self-check in `scanner/entrypoint.sh`, `probe iptables 169.254.169.254 169.254.0.0/16`).

The tests that show it:
- `tests/e2e/run_demo.sh` check "1 the scanner installed and verified its firewall, then started the runner as uid 10001" (the container exits if the metadata probe connects);
- `tests/e2e/run_demo.sh` check "6 the scanner cannot connect to the decoy by address" (a private address that a plain container reaches is unreachable from the scanner);
- `tests/e2e/run_demo.sh` check "7 without NET_ADMIN the scanner exits non-zero" (the scanner does not start without its firewall);
- `deploy/aws/test_template.py::TemplateTest::test_metadata_hop_limit_is_2` (the template value, and that the scanner's start-up probe is in place).

## Optional permissions (all off by default)

**The seeder and Route 53** (`docker compose --profile seed ...`, settings in `seed.env`; see `.env.example`):
- `SeederHostedZoneIds=Z...,Z...`: the instance role may call `route53:ListHostedZones` (an action with no resource type, so on `*`) and `route53:ListResourceRecordSets` on those hosted zones only. Then set `SEED_ROUTE53=1` in `seed.env`. The seeder reads only public zones under domains the scanner has DNS-verified. That list comes from the scanner, so the scanner's list decides which zones the seeder lists: limit `SeederHostedZoneIds` (or the role in `SeederRoleArn`) to the zones meant to be seeded.
- `SeederRoleArn=arn:aws:iam::<account>:role/<name>`: the instance role may assume that one role (for example a read-only DNS role in another account; that role's trust policy must allow this stack's instance role). Then set `SEED_ROUTE53_ROLE_ARN` to the same ARN in `seed.env`.

**The brain's analyst and Amazon Bedrock** (no key: the brain's Bedrock adapter then uses the default AWS credential chain, here the instance role, with `MOMUS_ANALYST_REGION`). The analyst calls Converse, which needs `bedrock:InvokeModel`; the provider check tool also reads the model or profile once (below). Nothing else is granted:
- `BedrockAccess=model`, `BedrockModelId=<model id>`, optional `BedrockRegion` (default: the stack's region): `bedrock:InvokeModel` on that one foundation model in that region. This statement is this project's own construction from the documented ARN format, not a documented example. (The Converse page says the permission applies to "the inference target and the project"; the Service Authorization Reference marks the `project` resource as optional for `InvokeModel`, and the brain names no project, so none is granted.) In `.env`: `MOMUS_ANALYST_PROVIDER=bedrock`, `MOMUS_ANALYST_MODEL=<model id>`, `MOMUS_ANALYST_REGION=<region>`.
- `BedrockAccess=global-profile`, `BedrockModelId=<model id without the global. prefix>`: the three statements of the Bedrock user guide's example for a global cross-Region inference profile: the profile `global.<model id>` in the requesting region, and the model in that region and as the global model ARN (no region or account), each only when called through that profile. In `.env`: `MOMUS_ANALYST_MODEL=global.<model id>`.
- Geographic inference profiles (`us.`, `eu.`, and so on) need the model's ARN in each destination region of the profile; this template does not cover them. Follow the Bedrock user guide's "geographic cross-Region inference" example if you need one.

The provider check tool (`brain/tools/smoke_provider.py`, see `docs/analyst.md`) first asks Bedrock about the model: `GetFoundationModel` for a model id, or `GetInferenceProfile` for a profile id. Each policy grants that one read on the same resource it may invoke (`model`: `bedrock:GetFoundationModel` on the one foundation model; `global-profile`: `bedrock:GetInferenceProfile` on the `global.<model id>` profile in the requesting region), so the tool runs with the instance role alone. The analyst in the application does not make that call.

## Remove it

```
aws cloudformation delete-stack --stack-name momus
aws cloudformation wait stack-delete-complete --stack-name momus
```

This deletes the instance and its root volume (with the scan data and the app database on it), the Elastic IP, the network, the roles and policies, the lifecycle policy, the alarm, and, if the stack created it, the SNS topic. Snapshots are separate resources, and the AWS documentation does not confirm whether the lifecycle policy's snapshots are removed with it. Look for them afterwards (EC2 console, Snapshots, tag `Backup=scan`, or `aws ec2 describe-snapshots --owner-ids self --filters Name=tag:Backup,Values=scan`) and delete the ones you do not want to keep.

## Checks

Offline only; nothing below calls AWS. PyYAML and cfn-lint are not project dependencies; a throwaway container works:

```
# throwaway image (network is used only by this build, to install the two tools)
printf 'FROM python:3.13-slim\nRUN pip install --no-cache-dir pyyaml cfn-lint\n' | docker build -t momus-cfn-tools -
docker run --rm --network none -v "$PWD:/src:ro" -w /src momus-cfn-tools python3 -B -m unittest deploy/aws/test_template.py
docker run --rm --network none -v "$PWD:/src:ro" -w /src momus-cfn-tools cfn-lint --regions us-east-1 -- deploy/aws/scanner-host.yaml
```

`test_template.py` checks, among other things: no inbound rule, an encrypted gp3 root volume, IMDSv2 with hop limit 2, no key pair, no wildcard action or resource except where `route53:ListHostedZones` needs one, every optional permission off by default, an allowed pattern on every free-text parameter, and user data that installs only Docker and Compose.
