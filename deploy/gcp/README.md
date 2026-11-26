# Google Cloud example: one VM for the Momus Compose stack

`momus-host.sh` prints, and with `--apply` runs, the `gcloud` commands for one Compute Engine VM that runs this project's Compose stack, with no public inbound access.

Every flag it uses is listed below with the Google Cloud documentation page it follows. `test_momus_host.sh` checks the script without contacting Google Cloud (see "Checks").

## What it creates

| Resource | Command | Why |
|---|---|---|
| A custom-mode VPC network `<name>-net` and one subnet `<name>-subnet` (default `10.80.0.0/24`, private Google access on) | `networks create`, `networks subnets create` | The VM's own network. |
| One firewall rule `<name>-allow-iap-ssh`: inbound TCP 22 **only from 35.235.240.0/20**, only to VMs tagged `<name>` | `firewall-rules create` | 35.235.240.0/20 is the range Identity-Aware Proxy uses for TCP forwarding. The script adds no other inbound rule. |
| A regional static external address `<name>-egress` | `addresses create` | Used only as Cloud NAT's outbound address: a static outbound address the owners of your targets can recognize. The VM itself has **no external address**. |
| A Cloud Router `<name>-router` and Cloud NAT `<name>-nat` using that address | `routers create`, `routers nats create` | Outbound access for a VM with no external address. |
| The VM `<name>`: Ubuntu 24.04 LTS (`ubuntu-os-cloud`, family `ubuntu-2404-lts-amd64` or `-arm64`), default `e2-standard-2` (`t2a-standard-2` for arm64), a 60 GB `pd-balanced` persistent boot disk, shielded VM options on, OS Login on, project-wide SSH keys blocked, **no service account and no API scopes** | `instances create` | The host. It needs no Google API access. |
| A startup script (`startup.sh`) | `--metadata-from-file=startup-script=...` | Compute Engine runs it as root at boot. It installs Docker and the Compose plugin from Ubuntu's archive (`docker.io`, `docker-compose-v2`, and `docker-buildx`, Docker's build component, for `docker compose build`) and nothing else: it clones no repository and starts nothing. When Docker and Compose are already present, it does nothing. |

Not created: snapshots (add a snapshot schedule to the boot disk if you want backups), and any IAM grant (below).

## Costs to think about

No prices here; check Google Cloud's pricing pages for your region. The VM while it runs; the persistent disk; the static external address; Cloud NAT (per gateway and per data processed); outbound data transfer (scan traffic and image downloads); and, if you configure the analyst with a model provider, that provider's usage.

## Before you start

- The `gcloud` CLI, signed in to an account that can create these resources in the project.
- To connect, your account needs the IAP-secured tunnel role on the VM or project (`roles/iap.tunnelResourceAccessor`) and the OS Login roles described on Google Cloud's OS Login page.
- The Compute Engine API enabled in the project.

## Create

Print the commands first (nothing runs):

```
deploy/gcp/momus-host.sh --project <project id> --region us-central1 --zone us-central1-a
```

Read them. Then run them, in order, stopping at the first failure:

```
deploy/gcp/momus-host.sh --project <project id> --region us-central1 --zone us-central1-a --apply
```

Options: `--name` (prefix of every resource, default `momus`), `--arch amd64|arm64` (default `amd64`), `--machine-type`, `--disk-gb` (30 to 1024, default 60), `--range` (the subnet: an IPv4 range from /16 to /28 whose first number is 10, 172, or 192; use a private range, because the script does not check the rest). Every value is checked against a whole-string pattern before it is put in a command, and the zone must be in the region.

## Connect

A shell, through Identity-Aware Proxy (the VM has no external address):

```
gcloud compute ssh <name> --project=<project id> --zone=<zone> --tunnel-through-iap
```

The web UI on your own machine at `127.0.0.1:8080` (the brain publishes port 8080 on the VM's loopback address only):

```
gcloud compute ssh <name> --project=<project id> --zone=<zone> --tunnel-through-iap --ssh-flag="-L 8080:localhost:8080"
```

Then open `http://127.0.0.1:8080` locally, while that session stays open.

## After connecting (once)

The startup script's log is `/var/log/momus-startup.log`. Then:
1. Put a copy of this project on the VM, for example `sudo apt-get install -y git` and `git clone <your copy of the repository> momus`. Review what you copy.
2. `cd momus`, then optionally create `.env` from `.env.example` (the brain's settings) and `seed.env` (the seeder's settings, the `SEED_*` variables in `.env.example`).
3. `sudo docker compose up -d --build`, then `sudo docker compose logs brain` for the one-time bootstrap token, and create the first admin account through the UI.

The VM has no service account, so neither the brain nor the seeder gets Google credentials from the metadata server. The analyst's provider key and the seeder's keys go in Docker secret files as described in `compose.yaml` and `.env.example`.

## Remove it

```
deploy/gcp/momus-host.sh --project <project id> --region <region> --zone <zone> --delete            # print
deploy/gcp/momus-host.sh --project <project id> --region <region> --zone <zone> --delete --apply    # run
```

This deletes, in order: the VM (and its boot disk, which holds the scan data and the app database), the Cloud NAT, the router, the static address, the firewall rule, the subnet, and the network.

## Checks

`deploy/gcp/test_momus_host.sh` (offline):
- `bash -n` on both scripts, and `shellcheck` (image `koalaman/shellcheck:v0.10.0`) on all three when Docker can provide that image (otherwise the shellcheck step is skipped and says so);
- the default mode and `--delete` without `--apply` run no command: the script runs in a `bash:5.2` container with no network and no variable from this machine, with a recording stand-in `gcloud` first on `PATH`, and the stand-in records nothing; `--apply` is never passed;
- the printed commands carry the settings above (no external address, OS Login, no service account, the IAP-only firewall rule, the NAT address, and the arm64 image), and every invalid value is refused.

## Documentation the commands follow

Every page is under `https://docs.cloud.google.com/`. Each `instances create` flag follows its reference page; `--image-family`, `--no-address`, `--no-service-account`, and `--no-scopes` are members of "at most one of these" groups there (with `--image`, `--address`, `--service-account`, and `--scopes`), which this script respects.

| Command or setting | Page |
|---|---|
| `networks create --subnet-mode=custom` | `sdk/gcloud/reference/compute/networks/create` |
| `networks subnets create --network --region --range --enable-private-ip-google-access` | `sdk/gcloud/reference/compute/networks/subnets/create` |
| `firewall-rules create --network --direction=INGRESS --action=allow --rules=tcp:22 --source-ranges --target-tags` | `sdk/gcloud/reference/compute/firewall-rules/create` |
| 35.235.240.0/20 is IAP's TCP forwarding range; `roles/iap.tunnelResourceAccessor` | `iap/docs/using-tcp-forwarding` |
| `addresses create --region` (regional external IPv4 address) | `sdk/gcloud/reference/compute/addresses/create`, `vpc/docs/reserve-static-external-ip-address` |
| `routers create --network --region` | `sdk/gcloud/reference/compute/routers/create` |
| `routers nats create --router --region --nat-all-subnet-ip-ranges --nat-external-ip-pool` | `sdk/gcloud/reference/compute/routers/nats/create`, `nat/docs/set-up-manage-network-address-translation` |
| `instances create --zone --machine-type --subnet --no-address --boot-disk-size --boot-disk-type --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring --tags --metadata --metadata-from-file --no-service-account --no-scopes --image-project` | `sdk/gcloud/reference/compute/instances/create` |
| `--image-family` with `--image-project` on `instances create`, and the metadata `enable-oslogin=TRUE` | `compute/docs/oslogin/set-up-oslogin` (its `instances create` example) |
| metadata `block-project-ssh-keys=TRUE` | `compute/docs/connect/restrict-ssh-keys` |
| Ubuntu 24.04 LTS: project `ubuntu-os-cloud`, families `ubuntu-2404-lts-amd64`, `ubuntu-2404-lts-arm64` | `compute/docs/images/os-details` |
| `pd-balanced` is the Balanced Persistent Disk type | `compute/docs/disks/persistent-disks` |
| `e2-standard-2` and `t2a-standard-2` are machine types; T2A "runs on the Ampere Altra Arm processor" | `compute/docs/general-purpose-machines` (pairing T2A with the `-arm64` image family is this script's inference: the page does not say which images T2A needs) |
| the `startup-script` metadata key runs as root at boot | `compute/docs/instances/startup-scripts/linux` |
| `compute ssh --tunnel-through-iap --ssh-flag` | `sdk/gcloud/reference/compute/ssh` |
| `--project` is a global flag | `sdk/gcloud/reference` (Global flags) |
| `instances delete`, `routers nats delete --router --region`, `routers delete`, `addresses delete`, `firewall-rules delete`, `networks subnets delete`, `networks delete` | `sdk/gcloud/reference/compute/<command>/delete` for each |

Not from Google Cloud's documentation: the package names `docker.io`, `docker-buildx`, and `docker-compose-v2` are packages in Ubuntu 24.04's own archive.
