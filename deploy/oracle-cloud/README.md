# 🚀 Deploy Kelan Security to Oracle Cloud (Always Free ARM)

**Estimated time to live server: ~20 minutes. Zero cloud experience required.**

---

## Step 1 — Create a Free Oracle Cloud Account

1. Go to [cloud.oracle.com](https://cloud.oracle.com) → click **"Start for free"**
2. Sign up with a real email (card required for verification, but **not charged**)
3. Choose your **Home Region** — pick the closest one (you can't change this later)
4. Wait for the confirmation email and finish account activation

> **Always Free limits:** 4x Ampere A1 OCPU + 24 GB RAM + 200 GB block storage — permanently free.

---

## Step 2 — Create a Compartment

1. Log in → top-left hamburger → **"Identity & Security"** → **"Compartments"**
2. Click **"Create Compartment"**
   - Name: `kelan-demo`
   - Click **"Create"**
3. Copy the **Compartment OCID** (you'll need it for Terraform)

---

## Step 3 — Generate an API Key for Terraform

1. Top-right → click your profile → **"User Settings"**
2. Scroll to **"API Keys"** → click **"Add API Key"**
3. Select **"Generate API Key Pair"** → download the private key
4. Click **"Add"** — copy the **Configuration file preview** (has all the OCIDs)

---

## Step 4 — Set Up Terraform

```bash
# Install Terraform (macOS)
brew install terraform

# Or Linux
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg
echo "deb [arch=arm64 signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt-get update && sudo apt-get install terraform

cd kelan-core/deploy/oracle-cloud/terraform
```

Create `terraform.tfvars`:
```hcl
tenancy_ocid     = "ocid1.tenancy.oc1..your_tenancy_id"
user_ocid        = "ocid1.user.oc1..your_user_id"
fingerprint      = "xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx"
private_key_path = "/path/to/your/oci_private_key.pem"
region           = "us-ashburn-1"  # your home region
compartment_id   = "ocid1.compartment.oc1..your_compartment_id"
ssh_public_key   = "ssh-rsa AAAA... your@email.com"
your_home_ip     = "1.2.3.4/32"  # your public IP - curl ifconfig.me
```

---

## Step 5 — Deploy

```bash
terraform init
terraform plan   # Review what will be created (safe, no changes yet)
terraform apply  # Type 'yes' — takes ~3 minutes
```

Terraform will output:
```
instance_public_ip = "129.xxx.xxx.xxx"
aitp_api_url       = "http://129.xxx.xxx.xxx:3000"
grafana_url        = "http://129.xxx.xxx.xxx:3003"
```

**Cloud-init will run in the background (~8 minutes).** The instance is booting.

---

## Step 6 — Verify Deployment

```bash
# SSH into the instance
ssh ubuntu@129.xxx.xxx.xxx

# Watch cloud-init progress
sudo tail -f /var/log/cloud-init-output.log

# Once complete, run the health check
curl http://localhost:3000/health
# Expected: {"status":"ok","version":"0.3.0"}

# Check AITP UDP listener
ss -ulnp | grep 9999

# View live logs
sudo docker logs -f kelan-server

# Grafana URL
echo "http://$(curl -s ifconfig.me):3003"
```

### Run `kelan doctor` (health check all services):
```bash
sudo docker exec kelan-server curl -s http://localhost:3000/health | jq .
sudo ss -ulnp | grep 9999  # AITP UDP
sudo bpftool prog list | grep xdp  # eBPF (if eBPF-native build)
sudo systemctl status kelan
```

---

## Step 7 — Edit Configuration

```bash
sudo nano /opt/kelan/.env
# Set:
#   AITP_AI_ENGINE_OLLAMA_BASE_URL=http://localhost:11434
#   JWT_SECRET=a_random_64_char_string
#   GRAFANA_PASSWORD=your_grafana_password

sudo systemctl restart kelan
```

---

## Step 8 (Optional) — Point a Domain + Cloudflare Free SSL

**You get HTTPS for free via Cloudflare's "Flexible" SSL mode:**

1. Register a domain (Namecheap: ~$8/year, or free at Freenom)
2. Add it to [dash.cloudflare.com](https://dash.cloudflare.com) (Free plan)
3. Add these DNS records:
   ```
   Type: A    Name: @        Value: 129.xxx.xxx.xxx  (your Oracle IP)
   Type: A    Name: demo     Value: 129.xxx.xxx.xxx
   ```
4. In Cloudflare: **SSL/TLS** → set to **"Flexible"**
5. In Cloudflare: **Rules** → Page Rules → redirect HTTP to HTTPS
6. Add a Cloudflare **Firewall Rule** to proxy through Cloudflare (hides your real IP)

Your API is now at `https://demo.yourdomain.com/health` with free SSL.

---

## Useful Commands

```bash
# Server management
sudo systemctl status kelan
sudo systemctl restart kelan
sudo docker compose -f /opt/kelan/docker-compose.yml logs -f

# Attack simulation (test eBPF enforcement)
cd /opt/kelan-src && cargo run --example attack_sim -- --server localhost:9999 --mode ddos

# Block volume usage
df -h /mnt/kelan-data

# Generate JWT token for API access
sudo docker exec kelan-server aitp-server generate-token \
  --org-id "my-org" --email "admin@myorg.com" --role "admin"
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `cloud-init` still running | `sudo tail -f /var/log/cloud-init-output.log` |
| Port 3000 not responding | `sudo systemctl status kelan` + `sudo docker logs kelan-server` |
| eBPF fails to load | Normal without `--features ebpf-native`. Kelan falls back to userspace enforcement |
| Block volume not mounted | `sudo mount -a` then `ls /mnt/kelan-data` |
| Image pull fails | Edit `/opt/kelan/docker-compose.yml` to use `build: .` instead |
