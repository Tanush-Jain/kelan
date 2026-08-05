###############################################################################
# Kelan Security — Oracle Cloud ARM Deployment
# Provisions 1x Ampere A1.Flex (4 OCPU / 24 GB) — Always Free
###############################################################################

terraform {
  required_version = ">= 1.3"
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 6.0"
    }
  }
}

# ──────────────────────────────────────────────────────────────────────────────
# Variables — set via terraform.tfvars or environment (TF_VAR_*)
# ──────────────────────────────────────────────────────────────────────────────

variable "tenancy_ocid"         { description = "OCI tenancy OCID" }
variable "user_ocid"            { description = "OCI user OCID" }
variable "fingerprint"          { description = "API key fingerprint" }
variable "private_key_path"     { description = "Path to OCI private key PEM" }
variable "region"               { description = "OCI region (e.g. us-ashburn-1)" }
variable "compartment_id"       { description = "Target compartment OCID" }
variable "ssh_public_key"       { description = "SSH public key for instance access" }
variable "your_home_ip"         { description = "Your home/office IP for SSH (e.g. 1.2.3.4/32)" }

variable "instance_display_name" {
  default = "kelan-security-demo"
}

# ──────────────────────────────────────────────────────────────────────────────
# Provider
# ──────────────────────────────────────────────────────────────────────────────

provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.region
}

# ──────────────────────────────────────────────────────────────────────────────
# Data sources
# ──────────────────────────────────────────────────────────────────────────────

# Ubuntu 22.04 ARM64 — Canonical's official OCI image
data "oci_core_images" "ubuntu_arm" {
  compartment_id           = var.compartment_id
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "22.04"
  shape                    = "VM.Standard.A1.Flex"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

# Availability domains
data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

# ──────────────────────────────────────────────────────────────────────────────
# Network
# ──────────────────────────────────────────────────────────────────────────────

resource "oci_core_vcn" "kelan_vcn" {
  compartment_id = var.compartment_id
  cidr_block     = "10.0.0.0/16"
  display_name   = "kelan-vcn"
  dns_label      = "kelanvcn"
}

resource "oci_core_internet_gateway" "kelan_igw" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.kelan_vcn.id
  display_name   = "kelan-igw"
  enabled        = true
}

resource "oci_core_route_table" "kelan_rt" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.kelan_vcn.id
  display_name   = "kelan-route-table"

  route_rules {
    destination       = "0.0.0.0/0"
    network_entity_id = oci_core_internet_gateway.kelan_igw.id
  }
}

resource "oci_core_security_list" "kelan_sl" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.kelan_vcn.id
  display_name   = "kelan-security-list"

  # ── Egress: allow all outbound ──
  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }

  # ── Ingress rules ──

  # SSH — restricted to your IP for security
  ingress_security_rules {
    protocol    = "6" # TCP
    source      = var.your_home_ip
    description = "SSH — admin only"
    tcp_options { min = 22; max = 22 }
  }

  # HTTP — Kelan REST API
  ingress_security_rules {
    protocol    = "6"
    source      = "0.0.0.0/0"
    description = "Kelan HTTP API"
    tcp_options { min = 3000; max = 3000 }
  }

  # HTTPS — Kelan TLS API (optional, Cloudflare terminates SSL)
  ingress_security_rules {
    protocol    = "6"
    source      = "0.0.0.0/0"
    description = "Kelan HTTPS API"
    tcp_options { min = 3001; max = 3001 }
  }

  # Grafana dashboard
  ingress_security_rules {
    protocol    = "6"
    source      = var.your_home_ip
    description = "Grafana — admin only"
    tcp_options { min = 3003; max = 3003 }
  }

  # AITP UDP transport — the core protocol
  ingress_security_rules {
    protocol    = "17" # UDP
    source      = "0.0.0.0/0"
    description = "AITP Secure Transport"
    udp_options { min = 9999; max = 9999 }
  }

  # ICMP for diagnostics
  ingress_security_rules {
    protocol    = "1"
    source      = "0.0.0.0/0"
    description = "ICMP ping"
    icmp_options { type = 3; code = 4 }
  }
}

resource "oci_core_subnet" "kelan_subnet" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.kelan_vcn.id
  cidr_block                 = "10.0.1.0/24"
  display_name               = "kelan-subnet"
  dns_label                  = "kelansubnet"
  route_table_id             = oci_core_route_table.kelan_rt.id
  security_list_ids          = [oci_core_security_list.kelan_sl.id]
  prohibit_public_ip_on_vnic = false
}

# ──────────────────────────────────────────────────────────────────────────────
# Block Volume — persistent DB storage (50 GB, free up to 200 GB total)
# ──────────────────────────────────────────────────────────────────────────────

resource "oci_core_volume" "kelan_data" {
  compartment_id      = var.compartment_id
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  display_name        = "kelan-data-volume"
  size_in_gbs         = 50
  vpus_per_gb         = 10 # Balanced performance
}

# ──────────────────────────────────────────────────────────────────────────────
# Compute Instance — Ampere A1 (Always Free: 4 OCPU / 24 GB RAM)
# ──────────────────────────────────────────────────────────────────────────────

resource "oci_core_instance" "kelan_server" {
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  compartment_id      = var.compartment_id
  display_name        = var.instance_display_name
  shape               = "VM.Standard.A1.Flex"

  shape_config {
    ocpus         = 4
    memory_in_gbs = 24
  }

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.ubuntu_arm.images[0].id
    boot_volume_size_in_gbs = 50
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.kelan_subnet.id
    assign_public_ip = true
    display_name     = "kelan-primary-vnic"
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    # cloud-init user_data (base64 encoded at apply time)
    user_data = base64encode(file("${path.module}/../cloud-init/kelan-init.yaml"))
  }

  freeform_tags = {
    "project"     = "kelan-security"
    "environment" = "demo"
    "managed-by"  = "terraform"
  }
}

# Attach block volume
resource "oci_core_volume_attachment" "kelan_data_attach" {
  attachment_type = "paravirtualized"
  instance_id     = oci_core_instance.kelan_server.id
  volume_id       = oci_core_volume.kelan_data.id
  display_name    = "kelan-data-attachment"
  is_read_only    = false
}

# ──────────────────────────────────────────────────────────────────────────────
# Outputs
# ──────────────────────────────────────────────────────────────────────────────

output "instance_public_ip" {
  description = "Public IP — SSH using: ssh ubuntu@<ip>"
  value       = oci_core_instance.kelan_server.public_ip
}

output "aitp_api_url" {
  description = "Kelan REST API endpoint"
  value       = "http://${oci_core_instance.kelan_server.public_ip}:3000"
}

output "grafana_url" {
  description = "Grafana (admin only)"
  value       = "http://${oci_core_instance.kelan_server.public_ip}:3003"
}

output "aitp_udp_endpoint" {
  description = "AITP protocol endpoint"
  value       = "${oci_core_instance.kelan_server.public_ip}:9999"
}
