packer {
  required_version = "= 1.16.0"

  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = "= 1.8.0"
    }
  }
}

variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "base_ami_id" {
  type = string
  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.base_ami_id))
    error_message = "base_ami_id must be an exact AMI ID"
  }
}

variable "builder_subnet_id" {
  type = string
}

variable "builder_security_group_id" {
  type = string
}

variable "builder_instance_profile" {
  type = string
  validation {
    condition     = var.builder_instance_profile == "archon-datahub-core-ami-builder-staging"
    error_message = "builder_instance_profile must be the exact foundation-managed profile"
  }
}

variable "builder_key_pair_name" {
  type = string
  validation {
    condition     = can(regex("^archon-datahub-core-ami-[1-9][0-9]{0,19}$", var.builder_key_pair_name))
    error_message = "builder_key_pair_name must be owned by the exact workflow run"
  }
}

variable "builder_private_key_file" {
  type = string
}

variable "source_bundle" {
  type = string
}

variable "release_sha" {
  type = string
}

variable "generation" {
  type = string
}

variable "companion_source_sha" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.companion_source_sha))
    error_message = "companion_source_sha must be one exact Git commit"
  }
}

variable "capability_digest" {
  type = string
}

variable "image_manifest_digest" {
  type = string
}

variable "workflow_run_id" {
  type = string
}

variable "packer_manifest_output" {
  type = string
}

variable "bake_evidence_output" {
  type = string
}

source "amazon-ebs" "datahub_core" {
  region                      = var.region
  source_ami                  = var.base_ami_id
  instance_type               = "t3a.xlarge"
  communicator                = "ssh"
  ssh_username                = "ec2-user"
  ssh_interface               = "session_manager"
  ssh_timeout                 = "20m"
  ssh_clear_authorized_keys   = true
  subnet_id                   = var.builder_subnet_id
  security_group_id           = var.builder_security_group_id
  iam_instance_profile        = var.builder_instance_profile
  associate_public_ip_address = true
  ssh_keypair_name            = var.builder_key_pair_name
  ssh_private_key_file        = var.builder_private_key_file
  force_deregister            = false
  force_delete_snapshot       = false
  ami_name                    = "archon-datahub-core-${var.generation}-${formatdate("YYYYMMDDhhmmss", timestamp())}"
  ami_description             = "CI-baked four-component ephemeral DataHub Core ${var.generation}"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_type           = "gp3"
    volume_size           = 50
    iops                  = 3000
    throughput            = 125
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Application               = "archon-datahub"
    Environment               = "staging"
    ArchonDataHubCore         = "verified"
    ArchonFourComponents      = "mcp,ack,skills,analytics"
    ArchonGeneration          = var.generation
    ArchonCapabilityDigest    = var.capability_digest
    ArchonImageManifestDigest = var.image_manifest_digest
    ArchonReleaseSha          = var.release_sha
    ArchonCompanionSourceSha  = var.companion_source_sha
    ArchonBuildRun            = var.workflow_run_id
    ManagedBy                 = "github-actions"
    "archon:Purpose"          = "datahub-core-ami"
    "archon:BuildRun"         = var.workflow_run_id
  }

  run_tags = {
    Application       = "archon-datahub"
    Environment       = "staging"
    ArchonBuildRun    = var.workflow_run_id
    ManagedBy         = "github-actions"
    "archon:Purpose"  = "datahub-core-ami"
    "archon:BuildRun" = var.workflow_run_id
  }

  run_volume_tags = {
    Application       = "archon-datahub"
    Environment       = "staging"
    ArchonBuildRun    = var.workflow_run_id
    ManagedBy         = "github-actions"
    "archon:Purpose"  = "datahub-core-ami"
    "archon:BuildRun" = var.workflow_run_id
  }

  snapshot_tags = {
    Application       = "archon-datahub"
    Environment       = "staging"
    ArchonBuildRun    = var.workflow_run_id
    ManagedBy         = "github-actions"
    "archon:Purpose"  = "datahub-core-ami"
    "archon:BuildRun" = var.workflow_run_id
  }
}

build {
  name    = "archon-datahub-core"
  sources = ["source.amazon-ebs.datahub_core"]

  provisioner "file" {
    source      = var.source_bundle
    destination = "/tmp/archon-datahub-core-source.tar.gz"
  }

  provisioner "shell" {
    script           = "infra/aws/packer/provision-datahub-core.sh"
    execute_command  = "chmod +x ${path}; sudo -E ${path}"
    environment_vars = [
      "ARCHON_RELEASE_SHA=${var.release_sha}",
      "ARCHON_BASE_AMI_ID=${var.base_ami_id}",
      "ARCHON_COMPANION_SOURCE_SHA=${var.companion_source_sha}",
      "ARCHON_GENERATION=${var.generation}",
      "ARCHON_CAPABILITY_DIGEST=${var.capability_digest}",
      "ARCHON_IMAGE_MANIFEST_DIGEST=${var.image_manifest_digest}"
    ]
  }

  provisioner "file" {
    direction   = "download"
    source      = "/tmp/archon-datahub-core-bake-evidence.tar.gz"
    destination = var.bake_evidence_output
  }

  provisioner "shell" {
    inline = [
      "sudo rm -f -- /tmp/archon-datahub-core-bake-evidence.tar.gz",
      "test ! -e /tmp/archon-datahub-core-bake-evidence.tar.gz"
    ]
  }

  post-processor "manifest" {
    output      = var.packer_manifest_output
    strip_path  = true
    custom_data = {
      releaseSha          = var.release_sha
      companionSourceSha  = var.companion_source_sha
      generation          = var.generation
      capabilityDigest    = var.capability_digest
      imageManifestDigest = var.image_manifest_digest
      baseAmiId            = var.base_ami_id
      osPatched             = true
    }
  }
}