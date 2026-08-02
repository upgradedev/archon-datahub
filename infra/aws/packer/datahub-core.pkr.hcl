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

variable "capability_digest" {
  type = string
}

variable "image_manifest_digest" {
  type = string
}

variable "workflow_run_id" {
  type = string
}

source "amazon-ebs" "datahub_core" {
  region                      = var.region
  source_ami                  = var.base_ami_id
  instance_type               = "t3a.xlarge"
  ssh_username                = "ec2-user"
  subnet_id                   = var.builder_subnet_id
  security_group_id           = var.builder_security_group_id
  iam_instance_profile        = var.builder_instance_profile
  associate_public_ip_address = true
  temporary_key_pair_type     = "ed25519"
  shutdown_behavior           = "terminate"
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
    Application                    = "archon-datahub"
    ArchonDataHubCore              = "verified"
    ArchonFourComponents           = "mcp,ack,skills,analytics"
    ArchonGeneration               = var.generation
    ArchonCapabilityDigest         = var.capability_digest
    ArchonImageManifestDigest      = var.image_manifest_digest
    ArchonReleaseSha               = var.release_sha
    ArchonBuildRun                 = var.workflow_run_id
    ManagedBy                      = "github-actions"
  }

  run_tags = {
    Application      = "archon-datahub"
    ArchonBuildRun   = var.workflow_run_id
    ManagedBy        = "github-actions"
  }

  run_volume_tags = {
    Application      = "archon-datahub"
    ArchonBuildRun   = var.workflow_run_id
    ManagedBy        = "github-actions"
  }

  snapshot_tags = {
    Application      = "archon-datahub"
    ArchonBuildRun   = var.workflow_run_id
    ManagedBy        = "github-actions"
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
    script          = "infra/aws/packer/provision-datahub-core.sh"
    execute_command = "chmod +x ${path}; sudo -E ${path}"
    environment_vars = [
      "ARCHON_RELEASE_SHA=${var.release_sha}",
      "ARCHON_GENERATION=${var.generation}",
      "ARCHON_CAPABILITY_DIGEST=${var.capability_digest}",
      "ARCHON_IMAGE_MANIFEST_DIGEST=${var.image_manifest_digest}"
    ]
  }

  post-processor "manifest" {
    output     = "datahub-core-packer-manifest.json"
    strip_path = true
    custom_data = {
      releaseSha         = var.release_sha
      generation         = var.generation
      capabilityDigest   = var.capability_digest
      imageManifestDigest = var.image_manifest_digest
    }
  }
}
