# Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.

# ─────────────────────────────────────────────────────────────────────────────
# function.tf
#
# Build flow:
#   1. null_resource.deploy_function_image
#        a) docker login  → OCIR
#        b) fn build      → build the Docker image from func.py / func.yaml
#        c) docker tag    → apply the full OCIR path tag
#        d) docker push   → push to OCIR
#   2. oci_functions_application  – Functions Application (VCN-attached, optional)
#   3. oci_functions_function     – Function pointing at the pushed image
# ─────────────────────────────────────────────────────────────────────────────

# ── OCIR Container Repository ─────────────────────────────────────────────────
resource "oci_artifacts_container_repository" "fn_repo" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.repository_name}/${local.function_name}"
  is_public      = false

  lifecycle {
    ignore_changes = [defined_tags]
  }
}

# ── Build & Push ──────────────────────────────────────────────────────────────
resource "null_resource" "deploy_function_image" {
  depends_on = [oci_artifacts_container_repository.fn_repo]

  triggers = {
    version = local.function_version
  }

  # Step 1 – docker login to OCIR
  provisioner "local-exec" {
    command = "echo '${var.ocir_password}' | docker login ${local.region_key}.ocir.io --username ${data.oci_objectstorage_namespace.ns.namespace}/${var.ocir_username} --password-stdin"
  }

  # Step 2 – build the function image using the fn CLI
  provisioner "local-exec" {
    command     = "fn --verbose build"
    working_dir = var.function_working_dir
  }

  # Step 3 – tag the locally built image with the full OCIR path
  provisioner "local-exec" {
    command     = <<-EOT
      IMAGE=$(docker images | grep ${local.function_name} | awk '{print $3}') ; \
      docker tag $IMAGE ${local.image_path}
    EOT
    working_dir = var.function_working_dir
  }

  # Step 4 – push the tagged image to OCIR
  provisioner "local-exec" {
    command     = "docker push ${local.image_path}"
    working_dir = var.function_working_dir
  }
}

# ── Functions Application ─────────────────────────────────────────────────────
resource "oci_functions_application" "this" {
  count = var.create_functions_application ? 1 : 0

  compartment_id = var.compartment_ocid
  display_name   = var.app_display_name
  subnet_ids     = [var.subnet_ocid]
  shape          = "GENERIC_ARM"

  lifecycle {
    ignore_changes = [defined_tags]
  }
}

# ── Function ──────────────────────────────────────────────────────────────────
resource "oci_functions_function" "this" {
  depends_on = [null_resource.deploy_function_image]

  application_id     = local.effective_application_id
  display_name       = var.function_display_name
  image              = local.image_path
  memory_in_mbs      = local.function_memory
  timeout_in_seconds = local.function_timeout

  config = local.function_config

  lifecycle {
    ignore_changes = [defined_tags]
  }
}
