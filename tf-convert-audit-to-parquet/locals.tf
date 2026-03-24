# Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.

locals {
  # Derive the short 3-letter OCIR region key from the full region name.
  # Used to construct OCIR image URLs: <region_key>.ocir.io/...
  region_key = lower(
    one([
      for r in data.oci_identity_regions.all.regions : r.key
      if r.name == var.region
    ])
  )

  # Read function metadata once from func.yaml so all resources stay in sync.
  func_yaml        = yamldecode(file("${var.function_working_dir}/func.yaml"))
  function_name    = local.func_yaml["name"]
  function_version = local.func_yaml["version"]
  function_memory  = try(local.func_yaml["memory"], var.function_memory_in_mbs)
  function_timeout = try(local.func_yaml["timeout"], var.function_timeout_in_seconds)

  # Full OCIR image reference used by oci_functions_function and docker commands
  image_path = "${local.region_key}.ocir.io/${data.oci_objectstorage_namespace.ns.namespace}/${var.repository_name}/${local.function_name}:${local.function_version}"

  # ---------------------------------------------------------------------------
  # Function config environment variables.
  #
  # The converter function reads gzip-JSON files from the raw bucket (written
  # by Service Connector Hub) and writes ZSTD-compressed Parquet files to the
  # Parquet bucket, partitioned by logs/{source}/{yyyy}/{MM}/{dd}/{HH}/.
  # ---------------------------------------------------------------------------
  function_config = {
    PARQUET_BUCKET    = var.parquet_bucket
    PARQUET_NAMESPACE = var.parquet_namespace != "" ? var.parquet_namespace : data.oci_objectstorage_namespace.ns.namespace
  }

  # Resolve the application OCID – either the newly created one or an existing one
  effective_application_id = (
    var.create_functions_application
    ? oci_functions_application.this[0].id
    : var.existing_application_ocid
  )
}
