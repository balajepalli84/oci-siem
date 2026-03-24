# Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.

output "function_ocid" {
  description = "OCID of the deployed log-converter function"
  value       = oci_functions_function.this.id
}

output "function_invoke_endpoint" {
  description = "HTTPS endpoint to invoke the function directly"
  value       = oci_functions_function.this.invoke_endpoint
}

output "functions_application_id" {
  description = "OCID of the Functions Application"
  value       = local.effective_application_id
}

output "image_path" {
  description = "Full OCIR image path that was built and pushed"
  value       = local.image_path
}

output "object_storage_namespace" {
  description = "Object Storage namespace used by the function"
  value       = data.oci_objectstorage_namespace.ns.namespace
}
