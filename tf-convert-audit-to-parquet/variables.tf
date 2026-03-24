# Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.

# ORM injects this automatically; not shown in the UI form
variable "tenancy_ocid" {}

variable "region" {
  description = "OCI region identifier (e.g. us-ashburn-1)"
  type        = string
}

# ── Placement ─────────────────────────────────────────────────────────────────
variable "compartment_ocid" {
  description = "Compartment where all resources are created"
  type        = string
}

variable "vcn_ocid" {
  description = "VCN OCID"
  type        = string
}

variable "subnet_ocid" {
  description = "Subnet OCID for the Functions Application"
  type        = string
}

# ── OCIR ──────────────────────────────────────────────────────────────────────
variable "ocir_username" {
  description = "OCIR login username (format: oracleidentitycloudservice/<email>)"
  type        = string
}

variable "ocir_password" {
  description = "OCI Auth Token for OCIR (generate under User Settings → Auth Tokens)"
  type        = string
  sensitive   = true
}

variable "repository_name" {
  description = "OCIR repository name"
  type        = string
  default     = "security-lake-repo"
}

# ── Functions Application & Function ──────────────────────────────────────────
variable "app_display_name" {
  description = "Display name for the OCI Functions Application"
  type        = string
  default     = "security-lake-app"
}

variable "create_functions_application" {
  description = "Set to true to create a new Functions Application, false to use an existing one"
  type        = bool
  default     = true
}

variable "existing_application_ocid" {
  description = "OCID of an existing Functions Application (used when create_functions_application = false)"
  type        = string
  default     = ""
}

variable "function_display_name" {
  description = "Display name for the OCI Function"
  type        = string
  default     = "log-converter"
}

# ── Parquet output ─────────────────────────────────────────────────────────────
variable "parquet_bucket" {
  description = "Object Storage bucket where converted Parquet files are written"
  type        = string
  default     = "Parquet_Security_Lake_Audit_Logs"
}

variable "parquet_namespace" {
  description = "Object Storage namespace for the Parquet bucket. Leave blank to use the tenancy namespace automatically."
  type        = string
  default     = ""
}

# ── Function tuning ───────────────────────────────────────────────────────────
variable "function_memory_in_mbs" {
  description = "Memory allocated to the function (MB) – overridden by func.yaml if set"
  type        = number
  default     = 1024
}

variable "function_timeout_in_seconds" {
  description = "Function execution timeout (seconds) – overridden by func.yaml if set"
  type        = number
  default     = 300
}

# ── Internal – not shown in ORM UI ────────────────────────────────────────────
variable "function_working_dir" {
  description = "Path to the directory containing func.py, func.yaml, requirements.txt"
  type        = string
  default     = "./function"
}
