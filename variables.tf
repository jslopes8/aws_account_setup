variable "create" {
    type    = bool
    default = true
}
variable "account_master" {
    type    = string
}
variable "cross_account_arn" {
    type    = string
    default = null
}
variable "account_alias" {
    type    = string
    default = null
}
variable "enable_admin_group" {
    type    = bool
    default = true
}
variable "iam_group_name" {
    type    = string
    default = null
}
variable "account_password_policy" {
    type    = any 
    default = []
}
variable "enable_mfa" {
    type    = bool
    default = false
}
variable "enable_cloudtrail" {
    type    = bool
    default = false
}
variable "is_multi_region_trail" {
    type    = bool
    default = false
}
variable "enable_cross_account_admin" {
    type    = bool
    default = false
}
variable "enable_cross_account_billing" {
    type    = bool
    default = false
}
variable "enable_cloudhealth" {
    type    = bool
    default = false
}
variable "account_id" {
    type    = number
    default = null
}
variable "external_id" {
    type    = string
    default = null
}
variable "is_account_catho" {
    type    = bool
    default = false
}
variable "set_permission_control_tower" {
    type    = bool
    default = false
}
variable "set_guardrails_detection" {
    type = bool
    default = false
}
variable "check_ec2_volume_inuse" {
    type = bool
    default = false
}
variable "check_eip_attached" {
    type = bool
    default = false
}
variable "check_sg_open_only_authorized_ports" {
    type = bool
    default = false
}
variable "check_iam_password_policy" {
    type = bool
    default = false
}
variable "check_iam_user_mfa_enabled" {
    type = bool
    default = false
}
variable "check_iam_user_console_mfa_enabled" {
    type = bool
    default = false
}
variable "check_root_mfa_enabled" {
    type = bool
    default = false
}
variable "check_access_keys_rotated" {
    type = bool
    default = false
}
variable "check_ebs_optimized_instance" {
  type = bool
  default = false
}
variable "check_rds_public_access" {
  type = bool
  default = false
}
variable "check_rds_public_snapshots" {
  type = bool
  default = false
}
variable "check_rds_storage_encryption" {
  type = bool
  default = false
}
variable "check_restricted_common_ports_policy" {
  type = bool
  default = false
}
variable "check_restricted_ssh_policy" {
  type = bool
  default = false
}
variable "check_s3_bucket_public_write" {
  type = bool
  default = false
}
variable "check_s3_bucket_versioning_enabled" {
  type = bool
  default = false
}
variable "check_s3_bucket_public_read" {
  type = bool
  default = false
}
variable "check_encrypted_volumes" {
  type = bool
  default = false
}
