variable "create" {
    type    = bool
    default = true
}
variable "account_master" {
    type    = string
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
