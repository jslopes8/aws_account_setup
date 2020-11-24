output "account_alias" {
    value   = length(aws_iam_account_alias.main) > 0 ? aws_iam_account_alias.main.*.account_alias : null
}
output "group_name" {
    value   = length(aws_iam_group.admin) > 0 ? aws_iam_group.admin.*.name : null 
}
output "group_arn" {
    value   = length(aws_iam_group.admin) > 0 ? aws_iam_group.admin.*.arn : null
}
output "role_admin" {
    value   = length(aws_iam_role.enable_cross_account_admin) > 0 ? aws_iam_role.enable_cross_account_admin[0].name : null
}
output "role_billing" {
    value   = length(aws_iam_role.enable_cross_account_billing) > 0 ? aws_iam_role.enable_cross_account_billing[0].name : null
}
output "cloudhealth" {
    value   = length(aws_iam_role.enable_cloudhealth) > 0 ? aws_iam_role.enable_cloudhealth[0].arn : null
}
output "catho" {
    value   = [
        length(aws_s3_bucket.is_account_catho) > 0 ? aws_s3_bucket.is_account_catho.0.id : null,
        length(aws_iam_role.is_account_catho) > 0 ? aws_iam_role.is_account_catho.0.name : null
    ]
}
