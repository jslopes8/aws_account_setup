# Terraform module to AWS Account Setup

The code will provide the following features on AWS.

* [IAM Account Alias](https://www.terraform.io/docs/providers/aws/r/iam_account_alias.html)
* [IAM Account Password Policy](https://www.terraform.io/docs/providers/aws/r/iam_account_password_policy.html)
* [CloudTrail](https://www.terraform.io/docs/providers/aws/r/cloudtrail.html)
* [IAM Policy Document](https://www.terraform.io/docs/providers/aws/d/iam_policy_document.html)


This template will perform setup on a new aws account, adjusting:

- The alias for account
- Account Setting Password Policy
- Enabled CloudTrail
- Enable MFA
- Is Account Catho (set up s3 bucket for cloud8)

## Usage
Example of use Complete: Enabled CloudTrail, Set Permission Control Tower, adjusting password policy and account alias.

```hcl
module "compasso_baseline" {
    source = "git@gitlab.uoldiveo.intranet:ump/aws_compasso_baseline.git?ref=v0.1"

    account_master  = "arn:aws:iam::471784020190:root"

    account_alias   = "test-baseline"
    iam_group_name  = "Admin"

    set_permission_control_tower = "true"

    enable_mfa              = "false"
    enable_cloudtrail       = "true"
    is_multi_region_trail   = "false"

    enable_cross_account_admin      = "true"
    enable_cross_account_billing    = "true"

    enable_cloudhealth  = "true"
    account_id  = "454464851268"
    external_id = "8745c229b2d2f7e2d0b6444b0d390f"

    is_account_catho    = "true"

    account_password_policy = [
        {
            minimum_password_length         = "8"
            require_lowercase_characters    = "true"
            require_uppercase_characters    = "true"
            require_symbols                 = "true"
            require_numbers                 = "true"
            hard_expiry                     = "true"
            max_password_age                = "90"
        }
    ]
}
```

## Requirements
| Name | Version |
| ---- | ------- |
| aws | ~> 2.70 |
| terraform | ~> 0.12.28 |

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Variables Inputs
| Name | Description | Required | Type | Default |
| ---- | ----------- | -------- | ---- | ------- |
| account_alias | The alias of the account | `yes` | `string` | ` ` |
| account_password_policy | Manages Password Policy for the AWS Account. | `no` | `any` | `[ ]` |
| enable_cloudtrail | If you want to create the cloudtrail resource. | `no` | `bool` | `true` |
| enable_logging | Enables logging for the trail. | `no` | `bool` | `true` |
| is_multi_region_trail | Specifies whether the trail is created in the current region or in all regions. | `no` | `bool` | `false` |
| enable_mfa | Limits the user to manage only themselves and no other resources are allowed until he sets up MFA | `no` | `bool` | `false` |
| set_permission_control_tower | Allows AWS Control Tower to manage your individual accounts and report information about them to your audit and logging accounts. | `no` | `bool` | `false` |
| is_account_catho | Creates a bucket with permission for another third party account to access the CUR. | `no` | `bool` | `false` |



## Variable Outputs
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
| Name | Description |
| ---- | ----------- |
