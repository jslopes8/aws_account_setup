### Get Account id current
data "aws_caller_identity" "current" {}

#####################################
#                                   #
# Compasso UOL Baseline             #
# Set up Account Alias              #
#                                   #
#####################################
resource "aws_iam_account_alias" "main" {
    count   = var.create ? 1 : 0

    account_alias = var.account_alias
}

#####################################
#                                   #
# Compasso UOL Baseline             #
# Set up IAM Group Admin            #
#                                   #
######################################
resource "aws_iam_group" "admin" {
  count = var.enable_admin_group ? 1 : 0

  name = var.iam_group_name
}
resource "aws_iam_group_policy_attachment" "admin" {
  count = var.enable_admin_group ? 1 : 0

  group      = aws_iam_group.admin[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
resource "aws_iam_group_policy_attachment" "manage_pass" {
  count = var.enable_admin_group ? 1 : 0

  group      = aws_iam_group.admin[0].name
  policy_arn = "arn:aws:iam::aws:policy/IAMUserChangePassword"
}

#####################################
#                                   #
# Compasso UOL Baseline             #
# Set up Password Policy            #
#                                   #
#####################################
resource "aws_iam_account_password_policy" "main" {
    count = var.create ? length(var.account_password_policy) : 0


    minimum_password_length         = lookup(var.account_password_policy[count.index], "minimum_password_length", null)
    require_lowercase_characters    = lookup(var.account_password_policy[count.index], "require_lowercase_characters", null)
    require_numbers                 = lookup(var.account_password_policy[count.index], "require_numbers", null)
    require_uppercase_characters    = lookup(var.account_password_policy[count.index], "require_uppercase_characters", null)
    require_symbols                 = lookup(var.account_password_policy[count.index], "require_symbols", null)
    allow_users_to_change_password  = lookup(var.account_password_policy[count.index], "allow_users_to_change_password", null)
    max_password_age                = lookup(var.account_password_policy[count.index], "max_password_age", null)
    hard_expiry                     = lookup(var.account_password_policy[count.index], "hard_expiry", null)
}

#####################################
#                                   #
# Compasso UOL Baseline             #
# Set up Force MFA                  #
#                                   #
#####################################
data "aws_iam_policy_document" "force_mfa" {
    count = var.enable_mfa ? 1 : 0

    statement {
        sid = "AllowAllUsersToListAccounts"
        effect = "Allow"
        actions = [
            "iam:ListAccountAliases",
            "iam:ListUsers",
            "iam:ListVirtualMFADevices",
            "iam:GetAccountPasswordPolicy",
            "iam:GetAccountSummary"
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowIndividualUserToSeeAndManageOnlyTheirOwnAccountInformation"
        effect = "Allow"
        actions = [
            "iam:ChangePassword",
            "iam:CreateAccessKey",
            "iam:CreateLoginProfile",
            "iam:DeleteAccessKey",
            "iam:DeleteLoginProfile",
            "iam:GetLoginProfile",
            "iam:ListAccessKeys",
            "iam:UpdateAccessKey",
            "iam:UpdateLoginProfile",
            "iam:ListSigningCertificates",
            "iam:DeleteSigningCertificate",
            "iam:UpdateSigningCertificate",
            "iam:UploadSigningCertificate",
            "iam:ListSSHPublicKeys",
            "iam:GetSSHPublicKey",
            "iam:DeleteSSHPublicKey",
            "iam:UpdateSSHPublicKey",
            "iam:UploadSSHPublicKey",
            "iam:ListUsers"
          ]
          resources = [
            "arn:aws:iam::*:user/*"
          ]
    }
    statement {
      sid = "AllowIndividualUserToListOnlyTheirOwnMFA"
      effect = "Allow"
      actions = [
        "iam:ListMFADevices",
        "iam:ListUsers"
      ]
      resources = [
        "arn:aws:iam::*:mfa/*",
        "arn:aws:iam::*:user/$${aws:username}"
      ]
    }
    statement {
      sid = "AllowIndividualUserToManageTheirOwnMFA"
        effect = "Allow"
        actions = [
          "iam:CreateVirtualMFADevice",
          "iam:DeleteVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ResyncMFADevice",
          "iam:ChangePassword",
          "iam:ListUsers"
        ]
        resources = [
          "arn:aws:iam::*:mfa/$${aws:username}",
          "arn:aws:iam::*:user/$${aws:username}"
        ]
      }
      statement {
        sid = "AllowIndividualUserToDeactivateOnlyTheirOwnMFAOnlyWhenUsingMFA"
        effect = "Allow"
        actions = [
          "iam:DeactivateMFADevice"
        ]
        resources = [
          "arn:aws:iam::*:mfa/$${aws:username}",
          "arn:aws:iam::*:user/$${aws:username}"
        ]
        condition {
          test = "Bool"
          variable = "aws:MultiFactorAuthPresent"
          values = [
            "true"
          ]
        }
      }
      statement {
        sid = "BlockMostAccessUnlessSignedInWithMFA"
        effect = "Deny"
        not_actions = [
          "iam:CreateVirtualMFADevice",
          "iam:DeleteVirtualMFADevice",
          "iam:ListVirtualMFADevices",
          "iam:EnableMFADevice",
          "iam:ResyncMFADevice",
          "iam:ListAccountAliases",
          "iam:ListUsers",
          "iam:ListSSHPublicKeys",
          "iam:ListAccessKeys",
          "iam:ListServiceSpecificCredentials",
          "iam:ListMFADevices",
          "iam:GetAccountSummary",
          "sts:GetSessionToken",
          "iam:ChangePassword"
        ]
        resources = [
          "*"
        ]
        condition {
          test = "BoolIfExists"
          variable = "aws:MultiFactorAuthPresent"
          values = [
            "false",
          ]
        }
      }
}
resource "aws_iam_policy" "mfa" {
  count = var.enable_mfa ? 1 : 0

    name        = "MFAForceRolePolicy"
    path        = "/"
    description = "Policy to enforce MFA"

    policy  = data.aws_iam_policy_document.force_mfa.0.json
}
resource "aws_iam_group_policy_attachment" "mfa" {
  count = var.enable_admin_group && var.enable_mfa ? 1 : 0

  group      = aws_iam_group.admin[0].name
  policy_arn = aws_iam_policy.mfa.0.arn
}

#####################################
#                                   #
# Compasso UOL Baseline             #
# Set up Account Catho              #
#                                   #
#####################################
resource "aws_s3_bucket" "is_account_catho" {
    count   = var.is_account_catho ? 1 : 0

    bucket              = "billing-data-${var.account_alias}"
    acl                 = "private"
    #region              = "us-east-1"
    server_side_encryption_configuration {
        rule {
            apply_server_side_encryption_by_default {
                sse_algorithm = "AES256"
            }
        }
    }
    versioning {
        enabled = "true"
    }
}
resource "aws_iam_role" "is_account_catho" {
    count = var.is_account_catho ? 1 : 0

    name        = "CrossAccountLambdaBilling"
    path        = "/"

    assume_role_policy    = data.aws_iam_policy_document.is_account_catho.0.json
    force_detach_policies = "false"
    max_session_duration  = "3600"
}
data "aws_iam_policy_document" "is_account_catho" {
    count   = var.is_account_catho ? 1 : 0

    statement   {
        effect  = "Allow"
        actions = [
            "sts:AssumeRole"
        ]
        principals {
            type        = "AWS"
            identifiers = [ 
                "${var.account_master}"
            ]
        }
    }
}
resource "aws_iam_role_policy" "is_account_catho_1" {
    count = var.is_account_catho ? 1 : 0

    name      = "${aws_iam_role.is_account_catho.0.name}-RolePolicy"
    role      = aws_iam_role.is_account_catho.0.id
    policy    = data.aws_iam_policy_document.is_account_catho_1.0.json
}
data "aws_iam_policy_document" "is_account_catho_1" {
    count   = var.is_account_catho ? 1 : 0

    statement   {
        effect  = "Allow"
        actions = [
            "s3:*"
        ]
        resources   = [
            "arn:aws:s3:::${aws_s3_bucket.is_account_catho.0.id}",
            "arn:aws:s3:::${aws_s3_bucket.is_account_catho.0.id}/*"
        ]
    }
   statement   {
        effect  = "Deny"
        actions = [
            "s3:DeleteBucket",
            "s3:DeleteBucketPolicy",
            "s3:DeleteBucketWebsite",
            "s3:DeleteObject",
            "s3:DeleteObjectVersion"
        ]
        resources   = [
            "arn:aws:s3:::${aws_s3_bucket.is_account_catho.0.id}",
            "arn:aws:s3:::${aws_s3_bucket.is_account_catho.0.id}/*"
        ]
    }
}

#####################################
#                                   #
# Compasso UOL Baseline             #
# Set Permission Control Tower      #
#                                   #
#####################################

resource "aws_iam_role" "control_tower" {
    count = var.set_permission_control_tower ? 1 : 0

    name        = "AWSControlTowerExecution"
    path        = "/"

    assume_role_policy    = data.aws_iam_policy_document.control_tower.0.json
    force_detach_policies = "false"
    max_session_duration  = "3600"
}
data "aws_iam_policy_document" "control_tower" {
    count   = var.set_permission_control_tower ? 1 : 0

    statement   {
        effect  = "Allow"
        actions = [
            "sts:AssumeRole"
        ]
        principals {
            type        = "AWS"
            identifiers = [ 
                "${var.account_master}"
            ]
        }
    }
}
resource "aws_iam_role_policy_attachment" "control_tower" {
    count = var.set_permission_control_tower ? 1 : 0

    role       = aws_iam_role.control_tower.0.id
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}