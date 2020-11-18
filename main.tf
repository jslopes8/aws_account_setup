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
# Set up CloudTrail                 #
#                                   #
#####################################
resource "aws_cloudtrail" "main" {
    count  = var.enable_cloudtrail ? 1 : 0

    depends_on = [ aws_s3_bucket.enable_cloudtrail ]

    name                            = "compasso-uol-basesline-cloudtrail-${data.aws_caller_identity.current.account_id}"
    s3_bucket_name                  = aws_s3_bucket.enable_cloudtrail.0.id
    include_global_service_events   = "true"
    enable_logging                  = "true"
    is_multi_region_trail           = var.is_multi_region_trail
    
    event_selector {
            include_management_events   = "true"
            read_write_type             = "All"
            data_resource {
                type    = "AWS::Lambda::Function"
                values  = [ "arn:aws:lambda" ]
            }
    }
    event_selector {
            include_management_events   = "true"
            read_write_type             = "All"
            data_resource {
                type    = "AWS::S3::Object"
                values  = [ "arn:aws:s3:::" ]
            }
    }
}
resource "aws_s3_bucket" "enable_cloudtrail" {
    count   = var.enable_cloudtrail ? 1 : 0

    bucket              = "s3-compasso-uol-basesline-cloudtrail-${data.aws_caller_identity.current.account_id}"
    acl                 = "private"
    #region              = "us-east-1"
    server_side_encryption_configuration {
        rule  {
            apply_server_side_encryption_by_default {
                sse_algorithm = "AES256"
            }
        }
    }
    versioning {
        enabled = "true"
    }
}
resource "aws_s3_bucket_policy" "main" {    
    count   = var.enable_cloudtrail ? 1 : 0

    depends_on = [ aws_s3_bucket.enable_cloudtrail ]

    bucket  = aws_s3_bucket.enable_cloudtrail.0.id
    policy  = data.aws_iam_policy_document.role_policy.0.json
}
data "aws_iam_policy_document" "role_policy" {
    count   = var.enable_cloudtrail ? 1 : 0

    statement   {
        sid     = "AWSCloudTrailAclCheck"
        effect  = "Allow"
        actions = [ 
                "s3:GetBucketAcl",
        ]
        principals {
            type = "Service"
            identifiers = [ "cloudtrail.amazonaws.com" ]
        }
        resources   = [
            "${aws_s3_bucket.enable_cloudtrail.0.arn}"
        ]
    }
    statement   {
        sid = "AWSCloudTrailWrite"
        effect  = "Allow"
        actions     = [ 
            "s3:PutObject" 
        ]
        principals {
            type = "Service"
            identifiers = [ "cloudtrail.amazonaws.com" ]
        }
        resources   = [ 
            "${aws_s3_bucket.enable_cloudtrail.0.arn}/AWSLogs/*",
        ]
        condition {
            test        = "StringEquals"
            variable    = "s3:x-amz-acl"
            values      = [ 
                "bucket-owner-full-control" 
            ]
        }
    }
}

#####################################
#                                   #
# Compasso UOL Baseline             #
# Set up CrossAccountAdmin          #
#                                   #
#####################################
resource "aws_iam_role" "enable_cross_account_admin" {
    count = var.enable_cross_account_admin ? 1 : 0

    name        = "CrossAccountAdmin"
    path        = "/"
    description = "Compasso UOL Baseline - Allows Access via Payer/222"

    assume_role_policy    = data.aws_iam_policy_document.enable_cross_account_admin_0.0.json
    force_detach_policies = "false"
    max_session_duration  = "3600"
}
data "aws_iam_policy_document" "enable_cross_account_admin_0" {
    count   = var.enable_cross_account_admin ? 1 : 0

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
resource "aws_iam_role_policy" "enable_cross_account_admin" {
    count = var.enable_cross_account_admin ? 1 : 0

    name      = "${aws_iam_role.enable_cross_account_admin.0.name}-RolePolicy"
    role      = aws_iam_role.enable_cross_account_admin.0.id
    policy    = data.aws_iam_policy_document.enable_cross_account_admin_1.0.json
}
data "aws_iam_policy_document" "enable_cross_account_admin_1" {
    count   = var.enable_cross_account_admin ? 1 : 0

    statement   {
        sid = "AdministratorAccess"
        effect  = "Allow"
        actions = [
            "*"
        ]
        resources   = [
            "*"
        ]
    }
}

#####################################
#                                   #
# Compasso UOL Baseline             #
# Set up CrossAccountBilling        #
#                                   #
#####################################
resource "aws_iam_role" "enable_cross_account_billing" {
    count = var.enable_cross_account_billing ? 1 : 0

    name        = "CrossAccountBilling"
    path        = "/"
    description = "Compasso UOL Baseline - Allows Access via Payer/222"

    assume_role_policy    = data.aws_iam_policy_document.enable_cross_account_billing_0.0.json
    force_detach_policies = "false"
    max_session_duration  = "3600"
}
data "aws_iam_policy_document" "enable_cross_account_billing_0" {
    count   = var.enable_cross_account_billing ? 1 : 0

    statement   {
        effect  = "Allow"
        actions = [
            "sts:AssumeRole"
        ]
        principals  {
            type        = "AWS"
            identifiers = [ 
                "${var.account_master}"
            ]
        }
    }
}
resource "aws_iam_role_policy" "enable_cross_account_billing_1" {
    count = var.enable_cross_account_billing ? 1 : 0

    name      = "${aws_iam_role.enable_cross_account_billing.0.name}-RolePolicy"
    role      = aws_iam_role.enable_cross_account_billing.0.id
    policy    = data.aws_iam_policy_document.enable_cross_account_billing_1.0.json
}
data "aws_iam_policy_document" "enable_cross_account_billing_1" {
    count   = var.enable_cross_account_billing ? 1 : 0

    statement   {
        sid = "TrustedAdvisorAdmin"
        effect  = "Allow"
        actions = [
            "trustedadvisor:*"
        ]
        resources   = [
            "*"
        ]
    }
}
resource "aws_iam_role_policy_attachment" "enable_cross_account_billing_0" {
    count = var.enable_cross_account_billing ? 1 : 0

    role       = aws_iam_role.enable_cross_account_billing.0.id
    policy_arn = "arn:aws:iam::aws:policy/job-function/Billing"
}

#####################################
#                                   #
# Compasso UOL Baseline             #
# Set up CloudHealth                #
#                                   #
#####################################
resource "aws_iam_role" "enable_cloudhealth" {
    count = var.enable_cloudhealth ? 1 : 0

    name        = "Compasso-UOL-MGMT"
    path        = "/"
    description = "Compasso UOL Baseline - Enabled of the CloudHealth on Your Account"

    assume_role_policy    = data.aws_iam_policy_document.enable_cloudhealth_0.0.json
    force_detach_policies = "false"
    max_session_duration  = "3600"
}
data "aws_iam_policy_document" "enable_cloudhealth_0" {
    count = var.enable_cloudhealth ? 1 : 0

    statement   {
        effect  = "Allow"
        actions = [
            "sts:AssumeRole"
        ]
        principals {
            type        = "AWS"
            identifiers = [ 
                "${var.account_id}"
            ]
        }
        condition {
            test        =   "StringEquals"
            variable    =   "sts:ExternalId"
            values  = [
                "${var.external_id}"
            ]
        }
    }
}
resource "aws_iam_policy" "enable_cloudhealth" {
    count   = var.enable_cloudhealth ? 1 : 0

    name    = "Compasso-UOL-MGMT"
    policy  = data.aws_iam_policy_document.enable_cloudhealth_1.0.json
}
data "aws_iam_policy_document" "enable_cloudhealth_1" {
    count   = var.enable_cloudhealth ? 1 : 0
    statement {
        sid = "AllowIAM"
        effect = "Allow"
        actions = [
            "iam:List*",
            "iam:Get*",
            "iam:GenerateCredentialReport",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowEC2"
        effect = "Allow"
        actions = [
            "ec2:Describe*",
            "ec2:GetReservedInstancesExchangeQuote",
            "ecs:List*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowCloudFormation"
        effect = "Allow"
        actions = [
                "cloudformation:ListStacks",
                "cloudformation:ListStackResources",
                "cloudformation:DescribeStacks",
                "cloudformation:DescribeStackEvents",
                "cloudformation:DescribeStackResources",
                "cloudformation:GetTemplate",
                "cloudfront:Get*",
                "cloudfront:List*",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetEventSelectors",
                "cloudtrail:ListTags",
                "cloudwatch:Describe*",
                "cloudwatch:Get*",
                "cloudwatch:List*",
        ]
        resources = [
            "*"
        ]
    } 
    statement {
        sid = "AllowAWSConfig"
        effect = "Allow"
        actions = [
                "config:Get*",
                "config:Describe*",
                "config:Deliver*",
                "config:List*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowPortal"
        effect = "Allow"
        actions = [
                "aws-portal:ViewBilling",
                "aws-portal:ViewUsage",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowASG"
        effect = "Allow"
        actions = [
            "autoscaling:Describe*"
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowCurDMS"
        effect = "Allow"
        actions = [
                "cur:Describe*",
                "dms:Describe*",
                "dms:List*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowDynamodb"
        effect = "Allow"
        actions = [
                "dynamodb:DescribeTable",
                "dynamodb:List*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowECS"
        effect = "Allow"
        actions = [
                "ecs:Describe*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowElaticache"
        effect = "Allow"
        actions = [
                "elasticache:Describe*",
                "elasticache:ListTagsForResource",
                "elasticbeanstalk:Check*",
                "elasticbeanstalk:Describe*",
                "elasticbeanstalk:List*",
                "elasticbeanstalk:RequestEnvironmentInfo",
                "elasticbeanstalk:RetrieveEnvironmentInfo",
                "elasticfilesystem:Describe*",
                "elasticloadbalancing:Describe*",
                "elasticmapreduce:Describe*",
                "elasticmapreduce:List*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowES"
        effect = "Allow"
        actions = [
                "es:List*",
                "es:Describe*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowFirehose"
        effect = "Allow"
        actions = [
                "firehose:ListDeliveryStreams",
                "firehose:DescribeDeliveryStream",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowS3"
        effect = "Allow"
        actions = [
                "s3:GetBucketAcl",
                "s3:GetBucketLocation",
                "s3:GetBucketLogging",
                "s3:GetBucketPolicy",
                "s3:GetBucketTagging",
                "s3:GetBucketVersioning",
                "s3:GetBucketWebsite",
                "s3:List*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowKMS"
        effect = "Allow"
        actions = [
                "kms:DescribeKey",
                "kms:GetKeyRotationStatus",
                "kms:ListKeys",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowKinesis"
        effect = "Allow"
        actions = [
                "kinesis:Describe*",
                "kinesis:List*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowRDS"
        effect = "Allow"
        actions = [
                "rds:Describe*",
                "rds:ListTagsForResource",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowRoute53"
        effect = "Allow"
        actions = [
                "route53:Get*",
                "route53:List*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowLambda"
        effect = "Allow"
        actions = [
                "lambda:List*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowLogs"
        effect = "Allow"
        actions = [
                "logs:Describe*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowRedshift"
        effect = "Allow"
        actions = [
                "redshift:Describe*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowSagemaker"
        effect = "Allow"
        actions = [
                "sagemaker:Describe*",
                "sagemaker:List*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowSDB"
        effect = "Allow"
        actions = [
                "sdb:GetAttributes",
                "sdb:List*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowSES"
        effect = "Allow"
        actions = [
                "ses:Get*",
                "ses:List*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowSNS"
        effect = "Allow"
        actions = [
                "sns:Get*",
                "sns:List*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowSQS"
        effect = "Allow"
        actions = [
                "sqs:GetQueueAttributes",
                "sqs:ListQueues",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowStorageGateway"
        effect = "Allow"
        actions = [
                "storagegateway:List*",
                "storagegateway:Describe*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowWorkspaces"
        effect = "Allow"
        actions = [
                "workspaces:Describe*",
        ]
        resources = [
            "*"
        ]
    }
    statement {
        sid = "AllowSavinsPlans"
        effect = "Allow"
        actions = [
                "savingsplans:DescribeSavingsPlans"
        ]
        resources = [
            "*"
        ]
    }
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

#####################################
#                                   #
# Compasso UOL Baseline             #
# Set conforme Pack                 #
#                                   #
#####################################

resource "aws_config_config_rule" "volume_inuse" {
    count = var.set_guardrails_detection || var.check_ec2_volume_inuse ? 1 : 0

    name = "Compasso-Baseline-EC2VolumeInUseCheck"
    description = "A Config rule that checks whether EBS volumes are attached to EC2 instances. Optionally checks if EBS volumes are marked for deletion when an instance is terminated."

    source {
        owner = "AWS"
        source_identifier = "EC2_VOLUME_INUSE_CHECK"
    }
    scope {
        compliance_resource_types = ["AWS::EC2::Volume"]
    }
}

resource "aws_config_config_rule" "eip_attached" {
    count = var.set_guardrails_detection || var.check_eip_attached ? 1 : 0

    name = "Compasso-Baseline-EIPAttached"
    description = "A Config rule that checks whether all Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs)."

    source {
        owner = "AWS"
        source_identifier = "EIP_ATTACHED"
    }
    scope {
        compliance_resource_types = ["AWS::EC2::EIP"]
    }
}
resource "aws_config_config_rule" "sg_open_only-to-authorized" {
    count = var.set_guardrails_detection || var.check_sg_open_only_authorized_ports ? 1 : 0

    name = "Compasso-Baseline-SecurityGroup-OnlyAuthorizedPorts"
    description = "A Config rule that checks whether the security group with 0.0.0.0/0 of any Amazon Virtual Private Cloud (Amazon VPCs) allows only specific inbound TCP or UDP traffic. The rule and any security group with inbound 0.0.0.0/0. is NON_COMPLIANT, if you do n..."

    source {
        owner = "AWS"
        source_identifier = "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS"
    }
    scope {
        compliance_resource_types = ["AWS::EC2::SecurityGroup"]
    }
}
resource "aws_config_config_rule" "iam_user_mfa" {
    count = var.set_guardrails_detection || var.check_iam_user_mfa_enabled ? 1 : 0

    name = "Compasso-Baseline-IAMUser-MFA-Enabled"
    description = "A config rule that checks whether the AWS Identity and Access Management users have multi-factor authentication (MFA) enabled."

    source {
        owner = "AWS"
        source_identifier = "IAM_USER_MFA_ENABLED"
    }
    scope {
        compliance_resource_types = []
    }
}
resource "aws_config_config_rule" "root_mfa" {
    count = var.set_guardrails_detection || var.check_root_mfa_enabled ? 1 : 0

    name = "Compasso-Baseline-RootAccount-MFA-Enabled"
    description = "A Config rule that checks whether users of your AWS account require a multi-factor authentication (MFA) device to sign in with root credentials."

    source {
        owner = "AWS"
        source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
    }
    scope {
        compliance_resource_types = []
    }
}
resource "aws_config_config_rule" "access_keys_rotated" {
    count = var.set_guardrails_detection || var.check_access_keys_rotated ? 1 : 0

    name = "Compasso-Baseline-AccessKeys-Rotated"
    description = "A config rule that checks whether the active access keys are rotated within the number of days specified in maxAccessKeyAge. The rule is NON_COMPLIANT if the access keys have not been rotated for more than maxAccessKeyAge number of days."
    input_parameters = "{\"maxAccessKeyAge\":\"90\"}"

    source {
        owner = "AWS"
        source_identifier = "ACCESS_KEYS_ROTATED"
    }
    scope {
        compliance_resource_types = []
    }
}
resource "aws_config_config_rule" "iam_password_policy" {
    count = var.set_guardrails_detection || var.check_iam_password_policy ? 1 : 0

    name = "Compasso-Baseline-IAM-Password-Policy"
    description = "A Config rule that checks whether the account password policy for IAM users meets the specified requirements."
    input_parameters = "{\"RequireUppercaseCharacters\":\"true\",\"RequireLowercaseCharacters\":\"true\",\"RequireSymbols\":\"true\",\"RequireNumbers\":\"true\",\"MinimumPasswordLength\":\"14\",\"PasswordReusePrevention\":\"24\",\"MaxPasswordAge\":\"90\"}"

    source {
        owner = "AWS"
        source_identifier = "IAM_PASSWORD_POLICY"
    }
    scope {
        compliance_resource_types = []
    }
}
