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