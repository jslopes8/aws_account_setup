#####################################
#                                   #
# Compasso UOL Baseline             #
# Set conforme Pack                 #
#                                   #
#####################################

## Config Rule - Volume in Use
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

## Config Rule - EIP Attached
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

## Config Rule - Security Group Open Only to authorized
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

## Config Rule - IAM User MFA
resource "aws_config_config_rule" "iam_user_mfa" {
    count = var.set_guardrails_detection || var.check_iam_user_mfa_enabled ? 1 : 0

    name = "Compasso-Baseline-IAMUser-MFA-Enabled"
    description = "A config rule that checks whether the AWS Identity and Access Management users have multi-factor authentication (MFA) enabled."

    maximum_execution_frequency = "One_Hour"

    source {
        owner = "AWS"
        source_identifier = "IAM_USER_MFA_ENABLED"
    }
    scope {
        compliance_resource_types = []
    }
}

## Config Rule - IAM User Console MFA
resource "aws_config_config_rule" "iam_user_console_mfa" {
    count = var.set_guardrails_detection || var.check_iam_user_console_mfa_enabled ? 1 : 0

    name = "Compasso-Baseline-IAM-User-Console-MFA-Enabled"
    description = "Disallow console access to IAM users without MFA - Checks whether AWS Multi-Factor Authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password. The rule is COMPLIANT if MFA is enabled."

    maximum_execution_frequency = "One_Hour"
    
    source {
        owner = "AWS"
        source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
    }
    scope {
        compliance_resource_types = []
    }
}

## Config Rule - Root MFA
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

## Config Rule - Access Keys Rotated
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

## Config Rule - IAM Password Policy
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

## Config Rule - EBS Optimized Instance
resource "aws_config_config_rule" "ebs_optimized_instance" {
    count = var.set_guardrails_detection || var.check_ebs_optimized_instance ? 1 : 0

    name = "Compasso-Baseline-EBS_Optimized_Instance"
    description = "Disallow launch of EC2 instance types that are not EBS-optimized - Checks whether EBS optimization is enabled for your EC2 instances that can be EBS-optimized."

    source {
        owner = "AWS"
        source_identifier = "EBS_OPTIMIZED_INSTANCE"
    }
    scope {
        compliance_resource_types = ["AWS::EC2::Instance"]
    }
}

## Config Rule - EBS Optimized Instance
resource "aws_config_config_rule" "encrypted_volumes" {
    count = var.set_guardrails_detection || var.check_encrypted_volumes ? 1 : 0

    name = "Compasso-Baseline-Encrypted_Volumes"
    description = "Enable encryption for EBS volumes attached to EC2 instances - Checks whether EBS volumes that are in an attached state are encrypted."

    source {
        owner = "AWS"
        source_identifier = "ENCRYPTED_VOLUMES"
    }
    scope {
        compliance_resource_types = [ "AWS::EC2::Volume"]
    }
}

## Config Rule - RDS Public Access
resource "aws_config_config_rule" "rds_public_access" {
    count = var.set_guardrails_detection || var.check_rds_public_access ? 1 : 0

    name = "Compasso-Baseline-RDS-Public-Access"
    description = "Disallow public access to RDS database instances - Checks whether the Amazon Relational Database Service (RDS) instances are not publicly accessible. The rule is non-compliant if the publiclyAccessible field is true in the instance configuration item."

    source {
        owner = "AWS"
        source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
    }
    scope {
        compliance_resource_types = [ "AWS::RDS::DBInstance"]
    }
}

## Config Rule - RDS Public Snapshots
resource "aws_config_config_rule" "rds_public_snapshots" {
    count = var.set_guardrails_detection || var.check_rds_public_snapshots ? 1 : 0

    name = "Compasso-Baseline-RDS-Public-Snapshots-PROHIBITED"
    description = "Disallow public access to RDS database snapshots - Checks if Amazon Relational Database Service (Amazon RDS) snapshots are public. The rule is non-compliant if any existing and new Amazon RDS snapshots are public."

    source {
        owner = "AWS"
        source_identifier = "RDS_SNAPSHOTS_PUBLIC_PROHIBITED"
    }
    scope {
        compliance_resource_types = [ "AWS::RDS::DBSnapshot"]
    }
}

## Config Rule - RDS Storage Encryption
resource "aws_config_config_rule" "rds_storage_encryption" {
    count = var.set_guardrails_detection || var.check_rds_storage_encryption ? 1 : 0

    name = "Compasso-Baseline-RDS-Public-Snapshots-PROHIBITED"
    description = "Disallow RDS database instances that are not storage encrypted - Checks whether storage encryption is enabled for your RDS DB instances."

    source {
        owner = "AWS"
        source_identifier = "RDS_STORAGE_ENCRYPTED"
    }
    scope {
        compliance_resource_types = [ "AWS::RDS::DBInstance"]
    }
}

## Config Rule - Restricted Common Ports Policy
resource "aws_config_config_rule" "restricted_common_ports_policy" {
    count = var.set_guardrails_detection || var.check_restricted_common_ports_policy ? 1 : 0

    name = "Compasso-Baseline-Restricted-Common-Ports-Policy"
    description = "Disallow internet connection through RDP - Checks whether security groups that are in use disallow unrestricted incoming TCP traffic to the specified ports."

    input_parameters = "{\"blockedPort1\":\"20\",\"blockedPort2\":\"21\",\"blockedPort3\":\"3389\",\"blockedPort4\":\"3306\",\"blockedPort5\":\"4333\"}"
    source {
        owner = "AWS"
        source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
    }
    scope {
        compliance_resource_types = [ "AWS::EC2::SecurityGroup"]
    }
}

## Config Rule - Restricted SSH Policy
resource "aws_config_config_rule" "restricted_ssh_policy" {
    count = var.set_guardrails_detection || var.check_restricted_ssh_policy ? 1 : 0

    name = "Compasso-Baseline-Restricted-SSH-Policy"
    description = "Disallow internet connection through SSH - Checks whether security groups that are in use disallow unrestricted incoming SSH traffic."

    source {
        owner = "AWS"
        source_identifier = "INCOMING_SSH_DISABLED"
    }
    scope {
        compliance_resource_types = [ "AWS::EC2::SecurityGroup"]
    }
}

## Config Rule - S3 Bucket Public Read
resource "aws_config_config_rule" "s3_bucket_public_read" {
    count = var.set_guardrails_detection || var.check_s3_bucket_public_read ? 1 : 0

    name = "Compasso-Baseline-S3-Bucket-Public-Read-PROHIBITED"
    description = "Disallow public read access to S3 buckets - Checks that your S3 buckets do not allow public read access. If an S3 bucket policy or bucket ACL allows public read access, the bucket is noncompliant."

    source {
        owner = "AWS"
        source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    }
    scope {
        compliance_resource_types = [ "AWS::S3::Bucket"]
    }
}

## Config Rule - S3 Bucket Versioning
resource "aws_config_config_rule" "s3_bucket_versioning" {
    count = var.set_guardrails_detection || var.check_s3_bucket_versioning_enabled ? 1 : 0

    name = "Compasso-Baseline-S3-Bucket-Versioning-Enabled"
    description = "Disallow S3 buckets that are not versioning enabled - Checks whether versioning is enabled for your S3 buckets."

    source {
        owner = "AWS"
        source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
    }
    scope {
        compliance_resource_types = [ "AWS::S3::Bucket"]
    }
}

## Config Rule - S3 Bucket Public Write
resource "aws_config_config_rule" "s3_bucket_public_write" {
    count = var.set_guardrails_detection || var.check_s3_bucket_public_write ? 1 : 0

    name = "Compasso-Baseline-S3-Bucket-Public-Write-PROHIBITED"
    description = "Disallow public write access to S3 buckets - Checks that your S3 buckets do not allow public write access. If an S3 bucket policy or bucket ACL allows public write access, the bucket is noncompliant."

    source {
        owner = "AWS"
        source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
    }
    scope {
        compliance_resource_types = [ "AWS::S3::Bucket"]
    }
}