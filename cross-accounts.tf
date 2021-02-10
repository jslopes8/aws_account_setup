#####################################
#                                   #
# Compasso UOL Baseline             #
# Set up Cross Account              #
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
                "${var.cross_account_arn}"
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
                "${var.cross_account_arn}"
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