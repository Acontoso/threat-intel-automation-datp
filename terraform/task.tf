resource "aws_ecs_task_definition" "task_definition_intel" {
  family = var.ecs_task_name
  container_definitions = jsonencode([
    {
      name                   = "${var.container_name}"
      image                  = "${var.ecr_registry}/${var.image_repo_name}:${var.image_tag}"
      essential              = true
      readonlyRootFilesystem = true
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-create-group  = "true"
          awslogs-group         = "ecs-threat-intel-task"
          awslogs-region        = "${local.aws_region}"
          awslogs-stream-prefix = "contoso"
        }
      }
    }
  ])

  execution_role_arn       = aws_iam_role.task_execution_role.arn
  task_role_arn            = aws_iam_role.task_role.arn
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "1024"
  memory                   = "2048"
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  tags = local.tags
}

data "aws_iam_policy_document" "trust_policy_document_ecs" {
  statement {
    sid    = "LambdaTrustPolicy"
    effect = "Allow"

    actions = [
      "sts:AssumeRole",
    ]

    principals {
      identifiers = [
        "ecs-tasks.amazonaws.com",
      ]

      type = "Service"
    }
  }
}

resource "aws_iam_role" "task_role" {
  name               = var.task_role
  assume_role_policy = data.aws_iam_policy_document.trust_policy_document_ecs.json
  tags               = local.tags
}

resource "aws_iam_role" "task_execution_role" {
  name               = var.task_execution_role
  assume_role_policy = data.aws_iam_policy_document.trust_policy_document_ecs.json
  tags               = local.tags
}

data "aws_iam_policy_document" "task_role_policy" {
  version = "2012-10-17"

  statement {
    sid    = "AllowKMS"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [
      data.aws_kms_key.cmk_ssm_alias.arn
    ]
  }

  statement {
    sid    = "AllowSSM"
    effect = "Allow"
    actions = [
      "ssm:GetParameter*"
    ]
    resources = [
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/threat-intel/*"
    ]
  }
}

data "aws_iam_policy_document" "task_execution_policy" {
  #checkov:skip=CKV_AWS_111: "Ensure IAM policies does not allow write access without constraints"
  #checkov:skip=CKV_AWS_356: "Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions"
  version = "2012-10-17"

  statement {
    sid    = "AllowExecutionCore"
    effect = "Allow"
    actions = [
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:ListImages",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetAuthorizationToken",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:CreateLogGroup"
    ]
    resources = [
      "*"
    ]
  }

  statement {
    sid    = "DecryptKMS"
    effect = "Allow"
    actions = [
      "kms:Decrypt"
    ]
    resources = [
      "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alias/${var.ecr_cmk_kms_key_alias}"
    ]
  }
}

resource "aws_iam_policy" "task_iam_policy" {
  name   = "${var.task_role}-policy"
  policy = data.aws_iam_policy_document.task_role_policy.json
  tags   = local.tags
}

resource "aws_iam_policy" "execution_task_iam_policy" {
  name   = "${var.task_execution_role}-policy"
  policy = data.aws_iam_policy_document.task_execution_policy.json
  tags   = local.tags
}

resource "aws_iam_role_policy_attachment" "default_policy_attachment_lambda_role" {
  role       = aws_iam_role.task_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy_attachment" "policy_attachment_task_role" {
  name       = "role-policy-attachment-1"
  roles      = [aws_iam_role.task_role.name]
  policy_arn = aws_iam_policy.task_iam_policy.arn
}

resource "aws_iam_policy_attachment" "policy_attachment_task_execution_role" {
  name       = "role-policy-attachment-2"
  roles      = [aws_iam_role.task_execution_role.name]
  policy_arn = aws_iam_policy.execution_task_iam_policy.arn
}
