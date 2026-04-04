resource "aws_ecs_task_definition" "task_definition_intel" {
  family = var.ecs_task_name
  container_definitions = jsonencode([
    {
      name                   = "${var.container_name}"
      image                  = var.image_digest != "" ? "${var.ecr_registry}/${var.image_repo_name}@${var.image_digest}" : "${var.ecr_registry}/${var.image_repo_name}:${var.image_tag}"
      # New task definition versions will need to be pushed with the new image tag, which should be updated in terraform.tfvars
      essential              = true
      readonlyRootFilesystem = true
      environment = [
        {
          name  = "ENVIRONMENT"
          value = var.environment
        },
        {
          name  = "COST_CENTRE"
          value = var.cost_centre
        },
        {
          name  = "MS_CLIENT_ID"
          value = var.enc_string_az_client_id
        },
        {
          name  = "MS_TENANT_ID"
          value = var.enc_string_az_tenant_id
        },
        {
          name  = "UMBRELLA_ID"
          value = var.enc_string_umbrella_id
        },
        {
          name  = "UMBRELLA_SECRET"
          value = var.enc_string_umbrella_secret
        },
        {
          name  = "ANOMALI_USERNAME"
          value = var.enc_string_anomali_username
        },
        {
          name  = "ANOMALI_APIKEY"
          value = var.enc_string_anomali_apikey
        }
      ]
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 80
        }
      ]
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
  network_mode             = var.ecs_networking_mode
  cpu                      = var.ecs_vcpu_size
  memory                   = var.ecs_memory_size
  runtime_platform {
    operating_system_family = var.os_platform
    cpu_architecture        = var.cpu_architecture
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
  
  statement {
    sid    = "CognitoIdentityPoolOIDC"
    effect = "Allow"
    actions = [
      "cognito-identity:GetOpenIdTokenForDeveloperIdentity",
      "cognito-identity:LookupDeveloperIdentity",
      "cognito-identity:MergeDeveloperIdentities",
      "cognito-identity:UnlinkDeveloperIdentity"
    ]
    resources = [
      data.aws_cognito_identity_pool.identity_pool_oidc.arn
    ]
  }
}

data "aws_iam_policy_document" "task_execution_policy" {
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

resource "aws_iam_role_policy_attachment" "execution_role_managed_policy" {
  role       = aws_iam_role.task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
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
