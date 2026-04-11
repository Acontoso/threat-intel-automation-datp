resource "aws_ecs_task_definition" "task_definition_intel" {
  family = var.ecs_task_name
  container_definitions = jsonencode([
    {
      name                   = "${var.container_name}"
      image                  = var.image_digest != "" ? "${var.ecr_registry}/${var.image_repo_name}@${var.image_digest}" : "${var.ecr_registry}/${var.image_repo_name}:${var.image_tag}"
      essential              = true
      readonlyRootFilesystem = true
      environment = [
        {
          name  = "ENVIRONMENT"
          value = var.environment
        },
        {
          name  = "BEDROCK_MODEL_ID"
          value = ""
        },
        {
          name  = "GUARDRAIL_ID"
          value = ""
        },
        {
          name  = "AGENTCORE_MEMORY_SHORT_ID"
          value = ""
        }
      ]
      portMappings = [
        {
          containerPort = 8000
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-create-group  = "true"
          awslogs-group         = "ecs-intel-task-logs"
          awslogs-region        = "ap-southeast-2"
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
  tags = var.tags
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
  tags               = var.tags
}

resource "aws_iam_role" "task_execution_role" {
  name               = var.task_execution_role
  assume_role_policy = data.aws_iam_policy_document.trust_policy_document_ecs.json
  tags               = var.tags
}

data "aws_iam_policy_document" "task_role_policy" {
  version = "2012-10-17"

  statement {
    sid    = "AllowKMSDecrypt"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [
      "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alias/${var.ssm_cmk_kms_key_alias}"
    ]
  }

  statement {
    sid    = "AllowSSMGetParameters"
    effect = "Allow"
    actions = [
      "ssm:GetParameter*"
    ]
    resources = [
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/intel-agent/*"
    ]
  }

  statement {
    sid    = "AllowModelInvoke"
    effect = "Allow"
    actions = [
      "bedrock:InvokeModelWithResponseStream",
      "bedrock:InvokeModel"
    ]
    resources = [
      var.bedrock_model_arn
    ]
  }

  statement {
    sid    = "AllowMemory"
    effect = "Allow"
    actions = [
      "bedrock-agentcore:GetEvent",
      "bedrock-agentcore:ListEvents",
      "bedrock-agentcore:RetrieveMemoryRecords"
    ]
    resources = [
      var.bedrock_agentcore_memory_arn
    ]
  }

  statement {
    sid    = "ApplyGuardrail"
    effect = "Allow"
    actions = [
      "bedrock:ApplyGuardrail"
    ]
    resources = [
      var.bedrock_guardrail_arn
    ]
  }
  
}

data "aws_iam_policy_document" "task_execution_policy" {
  version = "2012-10-17"

  statement {
    sid    = "AllowExecutionCore"
    effect = "Allow"
    actions = [
      "logs:PutLogEvents",
      "logs:CreateLogStream",
      "ecr:GetAuthorizationToken"
    ]
    resources = [
      "*"
    ]
  }

  statement {
    sid    = "AllowExecutionPull"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage"
    ]
    resources = [
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/*"
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
  tags   = var.tags
}

resource "aws_iam_policy" "execution_task_iam_policy" {
  name   = "${var.task_execution_role}-policy"
  policy = data.aws_iam_policy_document.task_execution_policy.json
  tags   = var.tags
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
