resource "aws_cloudwatch_event_rule" "schedule" {
  name                = var.eventbridge_trigger_name
  description         = "Fire twice a day"
  schedule_expression = "rate(12 hours)"
  tags                = local.tags
}

data "aws_iam_policy_document" "assume_role_eventbridge" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "ecs_events" {
  name               = var.ecs_iam_role_eventbridge_name
  assume_role_policy = data.aws_iam_policy_document.assume_role_eventbridge.json
  tags               = local.tags
}

data "aws_iam_policy_document" "ecs_policy_document_eventbridge" {
  #checkov:skip=CKV_AWS_356: "Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions"
  statement {
    sid    = "AllowEcsTask"
    effect = "Allow"
    actions = [
      "ecs:RunTask"
    ]
    resources = [
      "arn:aws:ecs:*:${data.aws_caller_identity.current.account_id}:task-definition/${var.ecs_task_name}:*",
      "arn:aws:ecs:*:${data.aws_caller_identity.current.account_id}:task-definition/${var.ecs_task_name}"
    ]
    condition {
      test     = "ArnLike"
      variable = "ecs:cluster"
      values   = ["arn:aws:ecs:*:${data.aws_caller_identity.current.account_id}:cluster/security-engineering-cluster"]
    }
  }

  statement {
    sid    = "AllowPassRole"
    effect = "Allow"
    actions = [
      "iam:PassRole"
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }

  statement {
    sid    = "AllowTaggingECS"
    effect = "Allow"
    actions = [
      "ecs:TagResource"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "ecs_eventbridge_policy" {
  name   = "${var.ecs_iam_role_eventbridge_name}-policy"
  policy = data.aws_iam_policy_document.ecs_policy_document_eventbridge.json
  tags   = local.tags
}

resource "aws_iam_policy_attachment" "policy_attachment_eventbridge_role" {
  name       = "role-policy-attachment-3"
  roles      = [aws_iam_role.ecs_events.name]
  policy_arn = aws_iam_policy.ecs_eventbridge_policy.arn
}

resource "aws_cloudwatch_event_target" "ecs_scheduled_task" {
  target_id = "run-scheduled-task-half-day"
  arn       = data.aws_ecs_cluster.ecs_threat_intel.arn
  rule      = aws_cloudwatch_event_rule.schedule.name
  role_arn  = aws_iam_role.ecs_events.arn

  ecs_target {
    task_count          = 1
    task_definition_arn = aws_ecs_task_definition.task_definition_intel.arn
    launch_type         = "FARGATE"
    platform_version    = "1.4.0"
    propagate_tags      = "TASK_DEFINITION"
    tags                = local.tags
    network_configuration {
      subnets         = var.subnet_ids
      security_groups = var.security_group_id
    }
  }
}
