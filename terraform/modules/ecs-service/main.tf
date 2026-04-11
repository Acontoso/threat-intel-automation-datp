resource "aws_ecs_service" "threat_intel_service" {
  name                    = "threat-intel-service"
  cluster                 = data.aws_ecs_cluster.ecs_threat_intel.id
  task_definition         = aws_ecs_task_definition.task_definition_intel.arn
  desired_count           = var.service_desired_count
  force_new_deployment    = true
  launch_type             = "FARGATE"
  enable_ecs_managed_tags = true
  enable_execute_command  = false
  platform_version        = "LATEST"
  network_configuration {
    assign_public_ip = false
    security_groups  = var.security_group_id
    subnets          = var.subnet_ids
  }
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  deployment_configuration {
    bake_time_in_minutes = var.bake_time_in_minutes
    strategy             = "ROLLING"
  }
  load_balancer {
    container_name   = aws_ecs_task_definition.task_definition_intel.container_definitions[0].name
    container_port   = aws_ecs_task_definition.task_definition_intel.container_definitions[0].portMappings[0].containerPort
    target_group_arn = var.target_group_arn # Health Check will be done against service connect container port
  }
  service_connect_configuration {
    enabled   = true
    namespace = aws_service_discovery_http_namespace.service_discovery_http_namespace.arn

    log_configuration {
      log_driver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.cloudwatch_log_group_threat_intel.name
        "awslogs-region"        = data.aws_region.current.name
        "awslogs-stream-prefix" = "threat-intel-webhook"
      }
    }

    access_log_configuration {
      format                   = "JSON"
      include_query_parameters = "DISABLED"
    }

    service {
      port_name      = "http"
      discovery_name = var.service_discovery_name

      client_alias {
        dns_name = var.client_alias_dns_name
        port     = var.container_port
      }
      tls {
        kms_key = "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alias/${var.ca_cmk_kms_key_alias}"
        issuer_cert_authority {
          aws_pca_authority_arn = var.aws_private_ca_arn
        }
      }
    }
  }
  tags = var.tags
}

resource "aws_cloudwatch_log_group" "cloudwatch_log_group_threat_intel" {
  name = var.ecs_service_logs_prefix
  retention_in_days = 30
}

resource "aws_service_discovery_http_namespace" "service_discovery_http_namespace" {
  name        = var.service_discovery_namespace_name
  description = "Service Discovery HTTP Namespace for ECS Service Connect"
}
