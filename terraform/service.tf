resource "aws_ecs_service" "threat_intel_service" {
  name            = "threat-intel-service"
  cluster         = data.aws_ecs_cluster.ecs_threat_intel.id
  task_definition = aws_ecs_task_definition.task_definition_intel.arn
  desired_count   = var.service_desired_count
  force_new_deployment = true
  launch_type = "FARGATE"
  enable_ecs_managed_tags = true
  enable_execute_command = false
  platform_version = "LATEST"
  network_configuration {
    assign_public_ip = false
    security_groups = var.security_group_id
    subnets = var.subnet_ids
  }
  deployment_circuit_breaker {
    enable = true
    rollback = true
  }
  deployment_configuration {
    bake_time_in_minutes = 60
    strategy = "ROLLING"
  }
  load_balancer {
    container_name = aws_ecs_task_definition.task_definition_intel.container_definitions[0].name
    container_port = aws_ecs_task_definition.task_definition_intel.container_definitions[0].portMappings[0].containerPort
    target_group_arn = data.aws_lb_target_group.target_group_ecs_service.arn # Health Check will be done against service connect contianer port.
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
      discovery_name = "threat_intel_service"

      client_alias {
        dns_name = "tiservice"
        port     = 8080
      }
      tls {
        kms_key               = data.aws_kms_key.cmk_ca_alias.arn
        issuer_cert_authority {
          aws_pca_authority_arn = var.aws_private_ca_arn
        }
      }
    }
  }
  tags = local.tags
}

resource "aws_cloudwatch_log_group" "cloudwatch_log_group_threat_intel" {
  name = "/ecs/threat-intel/logs"
}

resource "aws_service_discovery_http_namespace" "service_discovery_http_namespace" {
  name        = var.service_discovery_namespace_name
  description = "Service Discovery HTTP Namespace for ECS Service Connect"
}
