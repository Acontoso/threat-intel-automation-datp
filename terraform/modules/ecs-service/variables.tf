variable "service_desired_count" {
	type        = number
	description = "Desired number of ECS service tasks."

	validation {
		condition     = var.service_desired_count >= 0
		error_message = "service_desired_count must be greater than or equal to 0."
	}
}

variable "security_group_id" {
	type        = list(string)
	description = "Security group IDs attached to the ECS service ENIs."

	validation {
		condition     = length(var.security_group_id) > 0
		error_message = "At least one security group ID must be provided."
	}
}

variable "subnet_ids" {
	type        = list(string)
	description = "Subnet IDs used by the ECS service network configuration."

	validation {
		condition     = length(var.subnet_ids) > 0
		error_message = "At least one subnet ID must be provided."
	}
}

variable "target_group_arn" {
	type        = string
	description = "ARN of the ALB target group used by the ECS service."
}

variable "aws_private_ca_arn" {
	type        = string
	description = "ARN of the AWS Private CA used by ECS Service Connect TLS."
}

variable "service_discovery_namespace_name" {
	type        = string
	description = "Name of the Service Discovery HTTP namespace for ECS Service Connect."
}

variable "service_discovery_name" {
	type        = string
	description = "Service Connect discovery name for the ECS service."
}

variable "client_alias_dns_name" {
	type        = string
	description = "DNS alias exposed by Service Connect for clients."
}

variable "container_port" {
	type        = number
	description = "Container port exposed by Service Connect client alias."

	validation {
		condition     = var.container_port > 0 && var.container_port <= 65535
		error_message = "container_port must be between 1 and 65535."
	}
}

variable "tags" {
	type        = map(string)
	description = "Tags to apply to ECS service and related resources."
	default     = {}
}

variable "ecs_service_logs_prefix" {
	type        = string
	description = "Prefix for the ECS service logs in CloudWatch."
    default     = "/ecs/threat-intel/logs"
}

variable "ca_cmk_kms_key_alias" {
  type = string
  description = "KMS key used to encrypt the CA certificate for ECS Service Connect TLS"
}

variable "bake_time_in_minutes" {
	type        = number
	description = "Time in minutes to wait before considering a deployment successful."
	default     = 60
}
