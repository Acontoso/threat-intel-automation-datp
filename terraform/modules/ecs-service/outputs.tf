output "ecs_service_id" {
	description = "ID of the ECS service."
	value       = aws_ecs_service.threat_intel_service.id
}

output "ecs_service_name" {
	description = "Name of the ECS service."
	value       = aws_ecs_service.threat_intel_service.name
}

output "ecs_service_cluster_arn" {
	description = "ARN of the ECS cluster hosting the service."
	value       = aws_ecs_service.threat_intel_service.cluster
}

output "ecs_service_task_definition" {
	description = "Task definition ARN currently used by the ECS service."
	value       = aws_ecs_service.threat_intel_service.task_definition
}

output "ecs_service_desired_count" {
	description = "Desired task count configured on the ECS service."
	value       = aws_ecs_service.threat_intel_service.desired_count
}

output "service_discovery_namespace_arn" {
	description = "ARN of the service discovery HTTP namespace used by Service Connect."
	value       = aws_service_discovery_http_namespace.service_discovery_http_namespace.arn
}

output "service_discovery_namespace_id" {
	description = "ID of the service discovery HTTP namespace used by Service Connect."
	value       = aws_service_discovery_http_namespace.service_discovery_http_namespace.id
}

output "cloudwatch_log_group_name" {
	description = "CloudWatch log group name for ECS Service Connect logs."
	value       = aws_cloudwatch_log_group.cloudwatch_log_group_threat_intel.name
}

output "cloudwatch_log_group_arn" {
	description = "CloudWatch log group ARN for ECS Service Connect logs."
	value       = aws_cloudwatch_log_group.cloudwatch_log_group_threat_intel.arn
}
