output "task_definition_arn" {
	description = "ARN of the ECS task definition."
	value       = aws_ecs_task_definition.task_definition_intel.arn
}

output "task_definition_family" {
	description = "Family name of the ECS task definition."
	value       = aws_ecs_task_definition.task_definition_intel.family
}

output "task_definition_revision" {
	description = "Revision number of the ECS task definition."
	value       = aws_ecs_task_definition.task_definition_intel.revision
}

output "task_role_arn" {
	description = "ARN of the ECS task role."
	value       = aws_iam_role.task_role.arn
}

output "task_role_name" {
	description = "Name of the ECS task role."
	value       = aws_iam_role.task_role.name
}

output "task_execution_role_arn" {
	description = "ARN of the ECS task execution role."
	value       = aws_iam_role.task_execution_role.arn
}

output "task_execution_role_name" {
	description = "Name of the ECS task execution role."
	value       = aws_iam_role.task_execution_role.name
}

output "task_policy_arn" {
	description = "ARN of the custom IAM policy attached to the task role."
	value       = aws_iam_policy.task_iam_policy.arn
}

output "task_execution_policy_arn" {
	description = "ARN of the custom IAM policy attached to the task execution role."
	value       = aws_iam_policy.execution_task_iam_policy.arn
}
