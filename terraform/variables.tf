variable "source_code_repo_url" {
  type        = string
  description = "Repository where IaC and Lambda function source code resides"
}

variable "environment" {
  description = "Environment the infrastructure is deployed in"
  type        = string
}

variable "cost_centre" {
  description = "Cost centre to apply the resources too"
  type        = string
}

variable "eventbridge_trigger_name" {
  type        = string
  description = "Name of eventbridge trigger to start lambda function"
}

variable "ecs_task_name" {
  type = string
}

variable "image_tag" {
  type    = string
  default = "1.0.0"
}

variable "ecr_registry" {
  description = "ECR registry in account"
  type        = string
}

variable "image_repo_name" {
  type        = string
  description = "Name to give the ECR private repository to store container images used in scheduled ecs task instances"
}

variable "container_name" {
  type        = string
  description = "Name of container in task definition"
}

variable "ssm_cmk_kms_key_alias" {
  type        = string
  description = "KMS key to decrypt SSM values"
}

variable "task_role" {
  type        = string
  description = "ECS task role name"
}

variable "task_execution_role" {
  type        = string
  description = "ECS task execution role name"
}

variable "cluster_name" {
  type        = string
  description = "Name of ECS cluster"
}

variable "ecs_iam_role_eventbridge_name" {
  type        = string
  description = "Name of eventbridge role"
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnet IDs to run ECS task in"
}

variable "security_group_id" {
  type        = list(string)
  description = "Security group ID to assign to running ECS task"
}

variable "ecr_cmk_kms_key_alias" {
  type = string
}
