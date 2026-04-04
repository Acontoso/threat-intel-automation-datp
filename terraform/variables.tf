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

variable "image_digest" {
  type    = string
  default = ""
  description = "The image digest is the SHA256 hash of the docker image used for deployment"
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

variable "load_balancer_target_group_name" {
  type        = string
  description = "Name of the ALB target group used by the ECS service"
}

variable "service_desired_count" {
  type        = number
  description = "Desired number of ECS service tasks"
}

variable "service_discovery_namespace_name" {
  type        = string
  description = "Service discovery HTTP namespace for ECS Service Connect"
}

variable "aws_private_ca_arn" {
  type        = string
  description = "ARN of the AWS Private CA used for ECS Service Connect TLS"
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

variable "ecs_networking_mode" {
  type        = string
  description = "Networking mode used by ECS"
}

variable "ecs_vcpu_size" {
  type        = string
  description = "CPU allocation to ECS task"
}

variable "ecs_memory_size" {
  type        = string
  description = "Memory allocation to ECS task"
}

variable "os_platform" {
  type        = string
  description = "OS Platform that can run ECS task"
}
variable "cpu_architecture" {
  type = string
}

variable "enc_string_az_client_id" {
  type        = string
  description = "Encrypted value for Az Client ID"
}

variable "enc_string_az_tenant_id" {
  type        = string
  description = "Encrypted value for Az Client Secret"
}

variable "enc_string_umbrella_id" {
  type        = string
  description = "Encrypted value for Umbrella ID"
}

variable "enc_string_umbrella_secret" {
  type        = string
  description = "Encrypted value for Umbrella Secret"
}

variable "enc_string_anomali_username" {
  type        = string
  description = "Encrypted value for Anomali Username"
}

variable "enc_string_anomali_apikey" {
  type        = string
  description = "Encrypted value for Anomali API Key"
}
