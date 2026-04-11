variable "source_code_repo_url" {
  type        = string
  description = "Repository where IaC and Lambda function source code resides"
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply to the gateway"
}

variable "environment" {
  description = "Environment the infrastructure is deployed in"
  type        = string
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

variable "ecr_cmk_kms_key_alias" {
  type = string
  description = "KMS key used to encrypt ECR artefacts"
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
  description = "CPU architecture to run ECS task on"
}

variable "bedrock_model_arn" {
  type        = string
  description = "ARN of the Bedrock model, LLM used by the strands agent"
}

variable "bedrock_agentcore_memory_arn" {
  type        = string
  description = "ARN of the Bedrock AgentCore memory used by the strands agent for session management via short term memory"
}

variable "bedrock_guardrail_arn" {
  type        = string
  description = "ARN of the Bedrock Guardrail used by the strands agent"
}
