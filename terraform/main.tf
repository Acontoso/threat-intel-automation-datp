provider "aws" {
  region = local.aws_region
}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket = "security-terraform-state-weshealth"
    key    = "statefiles/ti-runner"
  }
}
