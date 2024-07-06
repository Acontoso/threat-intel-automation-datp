provider "aws" {
  region = local.aws_region
}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

terraform {
  backend "s3" {
    bucket = "security-terraform-state-weshealth"
    key    = "statefiles/ti-runner"
  }
}
