data "aws_ecs_cluster" "ecs_threat_intel" {
  cluster_name = var.cluster_name
}

data "aws_kms_key" "cmk_ssm_alias" {
  key_id = "alias/${var.ssm_cmk_kms_key_alias}"
}

data "aws_cognito_identity_pool" "identity_pool_oidc" {
  identity_pool_name = "azure-ad-oidc-sentinel"
}
