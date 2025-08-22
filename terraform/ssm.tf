#aws kms encrypt --profile <> --key-id <kms key id> --plaintext fileb://<(echo -n 'secret') --output text --query
resource "aws_ssm_parameter" "az_client_id" {
  name        = "/threat-intel/client_id_new"
  type        = "SecureString"
  description = "Azure client ID for Sentinel Ingestion"
  key_id      = data.aws_kms_key.cmk_ssm_alias.id
  value       = var.enc_string_az_client_id
  tags        = local.tags
}

resource "aws_ssm_parameter" "az_tenant_id" {
  name        = "/threat-intel/tenant_id_new"
  type        = "SecureString"
  description = "Azure tenant ID for Sentinel Ingestion"
  key_id      = data.aws_kms_key.cmk_ssm_alias.id
  value       = var.enc_string_az_tenant_id
  tags        = local.tags
}

resource "aws_ssm_parameter" "umbrella_key" {
  name        = "/threat-intel/umbrella_key_new"
  type        = "SecureString"
  description = "Umbrella client ID, oauth to pull logs/alerts"
  key_id      = data.aws_kms_key.cmk_ssm_alias.id
  value       = var.enc_string_umbrella_id
  tags        = local.tags
}

resource "aws_ssm_parameter" "umbrella_secret" {
  name        = "/threat-intel/umbrella_secret_new"
  type        = "SecureString"
  description = "Umbrella client secret, oauth to pull logs/alerts"
  key_id      = data.aws_kms_key.cmk_ssm_alias.id
  value       = var.enc_string_umbrella_secret
  tags        = local.tags
}

resource "aws_ssm_parameter" "anomali_username" {
  name        = "/threat-intel/username_new"
  type        = "SecureString"
  description = "Anomali username needed for anomali integration"
  key_id      = data.aws_kms_key.cmk_ssm_alias.id
  value       = var.enc_string_anomali_username
  tags        = local.tags
}

resource "aws_ssm_parameter" "anomali_apikey" {
  name        = "/threat-intel/api_key_new"
  type        = "SecureString"
  description = "Anomali api key needed for anomali integration"
  key_id      = data.aws_kms_key.cmk_ssm_alias.id
  value       = var.enc_string_anomali_apikey
  tags        = local.tags
}
