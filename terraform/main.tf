locals {
  tags = merge(
    {
      "env"        = "${var.environment}"
      "terraform"  = "true"
      "repourl"    = "${var.source_code_repo_url}"
      "service"    = "threat-intel-agent"
      "author"     = "alex skoro"
    }
  )
  aws_region = "ap-southeast-2"
}

data "aws_ecs_cluster" "ecs_threat_intel" {
  cluster_name = var.cluster_name
}

