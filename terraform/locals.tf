locals {
  tags = merge(
    {
      "env"        = "${var.environment}"
      "terraform"  = "true"
      "repourl"    = "${var.source_code_repo_url}"
      "service"    = "threat-intel-runner"
      "author"     = "alex skoro"
    }
  )
  aws_region = "ap-southeast-2"
}
