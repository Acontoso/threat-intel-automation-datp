data "aws_ecs_cluster" "ecs_threat_intel" {
  cluster_name = var.cluster_name
}
