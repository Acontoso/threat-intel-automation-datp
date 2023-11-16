# Threat Intel Automation DATP
This microservice is a containerized service that will poll a specific Threat Intel feed (Mandiant) from our Threat Intelligence feed, Anomali. This will look for active Hash IOC’s with a confidence of above 85, where it will programmatically pull these IOC’s and upload them into Microsoft 365 Defender. These will then become “Indicators“ in which Defender for Endpoint can then use to proactively block these known malicious hashes prior to execution of the malicious binary (or can alert and monitor too without providing any remediation action or proactive blocking).

The service works by having a ECS cluster, which is used as the management plane to control containerised tasks and services. This ECS cluster will define the runtime fabric (EC2 or Fargate), and controls the tasks (equivalent to a Kuberentes POD) and services (equivalent to a Kuberentes Deployment controller resource - Deployment, StatefulSet, ReplicaSet). In our case, we will have a task definition, in which the task and corresponding container/s will run on a fargate instance. This task will be triggered from an AWS EventBridge scheduled task, where each day (or set defined period), will spin up a ECS task to run the container orchestrate the automation. The container will reside in an private ECR repository and follow a suited CICD process as shown below.

The reason why ECS cluster is needed is since Lambda has a maximum runtime of 15 minutes, operations could last longer than that and utilising an ECS task does not limit us on time of required completion. The scheduled task will run as long as the task is running and no exit status is generated from the entry point of the container within the task.

Due to the fact there is a hard limit of 15000 indicators that can be added to a single Microsoft tenant, each IOC will have a 6 month expiry.

Workflows will represent what CICD looks like from an Azure DevOps point of view
