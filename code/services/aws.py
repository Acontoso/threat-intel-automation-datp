import boto3
import base64
import time
from botocore.exceptions import ClientError
from code.utils.logs import logger


class AWSClient:
    """Reusable client for AWS interactions needed by ingestion workflows."""

    def __init__(self, region: str):
        self.region = region
        self.ssm_client = boto3.client("ssm", region_name=region)
        self.kms_client = boto3.client("kms", region_name=region)

    def get_ssm_parameters(self, parameters: list[str]) -> list[str]:
        """Get and decrypt SSM parameters during runtime."""
        resolved_params = []
        for param in parameters:
            retries = 5
            while retries > 0:
                try:
                    data = (
                        self.ssm_client.get_parameter(
                            Name=f"/recorded-futures/{param}", WithDecryption=True
                        )
                        .get("Parameter")
                        .get("Value")
                    )
                    raw_bytes = base64.b64decode(data)
                    return_data = self.kms_client.decrypt(CiphertextBlob=raw_bytes)
                    unencrypted_string = return_data.get("Plaintext").decode("utf-8")
                    resolved_params.append(unencrypted_string)
                    break
                except ClientError as error:
                    retries -= 1
                    if error.response["Error"]["Code"] == "ThrottlingException":
                        logger.error(
                            "[-] Throttling Exception occurred - sleeping before restart"
                        )
                    else:
                        logger.error(f"[-] Printing other error -> {error}")
                    time.sleep(3)
            else:
                raise Exception(f"Max retries reached for parameter {param}")
        return resolved_params
