import boto3
import base64
import time
from botocore.exceptions import ClientError
from code.utils.logs import logger


class AWSServices:
    """Class used to store static methods used to interact with AWS SDK services"""

    @staticmethod
    def get_ssm_parameters(parameters: list, region: str) -> list:
        """Get SSM parameter during runtime"""
        ssm_client = boto3.client("ssm", region_name=region)
        kms_client = boto3.client("kms", region_name=region)
        resolved_params = []
        for param in parameters:
            retries = 5
            while retries > 0:
                try:
                    data = (
                        ssm_client.get_parameter(
                            Name=f"/threat-intel/{param}", WithDecryption=True
                        )
                        .get("Parameter")
                        .get("Value")
                    )
                    raw_bytes = base64.b64decode(data)
                    return_data = kms_client.decrypt(CiphertextBlob=raw_bytes)
                    unencrypted_string = return_data.get("Plaintext").decode("utf-8")
                    resolved_params.append(unencrypted_string)
                    break
                except ClientError as e:
                    retries -= 1
                    if e.response["Error"]["Code"] == "ThrottlingException":
                        logger.error(
                            f"[-] Throttling Exception occurred - sleeping before restart"
                        )
                    else:
                        logger.error(f"[-] Printing other error -> {e}")
                    time.sleep(3)
            else:
                raise Exception(f"Max retries reached for parameter {param}")
        return resolved_params
