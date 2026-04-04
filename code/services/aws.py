import boto3
import base64
import time
from botocore.exceptions import ClientError
from code.utils.logs import logger

IDENTITY_POOL_LOGIN = "sentinelloglambda"
IDENTITY_POOL_ID = "ap-southeast-2:5a1433aa-088e-431e-a69e-fe0c30b580a7"


class AWSClient:
    """Reusable client for AWS interactions needed by ingestion workflows."""

    def __init__(self, region: str):
        self.region = region
        self.ssm_client = boto3.client("ssm", region_name=region)
        self.kms_client = boto3.client("kms", region_name=region)

    def get_ssm_parameters(self, parameters: list[str]) -> list[str]:
        """Get and decrypt SSM parameters during runtime."""
        # Method also relies on SSM parameters being stored in encrypted form, with the same KMS key - outside of this repository.
        resolved_params = []
        for param in parameters:
            retries = 5
            while retries > 0:
                try:
                    data = (
                        self.ssm_client.get_parameter(
                            Name=f"/threat-intel/{param}", WithDecryption=True
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

    def get_token(self) -> str:
        # Relies on OIDC service between AWS Cognito userpool & Azure. - outside of this repository
        logins = {"azuread": IDENTITY_POOL_LOGIN}
        client = boto3.client("cognito-identity")

        response = client.get_open_id_token_for_developer_identity(
            IdentityPoolId=IDENTITY_POOL_ID, Logins=logins
        )
        return response["Token"]


class AWSServices:
    """Backward-compatible static facade for legacy call sites."""

    @staticmethod
    def get_ssm_parameters(parameters: list[str], region: str) -> list[str]:
        return AWSClient(region).get_ssm_parameters(parameters)

    @staticmethod
    def get_token() -> str:
        return AWSClient("ap-southeast-2").get_token()
