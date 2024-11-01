import boto3


class AWSServices:
    """Class used to store static methods used to interact with AWS SDK services"""

    @staticmethod
    def get_ssm_parameters(parameters: list, region: str) -> list:
        """Get SSM parameter during runtime"""
        ssm_client = boto3.client("ssm", region_name=region)
        resolved_params = []
        for param in parameters:
            data = (
                ssm_client.get_parameter(
                    Name=f"/threat-intel/{param}", WithDecryption=True
                )
                .get("Parameter")
                .get("Value")
            )
            resolved_params.append(data)
        return resolved_params
