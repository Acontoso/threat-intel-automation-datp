import unittest
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError
from code.services.aws import AWSServices

class TestAWSServices(unittest.TestCase):
    @patch("code.services.aws.boto3.client")
    def test_get_ssm_parameters_success(self, mock_boto_client):
        mock_ssm = MagicMock()
        mock_kms = MagicMock()
        mock_ssm.get_parameter.return_value = {"Parameter": {"Value": b"c2VjcmV0"}}
        mock_kms.decrypt.return_value = {"Plaintext": b"secret-value"}
        def client_side_effect(service_name, *args, **kwargs):
            if service_name == "ssm":
                return mock_ssm
            elif service_name == "kms":
                return mock_kms
            else:
                raise ValueError("Unknown service")
        mock_boto_client.side_effect = client_side_effect
        params = ["param1"]
        result = AWSServices.get_ssm_parameters(params, "us-east-1")
        self.assertEqual(result, ["secret-value"])
        mock_ssm.get_parameter.assert_called_once()
        mock_kms.decrypt.assert_called_once()

    @patch("code.services.aws.time.sleep")
    @patch("code.services.aws.logger")
    @patch("code.services.aws.boto3.client")
    def test_get_ssm_parameters_throttling_then_success(self, mock_boto_client, mock_logger, mock_sleep):
        mock_ssm = MagicMock()
        mock_kms = MagicMock()
        throttling_error = ClientError({
            'Error': {'Code': 'ThrottlingException', 'Message': 'Throttled'}
        }, 'GetParameter')
        mock_ssm.get_parameter.side_effect = [throttling_error, {"Parameter": {"Value": b"c2VjcmV0"}}]
        mock_kms.decrypt.return_value = {"Plaintext": b"secret-value"}
        def client_side_effect(service_name, *args, **kwargs):
            if service_name == "ssm":
                return mock_ssm
            elif service_name == "kms":
                return mock_kms
            else:
                raise ValueError("Unknown service")
        mock_boto_client.side_effect = client_side_effect
        params = ["param1"]
        result = AWSServices.get_ssm_parameters(params, "us-east-1")
        self.assertEqual(result, ["secret-value"])
        self.assertTrue(mock_logger.error.called)
        self.assertTrue(mock_sleep.called)

    @patch("code.services.aws.time.sleep")
    @patch("code.services.aws.logger")
    @patch("code.services.aws.boto3.client")
    def test_get_ssm_parameters_max_retries(self, mock_boto_client, mock_logger, mock_sleep):
        mock_ssm = MagicMock()
        mock_kms = MagicMock()
        error = ClientError({
            'Error': {'Code': 'OtherError', 'Message': 'Other'}
        }, 'GetParameter')
        mock_ssm.get_parameter.side_effect = [error] * 5
        def client_side_effect(service_name, *args, **kwargs):
            if service_name == "ssm":
                return mock_ssm
            elif service_name == "kms":
                return mock_kms
            else:
                raise ValueError("Unknown service")
        mock_boto_client.side_effect = client_side_effect
        params = ["param1"]
        with self.assertRaises(Exception) as cm:
            AWSServices.get_ssm_parameters(params, "us-east-1")
        self.assertIn("Max retries reached", str(cm.exception))
        self.assertTrue(mock_logger.error.called)
        self.assertTrue(mock_sleep.called)

if __name__ == "__main__":
    unittest.main()
