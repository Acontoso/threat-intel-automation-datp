import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from code.services.microsoft import MSServices
import asyncio

class TestMSServices(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.ms = MSServices(
            client_id="cid",
            client_secret="secret",
            tenant_id="tid",
            anomali_username="user",
            anomali_apikey="apikey",
            token="token123"
        )

    def test_generate_access_token_payload(self):
        scope = "scope-url"
        payload = self.ms.generate_access_token_payload(scope)
        self.assertIn("client_id=cid", payload)
        self.assertIn("scope=scope-url", payload)
        self.assertIn("client_secret=secret", payload)
        self.assertIn("grant_type=client_credentials", payload)

    @patch("aiohttp.ClientSession")
    @patch("code.services.microsoft.logger")
    async def test_check_indicator_exists(self, mock_logger, mock_session):
        mock_session_cm = AsyncMock()
        mock_response_cm = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"value": [1]})
        mock_response_cm.__aenter__.return_value = mock_response
        mock_response_cm.__aexit__.return_value = None
        mock_session_instance = AsyncMock()
        mock_session_instance.get = MagicMock(return_value=mock_response_cm)
        mock_session_cm.__aenter__.return_value = mock_session_instance
        mock_session.return_value = mock_session_cm
        self.ms.token = "token123"
        result = await self.ms.check_indicator("test-indicator")
        self.assertTrue(result)
        mock_logger.info.assert_called()

    @patch("aiohttp.ClientSession")
    @patch("code.services.microsoft.logger")
    async def test_check_indicator_not_exists(self, mock_logger, mock_session):
        mock_session_cm = AsyncMock()
        mock_response_cm = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"value": []})
        mock_response_cm.__aenter__.return_value = mock_response
        mock_response_cm.__aexit__.return_value = None
        mock_session_instance = AsyncMock()
        mock_session_instance.get = MagicMock(return_value=mock_response_cm)
        mock_session_cm.__aenter__.return_value = mock_session_instance
        mock_session.return_value = mock_session_cm
        self.ms.token = "token123"
        result = await self.ms.check_indicator("test-indicator")
        self.assertFalse(result)

    @patch("aiohttp.ClientSession")
    @patch("code.services.microsoft.logger")
    async def test_check_indicator_error(self, mock_logger, mock_session):
        mock_session_cm = AsyncMock()
        mock_response_cm = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 500
        mock_response.text = AsyncMock(return_value="error")
        mock_response_cm.__aenter__.return_value = mock_response
        mock_response_cm.__aexit__.return_value = None
        mock_session_instance = AsyncMock()
        mock_session_instance.get = MagicMock(return_value=mock_response_cm)
        mock_session_cm.__aenter__.return_value = mock_session_instance
        mock_session.return_value = mock_session_cm
        self.ms.token = "token123"
        result = await self.ms.check_indicator("test-indicator")
        self.assertFalse(result)
        mock_logger.error.assert_called()

    def test_construct_payload_defender(self):
        ioc = {
            "source": "testsrc",
            "value": "abcdef1234567890",
            "tags": [{"name": "tag1"}, {"name": "tag2"}]
        }
        payload = MSServices.construct_payload_defender(ioc)
        self.assertEqual(payload["indicatorValue"], "abcdef1234567890")
        self.assertTrue(payload["title"].startswith("testsrc-"))
        self.assertIn("tag1", payload["description"])
        self.assertIn("tag2", payload["description"])
        self.assertEqual(payload["action"], "BlockAndRemediate")
        self.assertEqual(payload["severity"], "High")
        self.assertEqual(payload["indicatorType"], "FileSha256")
        self.assertTrue(payload["generateAlert"])
        self.assertTrue(payload["expirationTime"].endswith("Z"))

    @patch("aiohttp.ClientSession")
    @patch.object(MSServices, "check_indicator", new_callable=AsyncMock)
    @patch("code.services.microsoft.logger")
    async def test_parse_and_send_exists(self, mock_logger, mock_check, mock_session):
        mock_check.return_value = True
        ioc = {"value": "abcdef1234567890", "source": "src", "tags": []}
        result = await self.ms.parse_and_send(ioc)
        self.assertTrue(result)
        mock_session.assert_not_called()

    @patch("aiohttp.ClientSession")
    @patch.object(MSServices, "check_indicator", new_callable=AsyncMock)
    @patch("code.services.microsoft.logger")
    async def test_parse_and_send_success(self, mock_logger, mock_check, mock_session):
        mock_check.return_value = False
        mock_session_cm = AsyncMock()
        mock_response_cm = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response_cm.__aenter__.return_value = mock_response
        mock_response_cm.__aexit__.return_value = None
        mock_session_instance = AsyncMock()
        mock_session_instance.post = MagicMock(return_value=mock_response_cm)
        mock_session_cm.__aenter__.return_value = mock_session_instance
        mock_session.return_value = mock_session_cm
        ioc = {"value": "abcdef1234567890", "source": "src", "tags": []}
        result = await self.ms.parse_and_send(ioc)
        self.assertTrue(result)
        mock_session_instance.post.assert_called()
        mock_logger.info.assert_called()

    @patch("aiohttp.ClientSession")
    @patch.object(MSServices, "check_indicator", new_callable=AsyncMock)
    @patch("code.services.microsoft.logger")
    async def test_parse_and_send_failure(self, mock_logger, mock_check, mock_session):
        mock_check.return_value = False
        mock_session_cm = AsyncMock()
        mock_response_cm = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 400
        mock_response.text = AsyncMock(return_value="fail")
        mock_response_cm.__aenter__.return_value = mock_response
        mock_response_cm.__aexit__.return_value = None
        mock_session_instance = AsyncMock()
        mock_session_instance.post = MagicMock(return_value=mock_response_cm)
        mock_session_cm.__aenter__.return_value = mock_session_instance
        mock_session.return_value = mock_session_cm
        ioc = {"value": "abcdef1234567890", "source": "src", "tags": []}
        result = await self.ms.parse_and_send(ioc)
        self.assertFalse(result)
        mock_logger.error.assert_called()

if __name__ == "__main__":
    asyncio.run(unittest.main())
