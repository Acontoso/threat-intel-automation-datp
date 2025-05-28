import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from code.services import anomali

class TestAnomaliServices(unittest.IsolatedAsyncioTestCase):
    def test_return_header(self):
        username = "user"
        api_key = "key"
        header = anomali.return_header(username, api_key)
        self.assertEqual(header, {"Authorization": f"apikey {username}:{api_key}"})

    @patch("code.services.anomali.logger")
    @patch("aiohttp.ClientSession")
    async def test_pull_indicators_success(self, mock_session, mock_logger):
        mock_session_cm = AsyncMock()
        mock_response_cm = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"objects": [1, 2, 3]})
        mock_response_cm.__aenter__.return_value = mock_response
        mock_response_cm.__aexit__.return_value = None
        mock_session_instance = AsyncMock()
        mock_session_instance.get = MagicMock(return_value=mock_response_cm)
        mock_session_cm.__aenter__.return_value = mock_session_instance
        mock_session.return_value = mock_session_cm
        result = await anomali.pull_indicators("http://test", {"Authorization": "x"})
        self.assertEqual(result, [1, 2, 3])
        mock_logger.error.assert_not_called()

    @patch("code.services.anomali.logger")
    @patch("aiohttp.ClientSession")
    async def test_pull_indicators_failure(self, mock_session, mock_logger):
        mock_session_cm = AsyncMock()
        mock_response_cm = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 400
        mock_response.text = "fail"
        mock_response_cm.__aenter__.return_value = mock_response
        mock_response_cm.__aexit__.return_value = None
        mock_session_instance = AsyncMock()
        mock_session_instance.get = MagicMock(return_value=mock_response_cm)
        mock_session_cm.__aenter__.return_value = mock_session_instance
        mock_session.return_value = mock_session_cm
        with self.assertRaises(Exception):
            await anomali.pull_indicators("http://test", {"Authorization": "x"})
        mock_logger.error.assert_called()

if __name__ == "__main__":
    unittest.main()
