import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from code.services.cisco import CiscoServices

class TestCiscoServices(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.cisco = CiscoServices(
            umbrella_key="key",
            umbrella_secret="secret",
            destination_lists=["list1", "list2"],
            anomali_username="user",
            anomali_apikey="apikey"
        )

    @patch("code.services.cisco.aiohttp.ClientSession")
    @patch("code.services.cisco.aiohttp.BasicAuth")
    async def test_generate_umbrella_jwt_success(self, mock_auth, mock_session):
        mock_session_cm = AsyncMock()
        mock_session_instance = AsyncMock()
        mock_post_cm = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"access_token": "jwt_token"})
        mock_post_cm.__aenter__.return_value = mock_response
        mock_post_cm.__aexit__.return_value = None
        mock_session_instance.post = MagicMock(return_value=mock_post_cm)
        mock_session_cm.__aenter__.return_value = mock_session_instance
        mock_session.return_value = mock_session_cm
        token = await self.cisco.generate_umbrella_jwt()
        self.assertEqual(token, "jwt_token")
        self.assertEqual(self.cisco.token, "jwt_token")

    @patch("code.services.cisco.logger")
    @patch("code.services.cisco.aiohttp.ClientSession")
    @patch("code.services.cisco.aiohttp.BasicAuth")
    async def test_generate_umbrella_jwt_failure(self, mock_auth, mock_session, mock_logger):
        mock_session_cm = AsyncMock()
        mock_session_instance = AsyncMock()
        mock_post_cm = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 400
        mock_response.text = "fail"
        mock_post_cm.__aenter__.return_value = mock_response
        mock_post_cm.__aexit__.return_value = None
        mock_session_instance.post = MagicMock(return_value=mock_post_cm)
        mock_session_cm.__aenter__.return_value = mock_session_instance
        mock_session.return_value = mock_session_cm
        with self.assertRaises(Exception):
            await self.cisco.generate_umbrella_jwt()
        mock_logger.error.assert_called()

    @patch("code.services.cisco.ioc_fanger.defang", return_value="defanged")
    @patch("code.services.cisco.logger")
    async def test_create_payload(self, mock_logger, mock_defang):
        threat_objects = [
            {"value": "malicious.com", "source": "anomali"},
            {"value": "bad.com", "source": "anomali"}
        ]
        payload = await self.cisco.create_payload(threat_objects)
        self.assertEqual(len(payload), 2)
        self.assertEqual(payload[0]["destination"], "malicious.com")
        self.assertIn("Automated threat intel ingestion", payload[0]["comment"])
        mock_logger.info.assert_called()
        mock_defang.assert_called()

    @patch("code.services.cisco.return_header", return_value={"header": "val"})
    #AsyncMock will return a coroutine that can be awaited
    #In this case, its used to mock the pull_indicators function which is expected to be an async function via the anomali service.
    @patch("code.services.cisco.pull_indicators", new_callable=AsyncMock)
    #Patch is used to replace and existing object or function with a mock object.
    #patch.object is used to patch a method of a class or module. Since they are async, these are defined as AsyncMock. new_callable is used to specify that the mock should be an AsyncMock.
    @patch.object(CiscoServices, "generate_umbrella_jwt", new_callable=AsyncMock)
    @patch.object(CiscoServices, "create_payload", new_callable=AsyncMock)
    @patch("code.services.cisco.aiohttp.ClientSession")
    @patch("code.services.cisco.logger")
    async def test_ingest_threat_intel_network_ioc_success(self, mock_logger, mock_session, mock_create_payload, mock_generate_jwt, mock_pull, mock_header):
        mock_generate_jwt.return_value = "jwt_token"
        mock_pull.return_value = [
            {"value": "malicious.com", "source": "anomali"}
        ]
        mock_create_payload.return_value = [{"destination": "malicious.com", "comment": "test"}]
        #Mocking async content manager for aiohttp.ClientSession.
        #When code triggers the context manager, it triggers mock_post_cm.__aenter__() and mock_post_cm.__aexit__() once finished.
        #mock_post_cm is a coroutine that simulates the behavior of an async context manager, hence __aenter__ and _aexit__ methods are defined.
        #on __aenter__, it returns a mock response (async couroutine) object that simulates the response from the API call.
        #the .json is a async method (hence AsyncMock) that returns a dictionary when called.
        mock_session_cm = AsyncMock()
        mock_session_instance = AsyncMock()
        mock_post_cm = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={})
        mock_post_cm.__aenter__.return_value = mock_response
        mock_post_cm.__aexit__.return_value = None
        #MagicMock is general purpose object that can be used to mock any python object (methods, attributes, MagicMethods - __enter__, __exit__, etc.)
        #Simulates the post method of the aiohttp.ClientSession instance.
        #When the post method is called, it returns the mock_post_cm coroutine, which is also an async coroutine.
        mock_session_instance.post = MagicMock(return_value=mock_post_cm)
        mock_session_cm.__aenter__.return_value = mock_session_instance
        mock_session.return_value = mock_session_cm
        await self.cisco.ingest_threat_intel_network_ioc("endpoint")
        mock_logger.info.assert_any_call("[+] Number of new network threat intel to import is 1")
        mock_logger.info.assert_any_call("[+] Successfully imported domain IOC's into Umbrella DNS destination list")

    @patch("code.services.cisco.return_header", return_value={"header": "val"})
    @patch("code.services.cisco.pull_indicators", new_callable=AsyncMock)
    @patch.object(CiscoServices, "generate_umbrella_jwt", new_callable=AsyncMock)
    @patch.object(CiscoServices, "create_payload", new_callable=AsyncMock)
    @patch("code.services.cisco.aiohttp.ClientSession")
    @patch("code.services.cisco.logger")
    async def test_ingest_threat_intel_network_ioc_failure(self, mock_logger, mock_session, mock_create_payload, mock_generate_jwt, mock_pull, mock_header):
        mock_generate_jwt.return_value = "jwt_token"
        mock_pull.return_value = [
            {"value": "malicious.com", "source": "anomali"}
        ]
        mock_create_payload.return_value = [{"destination": "malicious.com", "comment": "test"}]
        mock_session_cm = AsyncMock()
        mock_session_instance = AsyncMock()
        mock_post_cm = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 400
        mock_response.json = AsyncMock(return_value={})
        mock_post_cm.__aenter__.return_value = mock_response
        mock_post_cm.__aexit__.return_value = None
        mock_session_instance.post = MagicMock(return_value=mock_post_cm)
        mock_session_cm.__aenter__.return_value = mock_session_instance
        mock_session.return_value = mock_session_cm
        await self.cisco.ingest_threat_intel_network_ioc("endpoint")
        mock_logger.info.assert_any_call("[-] Failed to import domain IOC's into Umbrella DNS destination list")

    @patch("code.services.cisco.return_header", return_value={"header": "val"})
    @patch("code.services.cisco.pull_indicators", new_callable=AsyncMock)
    @patch.object(CiscoServices, "generate_umbrella_jwt", new_callable=AsyncMock)
    @patch("code.services.cisco.logger")
    async def test_ingest_threat_intel_network_ioc_no_threats(self, mock_logger, mock_generate_jwt, mock_pull, mock_header):
        mock_generate_jwt.return_value = "jwt_token"
        mock_pull.return_value = []
        await self.cisco.ingest_threat_intel_network_ioc("endpoint")
        mock_logger.info.assert_any_call("[+] No new network indicators.... returning")

if __name__ == "__main__":
    unittest.main()
