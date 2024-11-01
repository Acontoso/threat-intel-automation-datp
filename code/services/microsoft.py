from datetime import datetime, timedelta, timezone
import concurrent.futures
import time
import json
from io import StringIO
from utils.logs import configure_logging
import aiohttp
import requests
import asyncio
from .anomali import return_header, pull_indicators


class MSServices:
    """Class used to store static methods used to interact with Microsoft services"""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        tenant_id: str,
        anomali_username: str,
        anomali_apikey: str,
        token="",
    ):
        """Init function to class"""
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.logger = configure_logging()
        self.anomali_username = anomali_username
        self.anomali_apikey = anomali_apikey
        self.token = token

    def generate_access_token_payload(self, scope: str) -> str:
        """Generate payload for access token for client credential flow"""
        payload = (
            "client_id="
            + self.client_id
            + "&scope="
            + scope
            + "&client_secret="
            + self.client_secret
            + "&grant_type=client_credentials"
        )
        return payload

    async def access_token_ms_sec_api(self) -> str:
        """Get OAuth access token to send data to Microsoft Defender 365"""
        security_centre_scope = "https://api.securitycenter.windows.com/.default"
        payload = self.generate_access_token_payload(security_centre_scope)
        endpoint = (
            "https://login.microsoftonline.com/" + self.tenant_id + "/oauth2/v2.0/token"
        )
        headers = {"content-type": "application/x-www-form-urlencoded"}
        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                url=endpoint, data=payload, headers=headers
            ) as response:
                resp = await response.json()
        if response.status != 200:
            self.logger.error(f"[-] Failed to pull access token - {response.status}")
            raise Exception(f"[-] Failed to pull access token - {response.status}")
        token = resp["access_token"]
        self.token = token
        return token

    def check_indicator(self, indicator: str) -> bool:
        """Check to see if indicator already exists in Defender for Endpoint"""
        endpoint = f"https://api.securitycenter.microsoft.com/api/indicators?$filter=indicatorValue+eq+'{indicator}'"
        header = {"Authorization": f"Bearer {self.token}"}
        resp = requests.get(url=endpoint, headers=header, timeout=60)
        if resp.status_code == 200:
            if len(resp.json().get("value")) > 0:
                self.logger.info(f"[+] Indicator exists: {indicator}")
                return True
            return False
        self.logger.error(msg=f"[-] Failed to pull indicator", extra=resp.text)
        self.logger.info(f"[+] Going to attempt to import IOC {indicator}")
        return False

    @classmethod
    def construct_payload_defender(cls, ioc: dict) -> dict:
        """Create unique payload for DATP upload"""
        time_delta = (
            (datetime.now(timezone.utc) + timedelta(weeks=52))
            .isoformat("T", "seconds")
            .replace("+00:00", "Z")
        )
        msg_str = StringIO()
        msg_str.write("Tags assigned to TI\n\n")
        source = ioc.get("source")
        indicator = ioc.get("value")
        tags = ioc.get("tags")
        for tag in tags:
            name = tag.get("name")
            msg_str.write(f"{name}\n")
        identifier = indicator[-4:]
        ti_payload = {}
        ti_payload["indicatorValue"] = indicator
        ti_payload["title"] = f"{source}-{identifier}"
        ti_payload["description"] = msg_str.getvalue()
        ti_payload["action"] = "BlockAndRemediate"
        ti_payload["severity"] = "High"
        ti_payload["indicatorType"] = "FileSha256"
        ti_payload["generateAlert"] = True
        ti_payload["expirationTime"] = time_delta

        return ti_payload

    def parse_and_send(self, ioc: dict) -> bool:
        """Parsed the indicator and send to Defender for Endpoint"""
        ioc_value = ioc.get("value")
        exists = self.check_indicator(ioc_value)
        if exists:
            return True
        payload_dict = self.construct_payload_defender(ioc)
        endpoint = "https://api.securitycenter.microsoft.com/api/indicators"
        header = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        response = requests.post(
            url=endpoint, headers=header, data=json.dumps(payload_dict), timeout=60
        )
        if response.status_code == 200:
            self.logger.info(f"[+] Added indicator: {ioc.get('value')}")
            return True
        self.logger.error(
            f"[-] Response code from API call to submit indicator - {ioc_value} returned {response.status_code} status code"
        )
        self.logger.error(f"[-] {response.text}")
        return False

    async def runner(self, threat_objects: list) -> None:
        """Main thread pool runner"""
        success = 0
        failures = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(self.parse_and_send, threat_objects)
            for result in results:
                if result:
                    success = success + 1
                else:
                    failures = failures + 1
        self.logger.info(f"[+] Successful uploads {success}")
        self.logger.info(f"[-] Unsuccessful uploads {failures}")
        return

    async def ingest_threat_intel_hash(self, anomali_endpoint: str) -> None:
        """Main function to pull and send data to Defender for Endpoint"""
        header = return_header(self.anomali_username, self.anomali_apikey)
        await self.access_token_ms_sec_api()
        threat_objects = await pull_indicators(anomali_endpoint, header)
        total = len(threat_objects)
        self.logger.info(f"[+] Number of new threat intel to import is {total}")
        if total > 50:
            for index in range(0, total, 50):
                threat_objects_subset = threat_objects[index : index + 50]
                await self.runner(threat_objects_subset)
                await asyncio.sleep(60)
        else:
            if total == 0:
                self.logger.info("[+] No Intel to upload... returning")
                return
            else:
                self.runner(threat_objects)
                return
