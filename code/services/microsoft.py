from datetime import datetime, timedelta, timezone
from io import StringIO
from azure.identity import ClientAssertionCredential
from code.utils.logs import logger
import aiohttp
import asyncio
from code.services.anomali import return_header, pull_indicators
from code.services.aws import AWSServices


class MSServices:
    """Class used to store static methods used to interact with Microsoft services"""

    def __init__(
        self,
        client_id: str,
        tenant_id: str,
        anomali_username: str,
        anomali_apikey: str,
        token="",
    ):
        """Init function to class"""
        self.client_id = client_id
        self.tenant_id = tenant_id
        self.anomali_username = anomali_username
        self.anomali_apikey = anomali_apikey
        self.token = token

    async def access_token_ms_sec_api(self) -> None:
        """Get OAuth access token to send data to Microsoft Defender 365"""
        scope = "https://api.securitycenter.windows.com/.default"
        token = ClientAssertionCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            func=AWSServices.get_token,
        )
        if token:
            try:
                access_token = token.get_token(scope).token
                logger.info("[+] Successfully received token from Azure AD")
                self.token = access_token
                return None
            except Exception as error:
                logger.error(f"[-] Failed to get access token from Azure AD: {error}")
                return None
        else:
            logger.error("[-] Failed to get token from Cognito")
            return None

    async def check_indicator(self, indicator: str) -> bool:
        """Check to see if indicator already exists in Defender for Endpoint (async)"""
        endpoint = f"https://api.securitycenter.microsoft.com/api/indicators?$filter=indicatorValue+eq+'{indicator}'"
        header = {"Authorization": f"Bearer {self.token}"}
        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url=endpoint, headers=header) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if len(data.get("value", [])) > 0:
                        logger.info(f"[+] Indicator exists: {indicator}")
                        return True
                    return False
                logger.error(f"[-] Failed to pull indicator: {await resp.text()}")
                logger.info(f"[+] Going to attempt to import IOC {indicator}")
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

    async def parse_and_send(self, ioc: dict) -> bool:
        ioc_value = ioc.get("value")
        exists = await self.check_indicator(ioc_value)
        if exists:
            return True
        payload_dict = self.construct_payload_defender(ioc)
        endpoint = "https://api.securitycenter.microsoft.com/api/indicators"
        header = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60)
        ) as session:
            async with session.post(
                url=endpoint, headers=header, json=payload_dict
            ) as response:
                if response.status == 200:
                    logger.info(f"[+] Added indicator: {ioc.get('value')}")
                    return True
                logger.error(
                    f"[-] Response code from API call to submit indicator - {ioc_value} returned {response.status} status code"
                )
                logger.error(f"[-] {await response.text()}")
                return False

    async def runner(self, threat_objects: list) -> None:
        """Main async runner using asyncio.gather"""
        # * unpacks the list of threat objects and runs parse_and_send concurrently
        results = await asyncio.gather(
            *(self.parse_and_send(ioc) for ioc in threat_objects)
        )
        success = sum(1 for r in results if r)
        failures = len(results) - success
        logger.info(f"[+] Successful uploads {success}")
        logger.info(f"[-] Unsuccessful uploads {failures}")

    async def ingest_threat_intel_hash(self, anomali_endpoint: str) -> None:
        """Main function to pull and send data to Defender for Endpoint"""
        header = return_header(self.anomali_username, self.anomali_apikey)
        await self.access_token_ms_sec_api()
        threat_objects = await pull_indicators(anomali_endpoint, header)
        total = len(threat_objects)
        logger.info(f"[+] Number of new threat intel to import is {total}")
        if total > 50:
            for index in range(0, total, 50):
                threat_objects_subset = threat_objects[index : index + 50]
                await self.runner(threat_objects_subset)
                await asyncio.sleep(60)
        else:
            if total == 0:
                logger.info("[+] No Intel to upload... returning")
                return
            else:
                await self.runner(threat_objects)
                return
