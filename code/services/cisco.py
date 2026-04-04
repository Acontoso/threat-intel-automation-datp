from code.utils.logs import logger
import aiohttp
import json
import ioc_fanger
from code.services.anomali import AnomaliClient


class CiscoServices:
    """Reusable Cisco Umbrella client."""

    def __init__(
        self,
        umbrella_key: str,
        umbrella_secret: str,
        destination_lists: list[str],
        anomali_client: AnomaliClient | None = None,
        anomali_username: str | None = None,
        anomali_apikey: str | None = None,
    ):
        """Init function to class"""
        self.umbrella_key = umbrella_key
        self.umbrella_secret = umbrella_secret
        self.token = ""
        self.dest_list = destination_lists
        if anomali_client:
            self.anomali_client = anomali_client
        elif anomali_username and anomali_apikey:
            self.anomali_client = AnomaliClient(anomali_username, anomali_apikey)
        else:
            raise ValueError(
                "Either an anomali_client or anomali credentials must be provided"
            )
        self.timeout = aiohttp.ClientTimeout(total=60)

    async def generate_umbrella_jwt(self, session: aiohttp.ClientSession) -> str:
        """Generate JWT token via Client Credential flow"""
        header = {"Content-Type": "application/x-www-form-urlencoded"}
        token_endpoint = "https://api.umbrella.com/auth/v2/token"
        data = "grant_type=client_credentials"
        auth = aiohttp.BasicAuth(login=self.umbrella_key, password=self.umbrella_secret)
        async with session.post(
            url=token_endpoint, data=data, headers=header, auth=auth
        ) as response:
            if response.status != 200:
                logger.error(
                    "[-] Failed to pull JWT token from Umbrella... %s",
                    await response.text(),
                )
                raise Exception("Failed to pull JWT token from Umbrella")
            resp = await response.json()
            self.token = resp.get("access_token")
            return resp.get("access_token")

    async def ingest_threat_intel_network_ioc(self, anomali_endpoint: str) -> None:
        """Function to pull network based IOC's and upload to umbrella"""
        threat_objects = await self.anomali_client.pull_indicators(anomali_endpoint)
        total = len(threat_objects)
        if total == 0:
            logger.info("[+] No new network indicators.... returning")
            return

        logger.info(f"[+] Number of new network threat intel to import is {total}")
        payload = await self.create_payload(threat_objects)

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            jwt_token = await self.generate_umbrella_jwt(session)
            headers_umbrella = {
                "Authorization": f"Bearer {jwt_token}",
                "Content-Type": "application/json",
            }

            for index, umbrella_list in enumerate(self.dest_list):
                endpoint = f"https://api.umbrella.com/policies/v2/destinationlists/{umbrella_list}/destinations"
                async with session.post(
                    url=endpoint,
                    data=json.dumps(payload),
                    headers=headers_umbrella,
                ) as response:
                    await response.json()

                policy = "DNS" if index == 0 else "WEB" if index == 1 else umbrella_list
                if response.status == 200:
                    logger.info(
                        f"[+] Successfully imported domain IOC's into Umbrella {policy} destination list"
                    )
                else:
                    logger.info(
                        f"[-] Failed to import domain IOC's into Umbrella {policy} destination list"
                    )

    async def create_payload(self, threat_objects: list) -> list:
        """Convert threat objects returned into acceptable payload"""
        iocs = []
        for threat in threat_objects:
            value = threat.get("value")
            source = threat.get("source")
            logged_defanged_value = ioc_fanger.defang(value)
            logger.info(f"[+] Adding Indicator {logged_defanged_value}")
            ioc_dict = {
                "destination": value,
                "comment": f"Automated threat intel ingestion from {source} intel feeds",
            }
            iocs.append(ioc_dict)
        return iocs
