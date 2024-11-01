from utils.logs import configure_logging
import aiohttp
import json
import ioc_fanger
from .anomali import return_header, pull_indicators


class CiscoServices:
    """Class used to store static methods used to interact with Cisco API services"""

    def __init__(
        self,
        umbrella_key: str,
        umbrella_secret: str,
        destination_lists: list,
        anomali_username: str,
        anomali_apikey: str,
    ):
        """Init function to class"""
        self.umbrella_key = umbrella_key
        self.umbrella_secret = umbrella_secret
        self.logger = configure_logging()
        self.token = ""
        self.dest_list = destination_lists
        self.anomali_username = anomali_username
        self.anomali_apikey = anomali_apikey

    async def generate_umbrella_jwt(self) -> str:
        """Generate JWT token via Client Credential flow"""
        header = {"Content-Type": "application/x-www-form-urlencoded"}
        token_endpoint = "https://api.umbrella.com/auth/v2/token"
        timeout = aiohttp.ClientTimeout(total=60)
        data = "grant_type=client_credentials"
        auth = aiohttp.BasicAuth(login=self.umbrella_key, password=self.umbrella_secret)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                url=token_endpoint, data=data, headers=header, auth=auth
            ) as response:
                if response.status != 200:
                    self.logger.error(
                        f"[-] Failed to pull JWT token from Umbrella... {response.text}"
                    )
                    raise Exception(
                        f"[-] Failed to pull JWT token from Umbrella... {response.text}"
                    )
                resp = await response.json()
                self.token = resp.get("access_token")
                return resp.get("access_token")

    async def ingest_threat_intel_network_ioc(self, anomali_endpoint: str) -> None:
        """Function to pull network based IOC's and upload to umbrella"""
        jwt_token = await self.generate_umbrella_jwt()
        header = return_header(self.anomali_username, self.anomali_apikey)
        threat_objects = await pull_indicators(anomali_endpoint, header)
        total = len(threat_objects)
        if total == 0:
            self.logger.info("[+] No new network indicators.... returning")
            return
        self.logger.info(f"[+] Number of new network threat intel to import is {total}")
        payload = await self.create_payload(threat_objects)
        headers_umbrella = {
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json",
        }
        for index, umbrella_list in enumerate(self.dest_list):
            endpoint = f"https://api.umbrella.com/policies/v2/destinationlists/{umbrella_list}/destinations"
            timeout = aiohttp.ClientTimeout(total=60)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    url=endpoint, data=json.dumps(payload), headers=headers_umbrella
                ) as response:
                    await response.json()
            match index:
                case 0:
                    policy = "DNS"
            match index:
                case 1:
                    policy = "WEB"
            if response.status == 200:
                self.logger.info(
                    f"[+] Successfully imported domain IOC's into Umbrella {policy} destination list"
                )
            else:
                self.logger.info(
                    f"[-] Failed to import domain IOC's into Umbrella {policy} destination list"
                )

    async def create_payload(self, threat_objects: list) -> list:
        """Convert threat objects returned into acceptable payload"""
        iocs = []
        for threat in threat_objects:
            value = threat.get("value")
            source = threat.get("source")
            logged_defanged_value = ioc_fanger.defang(value)
            self.logger.info(f"[+] Adding Indicator {logged_defanged_value}")
            ioc_dict = {
                "destination": value,
                "comment": f"Automated threat intel ingestion from {source} intel feeds",
            }
            iocs.append(ioc_dict)
        return iocs
