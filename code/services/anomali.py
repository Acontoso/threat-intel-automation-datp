import aiohttp
from code.utils.logs import logger


class AnomaliClient:
    """Reusable client for Anomali ThreatStream APIs."""

    def __init__(self, username: str, api_key: str, timeout_seconds: int = 60):
        self.username = username
        self.api_key = api_key
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)

    def build_header(self) -> dict[str, str]:
        """Return auth header for Anomali API calls."""
        return {"Authorization": f"apikey {self.username}:{self.api_key}"}

    async def pull_indicators(self, anomali_endpoint: str) -> list[dict]:
        """Pull indicators from the provided Anomali endpoint."""
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.get(
                url=anomali_endpoint,
                headers=self.build_header(),
            ) as response:
                if response.status != 200:
                    logger.error(
                        "[-] Failed to pull indicators from Anomali: %s",
                        await response.text(),
                    )
                    raise Exception("Failed to pull indicators from Anomali")
                resp = await response.json()
                return resp.get("objects", [])


def return_header(username: str, api_key: str) -> dict:
    """Backward-compatible helper for legacy call sites."""
    return AnomaliClient(username, api_key).build_header()


async def pull_indicators(anomali_endpoint: str, header: dict) -> dict:
    """Backward-compatible helper for legacy call sites."""
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url=anomali_endpoint, headers=header) as response:
            if response.status != 200:
                logger.error("[-] Failed to pull indicators from Anomali")
                raise Exception("Failed to pull indicators from Anomali")
            resp = await response.json()
            threat_objects = resp.get("objects", [])
            return threat_objects
