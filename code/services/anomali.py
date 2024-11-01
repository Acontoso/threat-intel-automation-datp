import aiohttp
from utils.logs import configure_logging

LOGGER = configure_logging


def return_header(username: str, api_key: str) -> dict:
    """Return header for Anomali API call"""
    return {"Authorization": f"apikey {username}:{api_key}"}


async def pull_indicators(anomali_endpoint: str, header: dict) -> dict:
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url=anomali_endpoint, headers=header) as response:
            if response.status != 200:
                LOGGER.error(f"[-] Failed to pull JWT token from Umbrella...")
                raise Exception(f"[-] Failed to pull JWT token from Umbrella...")
            resp = await response.json()
            threat_objects = resp.get("objects")
            return threat_objects
