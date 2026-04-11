import asyncio
import os
from typing import Any
import aiohttp
from code.services.aws import AWSClient
from code.utils.logs import logger
from code.models.opensourcemodels import PackageSearchResponse, MaliciousPackageResponse, CleanPackageResponse, ThreatReportResponse

from strands import tool

BASE_URL = "https://api.opensourcemalware.com"
DEFAULT_REGION = "ap-southeast-2"
DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 0.5
_RETRY_STATUS_CODES = (429, 500, 502, 503, 504)


class OpenSourceClient:
    """Typed client for Open Source Malware APIs with shared HTTP/session concerns."""

    def __init__(
        self,
        base_url: str = BASE_URL,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.session = session
        self._cached_headers: dict[str, str] | None = None
        self._owns_session = session is None
        self._token = _get_token_provider()

    def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session

    async def aclose(self) -> None:
        if self._owns_session and self.session and not self.session.closed:
            await self.session.close()

    def _headers(self) -> dict[str, str]:
        if self._cached_headers is None:
            self._cached_headers = {
                "Authorization": f"Bearer {self._token}",
            }
        return self._cached_headers

    async def _send_request(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        session = self._get_session()

        for attempt in range(self.max_retries + 1):
            try:
                async with session.get(
                    url,
                    headers=self._headers(),
                    params=payload,
                ) as response:
                    if response.status in _RETRY_STATUS_CODES and attempt < self.max_retries:
                        await asyncio.sleep(self.backoff_factor * (2 ** attempt))
                        continue
                    response.raise_for_status()
                    data = await response.json()
                    if not isinstance(data, dict):
                        raise ValueError("Expected JSON object response from Open Source API")
                    return data
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt >= self.max_retries:
                    raise
                await asyncio.sleep(self.backoff_factor * (2 ** attempt))

        raise RuntimeError("Open Source request retry loop terminated unexpectedly")

    @tool
    async def search_package(self, package_name: str, ecosystem: str, version: str | None = None) -> PackageSearchResponse:
        """
        Search for compromised packages in the Open Source Malware database based on package name, ecosystem and optionally version. The response includes details about the package, its risk score and any associated malware or threat reports.

        Args:
            package_name: The name of the package to search for.
            ecosystem: The ecosystem of the package (required: npm, pypi, maven, nuget, vscode).
            version: The version of the package (optional).
        """
        logger.info(f"Searching for package: {package_name}, ecosystem: {ecosystem}, version: {version}")
        payload = {
            "package_name": package_name,
            "ecosystem": ecosystem,
        }
        if version:
            payload["version"] = version
        json_response = await self._send_request("/functions/v1/check-package-malicious", payload)
        # Validate to appropriate model based on malicious field
        if json_response.get("malicious"):
            return MaliciousPackageResponse.model_validate(json_response)
        else:
            return CleanPackageResponse.model_validate(json_response)


    async def search_threat(self, threat_id: str) -> ThreatReportResponse:
        """Search for a package in the Open Source Malware database and return analysis results."""
        logger.info(f"Searching for IOCs related to threat ID: {threat_id}")
        payload = {
            "threat_id": threat_id,
        }
        json_response = await self._send_request("/functions/v1/threat-data", payload)
        return ThreatReportResponse.model_validate(json_response)


def _get_token_provider() -> str:
    if "AWS_LAMBDA_FUNCTION_NAME" in os.environ:
        aws_client = AWSClient(DEFAULT_REGION)
        return aws_client.get_ssm_parameters(["opensource_api_token"])[0]
    else:
        token = os.getenv("OPENSOURCE_API_TOKEN")
        if not token:
            raise EnvironmentError("OPENSOURCE_API_TOKEN environment variable is required when not running in AWS Lambda")
        return token
