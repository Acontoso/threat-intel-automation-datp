import asyncio
from typing import Any
import aiohttp
from models.recordedfuturemodels import (
    MalwareAnalysisResponse,
    MalwareLookupPayload,
    MalwareLookupResponse,
    IOCLookupPayload,
    IOCSearchResponse,
)
from strands import tool
from services.aws import AWSClient

BASE_URL = "https://api.recordedfuture.com"
DEFAULT_REGION = "ap-southeast-2"
DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 0.5
_RETRY_STATUS_CODES = (429, 500, 502, 503, 504)


class RecordedFutureClient:
    """Typed client for Recorded Future APIs with shared HTTP/session concerns."""

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
                "accept": "application/json",
                "content-type": "application/json",
                "X-RFToken": _get_recorded_future_token(),
            }
        return self._cached_headers

    async def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        session = self._get_session()

        for attempt in range(self.max_retries + 1):
            try:
                async with session.post(url, json=payload, headers=self._headers()) as response:
                    if response.status in _RETRY_STATUS_CODES and attempt < self.max_retries:
                        await asyncio.sleep(self.backoff_factor * (2 ** attempt))
                        continue
                    response.raise_for_status()
                    data = await response.json()
                    if not isinstance(data, dict):
                        raise ValueError("Expected JSON object response from Recorded Future API")
                    return data
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt >= self.max_retries:
                    raise
                await asyncio.sleep(self.backoff_factor * (2 ** attempt))

        raise RuntimeError("Recorded Future request retry loop terminated unexpectedly")

    @tool
    async def search_malware(
        self, event: MalwareLookupPayload
    ) -> list[MalwareLookupResponse]:
        """
        Search for malware reports found within the Recorded Future database.

        Args:
            event: The payload containing the malware lookup parameters (pydantic model).
        """
        payload = {
            "field": "sha256",
            "sha256_list": event.sha256_list,
            "start_date": "2023-11-01",
        }
        json_response = await self._post_json("/malware-intelligence/v1/query_iocs", payload)
        data = json_response.get("data", [])
        if not data:
            return [MalwareLookupResponse(risk_score=0, file_extensions=[], tags=[])]

        data_return: list[MalwareLookupResponse] = []
        for item in data:
            risk_score = item.get("risk_score", 0)
            file_extensions = item.get("file_extensions", [])
            tags = item.get("tags", [])
            sandbox_score = item.get("sandbox_score", 0)
            data_return.append(
                MalwareLookupResponse(
                    risk_score=risk_score,
                    file_extensions=file_extensions,
                    tags=tags,
                    sandbox_score=sandbox_score,
                    hash=item.get("name"),
                )
            )
        return data_return
    
    @tool
    async def search_ioc(self, event: IOCLookupPayload) -> IOCSearchResponse:
        """
        Search for IOC's found within the Recorded Future database. This looks at all 3 types of IOC's - IP, domain and hash. The response contains a risk score, details about the entity and related rules/evidence.

        Args:
            event: The payload containing the search IOC lookup parameters (pydantic model).
        """
        payload = {
            "ip": event.ip or [],
            "domain": event.domain or [],
            "hash": event.hash or [],
        }
        json_response = await self._post_json("/soar/v3/enrichment", payload)
        return IOCSearchResponse.model_validate(json_response)

    @tool
    async def search_sandbox(self, hash_value: str) -> MalwareAnalysisResponse:
        """
        Search for malware sandbox reports based on a provided SHA256 hash.

        Args:
            hash_value: The SHA256 hash to search for in the sandbox reports.
        """
        payload = {
            "query": "dynamic.signatures_count > 1",
            "sha256": hash_value,
            "start_date": "2023-11-01",
        }
        json_response = await self._post_json("/malware-intelligence/v1/reports", payload)
        return MalwareAnalysisResponse.model_validate(json_response)


def _get_recorded_future_token() -> str:
    return AWSClient(DEFAULT_REGION).get_ssm_parameters(["apikey"])[0]
