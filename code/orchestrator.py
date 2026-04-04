import asyncio
import time

from code.config import ThreatIntelConfig
from code.services.anomali import AnomaliClient
from code.services.aws import AWSClient
from code.services.cisco import CiscoServices
from code.services.microsoft import MSServices


class ThreatIntelOrchestrator:
    """Coordinates ingestion workflows across supported platforms."""

    def __init__(self, config: ThreatIntelConfig):
        self.config = config
        self.aws_client = AWSClient(config.region)
        self._credential_cache: dict[str, str] | None = None
        self._credential_cache_expiry = 0.0
        self._credential_cache_lock = asyncio.Lock()

    def _load_runtime_credentials(self) -> dict[str, str]:
        ms_client_id, ms_tenant_id = self.aws_client.get_ssm_parameters(
            self.config.ms_creds
        )
        umbrella_key, umbrella_secret = self.aws_client.get_ssm_parameters(
            self.config.cisco_creds
        )
        anomali_username, anomali_apikey = self.aws_client.get_ssm_parameters(
            self.config.anomali_creds
        )
        return {
            "ms_client_id": ms_client_id,
            "ms_tenant_id": ms_tenant_id,
            "umbrella_key": umbrella_key,
            "umbrella_secret": umbrella_secret,
            "anomali_username": anomali_username,
            "anomali_apikey": anomali_apikey,
        }

    async def _load_runtime_credentials_cached(
        self, force_refresh: bool = False
    ) -> dict[str, str]:
        now = time.monotonic()
        if (
            not force_refresh
            and self._credential_cache is not None
            and now < self._credential_cache_expiry
        ):
            return self._credential_cache

        async with self._credential_cache_lock:
            now = time.monotonic()
            if (
                not force_refresh
                and self._credential_cache is not None
                and now < self._credential_cache_expiry
            ):
                return self._credential_cache
            # Run this in thread to avoid blocking the event loop, as it involves network calls to AWS SSM which are synchronous.
            creds = await asyncio.to_thread(self._load_runtime_credentials)
            self._credential_cache = creds
            self._credential_cache_expiry = (
                time.monotonic() + self.config.secret_cache_ttl_seconds
            )
            return creds

    async def warmup(self) -> None:
        """Preload credentials into cache for lower first-request latency."""
        await self._load_runtime_credentials_cached(force_refresh=True)

    async def run(
        self,
        hours_back: int = 12,
        run_microsoft: bool = True,
        run_cisco: bool = True,
        force_refresh_credentials: bool = False,
    ) -> dict[str, str | list[str]]:
        if not run_microsoft and not run_cisco:
            raise ValueError("At least one target must be enabled")

        creds = await self._load_runtime_credentials_cached(
            force_refresh=force_refresh_credentials
        )
        anomali_client = AnomaliClient(
            creds["anomali_username"], creds["anomali_apikey"]
        )
        tasks = []
        triggered_targets = []

        if run_microsoft:
            ms_client = MSServices(
                creds["ms_client_id"],
                creds["ms_tenant_id"],
                anomali_client=anomali_client
            )
            tasks.append(
                ms_client.ingest_threat_intel_hash(
                    self.config.anomali_hash_endpoint(hours_back)
                )
            )
            triggered_targets.append("microsoft")

        if run_cisco:
            cisco_client = CiscoServices(
                creds["umbrella_key"],
                creds["umbrella_secret"],
                self.config.umbrella_dest_list_ids,
                anomali_client=anomali_client,
            )
            tasks.append(
                cisco_client.ingest_threat_intel_network_ioc(
                    self.config.anomali_domain_endpoint(hours_back)
                )
            )
            triggered_targets.append("cisco")

        await asyncio.gather(*tasks)

        return {
            "status": "ok",
            "triggered_targets": triggered_targets,
            "query_since": self.config._time_delta(hours_back),
        }
