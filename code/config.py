from dataclasses import dataclass, field
from datetime import datetime, timedelta
import os

# The instances are frozen to ensure immutability and thread-safety when shared across the application.
@dataclass(frozen=True)
class ThreatIntelConfig:
    """Configuration for threat-intel ingestion jobs."""

    region: str = field(default_factory=lambda: os.getenv("AWS_REGION", "ap-southeast-2"))
    umbrella_dest_list_ids: tuple[str, str] = ("17699844", "17699845")
    # Ensure default_factory are created per instance of data class, not when module is loaded.
    confidence: int = field(
        default_factory=lambda: int(os.getenv("THREAT_INTEL_CONFIDENCE", "60"))
    )
    mandiant_fusion_id: str = "375"
    cfc_id: str = "11711"
    cisa_id: str = "403"
    # The env vars store the SSM parameter names, which are then resolved at runtime by AWSClient. This allows for dynamic retrieval and decryption of secrets without hardcoding them in the codebase.
    ms_creds: list[str] = field(
        default_factory=lambda: [
            os.getenv("MS_CLIENT_ID", "client_id_new"),
            os.getenv("MS_TENANT_ID", "tenant_id_new"),
        ]
    )
    cisco_creds: list[str] = field(
        default_factory=lambda: [
            os.getenv("UMBRELLA_KEY", "umbrella_key_new"),
            os.getenv("UMBRELLA_SECRET", "umbrella_secret_new"),
        ]
    )
    anomali_creds: list[str] = field(
        default_factory=lambda: [
            os.getenv("ANOMALI_USERNAME", "username_new"),
            os.getenv("ANOMALI_APIKEY", "api_key_new"),
        ]
    )
    secret_cache_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("SECRET_CACHE_TTL_SECONDS", "300"))
    )

    def _time_delta(self, hours_back: int) -> str:
        return (datetime.now() - timedelta(hours=hours_back)).isoformat(
            sep="T", timespec="auto"
        )

    def anomali_hash_endpoint(self, hours_back: int) -> str:
        time_delta = self._time_delta(hours_back)
        return (
            "https://api.threatstream.com/api/v2/intelligence/?limit=0&q="
            f"(created_ts>={time_delta})+AND+confidence>={self.confidence}+"
            "AND+status=active+AND+type=hash+AND+subtype=SHA256+AND+"
            f"(trusted_circle_id={self.mandiant_fusion_id}+OR+"
            f"trusted_circle_id={self.cisa_id}+OR+trusted_circle_id={self.cfc_id})"
        )

    def anomali_domain_endpoint(self, hours_back: int) -> str:
        time_delta = self._time_delta(hours_back)
        return (
            "https://api.threatstream.com/api/v2/intelligence/?limit=0&q="
            f"(created_ts>={time_delta})+AND+confidence>={self.confidence}+"
            "AND+status=active+AND+type=domain+AND+"
            f"(trusted_circle_id={self.mandiant_fusion_id}+OR+"
            f"trusted_circle_id={self.cfc_id}+OR+trusted_circle_id={self.cisa_id})"
        )
    
    def anomali_ip_endpoint(self, hours_back: int) -> str:
        time_delta = self._time_delta(hours_back)
        return (
            "https://api.threatstream.com/api/v2/intelligence/?limit=0&q="
            f"(created_ts>={time_delta})+AND+confidence>={self.confidence}+"
            "AND+status=active+AND+type=ip+AND+"
            f"(trusted_circle_id={self.mandiant_fusion_id}+OR+"
            f"trusted_circle_id={self.cfc_id}+OR+trusted_circle_id={self.cisa_id})"
        )
