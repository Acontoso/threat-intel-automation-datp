from pydantic import BaseModel, Field
from typing import Optional


class ThreatDetails(BaseModel):
    """Details about a detected threat in a malicious package."""
    threat_id: str = Field(..., description="Unique identifier of the threat record.")
    severity_level: str = Field(..., description="Severity assigned to the detected threat.")
    description: str = Field(..., description="Human-readable description of the malicious behavior.")
    version_info: str = Field(..., description="Version metadata associated with the threat details.")


class MaliciousPackageResponse(BaseModel):
    """Response when a package is found to be malicious."""
    malicious: bool = Field(default=True, description="Indicates that the package is malicious.")
    package_name: str = Field(..., description="Name of the package that was searched.")
    ecosystem: str = Field(..., description="Package ecosystem/registry of the package.")
    version: str | None = Field(default=None, description="Version of the package if provided or available.")
    threat_count: int = Field(..., description="Number of threats associated with the package.")
    details: ThreatDetails = Field(..., description="Detailed threat metadata for the malicious package.")


class CleanPackageResponse(BaseModel):
    """Response when a package is not found in the malicious database."""
    malicious: bool = Field(default=False, description="Indicates that the package is not flagged as malicious.")
    package_name: str = Field(..., description="Name of the package that was searched.")
    ecosystem: str = Field(..., description="Package ecosystem/registry of the package.")
    version: str | None = Field(default=None, description="Version of the package if provided or available.")
    threat_count: int | None = Field(default=None, description="Threat count if provided by the API for non-malicious results.")
    message: str | None = Field(default=None, description="Informational API message for clean package results.")


PackageSearchResponse = MaliciousPackageResponse | CleanPackageResponse


class IOCEntry(BaseModel):
    """Indicator of compromise details associated with a threat report."""
    ioc_type: str = Field(..., description="Type/category of indicator of compromise (for example domain or c2_server).")
    value: str = Field(..., description="Observed IOC value.")
    confidence_level: str = Field(..., description="Confidence level assigned to the IOC.")
    description: str | None = Field(default=None, description="Optional context explaining the IOC.")


class ThreatReportResponse(BaseModel):
    """Detailed threat report for a malicious package or artifact."""
    threat_id: str = Field(..., description="Unique identifier of the threat report.")
    package_name: str = Field(..., description="Name of the affected package.")
    registry: str = Field(..., description="Registry/ecosystem where the package is published.")
    report_type: str = Field(..., description="Type of report returned by the service.")
    severity_level: str = Field(..., description="Severity level assigned to the report.")
    threat_description: str = Field(..., description="Narrative description of the threat behavior.")
    osm_url: str = Field(..., description="Open Source Malware URL for the threat report.")
    iocs: list[IOCEntry] = Field(..., description="List of indicators of compromise linked to this threat.")
    ioc_count: int = Field(..., description="Total number of IOCs returned in the report.")
