from pydantic import BaseModel, Field
from typing import Dict, List, Optional


class MalwareLookupPayload(BaseModel):
    sha256_list: List[str] = Field(..., description="List of SHA256 hashes")


class MalwareLookupResponse(BaseModel):
    risk_score: int = Field(..., description="Risk score of the malware")
    file_extensions: List[str] = Field(
        ..., description="List of file extensions associated with the malware"
    )
    tags: List[str] = Field(..., description="List of tags associated with the malware")
    sandbox_score: Optional[int] = Field(
        None, description="Sandbox score of the malware"
    )
    hash: str = Field(..., description="SHA256 hash of the malware")

class IOCLookupPayload(BaseModel):
    hash: List[str] = Field(..., description="List of SHA256 hashes")
    domain: List[str] = Field(..., description="List of domains")
    ip: List[str] = Field(..., description="List of IP addresses")


class RiskEvidence(BaseModel):
    rule: Optional[str] = None
    description: Optional[str] = None
    sightings: Optional[int] = None
    mitigation: Optional[str] = None
    timestamp: Optional[str] = None


class RiskRuleSummary(BaseModel):
    level: int = 0
    count: int = 0


class RiskRule(BaseModel):
    mostCritical: Optional[str] = None
    count: int = 0
    maxCount: int = 0
    evidence: Dict[str, RiskEvidence] = Field(default_factory=dict)


class Risk(BaseModel):
    score: int = 0
    rule: RiskRule = Field(default_factory=RiskRule)

class Entity(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None


class IOCResult(BaseModel):
    risk: Risk = Field(default_factory=Risk)
    entity: Entity = Field(default_factory=Entity)


class IOCSearchData(BaseModel):
    results: List[IOCResult] = Field(default_factory=list)


class IOCSearchResponse(BaseModel):
    data: IOCSearchData = Field(default_factory=IOCSearchData)

# Malware Analysis Report Models

class DumpedFile(BaseModel):
    """Model for dumped files in behavioral analysis"""
    md5: Optional[str] = None
    path: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    size: Optional[float] = None


class ExtractedConfig(BaseModel):
    """Model for extracted configuration from malware"""
    config: Optional[Dict] = None
    dumped_file: Optional[str] = None
    resource: Optional[str] = None


class DNSRecord(BaseModel):
    """Model for DNS records"""
    request_domain: Optional[List[str]] = None
    request_type: Optional[List[str]] = None
    response_type: Optional[List[str]] = None
    response_value: Optional[List[str]] = None


class NetworkFlow(BaseModel):
    """Model for network flows"""
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    id: Optional[int] = None
    proto: Optional[str] = None


class HTTPRequest(BaseModel):
    """Model for HTTP request details"""
    headers: Optional[List[str]] = None
    method: Optional[str] = None
    request: Optional[str] = None
    url: Optional[str] = None


class HTTPResponse(BaseModel):
    """Model for HTTP response details"""
    headers: Optional[List[str]] = None
    response: Optional[str] = None
    status: Optional[str] = None


class HTTPSequence(BaseModel):
    """Model for HTTP request/response sequence"""
    index: Optional[int] = None
    request: Optional[HTTPRequest] = None
    response: Optional[HTTPResponse] = None


class HTTPFlow(BaseModel):
    """Model for HTTP flow"""
    flow: Optional[int] = None
    sequence: Optional[List[HTTPSequence]] = None


class IPInfo(BaseModel):
    """Model for IP information"""
    asn: Optional[str] = None
    cc: Optional[str] = None
    ip: Optional[str] = None


class NetworkData(BaseModel):
    """Model for network data in behavioral analysis"""
    dns: Optional[List[DNSRecord]] = None
    dns_count: Optional[int] = None
    flows: Optional[List[NetworkFlow]] = None
    flows_count: Optional[int] = None
    http: Optional[List[HTTPFlow]] = None
    ips: Optional[List[IPInfo]] = None
    ips_count: Optional[int] = None


class Process(BaseModel):
    """Model for process information"""
    cmd: Optional[str] = None
    image: Optional[str] = None
    pid: Optional[int] = None
    procid: Optional[int] = None
    procid_parent: Optional[int] = None


class RegistryOperation(BaseModel):
    """Model for registry operations"""
    key: Optional[str] = None
    value: Optional[str] = None


class RegistryData(BaseModel):
    """Model for registry data"""
    create: Optional[List[RegistryOperation]] = None
    read: Optional[List[RegistryOperation]] = None
    write: Optional[List[RegistryOperation]] = None
    registry_count: Optional[int] = None


class Signature(BaseModel):
    """Model for behavioral signatures"""
    desc: Optional[str] = None
    name: Optional[str] = None
    label: Optional[str] = None


class Dynamic(BaseModel):
    """Model for dynamic analysis data"""
    dumped: Optional[List[DumpedFile]] = None
    dumped_count: Optional[int] = None
    extracted: Optional[List[ExtractedConfig]] = None
    network: Optional[NetworkData] = None
    processes: Optional[List[Process]] = None
    registry: Optional[RegistryData] = None
    signatures: Optional[List[Signature]] = None
    signatures_count: Optional[int] = None

class Sample(BaseModel):
    """Model for sample information"""
    completed: Optional[str] = None
    created: Optional[str] = None
    id: Optional[str] = None
    score: Optional[int] = None
    tags: Optional[List[str]] = None


class Report(BaseModel):
    """Model for a single malware analysis report"""
    file: Optional[str] = None
    dynamic: Optional[Dynamic] = None
    sample: Optional[Sample] = None


class MalwareAnalysisResponse(BaseModel):
    """Model for the complete malware analysis response"""
    reports: Optional[List[Report]] = None