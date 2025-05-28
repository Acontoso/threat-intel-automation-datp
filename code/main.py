#!/usr/bin/env python
"""Automated Threat Intel - Anomali - Defender For Endpoint & Umbrella"""
import asyncio
from datetime import datetime, timedelta
from code.services.microsoft import MSServices
from code.services.cisco import CiscoServices
from code.services.aws import AWSServices

REGION = "ap-southeast-2"
UMBRELLA_DEST_LIST_IDS = ("17699844", "17699845")
CONFIDENCE = 70
MANDIANT_FUSION_ID = "375"
CFC_ID = "11711"
CISA_ID = "403"
TIME_DELTA = (datetime.now() - timedelta(hours=12)).isoformat(sep="T", timespec="auto")
ANOMALI_ENDPOINT_HASH = f"https://api.threatstream.com/api/v2/intelligence/?limit=0&q=(created_ts>={TIME_DELTA})+AND+confidence>={CONFIDENCE}+AND+status=active+AND+type=hash+AND+subtype=SHA256+AND+(trusted_circle_id={MANDIANT_FUSION_ID}+OR+trusted_circle_id={CISA_ID}+OR+trusted_circle_id={CFC_ID})"
ANOMALI_ENDPOINT_DOMAIN = f"https://api.threatstream.com/api/v2/intelligence/?limit=0&q=(created_ts>={TIME_DELTA})+AND+confidence>={CONFIDENCE}+AND+status=active+AND+type=domain+AND+(trusted_circle_id={MANDIANT_FUSION_ID}+OR+trusted_circle_id={CFC_ID}+OR+trusted_circle_id={CISA_ID})"
MS_CREDS = ["client_id", "client_secret", "tenant_id"]
CISCO_CREDS = ["umbrella-key", "umbrella-secret"]
ANOMALI_CREDS = ["username", "api-key"]


async def main():
    """Main execution point"""
    ms_client_id, ms_client_secret, ms_tenant_id = AWSServices.get_ssm_parameters(
        MS_CREDS, REGION
    )
    umbrella_key, umbrella_secret = AWSServices.get_ssm_parameters(CISCO_CREDS, REGION)
    anomali_username, anomali_apikey = AWSServices.get_ssm_parameters(
        ANOMALI_CREDS, REGION
    )
    ms_client = MSServices(
        ms_client_id, ms_client_secret, ms_tenant_id, anomali_username, anomali_apikey
    )
    ms_future = ms_client.ingest_threat_intel_hash(ANOMALI_ENDPOINT_HASH)
    cisco_client = CiscoServices(
        umbrella_key,
        umbrella_secret,
        UMBRELLA_DEST_LIST_IDS,
        anomali_username,
        anomali_apikey,
    )
    cisco_future = cisco_client.ingest_threat_intel_network_ioc(ANOMALI_ENDPOINT_DOMAIN)
    await cisco_future
    await ms_future


if __name__ == "__main__":
    asyncio.run(main())
