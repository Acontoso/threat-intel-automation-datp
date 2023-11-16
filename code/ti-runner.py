#!/usr/bin/env python
"""Automated Threat Intel - Anomali - Defender For Endpoint"""
import json
import concurrent.futures
import time
import itertools
from datetime import datetime, timedelta, timezone
import requests
import boto3

REGION = "ap-southeast-2"


def generate_access_token_payload(
    client_id: str, client_secret: str, scope: str
) -> str:
    """Generate payload for access token for client credential flow"""
    payload = (
        "client_id="
        + client_id
        + "&scope="
        + scope
        + "&client_secret="
        + client_secret
        + "&grant_type=client_credentials"
    )

    return payload


def access_token_ms_sec_api(client_id: str, client_secret: str, tenant_id: str) -> str:
    """Get OAuth access token to send data to Microsoft Defender 365"""
    security_centre_scope = "https://api.securitycenter.windows.com/.default"
    payload = generate_access_token_payload(
        client_id, client_secret, security_centre_scope
    )
    headers = {"content-type": "application/x-www-form-urlencoded"}
    access_token_response = requests.post(
        "https://login.microsoftonline.com/" + tenant_id + "/oauth2/v2.0/token",
        headers=headers,
        data=payload,
    )
    if access_token_response.status_code != 200:
        raise Exception(
            f"[-] Failed to pull access token - {access_token_response.text}"
        )
    json_resp = access_token_response.json()
    token = json_resp["access_token"]
    return token


def get_boto_client(service: str) -> boto3.client:
    """Recieve client via Boto3"""
    ssm_client = boto3.client(service, region_name=REGION)
    return ssm_client


def get_ssm_params_ms(client: boto3.client) -> tuple:
    """Enumerate and return SSM parameters for script execution"""
    client_id = (
        client.get_parameter(Name="/threat-intel/client_id", WithDecryption=True)
        .get("Parameter")
        .get("Value")
    )
    client_secret = (
        client.get_parameter(Name="/threat-intel/client_secret", WithDecryption=True)
        .get("Parameter")
        .get("Value")
    )
    tenant_id = (
        client.get_parameter(Name="/threat-intel/tenant_id", WithDecryption=False)
        .get("Parameter")
        .get("Value")
    )
    return client_id, client_secret, tenant_id


def get_ms_tokens() -> str:
    """Get JWT for security centre API - Client Credential Oauth flow"""
    ssm_client = get_boto_client("ssm")
    client_id, client_secret, tenant_id = get_ssm_params_ms(ssm_client)
    jwt_token_ms_sec_api = access_token_ms_sec_api(client_id, client_secret, tenant_id)
    print("[+] Recieved security centre API token")
    return jwt_token_ms_sec_api


def get_anomali_creds() -> tuple:
    """Pull creds for anomali via SSM"""
    ssm_client = get_boto_client("ssm")
    username = (
        ssm_client.get_parameter(Name="/threat-intel/username", WithDecryption=True)
        .get("Parameter")
        .get("Value")
    )
    api_key = (
        ssm_client.get_parameter(Name="/threat-intel/api-key", WithDecryption=False)
        .get("Parameter")
        .get("Value")
    )
    return username, api_key


def check_indicator(jwt_token: str, indicator: str) -> bool:
    """Check to see if indicator already exists in Defender for Endpoint"""
    endpoint = f"https://api.securitycenter.microsoft.com/api/indicators?$filter=indicatorValue+eq+'{indicator}'"
    header = {"Authorization": f"Bearer {jwt_token}"}
    resp = requests.get(url=endpoint, headers=header)
    if resp.status_code == 200:
        if len(resp.json().get("value")) > 0:
            return True
        return False
    else:
        print(f"[-] Failed to pull indicator - response body {resp.text}")
        print(f"[+] Going to attempt to import IOC {indicator}")
        return False


def construct_payload_defender(ioc: dict) -> dict:
    """Create unique payload for DATP upload"""
    time = (
        (datetime.now(timezone.utc) + timedelta(weeks=24))
        .isoformat("T", "seconds")
        .replace("+00:00", "Z")
    )
    indicator = ioc.get("value")
    identifier = indicator[-4:]
    ti_payload = {}
    ti_payload["indicatorValue"] = indicator
    ti_payload["title"] = f"Mandiant-ThreatFeed-{identifier}"
    ti_payload["description"] = (
        "Generic Mandiant IOC via Anomali"
        if ioc.get("description") == None
        else ioc.get("description")
    )
    ti_payload["action"] = "Audit"
    ti_payload["severity"] = "High"
    ti_payload["indicatorType"] = "FileSha256"
    ti_payload["generateAlert"] = True
    ti_payload["expirationTime"] = time

    return ti_payload


def parse_and_send(ioc: dict, jwt_token: str) -> bool:
    """Parsed the indicator and send to Defender for Endpoint"""
    ioc_value = ioc.get("value")
    exists = check_indicator(jwt_token, ioc_value)
    if exists:
        return True
    payload_dict = construct_payload_defender(ioc)
    endpoint = "https://api.securitycenter.microsoft.com/api/indicators"
    header = {
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/json",
    }
    response = requests.post(
        url=endpoint, headers=header, data=json.dumps(payload_dict)
    )
    if response.status_code == 200:
        return True
    else:
        print(
            f"[-] Response code from API call to submit indicator - {ioc_value} returned {response.status_code} status code"
        )
        print(f"[-] {response.text}")
        return False


def ingest_threat_intel(username: str, api_key: str, jwt_token: str):
    """Main function to pull and send data to Defender for Endpoint"""
    time_delta = (datetime.now() - timedelta(hours=12)).isoformat(
        sep="T", timespec="auto"
    )
    endpoint = f"https://api.threatstream.com/api/v2/intelligence/?limit=0&q=(created_ts>={time_delta})+AND+confidence>=85+AND+status=active+AND+type=hash+AND+subtype=SHA256+AND+trusted_circle_id=379"
    header = {"Authorization": f"apikey {username}:{api_key}"}
    attempt = 0
    max_attempts = 3
    while attempt <= max_attempts:
        response = requests.get(url=endpoint, headers=header)
        if response.status_code == 200:
            threat_objects = response.json().get("objects")
            print(f"[+] Number of new threat intel to import is {len(threat_objects)}")
            success = 0
            failures = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                results = executor.map(
                    parse_and_send,
                    threat_objects,
                    itertools.repeat(jwt_token),
                    timeout=30,
                )
                for result in results:
                    if result:
                        success = success + 1
                    else:
                        failures = failures + 1
            print(f"[+] Successful uploads {success}")
            print(f"[-] Unsuccessful uploads {failures}")
            return
        else:
            attempt = attempt + 1
            print(
                f"[-] Status code returned {response.status_code} when pulling confidence, attempt: {attempt}"
            )
            time.sleep(10)
    if attempt > max_attempts:
        print("[-] Failed to return confidence, will return zero")
        return


# ignore C0123 for lambda comment!!
def lambda_handler():
    """Main execution point"""
    username, api_key = get_anomali_creds()
    jwt_token = get_ms_tokens()
    ingest_threat_intel(username, api_key, jwt_token)


if __name__ == "__main__":
    lambda_handler()
