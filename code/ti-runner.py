#!/usr/bin/env python
"""Automated Threat Intel - Anomali - Defender For Endpoint & Umbrella"""
import json
from io import StringIO
import concurrent.futures
import time
import itertools
from datetime import datetime, timedelta, timezone
import requests
import boto3
import ioc_fanger


REGION = "ap-southeast-2"
UMBRELLA_DEST_LIST_IDS = ("17699844", "17699845")
CONFIDENCE = 70
MANDIANT_FUSION_ID = "375"
CFC_ID = "11711"
CISA_ID = "403"


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
        timeout=60,
    )
    if access_token_response.status_code != 200:
        raise Exception(
            f"[-] Failed to pull access token - {access_token_response.status_code}"
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
        client.get_parameter(Name="/threat-intel/tenant_id", WithDecryption=True)
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
        ssm_client.get_parameter(Name="/threat-intel/api-key", WithDecryption=True)
        .get("Parameter")
        .get("Value")
    )
    return username, api_key


def check_indicator(jwt_token: str, indicator: str) -> bool:
    """Check to see if indicator already exists in Defender for Endpoint"""
    endpoint = f"https://api.securitycenter.microsoft.com/api/indicators?$filter=indicatorValue+eq+'{indicator}'"
    header = {"Authorization": f"Bearer {jwt_token}"}
    resp = requests.get(url=endpoint, headers=header, timeout=60)
    if resp.status_code == 200:
        if len(resp.json().get("value")) > 0:
            print(f"[+] Indicator exists: {indicator}, returning...")
            return True
        return False
    print(f"[-] Failed to pull indicator - response body {resp.text}")
    print(f"[+] Going to attempt to import IOC {indicator}")
    return False


def construct_payload_defender(ioc: dict) -> dict:
    """Create unique payload for DATP upload"""
    time_delta = (
        (datetime.now(timezone.utc) + timedelta(weeks=52))
        .isoformat("T", "seconds")
        .replace("+00:00", "Z")
    )
    msg_str = StringIO()
    msg_str.write("Tags assigned to TI\n\n")
    source = ioc.get("source")
    indicator = ioc.get("value")
    tags = ioc.get("tags")
    for tag in tags:
        name = tag.get("name")
        msg_str.write(f"{name}\n")
    identifier = indicator[-4:]
    ti_payload = {}
    ti_payload["indicatorValue"] = indicator
    ti_payload["title"] = f"{source}-{identifier}"
    ti_payload["description"] = msg_str.getvalue()
    ti_payload["action"] = "BlockAndRemediate"
    ti_payload["severity"] = "High"
    ti_payload["indicatorType"] = "FileSha256"
    ti_payload["generateAlert"] = True
    ti_payload["expirationTime"] = time_delta

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
        url=endpoint, headers=header, data=json.dumps(payload_dict), timeout=60
    )
    if response.status_code == 200:
        print(f"[+] Added indicator: {ioc.get('value')}")
        return True
    print(
        f"[-] Response code from API call to submit indicator - {ioc_value} returned {response.status_code} status code"
    )
    print(f"[-] {response.text}")
    return False


def runner(threat_objects: list, jwt_token: str) -> None:
    """Main thread pool runner"""
    success = 0
    failures = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(
            parse_and_send, threat_objects, itertools.repeat(jwt_token)
        )
        for result in results:
            if result:
                success = success + 1
            else:
                failures = failures + 1
    print(f"[+] Successful uploads {success}")
    print(f"[-] Unsuccessful uploads {failures}")


def ingest_threat_intel_hash(username: str, api_key: str, jwt_token: str):
    """Main function to pull and send data to Defender for Endpoint"""
    time_delta = (datetime.now() - timedelta(hours=12)).isoformat(
        sep="T", timespec="auto"
    )
    endpoint = f"https://api.threatstream.com/api/v2/intelligence/?limit=0&q=(created_ts>={time_delta})+AND+confidence>={CONFIDENCE}+AND+status=active+AND+type=hash+AND+subtype=SHA256+AND+(trusted_circle_id={MANDIANT_FUSION_ID}+OR+trusted_circle_id={CISA_ID}+OR+trusted_circle_id={CFC_ID})"
    header = {"Authorization": f"apikey {username}:{api_key}"}
    response = requests.get(url=endpoint, headers=header, timeout=60)
    if response.status_code == 200:
        threat_objects = response.json().get("objects")
        total = len(threat_objects)
        print(f"[+] Number of new threat intel to import is {total}")
        if total > 50:
            for index in range(0, total, 50):
                threat_objects_subset = threat_objects[index : index + 50]
                runner(threat_objects_subset, jwt_token)
                time.sleep(60)
        else:
            runner(threat_objects, jwt_token)
        return
    raise Exception(
        f"[-] Status code returned {response.status_code} when pulling theat intel...\n{response.text}"
    )


def create_payload(threat_objects: list) -> list:
    """Convert threat objects returned into acceptable payload"""
    iocs = []
    for threat in threat_objects:
        value = threat.get("value")
        source = threat.get("source")
        logged_defanged_value = ioc_fanger.defang(value)
        print(f"[+] Adding Indicator {logged_defanged_value}")
        ioc_dict = {
            "destination": value,
            "comment": f"Automated threat intel ingestion from {source} intel feeds",
        }
        iocs.append(ioc_dict)
    return iocs


def get_umbrella_api_key() -> tuple:
    """Pull Umbrella API key from SSM"""
    ssm_client = boto3.client("ssm", REGION)
    umbrella_key = (
        ssm_client.get_parameter(Name="/threat-intel/umbrella-key", WithDecryption=True)
        .get("Parameter")
        .get("Value")
    )
    umbrella_secret = (
        ssm_client.get_parameter(
            Name="/threat-intel/umbrella-secret", WithDecryption=True
        )
        .get("Parameter")
        .get("Value")
    )
    return umbrella_key, umbrella_secret


def generate_umbrella_jwt(umbrella_key: str, umbrella_secret: str) -> str:
    """Generate JWT token via Client Credential flow"""
    header = {"Content-Type": "application/x-www-form-urlencoded"}
    token_endpoint = "https://api.umbrella.com/auth/v2/token"  # nosec
    data = "grant_type=client_credentials"
    response = requests.post(
        url=token_endpoint,
        headers=header,
        data=data,
        auth=(umbrella_key, umbrella_secret),
        timeout=60,
    )
    if response.status_code != 200:
        raise Exception(
            f"[-] Failed to pull JWT token from Umbrella... {response.text}"
        )
    token = response.json().get("access_token")
    return token


def ingest_threat_intel_network_ioc(username: str, api_key: str) -> None:
    """Function to pull network based IOC's and upload to umbrella"""
    time_delta = (datetime.now() - timedelta(hours=12)).isoformat(
        sep="T", timespec="auto"
    )
    umbrella_key, umbrella_secret = get_umbrella_api_key()
    jwt_token = generate_umbrella_jwt(umbrella_key, umbrella_secret)
    endpoint = f"https://api.threatstream.com/api/v2/intelligence/?limit=0&q=(created_ts>={time_delta})+AND+confidence>={CONFIDENCE}+AND+status=active+AND+type=domain+AND+(trusted_circle_id={MANDIANT_FUSION_ID}+OR+trusted_circle_id={CFC_ID}+OR+trusted_circle_id={CISA_ID})"
    header = {"Authorization": f"apikey {username}:{api_key}"}
    response = requests.get(url=endpoint, headers=header, timeout=60)
    if response.status_code == 200:
        threat_objects = response.json().get("objects")
        total = len(threat_objects)
        print(f"[+] Number of new network threat intel to import is {total}")
        payload = create_payload(threat_objects)
        headers_umbrella = {
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json",
        }
        for index, umbrella_list in enumerate(UMBRELLA_DEST_LIST_IDS):
            endpoint = f"https://api.umbrella.com/policies/v2/destinationlists/{umbrella_list}/destinations"
            response = requests.post(
                url=endpoint,
                headers=headers_umbrella,
                data=json.dumps(payload),
                timeout=60,
            )
            match index:
                case 0:
                    policy = "DNS"
            match index:
                case 1:
                    policy = "WEB"
            if response.status_code == 200:
                print(
                    f"[+] Successfully imported domain IOC's into Umbrella {policy} destination list"
                )
            else:
                print(
                    f"[-] Failed to import domain IOC's into Umbrella {policy} destination list"
                )
    else:
        raise Exception(
            f"[-] Status code returned {response.status_code} when pulling theat intel...\n{response.text}"
        )


def main():
    """Main execution point"""
    username, api_key = get_anomali_creds()
    jwt_token = get_ms_tokens()
    ingest_threat_intel_hash(username, api_key, jwt_token)
    ingest_threat_intel_network_ioc(username, api_key)


if __name__ == "__main__":
    main()
