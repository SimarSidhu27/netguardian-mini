import os
import requests
import json
from dotenv import load_dotenv
from datetime import datetime, timezone

TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
PSIRT_BASE_URL = "https://apix.cisco.com/security/advisories/v2"

load_dotenv()

def get_token_access() -> str :
  """Request and return an access token from CISCO"""

  client_id = os.getenv("CISCO_CLIENT_ID");
  client_secret = os.getenv("CISCO_CLIENT_SECRET")

  if not client_id or not client_secret:
    raise ValueError("CISCO API credentials are missing")

  response = requests.post(
        TOKEN_URL,
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials"
        },
        timeout=10
    )

  response.raise_for_status()
  token_data = response.json()
  access_token = token_data.get("access_token")

  if not access_token:
    raise ValueError("CISCO didn't return an access token")
  return access_token


def get_advisories_for_version(
    access_token: str,
    os_type: str,
    version: str
) -> dict:
  """Return Cisco advisories affecting a software version."""
  url = f"{PSIRT_BASE_URL}/OSType/{os_type}"

  headers = {
    "Accept": "application/json",
    "Authorization": f"Bearer {access_token}"
  }
  params = {
        "version": version
    }

  response = requests.get(
    url=url,
    headers=headers,
    params=params,
    timeout=20
  )
  response.raise_for_status()
  advisory_data = response.json()
  return advisory_data
  

if __name__ == "__main__":
  try:
    os_type = "iosxe"
    software_version = "17.2.1"

    access_token = get_token_access()
    print("CISCO TOKEN IMPORTED SUCCESSFULLY")
    advisory_data = get_advisories_for_version(access_token,os_type,
            software_version)
    advisories = advisory_data.get("advisories",[])
    clean_advisories = []
    if advisories:
      for advisory in advisories:
        clean_advisory = {
        "advisory_id": advisory.get("advisoryId"),
        "title": advisory.get("advisoryTitle"),
        "severity": advisory.get("sir"),
        "cves": advisory.get("cves", []),
        "cvss_score": advisory.get("cvssBaseScore"),
        "first_fixed": advisory.get("firstFixed", []),
        "publication_url": advisory.get("publicationUrl")
      }
        clean_advisories.append(clean_advisory)
      print("Advisories prepared for analysis:",len(clean_advisories))
    else:
      print("No advisories were returned for this version.")
    psirt_result = {
            "source": "Cisco PSIRT OpenVuln API",
            "os_type": os_type,
            "software_version": software_version,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "advisory_count": len(clean_advisories),
            "advisories": clean_advisories
        }
    with open("data/psirt_advisories.json" ,"w", encoding="utf-8") as file:
      json.dump(psirt_result,file,indent= 2)
    print("Cisco advisories saved successfully.")
  
  except (ValueError, requests.exceptions.RequestException) as error :
    print("CISCO API request failed", error)

  
    
