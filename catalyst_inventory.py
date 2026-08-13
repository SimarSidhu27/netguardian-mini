import json
import os
import requests

from dotenv import load_dotenv
from datetime import datetime, timezone

load_dotenv()

CATALYST_CENTER_URL = os.getenv("CATALYST_CENTER_URL")
CATALYST_CENTER_USERNAME = os.getenv("CATALYST_CENTER_USERNAME")
CATALYST_CENTER_PASSWORD = os.getenv("CATALYST_CENTER_PASSWORD")

def get_catalyst_token(url :str,username:str,password:str) -> str:
  if not url or not username or not password:
    raise ValueError("Catalyst Token API credentials are missing")

  token_url = f"{url}/dna/system/api/v1/auth/token"

  response = requests.post(url= token_url, 
                           auth= (username,password),
                           timeout = 20,
                           verify=False)
  response.raise_for_status()
  catalyst_response = response.json()
  catalyst_token = catalyst_response.get("Token")
  if not catalyst_token:
    raise ValueError("CATALYST TOKEN MISSING")
  return catalyst_token


def get_device_inventory(url:str, token:str) -> list[dict]:
  if not url or not token:
    raise ValueError("Catalyst Center URL or token is missing.")
  inventory_url = f"{url}/dna/intent/api/v1/network-device"

  headers = {
    "Accept" : "application/json",
    "X-Auth-Token" : token
  }

  response = requests.get(url = inventory_url,headers = headers,timeout = 20, verify= False)
  response.raise_for_status()
  inventory_data = response.json()
  devices = inventory_data.get("response",[])
  return devices

def get_clean_device_inventory(device_list :list[dict]) -> list[dict]:
  clean_devices_list = []
  for device in device_list:
    clean_device = {
    "device_id": device.get("id"),
    "hostname": device.get("hostname"),
    "family": device.get("family"),
    "device_type": device.get("type"),
    "model": device.get("platformId"),
    "role": device.get("role"),
    "software_type": device.get("softwareType"),
    "software_version": device.get("softwareVersion"),
    "management_ip": device.get("managementIpAddress"),
    "reachability": device.get("reachabilityStatus"),
    "site": device.get("locationName") or "Unassigned"
  }
    clean_devices_list.append(clean_device)
  return clean_devices_list

if __name__ == "__main__":
  try:
    catalyst_token = get_catalyst_token(CATALYST_CENTER_URL,CATALYST_CENTER_USERNAME,CATALYST_CENTER_PASSWORD)
    devices = get_device_inventory(CATALYST_CENTER_URL,catalyst_token)
    clean_devices_list = get_clean_device_inventory(devices)
    inventory_result = {
      "source": "Cisco Catalyst Center Sandbox",
      "retrieved_at": datetime.now(timezone.utc).isoformat(),
      "device_count": len(clean_devices_list),
      "devices": clean_devices_list
      }

    with open("data/device_inventory_snapshot.json","w",encoding="utf-8") as file:
      json.dump(inventory_result,file, indent=2)
    print("Inventory saved")
  except (ValueError, requests.exceptions.RequestException, OSError) as error:
        print("Catalyst inventory collection failed:", error)
  
