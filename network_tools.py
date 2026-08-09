def get_interface_status(device_name: str) -> dict:
  """ Returns simulated interface status for a network device"""
  return {
    "device" : device_name,
    "interface" : "eth0",
    "status" : "Down"
  }

def analyze_interface_status(status : str) -> str :
  """ Analysze network interface status and provides probable diagnosis"""
  if status.lower() == "down":
    diagnosis  = "Interface down"
  else:
    diagnosis  = "Interafce up , Continue investigation"

  return diagnosis 