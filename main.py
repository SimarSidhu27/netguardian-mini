import json
import sys
from ticket_tools import validate_incident
from network_tools import get_interface_status, analyze_interface_status

try:
  with open("data/incident.json","r", encoding= "utf-8") as file :
    incident = json.load(file)
except FileNotFoundError:
  print("Incident File not Found")
  sys.exit(1)
except json.JSONDecodeError:
  print("Incident File doesn't contain valid json")
  sys.exit(1)

validation_result = validate_incident(incident)
print("Validation result:", validation_result)

if validation_result != "VALID":
  print("Cannot continue because incident data is incomplete.")
  sys.exit(1)

interface_result = get_interface_status(incident["device"])
print("Network diagnostic result:", interface_result)

network_analysis_result  = analyze_interface_status(interface_result["status"])
print(f"Network analysis result: {network_analysis_result}")

investigation_result = {
    "incident": incident,
    "validation": validation_result,
    "network_evidence": interface_result,
    "diagnosis": network_analysis_result
}

with open("data/investigation_result.json","w",encoding="utf-8") as file:
  json.dump(investigation_result,file,indent=2)
print("Report saved")
