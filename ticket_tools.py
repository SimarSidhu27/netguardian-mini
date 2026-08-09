def validate_incident(incident_data: dict) -> str:
  """Validate that all required incident fields are present."""
  required_fields = [
    "incident_id",
    "site",
    "device",
    "description",
    "severity"
  ]
  for field in required_fields:
    if field not in incident_data:
      return f"Missing important info: {field}"
  return "VALID"