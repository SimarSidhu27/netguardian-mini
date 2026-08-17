import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

from cisco_psirt import (
    get_advisories_for_version,
    get_token_access,
)


BASE_DIR = Path(__file__).resolve().parent
INVENTORY_FILE = BASE_DIR / "data" / "device_inventory_snapshot.json"
ASSESSMENT_FILE = BASE_DIR / "data" / "vulnerability_assessment.json"


def normalize_os_type(software_type: str | None) -> str | None:
    """Convert a Catalyst software type into the value expected by PSIRT."""

    if not software_type:
        return None

    cleaned_type = (
        software_type
        .strip()
        .upper()
        .replace("-", "")
        .replace(" ", "")
    )

    os_type_mapping = {
        "IOSXE": "iosxe",
        "IOS": "ios",
        "NXOS": "nxos",
        "ASA": "asa",
        "FTD": "ftd",
        "FMC": "fmc",
        "FXOS": "fxos",
        "ACI": "aci",
    }

    return os_type_mapping.get(cleaned_type)


def normalize_software_version(
    software_version: str | None,
) -> str | None:
    """Remove a Catalyst sandbox internal PRD build suffix."""

    if not software_version:
        return None

    cleaned_version = software_version.strip()

    return re.sub(
        r"prd\d+$",
        "",
        cleaned_version,
        flags=re.IGNORECASE,
    )


def get_unique_software_queries(
    device_list: list[dict],
) -> set[tuple[str, str]]:
    """Return unique PSIRT OS type and software version combinations."""

    software_queries = set()

    for device in device_list:
        normalized_os_type = normalize_os_type(
            device.get("software_type")
        )

        normalized_version = normalize_software_version(
            device.get("software_version")
        )

        if normalized_os_type and normalized_version:
            software_query = (
                normalized_os_type,
                normalized_version,
            )

            software_queries.add(software_query)

    return software_queries


def get_advisory_cache(
    software_queries: set[tuple[str, str]],
    access_token: str,
) -> dict[tuple[str, str], list[dict]]:
    """Retrieve PSIRT advisories once for each OS/version combination."""

    advisory_cache = {}

    for os_type, software_version in software_queries:
        advisory_data = get_advisories_for_version(
            access_token,
            os_type,
            software_version,
        )

        advisories = advisory_data.get("advisories", [])

        advisory_cache[
            (os_type, software_version)
        ] = advisories

    return advisory_cache


def create_assessment_row(
    device: dict,
    normalized_version: str | None,
    assessment_status: str,
    verification_required: bool,
    advisory: dict | None = None,
) -> dict:
    """Create one dashboard-ready assessment row."""

    advisory = advisory or {}

    return {
        "device_id": device.get("device_id"),
        "hostname": device.get("hostname"),
        "site": device.get("site"),
        "model": device.get("model"),
        "role": device.get("role"),
        "reachability": device.get("reachability"),
        "software_type": device.get("software_type"),
        "installed_version": device.get("software_version"),
        "queried_version": normalized_version,
        "assessment_status": assessment_status,
        "advisory_id": advisory.get("advisoryId"),
        "title": advisory.get("advisoryTitle"),
        "severity": advisory.get("sir"),
        "cves": advisory.get("cves", []),
        "cvss_score": advisory.get("cvssBaseScore"),
        "first_fixed": advisory.get("firstFixed", []),
        "publication_url": advisory.get("publicationUrl"),
        "verification_required": verification_required,
    }


def build_vulnerability_assessment(
    devices: list[dict],
    advisory_cache: dict[tuple[str, str], list[dict]],
) -> list[dict]:
    """Connect every device to the advisories for its OS version."""

    assessment_rows = []

    for device in devices:
        normalized_os_type = normalize_os_type(
            device.get("software_type")
        )

        normalized_version = normalize_software_version(
            device.get("software_version")
        )

        if not normalized_os_type or not normalized_version:
            assessment_rows.append(
                create_assessment_row(
                    device=device,
                    normalized_version=normalized_version,
                    assessment_status="Manual review required",
                    verification_required=True,
                )
            )

            continue

        software_query = (
            normalized_os_type,
            normalized_version,
        )

        advisories = advisory_cache.get(
            software_query,
            [],
        )

        if not advisories:
            assessment_rows.append(
                create_assessment_row(
                    device=device,
                    normalized_version=normalized_version,
                    assessment_status="No matching advisories",
                    verification_required=False,
                )
            )

            continue

        for advisory in advisories:
            assessment_rows.append(
                create_assessment_row(
                    device=device,
                    normalized_version=normalized_version,
                    assessment_status="Potentially affected",
                    verification_required=True,
                    advisory=advisory,
                )
            )

    return assessment_rows


def main() -> None:
    """Run the complete vulnerability assessment workflow."""

    with INVENTORY_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:
        inventory_data = json.load(file)

    devices = inventory_data.get("devices", [])

    if not isinstance(devices, list):
        raise ValueError(
            "The devices field in the inventory must be a list."
        )

    if not devices:
        raise ValueError(
            "The inventory snapshot does not contain any devices."
        )

    software_queries = get_unique_software_queries(devices)

    if not software_queries:
        raise ValueError(
            "No supported OS and software version combinations were found."
        )

    print("Software combinations:", software_queries)

    access_token = get_token_access()

    advisory_cache = get_advisory_cache(
        software_queries,
        access_token,
    )

    for software_query, advisories in advisory_cache.items():
        print(
            software_query,
            "Advisories:",
            len(advisories),
        )

    assessment_rows = build_vulnerability_assessment(
        devices,
        advisory_cache,
    )

    potentially_affected_device_ids = {
        row.get("device_id")
        for row in assessment_rows
        if (
            row.get("assessment_status") == "Potentially affected"
            and row.get("device_id")
        )
    }

    unique_advisory_ids = {
        row.get("advisory_id")
        for row in assessment_rows
        if row.get("advisory_id")
    }

    assessment_result = {
        "source": (
            "Cisco Catalyst Center and "
            "Cisco PSIRT OpenVuln API"
        ),
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "device_count": len(devices),
        "software_query_count": len(software_queries),
        "potentially_affected_device_count": len(
            potentially_affected_device_ids
        ),
        "unique_advisory_count": len(
            unique_advisory_ids
        ),
        "assessment_row_count": len(
            assessment_rows
        ),
        "assessments": assessment_rows,
    }

    ASSESSMENT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with ASSESSMENT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            assessment_result,
            file,
            indent=2,
        )

    print("Assessment rows:", len(assessment_rows))
    print(
        "Potentially affected devices:",
        len(potentially_affected_device_ids),
    )
    print(
        "Unique advisories:",
        len(unique_advisory_ids),
    )
    print(
        "Vulnerability assessment saved:",
        ASSESSMENT_FILE,
    )


if __name__ == "__main__":
    try:
        main()

    except FileNotFoundError as error:
        print("Inventory file was not found:", error)
        sys.exit(1)

    except json.JSONDecodeError as error:
        print("Inventory file contains invalid JSON:", error)
        sys.exit(1)

    except (
        ValueError,
        requests.exceptions.RequestException,
        OSError,
    ) as error:
        print("Vulnerability assessment failed:", error)
        sys.exit(1)