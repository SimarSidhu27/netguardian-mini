import json
import re
from pathlib import Path

import pandas as pd
import streamlit as st


BASE_DIR = Path(__file__).resolve().parent
LIVE_ASSESSMENT_FILE = (
    BASE_DIR / "data" / "vulnerability_assessment.json"
)

SAMPLE_ASSESSMENT_FILE = (
    BASE_DIR / "data" / "sample_vulnerability_assessment.json"
)

if LIVE_ASSESSMENT_FILE.exists():
    ASSESSMENT_FILE = LIVE_ASSESSMENT_FILE
    DATA_MODE = "Live generated assessment"
else:
    ASSESSMENT_FILE = SAMPLE_ASSESSMENT_FILE
    DATA_MODE = "Demonstration dataset"


st.set_page_config(
    page_title="NetGuardian Vulnerability Dashboard",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_data
def load_assessment_data(file_path: Path) -> dict:
    """Load the generated vulnerability-assessment JSON file."""

    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def format_collection(value) -> str:
    """Convert a list or other value into readable table text."""

    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in value)

    if value is None:
        return ""

    return str(value)


def count_unique_cves(cve_values: pd.Series) -> int:
    """Count unique CVE identifiers in a pandas Series."""

    unique_cves = set()

    for value in cve_values:
        if isinstance(value, (list, tuple, set)):
            text = " ".join(str(item) for item in value)
        elif value is None:
            continue
        else:
            text = str(value)

        matches = re.findall(
            r"CVE-\d{4}-\d+",
            text.upper(),
        )

        unique_cves.update(matches)

    return len(unique_cves)


try:
    assessment_data = load_assessment_data(ASSESSMENT_FILE)

except FileNotFoundError:
    st.error(
        "The vulnerability assessment file was not found. "
        "Run `python impact_engine.py` first."
    )
    st.stop()

except json.JSONDecodeError:
    st.error(
        "The vulnerability assessment file contains invalid JSON."
    )
    st.stop()

except OSError as error:
    st.error(f"Unable to read assessment data: {error}")
    st.stop()


assessment_rows = assessment_data.get("assessments", [])

if not assessment_rows:
    st.warning("No vulnerability assessment records are available.")
    st.stop()


assessment_df = pd.DataFrame(assessment_rows)


expected_columns = [
    "device_id",
    "hostname",
    "site",
    "model",
    "role",
    "reachability",
    "software_type",
    "installed_version",
    "queried_version",
    "assessment_status",
    "advisory_id",
    "title",
    "severity",
    "cves",
    "cvss_score",
    "first_fixed",
    "publication_url",
    "verification_required",
]

for column in expected_columns:
    if column not in assessment_df.columns:
        assessment_df[column] = None


filter_columns = [
    "assessment_status",
    "severity",
    "site",
    "model",
    "installed_version",
]

for column in filter_columns:
    assessment_df[column] = (
        assessment_df[column]
        .fillna("Not available")
        .astype(str)
    )


assessment_df["cvss_score"] = pd.to_numeric(
    assessment_df["cvss_score"],
    errors="coerce",
)


st.title("🛡️ NetGuardian Vulnerability Intelligence Dashboard")

st.write(
    "Cisco device inventory is correlated with Cisco PSIRT security "
    "advisories to identify devices that may require remediation."
)

source = assessment_data.get("source", "Not available")
generated_at = assessment_data.get("generated_at", "Not available")

st.caption(
    f"Source: {source} | Assessment generated: {generated_at}"
)

st.caption(f"Dashboard mode: {DATA_MODE}")

st.warning(
    "A potentially affected result is not final proof of exposure. "
    "Product model, configuration and Cisco advisory requirements must "
    "be verified before remediation."
)


st.sidebar.header("Dashboard Filters")


def create_filter(label: str, column: str) -> list[str]:
    options = sorted(
        assessment_df[column]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    return st.sidebar.multiselect(
        label,
        options=options,
        default=options,
    )


selected_statuses = create_filter(
    "Assessment status",
    "assessment_status",
)

selected_severities = create_filter(
    "Severity",
    "severity",
)

selected_sites = create_filter(
    "Site",
    "site",
)

selected_models = create_filter(
    "Device model",
    "model",
)

selected_versions = create_filter(
    "Installed version",
    "installed_version",
)


filtered_df = assessment_df.copy()

filtered_df = filtered_df[
    filtered_df["assessment_status"].isin(selected_statuses)
]

filtered_df = filtered_df[
    filtered_df["severity"].isin(selected_severities)
]

filtered_df = filtered_df[
    filtered_df["site"].isin(selected_sites)
]

filtered_df = filtered_df[
    filtered_df["model"].isin(selected_models)
]

filtered_df = filtered_df[
    filtered_df["installed_version"].isin(selected_versions)
]


affected_df = filtered_df[
    filtered_df["assessment_status"] == "Potentially affected"
]


total_devices = filtered_df["device_id"].nunique()

potentially_affected_devices = affected_df[
    "device_id"
].nunique()

unique_advisories = affected_df[
    "advisory_id"
].dropna().nunique()

critical_high_advisories = affected_df[
    affected_df["severity"].str.lower().isin(
        ["critical", "high"]
    )
]["advisory_id"].dropna().nunique()

unique_cves = count_unique_cves(
    affected_df["cves"]
)


metric_columns = st.columns(5)

metric_columns[0].metric(
    "Devices displayed",
    total_devices,
)

metric_columns[1].metric(
    "Potentially affected",
    potentially_affected_devices,
)

metric_columns[2].metric(
    "Unique advisories",
    unique_advisories,
)

metric_columns[3].metric(
    "Critical / High",
    critical_high_advisories,
)

metric_columns[4].metric(
    "Unique CVEs",
    unique_cves,
)


st.divider()

chart_column_one, chart_column_two = st.columns(2)


with chart_column_one:
    st.subheader("Advisories by severity")

    severity_data = (
        affected_df
        .dropna(subset=["advisory_id"])
        .drop_duplicates(subset=["advisory_id"])
        ["severity"]
        .value_counts()
    )

    if severity_data.empty:
        st.info("No advisory severity data matches the filters.")
    else:
        st.bar_chart(severity_data)


with chart_column_two:
    st.subheader("Affected devices by software version")

    version_data = (
        affected_df
        .drop_duplicates(
            subset=["device_id", "installed_version"]
        )
        .groupby("installed_version")["device_id"]
        .nunique()
        .sort_values(ascending=False)
    )

    if version_data.empty:
        st.info("No affected device data matches the filters.")
    else:
        st.bar_chart(version_data)


st.divider()

st.subheader("Device inventory overview")

inventory_columns = [
    "hostname",
    "site",
    "model",
    "role",
    "software_type",
    "installed_version",
    "reachability",
    "assessment_status",
]

inventory_table = (
    filtered_df[inventory_columns]
    .drop_duplicates()
    .sort_values(
        by=["site", "hostname"],
        na_position="last",
    )
)

st.dataframe(
    inventory_table,
    width="stretch",
    hide_index=True,
)


st.divider()

st.subheader("Device vulnerability assessment")

display_df = filtered_df.copy()

display_df["cves"] = display_df["cves"].apply(
    format_collection
)

display_df["first_fixed"] = display_df[
    "first_fixed"
].apply(format_collection)

severity_order = {
    "Critical": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4,
    "Informational": 5,
    "Not available": 6,
}

display_df["severity_order"] = (
    display_df["severity"]
    .map(severity_order)
    .fillna(7)
)

display_df = display_df.sort_values(
    by=["severity_order", "cvss_score"],
    ascending=[True, False],
)

display_columns = [
    "hostname",
    "model",
    "installed_version",
    "assessment_status",
    "advisory_id",
    "title",
    "severity",
    "cvss_score",
    "cves",
    "first_fixed",
    "publication_url",
]

display_table = display_df[display_columns].rename(
    columns={
        "hostname": "Hostname",
        "model": "Model",
        "installed_version": "Installed Version",
        "assessment_status": "Assessment",
        "advisory_id": "Advisory ID",
        "title": "Advisory Title",
        "severity": "Severity",
        "cvss_score": "CVSS Score",
        "cves": "CVEs",
        "first_fixed": "First Fixed Releases",
        "publication_url": "Cisco Advisory",
    }
)

st.dataframe(
    display_table,
    width="stretch",
    hide_index=True,
    height=500,
    column_config={
        "Cisco Advisory": st.column_config.LinkColumn(
            "Cisco Advisory",
            display_text="Open advisory",
        )
    },
)


download_df = filtered_df.copy()

download_df["cves"] = download_df["cves"].apply(
    format_collection
)

download_df["first_fixed"] = download_df[
    "first_fixed"
].apply(format_collection)

csv_data = download_df.to_csv(
    index=False
).encode("utf-8")

st.download_button(
    label="Download filtered assessment as CSV",
    data=csv_data,
    file_name="netguardian_vulnerability_assessment.csv",
    mime="text/csv",
)


with st.expander("How NetGuardian determines potential impact"):
    st.markdown(
        """
1. Device inventory is retrieved from Cisco Catalyst Center.
2. Device operating-system names and versions are normalized.
3. Each unique OS/version combination is queried through Cisco PSIRT.
4. PSIRT advisories are associated with devices using that version.
5. Results are labelled **Potentially affected** until product and
   configuration requirements are manually verified.
6. Fixed-release information supports remediation and lab-upgrade planning.
        """
    )