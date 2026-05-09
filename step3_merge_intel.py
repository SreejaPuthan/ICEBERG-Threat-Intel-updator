import requests
import os
import csv
from pathlib import Path
from datetime import datetime, timezone
import time

# ----------------------- Output --------------------------------

OUTPUT_FILE = Path("README_ICEBERG.md")


def write_md(line=""):
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# ----------------------- URLs ------------------------------------------

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

EXPLOITDB_REMOTE_URL = (
    "https://gitlab.com/exploit-database/exploitdb/"
    "-/raw/main/files_exploits.csv"
)

EXPLOITDB_LOCAL_PATH = Path("data/exploitdb_index.csv")

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"

ENABLE_GITHUB_POC = (
    os.getenv("ENABLE_GITHUB_POC", "false").lower() == "true"
)

# ----------------------- Fetch Functions --------------------------------


def fetch_nvd_cves():
    """
    Fetch all CVEs modified today from NVD.
    Handles pagination properly.
    """

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    headers = {
        "User-Agent": "ICEBERG/1.0"
    }

    api_key = os.getenv("NVD_API_KEY")

    if api_key:
        headers["apiKey"] = api_key

    all_vulnerabilities = []

    start_index = 0
    results_per_page = 100

    while True:

        params = {
            "lastModStartDate": f"{today}T00:00:00.000Z",
            "lastModEndDate": f"{today}T23:59:59.999Z",
            "startIndex": start_index,
            "resultsPerPage": results_per_page
        }

        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=60
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            break

        all_vulnerabilities.extend(vulnerabilities)

        total_results = data.get("totalResults", 0)

        start_index += results_per_page

        if start_index >= total_results:
            break

        time.sleep(0.6)

    return {
        "vulnerabilities": all_vulnerabilities
    }


def fetch_cisa_kev():

    response = requests.get(
        CISA_KEV_URL,
        timeout=30
    )

    response.raise_for_status()

    return response.json()


def extract_recent_kev_cves(kev_data):
    """
    ONLY return CVEs added to KEV today.
    Prevents old KEV CVEs from repeating forever.
    """

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    recent_kev = set()

    for item in kev_data.get("vulnerabilities", []):

        date_added = item.get("dateAdded", "")

        if date_added.startswith(today):
            recent_kev.add(item["cveID"])

    return recent_kev


def fetch_exploitdb_cves():

    exploitdb_cves = set()

    try:

        response = requests.get(
            EXPLOITDB_REMOTE_URL,
            timeout=60
        )

        response.raise_for_status()

        reader = csv.DictReader(
            response.text.splitlines()
        )

        for row in reader:

            if row.get("cve"):

                exploitdb_cves.update(
                    c.strip()
                    for c in row["cve"].split(",")
                )

        return exploitdb_cves

    except Exception:

        if EXPLOITDB_LOCAL_PATH.exists():

            with open(
                EXPLOITDB_LOCAL_PATH,
                newline="",
                encoding="utf-8"
            ) as f:

                reader = csv.DictReader(f)

                for row in reader:

                    if row.get("cve"):

                        exploitdb_cves.update(
                            c.strip()
                            for c in row["cve"].split(",")
                        )

    return set()


def github_poc_exists(cve_id):

    if not ENABLE_GITHUB_POC:
        return "UNKNOWN"

    try:

        response = requests.get(
            GITHUB_SEARCH_URL,
            params={
                "q": f"{cve_id} exploit poc",
                "per_page": 1
            },
            timeout=15
        )

        response.raise_for_status()

        time.sleep(1)

        total = response.json().get(
            "total_count",
            0
        )

        return "LIKELY" if total > 0 else "NO"

    except Exception:
        return "UNKNOWN"


# ----------------------- CPE Extraction --------------------------------


def extract_cpe_info(configurations):

    vendor = "Unknown"
    product = "Unknown"
    version = "Unknown"

    def recursive_nodes(nodes):

        nonlocal vendor, product, version

        for node in nodes:

            for cpe in node.get("cpeMatch", []):

                criteria = cpe.get("criteria", "")

                parts = criteria.split(":")

                if len(parts) > 5:

                    vendor = parts[3]
                    product = parts[4]
                    version = parts[5]

                    return True

            children = node.get("children", [])

            if children:

                if recursive_nodes(children):
                    return True

        return False

    recursive_nodes(configurations)

    return vendor, product, version


# ----------------------- CVSS Extraction --------------------------------


def extract_cvss(metrics):

    priority = [
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2"
    ]

    for metric_type in priority:

        if metric_type in metrics:

            metric = metrics[metric_type][0]

            cvss = metric.get("cvssData", {})

            return (
                cvss.get("baseScore", "N/A"),
                cvss.get("baseSeverity", "N/A"),
                cvss.get("attackVector", "N/A"),
                cvss.get("attackComplexity", "N/A")
            )

    return ("N/A", "N/A", "N/A", "N/A")


# ----------------------- Extract NVD Data --------------------------------


def extract_nvd_cves(nvd_data):

    results = []

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    for item in nvd_data.get("vulnerabilities", []):

        cve = item.get("cve", {})

        published = cve.get("published", "")

        last_modified = cve.get("lastModified", "")

        if published.startswith(today):

            status = "NEW"
            status_detail = published

        elif last_modified.startswith(today):

            status = "UPDATED"
            status_detail = last_modified

        else:

            status = "OLD"
            status_detail = last_modified

        metrics = cve.get("metrics", {})

        (
            cvss_score,
            severity,
            attack_vector,
            attack_complexity
        ) = extract_cvss(metrics)

        vendor, product, version = extract_cpe_info(
            cve.get("configurations", [])
        )

        results.append({

            "cve_id": cve.get("id"),

            "cvss_score": cvss_score,

            "severity": severity,

            "vendor": vendor,

            "product": product,

            "version": version,

            "attack_vector": attack_vector,

            "attack_complexity": attack_complexity,

            "status": status,

            "status_detail": status_detail
        })

    return results


# ----------------------- Console Table Printer ---------------------------


def print_table(title, cves):

    if not cves:
        return

    print(f"\n{title}")

    print("-" * 160)

    print(
        f"{'CVE ID':<18}"
        f"{'CVSSv3.x':<10}"
        f"{'Severity':<10}"
        f"{'Vendor':<15}"
        f"{'Product':<22}"
        f"{'Version':<10}"
        f"{'Attack Vector':<15}"
        f"{'Attack Complexity':<20}"
        f"{'Exploit':<12}"
        f"{'Status':<30}"
    )

    print("-" * 160)

    for cve in cves:

        print(
            f"{cve['cve_id']:<18}"
            f"{str(cve['cvss_score']):<10}"
            f"{cve['severity']:<10}"
            f"{cve['vendor'][:14]:<15}"
            f"{cve['product'][:21]:<22}"
            f"{cve['version']:<10}"
            f"{cve['attack_vector']:<15}"
            f"{cve['attack_complexity']:<20}"
            f"{cve['exploit_available']:<12}"
            f"{cve['status']} ({cve['status_detail']})"
        )


# ----------------------- MAIN --------------------------------


def main():

    # ---------------- RESET README ----------------

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("")

    # ---------------- HEADER ----------------

    print("\n" + "-" * 160)

    print("ICEBERG – Threat Advisory (Table Format)")

    runtime = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    print("Run Time (UTC):", runtime)

    print("-" * 160)

    write_md("# ICEBERG – Automated CVE Intelligence")
    write_md("")
    write_md(f"**Run Time (UTC):** {runtime}")
    write_md("")

    # ---------------- FETCH DATA ----------------

    print("Fetching NVD data...")

    nvd_data = fetch_nvd_cves()

    print("Finished NVD fetch")

    kev_data = fetch_cisa_kev()

    exploitdb_cves = fetch_exploitdb_cves()

    exploited_set = extract_recent_kev_cves(
        kev_data
    )

    nvd_cves = extract_nvd_cves(nvd_data)

    print(f"Total CVEs fetched: {len(nvd_cves)}")

    exploited = []

    high_risk = []

    # ---------------- PROCESS CVES ----------------

    for cve in nvd_cves:

        cve["exploited"] = (
            "YES"
            if cve["cve_id"] in exploited_set
            else "NO"
        )

        if cve["cve_id"] in exploitdb_cves:

            cve["exploit_available"] = "YES"

        else:

            cve["exploit_available"] = github_poc_exists(
                cve["cve_id"]
            )

        if cve["exploited"] == "YES":

            exploited.append(cve)

        elif cve["severity"] in (
            "HIGH",
            "CRITICAL"
        ):

            high_risk.append(cve)

    # ---------------- CONSOLE OUTPUT ----------------

    print_table(
        "🚨 Newly Added KEV Vulnerabilities",
        exploited
    )

    print_table(
        "⚠️ High / Critical Vulnerabilities",
        high_risk
    )

    # ---------------- README OUTPUT ----------------

    # KEV SECTION

    write_md("## 🚨 Newly Added KEV Vulnerabilities")
    write_md("")

    if exploited:

        write_md(
            "| CVE | Severity | Vendor | Product | CVSS | Exploit |"
        )

        write_md("|---|---|---|---|---|---|")

        for cve in exploited:

            write_md(
                f"| {cve['cve_id']} "
                f"| {cve['severity']} "
                f"| {cve['vendor']} "
                f"| {cve['product']} "
                f"| {cve['cvss_score']} "
                f"| {cve['exploit_available']} |"
            )

    else:

        write_md(
            "No newly added KEV vulnerabilities today."
        )

    write_md("")
    write_md("---")
    write_md("")

    # HIGH RISK SECTION

    write_md(
        "## ⚠️ High / Critical Vulnerabilities"
    )

    write_md("")

    if high_risk:

        write_md(
            "| CVE | Severity | Vendor | Product | CVSS | Status |"
        )

        write_md("|---|---|---|---|---|---|")

        for cve in high_risk:

            write_md(
                f"| {cve['cve_id']} "
                f"| {cve['severity']} "
                f"| {cve['vendor']} "
                f"| {cve['product']} "
                f"| {cve['cvss_score']} "
                f"| {cve['status']} |"
            )

    else:

        write_md(
            "No high-risk vulnerabilities found."
        )

    write_md("")
    write_md("---")
    write_md("")
    write_md(
        "_Generated automatically by ICEBERG Threat Intelligence Automation_"
    )

    print("README_ICEBERG.md updated successfully")


if __name__ == "__main__":
    main()
