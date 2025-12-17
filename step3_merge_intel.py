import requests
import os
import csv
from pathlib import Path
from datetime import datetime, timezone
import time

# ----------------------- URLs ------------------------------------------
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EXPLOITDB_REMOTE_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
EXPLOITDB_LOCAL_PATH = Path("data/exploitdb_index.csv")
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"

ENABLE_GITHUB_POC = os.getenv("ENABLE_GITHUB_POC", "false").lower() == "true"

# ----------------------- Fetch Functions --------------------------------
def fetch_nvd_cves():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    params = {
        "lastModStartDate": f"{today}T00:00:00.000Z",
        "lastModEndDate": f"{today}T23:59:59.999Z",
        "resultsPerPage": 200
    }
    headers = {"User-Agent": "ICEBERG/1.0"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json()

def fetch_cisa_kev():
    response = requests.get(CISA_KEV_URL, timeout=30)
    response.raise_for_status()
    return response.json()

def extract_exploited_cve_ids(kev_data):
    return {item["cveID"] for item in kev_data.get("vulnerabilities", [])}

def fetch_exploitdb_cves():
    exploitdb_cves = set()
    try:
        response = requests.get(EXPLOITDB_REMOTE_URL, timeout=60)
        response.raise_for_status()
        reader = csv.DictReader(response.text.splitlines())
        for row in reader:
            if row.get("cve"):
                exploitdb_cves.update(c.strip() for c in row["cve"].split(","))
        return exploitdb_cves
    except Exception:
        if EXPLOITDB_LOCAL_PATH.exists():
            with open(EXPLOITDB_LOCAL_PATH, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("cve"):
                        exploitdb_cves.update(c.strip() for c in row["cve"].split(","))
    return set()

def github_poc_exists(cve_id):
    if not ENABLE_GITHUB_POC:
        return "UNKNOWN"
    try:
        response = requests.get(
            GITHUB_SEARCH_URL,
            params={"q": f"{cve_id} exploit poc", "per_page": 1},
            timeout=15
        )
        response.raise_for_status()
        time.sleep(1)
        return "LIKELY" if response.json().get("total_count", 0) > 0 else "NO"
    except Exception:
        return "UNKNOWN"

# ----------------------- Extract NVD Data --------------------------------
def extract_nvd_cves(nvd_data):
    results = []
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    for item in nvd_data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        published = cve.get("published", "")
        last_modified = cve.get("lastModified", "")

        if published.startswith(today):
            status, status_detail = "NEW", published
        elif last_modified.startswith(today):
            status, status_detail = "UPDATED", last_modified
        else:
            status, status_detail = "OLD", last_modified

        metrics = cve.get("metrics", {})
        cvss_score = severity = attack_vector = attack_complexity = "N/A"

        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = cvss.get("baseScore", "N/A")
            severity = cvss.get("baseSeverity", "N/A")
            attack_vector = cvss.get("attackVector", "N/A")
            attack_complexity = cvss.get("attackComplexity", "N/A")

        vendor = product = version = "Unknown"
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    parts = cpe.get("criteria", "").split(":")
                    if len(parts) > 5:
                        vendor, product, version = parts[3], parts[4], parts[5]
                        break

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

# ----------------------- Table Printer --------------------------------
def print_table(title, cves):
    if not cves:
        return

    print(f"\n{title}")
    print("-" * 160)
    print(
        f"{'CVE ID':<18}{'CVSSv3.x':<10}{'Severity':<10}{'Vendor':<15}"
        f"{'Product':<22}{'Version':<10}{'Attack Vector':<15}"
        f"{'Attack Complexity':<20}{'Exploit':<12}{'Status':<30}"
    )
    print("-" * 160)

    for cve in cves:
        print(
            f"{cve['cve_id']:<18}{str(cve['cvss_score']):<10}{cve['severity']:<10}"
            f"{cve['vendor'][:14]:<15}{cve['product'][:21]:<22}"
            f"{cve['version']:<10}{cve['attack_vector']:<15}"
            f"{cve['attack_complexity']:<20}"
            f"{cve['exploit_available']:<12}"
            f"{cve['status']} ({cve['status_detail']})"
        )

# ----------------------- MAIN --------------------------------
def main():
    print("\n" + "-" * 160)
    print("ICEBERG – Threat Advisory (Table Format)")
    print("Run Time (UTC):", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
    print("-" * 160)

    nvd_data = fetch_nvd_cves()
    kev_data = fetch_cisa_kev()
    exploitdb_cves = fetch_exploitdb_cves()

    exploited_set = extract_exploited_cve_ids(kev_data)
    nvd_cves = extract_nvd_cves(nvd_data)

    exploited, high_risk = [], []

    for cve in nvd_cves:
        cve["exploited"] = "YES" if cve["cve_id"] in exploited_set else "NO"

        if cve["cve_id"] in exploitdb_cves:
            cve["exploit_available"] = "YES"
        else:
            cve["exploit_available"] = github_poc_exists(cve["cve_id"])

        if cve["exploited"] == "YES":
            exploited.append(cve)
        elif cve["severity"] in ("HIGH", "CRITICAL"):
            high_risk.append(cve)

    print_table("🚨 Actively Exploited Vulnerabilities (CISA KEV)", exploited)
    print_table("⚠️ High / Critical Vulnerabilities (Not Yet Exploited)", high_risk)

if __name__ == "__main__":
    main()
