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

# ----------------------- URLs ----------------------------------
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EXPLOITDB_REMOTE_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
EXPLOITDB_LOCAL_PATH = Path("data/exploitdb_index.csv")
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"

ENABLE_GITHUB_POC = os.getenv("ENABLE_GITHUB_POC", "false").lower() == "true"

# ----------------------- Fetch Functions -----------------------
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

    r = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()

def fetch_cisa_kev():
    r = requests.get(CISA_KEV_URL, timeout=30)
    r.raise_for_status()
    return r.json()

def extract_exploited_cve_ids(kev_data):
    return {v["cveID"] for v in kev_data.get("vulnerabilities", [])}

def fetch_exploitdb_cves():
    cves = set()
    try:
        r = requests.get(EXPLOITDB_REMOTE_URL, timeout=60)
        r.raise_for_status()
        reader = csv.DictReader(r.text.splitlines())
        for row in reader:
            if row.get("cve"):
                cves.update(x.strip() for x in row["cve"].split(","))
        return cves
    except Exception:
        if EXPLOITDB_LOCAL_PATH.exists():
            with open(EXPLOITDB_LOCAL_PATH, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("cve"):
                        cves.update(x.strip() for x in row["cve"].split(","))
    return set()

def github_poc_exists(cve_id):
    if not ENABLE_GITHUB_POC:
        return "NA"
    try:
        r = requests.get(
            GITHUB_SEARCH_URL,
            params={"q": f"{cve_id} exploit poc", "per_page": 1},
            timeout=15
        )
        r.raise_for_status()
        time.sleep(1)
        return "YES" if r.json().get("total_count", 0) > 0 else "NO"
    except Exception:
        return "NA"

# ----------------------- Extract NVD Data -----------------------
def extract_nvd_cves(nvd_data):
    results = []
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    for item in nvd_data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        published = cve.get("published", "")
        modified = cve.get("lastModified", "")

        if published.startswith(today):
            status = f"NEW ({published})"
        elif modified.startswith(today):
            status = f"UPDATED ({modified})"
        else:
            status = f"OLD ({modified})"

        metrics = cve.get("metrics", {})
        cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})

        vendor = product = version = "Unknown"
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    parts = cpe.get("criteria", "").split(":")
                    if len(parts) > 5:
                        vendor, product, version = parts[3], parts[4], parts[5]
                        break

        results.append({
            "cve_id": cve.get("id"),
            "cvss_score": cvss.get("baseScore", "N/A"),
            "severity": cvss.get("baseSeverity", "N/A"),
            "vendor": vendor,
            "product": product,
            "version": version,
            "attack_vector": cvss.get("attackVector", "N/A"),
            "attack_complexity": cvss.get("attackComplexity", "N/A"),
            "status": status
        })

    return results

# ----------------------- Markdown Table ------------------------
def write_table_md(title, cves):
    if not cves:
        return

    write_md(f"## {title}")
    write_md("")
    write_md("| CVE ID | CVSSv3.x | Severity | Vendor | Product | Version | Attack Vector | Attack Complexity | Exploit | Status |")
    write_md("|-------|----------|----------|--------|---------|---------|---------------|-------------------|---------|--------|")

    for c in cves:
        write_md(
            f"| {c['cve_id']} | {c['cvss_score']} | {c['severity']} | "
            f"{c['vendor']} | {c['product']} | {c['version']} | "
            f"{c['attack_vector']} | {c['attack_complexity']} | "
            f"{c['exploit_available']} | {c['status']} |"
        )

    write_md("")

# ----------------------- Console Table --------------------------
def print_console(title, cves):
    if not cves:
        return
    print(f"\n{title}")
    print("-" * 160)
    print(
        f"{'CVE ID':<18}{'CVSSv3.x':<10}{'Severity':<10}{'Vendor':<15}"
        f"{'Product':<22}{'Version':<10}{'Attack Vector':<15}"
        f"{'Attack Complexity':<20}{'Exploit':<10}{'Status'}"
    )
    print("-" * 160)

    for c in cves:
        print(
            f"{c['cve_id']:<18}{str(c['cvss_score']):<10}{c['severity']:<10}"
            f"{c['vendor'][:14]:<15}{c['product'][:21]:<22}"
            f"{c['version']:<10}{c['attack_vector']:<15}"
            f"{c['attack_complexity']:<20}{c['exploit_available']:<10}"
            f"{c['status']}"
        )

# ----------------------- MAIN ----------------------------------
def main():
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("# 🧊 ICEBERG – Live CVE Intelligence Feed\n\n")
        f.write(f"**Last Updated (UTC):** {now}\n\n")
        f.write("_Auto-generated. Do not edit manually._\n\n")

    nvd_data = fetch_nvd_cves()
    kev_data = fetch_cisa_kev()
    exploitdb = fetch_exploitdb_cves()

    exploited_set = extract_exploited_cve_ids(kev_data)
    cves = extract_nvd_cves(nvd_data)

    exploited, high_risk = [], []

    for c in cves:
        c["exploit_available"] = (
            "YES" if c["cve_id"] in exploitdb else github_poc_exists(c["cve_id"])
        )

        if c["cve_id"] in exploited_set:
            exploited.append(c)
        elif c["severity"] in ("HIGH", "CRITICAL"):
            high_risk.append(c)

    print_console("🚨 Actively Exploited Vulnerabilities (CISA KEV)", exploited)
    print_console("⚠️ High / Critical Vulnerabilities (Not Yet Exploited)", high_risk)

    write_table_md("🚨 Actively Exploited Vulnerabilities (CISA KEV)", exploited)
    write_table_md("⚠️ High / Critical Vulnerabilities (Not Yet Exploited)", high_risk)

if __name__ == "__main__":
    main()
