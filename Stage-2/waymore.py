"""
passive_urls.py
-------------------------------------
OOP version of standalone passive URL collector (inspired by waymore.py).

Reads:  subdomains.txt (only root-domains)   (list of subdomains/domains)
Writes: root-domain.txt  (deduplicated URLs)

Sources used:
  - Wayback Machine
  - AlienVault OTX
  - URLScan.io
  - VirusTotal (API key placeholder)
"""

import requests
import json
import os
import time


class PassiveURLCollector:
    """Passive URL collector using multiple public sources (Wayback, OTX, URLScan, VT)."""

    def __init__(self, input_file="D:\\ZAP\\domains.txt", output_file="D:\\ZAP\\passive_urls\\root-domain.txt", vt_apikey="0a879599dd54790428daab50604ffa6be88eaf6022d32c5d7b418271807acd72"):
        self.input_file = input_file
        self.output_file = output_file
        self.APIKEY = vt_apikey

        # Source endpoints
        self.WAYBACK_URL = "https://web.archive.org/cdx/search/cdx?url=*.{DOMAIN}/*&output=json&fl=original"
        self.ALIENVAULT_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{DOMAIN}/url_list?limit=500"
        self.URLSCAN_URL = "https://urlscan.io/api/v1/search/?q=domain:{DOMAIN}&size=10000"
        self.VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/domain/report?apikey={APIKEY}&domain={DOMAIN}"

        self.domains = []
        self.all_urls = set()

    # Individual fetch functions
    def fetch_wayback(self, domain):
        urls = set()
        try:
            resp = requests.get(self.WAYBACK_URL.format(DOMAIN=domain), timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data[1:]:
                    urls.add(entry[0])
        except Exception as e:
            print(f"[!] Wayback error for {domain}: {e}")
        return urls

    def fetch_alienvault(self, domain):
        urls = set()
        try:
            resp = requests.get(self.ALIENVAULT_URL.format(DOMAIN=domain), timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for e in data.get("url_list", []):
                    u = e.get("url")
                    if u:
                        urls.add(u)
        except Exception as e:
            print(f"[!] AlienVault error for {domain}: {e}")
        return urls

    def fetch_urlscan(self, domain):
        urls = set()
        try:
            resp = requests.get(self.URLSCAN_URL.format(DOMAIN=domain), timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for r in data.get("results", []):
                    u = r.get("task", {}).get("url")
                    if u:
                        urls.add(u)
        except Exception as e:
            print(f"[!] URLScan error for {domain}: {e}")
        return urls

    def fetch_virustotal(self, domain):
        """Fetch undetected URLs from VirusTotal."""
        urls = set()
        try:
            resp = requests.get(
                self.VIRUSTOTAL_URL.format(APIKEY=self.APIKEY, DOMAIN=domain),
                timeout=15,
            )

            if resp.status_code == 200:
                data = resp.json()
                undetected = data.get("undetected_urls", [])
                for item in undetected:
                    if len(item) > 0:
                        urls.add(item[0])
            else:
                print(f"[!] VirusTotal error {resp.status_code} for {domain}")

        except Exception as e:
            print(f"[!] VirusTotal exception for {domain}: {e}")
        return urls

    # Domain fetcher
    def fetch_all_for_domain(self, domain):
        """Fetch URLs from all sources for one domain."""
        domain_urls = set()

        print(f"[+] Fetching URLs for: {domain}")

        print("→ Wayback...")
        wayback_urls = self.fetch_wayback(domain)
        print(f"{len(wayback_urls)} URLs found")

        print("→ AlienVault...")
        otx_urls = self.fetch_alienvault(domain)
        print(f"{len(otx_urls)} URLs found")

        print("→ URLScan...")
        urlscan_urls = self.fetch_urlscan(domain)
        print(f"{len(urlscan_urls)} URLs found")

        print("→ VirusTotal (undetected URLs)...")
        vt_urls = self.fetch_virustotal(domain)
        print(f"{len(vt_urls)} URLs found")

        # Merge all
        domain_urls.update(wayback_urls)
        domain_urls.update(otx_urls)
        domain_urls.update(urlscan_urls)
        domain_urls.update(vt_urls)

        print(f"[+] Total for {domain}: {len(domain_urls)} URLs\n")
        return domain_urls

    # Utility methods
    def load_domains(self):
        if not os.path.exists(self.input_file):
            print(f"[!] Input file '{self.input_file}' not found.")
            return False
        with open(self.input_file, "r", encoding="utf-8") as f:
            self.domains = [line.strip() for line in f if line.strip()]
        print(f"[*] Loaded {len(self.domains)} domains from {self.input_file}")
        return True

    def save_results(self):
        print(f"[*] Writing {len(self.all_urls)} unique URLs to {self.output_file} ...")
        with open(self.output_file, "w", encoding="utf-8") as f:
            for u in sorted(self.all_urls):
                f.write(u + "\n")
        print("[+] Done!")

    # Runner
    def run(self):
        if not self.load_domains():
            return

        print("[*] Starting passive collection...\n")
        for d in self.domains:
            urls = self.fetch_all_for_domain(d)
            self.all_urls.update(urls)
            print(f"  [✓] Combined unique so far: {len(self.all_urls)}\n")
            time.sleep(1)

        self.save_results()

# Main entry
if __name__ == "__main__":
    collector = PassiveURLCollector()
    collector.run()
