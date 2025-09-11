from zapv2 import ZAPv2
import time
import os

# ZAP connection details
zap_proxy = "http://127.0.0.1:8090"
api_key = "changeme"

# Proxy for external connectivity (Zscaler)
corp_proxy_host = "prod.zscalar.hello.com"
corp_proxy_port = "443"

zap = ZAPv2(apikey=api_key, proxies={"http": zap_proxy, "https": zap_proxy})

# Configure upstream proxy inside ZAP
print("[*] Configuring upstream proxy in ZAP...")
zap.core.set_option_proxy_chain_name(corp_proxy_host)
zap.core.set_option_proxy_chain_port(corp_proxy_port)

# List of vulnerable URLs
target_urls = [
    "http://example.com/vuln1",  # no proxy needed
    "http://example.com/vuln2",  # proxy needed
    "http://example.com/vuln3",
    # ... up to 10
]

for url in target_urls:
    print(f"[+] Starting Active Scan on: {url}")
    
    # Open the URL in ZAP
    zap.urlopen(url)
    time.sleep(2)
    
    # Start Active Scan
    scan_id = zap.ascan.scan(url)
    
    # Monitor progress
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"    Scan progress: {zap.ascan.status(scan_id)}%")
        time.sleep(5)
    
    print(f"[+] Scan completed for: {url}")

# Export report (HTML + JSON)
print("\n[+] Generating reports...")

html_report = zap.core.htmlreport()
with open("zap_report.html", "w", encoding="utf-8") as f:
    f.write(html_report)

json_report = zap.core.jsonreport()
with open("zap_report.json", "w", encoding="utf-8") as f:
    f.write(json_report)

print("[+] Reports saved as zap_report.html and zap_report.json")
