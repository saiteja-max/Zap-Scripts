from zapv2 import ZAPv2
import time

# ZAP connection
zap_proxy = "http://127.0.0.1:8090"
api_key = "changeme"
zap = ZAPv2(apikey=api_key, proxies={"http": zap_proxy, "https": zap_proxy})

# Zscaler proxy config
proxy_host = "prod.zscalar.hello.com"
proxy_port = 443

# List of URLs with proxy requirement
urls_with_proxy = [
    "http://example.com/vuln2",
    "http://example.com/vuln5"
]

# List of URLs without proxy
urls_without_proxy = [
    "http://example.com/vuln1",
    "http://example.com/vuln3"
]

# Function to set or remove proxy
def configure_proxy(use_proxy):
    if use_proxy:
        print("[*] Using Zscaler proxy...")
        zap.core.set_option_proxy_chain_name(proxy_host)
        zap.core.set_option_proxy_chain_port(proxy_port)
    else:
        print("[*] No proxy for this URL...")
        zap.core.set_option_proxy_chain_name("")
        zap.core.set_option_proxy_chain_port(0)

# Function to scan a list of URLs
def scan_urls(url_list, use_proxy=False):
    configure_proxy(use_proxy)
    for url in url_list:
        print(f"[+] Starting Active Scan: {url}")
        zap.urlopen(url)
        time.sleep(2)
        scan_id = zap.ascan.scan(url)
        while int(zap.ascan.status(scan_id)) < 100:
            print(f"    Progress: {zap.ascan.status(scan_id)}%")
            time.sleep(5)
        print(f"[+] Scan completed for {url}")

# Scan URLs without proxy
scan_urls(urls_without_proxy, use_proxy=False)

# Scan URLs with proxy
scan_urls(urls_with_proxy, use_proxy=True)

# Generate reports
print("\n[+] Generating reports...")
with open("zap_report.html", "w", encoding="utf-8") as f:
    f.write(zap.core.htmlreport())

with open("zap_report.json", "w", encoding="utf-8") as f:
    f.write(zap.core.jsonreport())

print("[+] Reports saved as zap_report.html and zap_report.json")
