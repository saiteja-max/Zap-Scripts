import requests

# Config
API_KEY = "d4f196df-ab23-4d24-9353-710ef91a9fe5"   # Replace with your new key (don’t share publicly)
DOMAIN = "uber.com"                                # Target domain
OUTPUT_FILE = "subdomains.txt"

# API URL
url = f"https://dns.projectdiscovery.io/dns/{DOMAIN}/subdomains"
headers = {"Authorization": API_KEY}

# Make request
response = requests.get(url, headers=headers)
data = response.json()

# Extract root domain (from API response)
root_domain = data.get("domain", DOMAIN)

# Process subdomains
subdomains = data.get("subdomains", [])
full_domains = {f"{sub}.{root_domain}" if sub else root_domain for sub in subdomains}

# Save to file
with open(OUTPUT_FILE, "w") as f:
    for domain in sorted(full_domains):
        f.write(domain + "\n")

print(f"[+] Extracted {len(full_domains)} unique subdomains for {root_domain}")
print(f"[+] Saved to {OUTPUT_FILE}")
