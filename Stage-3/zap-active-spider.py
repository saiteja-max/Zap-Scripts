import time
import concurrent.futures
from zapv2 import ZAPv2

# --- Configuration ---
ZAP_ADDRESS = 'localhost'
ZAP_PORT = '8080'
API_KEY = 'changeme'
INPUT_FILE = 'D:\\ZAP\\domains.txt'
OUTPUT_FILE = 'D:\\ZAP\\Stage-3\\zap_spider_results.txt'

# Spider tuning
SPIDER_MAX_DEPTH = 10         # maximum crawl depth (0 = unlimited)
SPIDER_MAX_DURATION = 0       # duration in minutes (0 = unlimited)
THREADS = 5                   # number of concurrent spider threads

# --- Initialize ZAP API ---
zap = ZAPv2(apikey=API_KEY, proxies={
    'http': f'http://{ZAP_ADDRESS}:{ZAP_PORT}',
    'https': f'http://{ZAP_ADDRESS}:{ZAP_PORT}'
})

# --- Configure Spider Settings ---
def configure_spider_settings():
    print("[*] Configuring ZAP spider options...")
    zap.spider.set_option_max_depth(SPIDER_MAX_DEPTH)
    zap.spider.set_option_max_duration(SPIDER_MAX_DURATION)
    zap.ajaxSpider.set_option_max_crawl_depth(SPIDER_MAX_DEPTH)
    zap.ajaxSpider.set_option_max_duration(SPIDER_MAX_DURATION)
    print(f"[+] Spider depth set to {SPIDER_MAX_DEPTH}, duration {SPIDER_MAX_DURATION} min\n")

# --- Wait for spider completion ---
def wait_for_completion(func, scan_id, spider_type):
    while True:
        try:
            status = int(func(scan_id))
            print(f"[+] {spider_type} progress: {status}%")
            if status >= 100:
                break
            time.sleep(3)
        except Exception as e:
            print(f"[!] Error in {spider_type} status check: {e}")
            break
    print(f"[+] {spider_type} completed.\n")

# --- Perform all spider types for one target ---
def run_spiders(target):
    try:
        print(f"\n========== Scanning: {target} ==========")
        zap.urlopen(target)
        time.sleep(2)

        # --- Traditional Spider ---
        print(f"[TRADITIONAL SPIDER] Starting on {target}")
        try:
            scan_id = zap.spider.scan(target, recurse=True)
            wait_for_completion(zap.spider.status, scan_id, "Traditional Spider")
        except Exception as e:
            print(f"[!] Traditional Spider failed: {e}")

        # --- Client Spider ---
        print(f"[CLIENT SPIDER] Starting on {target}")
        try:
            scan_id = zap.spider.scan_as_user('', '', target, recurse=True)
            wait_for_completion(zap.spider.status, scan_id, "Client Spider")
        except Exception as e:
            print(f"[!] Client Spider failed: {e}")

        # --- AJAX Spider ---
        print(f"[AJAX SPIDER] Starting on {target}")
        try:
            zap.ajaxSpider.scan(target)
            known_urls = set()
            while True:
                status = zap.ajaxSpider.status
                current_urls = set(zap.core.urls())
                new_urls = current_urls - known_urls
                known_urls.update(new_urls)

                print(f"[+] AJAX Spider progress: {status} ({len(known_urls)} URLs found)")
                if status == 'stopped':
                    break
                time.sleep(5)
            print(f"[+] AJAX Spider completed for {target}\n")
        except Exception as e:
            print(f"[!] AJAX Spider failed: {e}")

        urls = set(zap.core.urls())
        print(f"[+] Total URLs discovered for {target}: {len(urls)}")
        return urls

    except Exception as e:
        print(f"[!] Failed scanning {target}: {e}")
        return set()

# --- Main ---
def main():
    try:
        with open(INPUT_FILE, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Input file not found: {INPUT_FILE}")
        return

    configure_spider_settings()
    all_urls = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        future_to_target = {executor.submit(run_spiders, 
            (t if t.startswith("http") else "https://" + t)): t for t in targets}

        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]
            try:
                urls = future.result()
                all_urls.update(urls)
            except Exception as e:
                print(f"[!] Exception from {target}: {e}")

    with open(OUTPUT_FILE, 'w') as f:
        for url in sorted(all_urls):
            f.write(url + "\n")

    print("\nAll spidering completed.")
    print(f"Total unique URLs discovered: {len(all_urls)}")
    print(f"Results saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
