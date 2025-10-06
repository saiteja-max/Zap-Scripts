import asyncio
from pathlib import Path
from urllib.parse import urlparse
import random
import httpx
import truststore

truststore.inject_into_ssl()

INPUT_FILE = "alienvault_output.txt"
OUTPUT_LIVE = "live_subdomains.txt"
OUTPUT_DEAD = "dead_subdomains.txt"
TIMEOUT_SECONDS = 6.0
CONCURRENCY = 50
RETRY_LIMIT = 1  # retry once on failure

# Optional: Adjust or remove proxy if not needed
PROXY_URL = "http://production.zscaler.nimbus.gs.com:443"

HEADERS = {"User-Agent": "SubdomainLivenessChecker/2.0"}

def normalize_url(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    if s.lower().startswith(("http://", "https://")):
        return s.rstrip("/")
    if "://" in s:
        return ""
    return f"https://{s}".rstrip("/")

def is_probably_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme) and bool(parsed.netloc)
    except Exception:
        return False

def load_urls(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    urls: list[str] = []
    seen: set[str] = set()
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            url = normalize_url(line)
            if not url or not is_probably_valid_url(url):
                continue
            if url in seen:
                continue
            seen.add(url)
            urls.append(url)
    return urls

async def check_once(url: str, client: httpx.AsyncClient, timeout: float) -> tuple[str, bool, int | None]:
    """Single check attempt"""
    try:
        resp = await client.get(url, headers=HEADERS, timeout=timeout)
        # Mark live only for 2xx or 3xx responses
        live = 200 <= resp.status_code < 400
        return (url, live, resp.status_code)
    except Exception:
        return (url, False, None)

async def check_with_retry(url: str, client: httpx.AsyncClient, timeout: float) -> tuple[str, bool, int | None]:
    """Check with retry and HTTP->HTTPS fallback"""
    url_checked = url
    result = await check_once(url_checked, client, timeout)

    # Retry once if failed
    if not result[1] and RETRY_LIMIT > 0:
        for _ in range(RETRY_LIMIT):
            # Try http if https failed
            if url_checked.startswith("https://"):
                fallback = url_checked.replace("https://", "http://", 1)
                result = await check_once(fallback, client, timeout)
                if result[1]:
                    return result
            # Random short delay before retrying same scheme
            await asyncio.sleep(random.uniform(0.2, 0.8))
            result = await check_once(url_checked, client, timeout)
            if result[1]:
                return result

    return result

async def check_all(urls: list[str], timeout: float, concurrency: int) -> list[tuple[str, bool, int | None]]:
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(follow_redirects=True, verify=True, http2=False, proxy=PROXY_URL) as client:
        async def worker(u: str):
            async with sem:
                # Optional light random delay to avoid rate-limits
                await asyncio.sleep(random.uniform(0.05, 0.15))
                return await check_with_retry(u, client, timeout)
        tasks = [asyncio.create_task(worker(u)) for u in urls]
        return await asyncio.gather(*tasks)

def write_results(results: list[tuple[str, bool, int | None]], live_path: Path, dead_path: Path) -> None:
    live_lines = []
    dead_lines = []
    for u, is_live, code in results:
        code_text = f"[{code}]" if code is not None else "[NO_RESPONSE]"
        if is_live:
            live_lines.append(f"{u} {code_text}")
        else:
            dead_lines.append(f"{u} {code_text}")
    live_path.write_text("\n".join(live_lines), encoding="utf-8")
    dead_path.write_text("\n".join(dead_lines), encoding="utf-8")

def main():
    input_path = Path(INPUT_FILE)
    live_path = Path(OUTPUT_LIVE)
    dead_path = Path(OUTPUT_DEAD)

    urls = load_urls(input_path)
    if not urls:
        print("No valid URLs found in input.")
        live_path.write_text("", encoding="utf-8")
        dead_path.write_text("", encoding="utf-8")
        return

    results = asyncio.run(check_all(urls, TIMEOUT_SECONDS, CONCURRENCY))
    write_results(results, live_path, dead_path)

    total = len(urls)
    live = sum(1 for _, is_live, _ in results if is_live)
    dead = total - live
    print(f"Checked {total} URLs → Live: {live}, Dead: {dead}")
    print(f"Live results saved to: {OUTPUT_LIVE}")
    print(f"Dead results saved to: {OUTPUT_DEAD}")

if __name__ == "__main__":
    main()
