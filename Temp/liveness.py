import asyncio
from pathlib import Path
from urllib.parse import urlparse
import httpx
import truststore

truststore.inject_into_ssl()

INPUT_FILE = "alienvault_output.txt"
OUTPUT_LIVE = "live_subdomains.txt"
OUTPUT_DEAD = "dead_subdomains.txt"
TIMEOUT_SECONDS = 5.0
CONCURRENCY = 50

# Proxy URL; add credentials if needed: "http://user:pass@production.zscaler.nimbus.gs.com:443"
PROXY_URL = "http://production.zscaler.nimbus.gs.com:443"

def normalize_url(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    lower = s.lower()
    if lower.startswith("http://") or lower.startswith("https://"):
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

async def check_one(url: str, client: httpx.AsyncClient, timeout: float) -> tuple[str, bool, int | None]:
    try:
        resp = await client.get(url, timeout=timeout)
        # Reachable = any valid HTTP response
        live = True
        return (url, live, resp.status_code)
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.NetworkError, httpx.HTTPError):
        return (url, False, None)
    except Exception:
        return (url, False, None)

async def check_all(urls: list[str], timeout: float, concurrency: int) -> list[tuple[str, bool, int | None]]:
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(follow_redirects=True, verify=True, http2=False, proxy=PROXY_URL) as client:
        async def worker(u: str):
            async with sem:
                return await check_one(u, client, timeout)
        tasks = [asyncio.create_task(worker(u)) for u in urls]
        return await asyncio.gather(*tasks)

def write_results(results: list[tuple[str, bool, int | None]], live_path: Path, dead_path: Path) -> None:
    live_urls = [u for (u, is_live, _code) in results if is_live]
    dead_urls = [u for (u, is_live, _code) in results if not is_live]
    live_path.write_text("\n".join(live_urls), encoding="utf-8")
    dead_path.write_text("\n".join(dead_urls), encoding="utf-8")

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
    print(f"Checked {total} URLs. Reachable: {live}. Unreachable: {dead}.")
    print(f"Reachable URLs written to {OUTPUT_LIVE}")
    print(f"Unreachable URLs written to {OUTPUT_DEAD}")

if __name__ == "__main__":
    main()
