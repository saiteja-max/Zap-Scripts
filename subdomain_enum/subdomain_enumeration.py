import sys 
import time 
import json 
import re 
import unicodedata 
import urllib.parse 
from urllib.parse import urlencode, urljoin 
from datetime import datetime, timezone
import requests 
import truststore

truststore.inject_into_ssl()

class SubdomainHarvester: 
    def __init__(self): # Core config 
        self.domain = 'goldman.com' 
        self.output_file = 'subdomains.txt'
        self.debug_enabled = True
        # Proxies (grounded in docs)
        self.proxies = {
            'http': 'production.zscaler.nimbus.gs.com:443',
            'https': 'production.zscaler.nimbus.gs.com:443'
        }

        # HTTP session
        self.session = requests.Session()
        self.session.proxies.update(self.proxies)
        self.session.headers.update({
            'User-Agent': 'subdomain-harvester/1.0',
            'Accept': 'application/json'
        })

        # Optional tokens/flags used by collectors (grounded in docs)
        self.certspotter_token = None          # Set to your Cert Spotter token to enable auth
        self.require_currently_valid = True    # Matches REQUIRE_CURRENTLY_VALID in certspotter.txt
        self.drop_wildcards = True             # Matches DROP_WILDCARDS in certspotter.txt
        self.chaos_api_key = "d4f196df-ab23-4d24-9353-710ef91a9fe5"    # Set to your ProjectDiscovery Chaos API key

        # Utilities
        self.DOTS_RE = re.compile(r'\.+')
        self.debug_enabled = True

        # Initial debug
        self.debug(f'Initialized SubdomainHarvester for domain {self.domain}')
        self.debug(f'Proxies configured: {self.proxies}')
        self.debug(f'Cert Spotter token present: {bool(self.certspotter_token)}')
        self.debug(f'Chaos API key present: {bool(self.chaos_api_key)}')

    # --------------- Debug helper ---------------
    def debug(self, msg: str):
        print(f'[DEBUG] {msg}', flush=True)

    # --------------- Helpers ---------------
    def strip_non_printable(self, s: str) -> str:
        return ''.join(ch for ch in s if ch.isprintable())

    def normalize(self, host: str) -> str:
        h = unicodedata.normalize('NFKC', str(host or '')).strip().lower()
        h = self.strip_non_printable(h)
        h = h.strip("\"'`")
        h = h.strip('.')
        h = self.DOTS_RE.sub('.', h)
        return h

    def is_wildcard(self, host: str) -> bool:
        return host.startswith('*.')

    def is_valid_hostname(self, host: str) -> bool:
        if not host or '..' in host:
            return False
        labels = host.split('.')
        # Ensure at least 3 labels like a.b.domain.com (grounded in crtsh.txt logic)
        if len(labels) < 3:
            return False
        for lbl in labels:
            if not lbl or len(lbl) > 63:
                return False
            if not re.fullmatch(r'[a-z0-9-]+', lbl):
                return False
            if lbl.startswith('-') or lbl.endswith('-'):
                return False
        return True

    def is_subdomain(self, hostname: str, domain: str = None) -> bool:
        if not hostname:
            return False
        hostname = hostname.strip().lower().rstrip('.')
        d = (domain or self.domain).strip().lower().rstrip('.')
        return hostname.endswith('.' + d) and hostname != d

    def is_in_scope(self, name: str, domain: str = None) -> bool:
        n = (name or '').lower().strip('.')
        d = (domain or self.domain).lower().strip('.')
        return n == d or n.endswith('.' + d)

    def remove_numeric_exact_firstlabel(self, hosts):
        pattern = re.compile(rf'^[0-9]+\.{re.escape(self.domain)}$', re.IGNORECASE)
        filtered = [h for h in hosts if not pattern.match(h)]
        removed = len(hosts) - len(filtered)
        if removed:
            self.debug(f'Removed {removed} numeric-only first-label host(s) like 123.{self.domain}')
        return filtered

    def is_current_certspotter(self, issuance: dict) -> bool:
        # Grounded in certspotter.txt: now between not_before and not_after and not revoked
        try:
            now = datetime.now(timezone.utc)
            nb = datetime.fromisoformat((issuance.get('not_before') or '').replace('Z', '+00:00'))
            na = datetime.fromisoformat((issuance.get('not_after') or '').replace('Z', '+00:00'))
            revoked = bool(issuance.get('revoked', False))
            current = (nb <= now <= na) and not revoked
            return current
        except Exception as e:
            self.debug(f'CertSpotter: failed to parse validity for issuance: {e}')
            return False

    # --------------- Collectors ---------------
    def fetch_alienvault(self, limit=500, timeout=30, max_retries=3, backoff_base=2) -> set:
        # Grounded in alienvault.txt
        subs = set()
        page = 1
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'subdomain-fetcher/1.3 (+https://otx.alienvault.com)'
        }
        self.debug(f'AlienVault: starting fetch for {self.domain} with limit={limit}')
        while True:
            url = f'https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/url_list?limit={limit}&page={page}'
            self.debug(f'AlienVault: GET {url}')
            resp = None
            for attempt in range(1, max_retries + 1):
                try:
                    resp = self.session.get(url, headers=headers, timeout=timeout)
                    break
                except requests.Timeout:
                    wait = backoff_base ** attempt
                    self.debug(f'AlienVault: timeout on page {page}, attempt {attempt}/{max_retries}; retrying in {wait}s')
                    time.sleep(wait)
                except requests.RequestException as e:
                    self.debug(f'AlienVault: request error on page {page}: {e}')
                    return subs
            if resp is None:
                self.debug(f'AlienVault: failed to fetch page {page} after {max_retries} retries')
                return subs

            if resp.status_code == 429:
                retry_after = resp.headers.get('Retry-After')
                try:
                    wait = float(retry_after) if retry_after else 5.0
                except ValueError:
                    wait = 5.0
                self.debug(f'AlienVault: rate limited (429). Waiting {wait}s then retrying same page')
                time.sleep(wait)
                try:
                    resp = self.session.get(url, headers=headers, timeout=timeout)
                except requests.RequestException as e:
                    self.debug(f'AlienVault: retry request error on page {page}: {e}')
                    return subs

            if resp.status_code == 404:
                self.debug('AlienVault: received 404; ending pagination')
                break
            if resp.status_code != 200:
                self.debug(f'AlienVault: HTTP {resp.status_code} on page {page}: {resp.text[:200]}')
                break

            try:
                data = resp.json()
            except ValueError:
                self.debug(f'AlienVault: non-JSON response on page {page}')
                break

            url_list = data.get('url_list', [])
            added_this_page = 0
            for item in url_list:
                hostname = (item.get('hostname') or '').strip().lower()
                if self.is_subdomain(hostname):
                    if hostname not in subs:
                        subs.add(hostname)
                        added_this_page += 1
            self.debug(f'AlienVault: page {page} added {added_this_page} subdomains; total {len(subs)}')

            has_next = bool(data.get('has_next'))
            if not has_next:
                self.debug('AlienVault: has_next=false; stopping')
                break
            page += 1
            time.sleep(0.5)  # polite pacing

        self.debug(f'AlienVault: finished with {len(subs)} subdomains')
        return subs

    def fetch_certspotter(self, timeout=30) -> set:
        # Grounded in certspotter.txt
        subs = set()
        API_BASE = 'https://api.certspotter.com'
        API_ISSUANCES = f'{API_BASE}/v1/issuances'
        headers = {}
        if self.certspotter_token:
            headers['Authorization'] = f'Bearer {self.certspotter_token}'
        params = {
            'domain': self.domain,
            'include_subdomains': 'true',
            'expand': 'dns_names',
        }
        next_url = API_ISSUANCES
        self.debug(f'CertSpotter: starting with token={"set" if self.certspotter_token else "not set"}')
        while next_url:
            use_params = params if next_url == API_ISSUANCES else None
            self.debug(f'CertSpotter: GET {next_url} params={use_params}')
            try:
                resp = self.session.get(next_url, headers=headers, params=use_params, timeout=timeout)
                resp.raise_for_status()
            except requests.RequestException as e:
                self.debug(f'CertSpotter: request failed: {e}')
                break

            try:
                data = resp.json()
            except ValueError:
                self.debug('CertSpotter: response not JSON; aborting')
                break

            count_before = len(subs)
            for issuance in data:
                if self.require_currently_valid and not self.is_current_certspotter(issuance):
                    continue
                for name in issuance.get('dns_names', []):
                    if self.drop_wildcards and str(name).startswith('*.'):
                        continue
                    h = self.normalize(name)
                    if self.is_in_scope(h) and self.is_subdomain(h) and self.is_valid_hostname(h):
                        subs.add(h)
            self.debug(f'CertSpotter: added {len(subs) - count_before} new; total {len(subs)}')

            # Pagination via Link header
            next_url = None
            link_header = resp.headers.get('Link', '')
            if link_header:
                parts = [p.strip() for p in link_header.split(',')]
                for part in parts:
                    if 'rel="next"' in part:
                        start = part.find('<') + 1
                        end = part.find('>', start)
                        if start > 0 and end > start:
                            candidate = part[start:end]
                            next_url = candidate if candidate.startswith('http') else urljoin(API_BASE, candidate)
                            self.debug(f'CertSpotter: next page -> {next_url}')
                            break
            time.sleep(0.2)

        self.debug(f'CertSpotter: finished with {len(subs)} subdomains')
        return subs

    def fetch_chaos(self, timeout=30) -> set:
        # Grounded in chaos.txt
        subs = set()
        if not self.chaos_api_key:
            self.debug('Chaos: API key not set; skipping')
            return subs

        url = f'https://dns.projectdiscovery.io/dns/{self.domain}/subdomains'
        headers = {'Authorization': self.chaos_api_key}
        self.debug(f'Chaos: GET {url}')
        try:
            resp = self.session.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
        except requests.RequestException as e:
            self.debug(f'Chaos: request failed: {e}')
            return subs

        try:
            data = resp.json()
        except ValueError:
            self.debug('Chaos: non-JSON response')
            return subs

        root_domain = data.get('domain', self.domain)
        self.debug(f'Chaos: root_domain in response {root_domain}')
        sublabels = data.get('subdomains', [])
        for sub in sublabels:
            full = f'{sub}.{root_domain}' if sub else root_domain
            h = self.normalize(full)
            if self.is_in_scope(h) and self.is_subdomain(h) and self.is_valid_hostname(h):
                subs.add(h)
        self.debug(f'Chaos: collected {len(subs)} subdomains')
        return subs

    def fetch_crtsh(self, timeout=30) -> set:
        # Grounded in crtsh.txt
        subs = set()
        url = f'https://crt.sh/?q={self.domain}&output=json'
        headers = {'User-Agent': 'subdomain-harvester/1.0'}
        self.debug(f'crt.sh: GET {url}')
        try:
            resp = self.session.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
        except requests.RequestException as e:
            self.debug(f'crt.sh: request failed: {e}')
            return subs

        text = resp.text.strip()
        if not text:
            self.debug('crt.sh: empty response body')
            return subs

        records = []
        if text.startswith('['):
            try:
                records = resp.json()
            except ValueError:
                self.debug('crt.sh: failed to parse JSON array')
                return subs
        else:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        self.debug(f'crt.sh: parsed {len(records)} records')

        added = 0
        for rec in records:
            cn = rec.get('common_name')
            if cn:
                h = self.normalize(cn)
                if self.is_in_scope(h) and not self.is_wildcard(h) and self.is_valid_hostname(h) and self.is_subdomain(h):
                    if h not in subs:
                        subs.add(h)
                        added += 1
            nv = rec.get('name_value')
            if nv:
                for name in [v.strip() for v in nv.split('\n') if v.strip()]:
                    h = self.normalize(name)
                    if self.is_in_scope(h) and not self.is_wildcard(h) and self.is_valid_hostname(h) and self.is_subdomain(h):
                        if h not in subs:
                            subs.add(h)
                            added += 1
        self.debug(f'crt.sh: added {added} subdomains; total {len(subs)}')
        return subs

    def fetch_hackertarget(self, timeout=10.0) -> set:
        # Grounded in hackertarget.txt
        subs = set()
        base_url = 'https://api.hackertarget.com/hostsearch/'
        params = {'q': self.domain}
        url = f"{base_url}?{urlencode(params)}"
        self.debug(f'HackerTarget: GET {url}')
        try:
            resp = self.session.get(url, timeout=timeout)
            resp.raise_for_status()
        except requests.RequestException as e:
            self.debug(f'HackerTarget: request failed: {e}')
            return subs

        lines = resp.text.splitlines()
        added = 0
        for line in lines:
            parts = line.strip().split(',')
            if len(parts) >= 1:
                hostname = parts[0].strip()
                h = self.normalize(hostname)
                if h and h.endswith(self.domain) and self.is_subdomain(h) and self.is_valid_hostname(h):
                    if h not in subs:
                        subs.add(h)
                        added += 1
        self.debug(f'HackerTarget: processed {len(lines)} lines; added {added}; total {len(subs)}')
        return subs

    def fetch_subdomain_center(self, timeout=30) -> set:
        # Grounded in subdomaincenter.txt
        subs = set()
        url = f'https://api.subdomain.center/?domain={self.domain}'
        self.debug(f'subdomain.center: GET {url}')
        try:
            resp = self.session.get(url, timeout=timeout)
            resp.raise_for_status()
        except requests.RequestException as e:
            self.debug(f'subdomain.center: request failed: {e}')
            return subs

        try:
            data = resp.json()
        except ValueError:
            self.debug('subdomain.center: non-JSON response')
            return subs

        if isinstance(data, dict) and 'results' in data:
            data = data['results']
        if not isinstance(data, list):
            self.debug(f'subdomain.center: unexpected response type {type(data)}')
            return subs

        cleaned = []
        for d in data:
            if not isinstance(d, str):
                continue
            s = d.strip()
            if s.endswith('.'):
                s = s[:-1]
            if s:
                cleaned.append(self.normalize(s))
        self.debug(f'subdomain.center: received {len(data)} entries; cleaned to {len(cleaned)} strings')

        for h in cleaned:
            if self.is_in_scope(h) and self.is_subdomain(h) and self.is_valid_hostname(h):
                subs.add(h)

        before = len(subs)
        subs = set(self.remove_numeric_exact_firstlabel(sorted(subs)))
        self.debug(f'subdomain.center: removed {before - len(subs)} numeric-only first-label hosts; total {len(subs)}')
        return subs

    def fetch_urlscan(self, timeout=30) -> set:
        # Grounded in urlscan.txt
        subs = set()
        url = f'https://urlscan.io/api/v1/search/?q=domain:{self.domain}'
        self.debug(f'urlscan.io: GET {url}')
        try:
            resp = self.session.get(url, timeout=timeout)
            resp.raise_for_status()
        except requests.RequestException as e:
            self.debug(f'urlscan.io: request failed: {e}')
            return subs

        try:
            data = resp.json()
        except ValueError:
            self.debug('urlscan.io: non-JSON response')
            return subs

        results = data.get('results', [])
        self.debug(f'urlscan.io: results {len(results)}')

        hostnames = []
        for r in results:
            task = r.get('task', {})
            task_url = task.get('url')
            if task_url:
                try:
                    u = urllib.parse.urlparse(task_url)
                    if u.hostname:
                        hostnames.append(u.hostname.lower())
                except Exception:
                    pass

        for r in results:
            page = r.get('page', {})
            page_url = page.get('url')
            if page_url:
                try:
                    u = urllib.parse.urlparse(page_url)
                    if u.hostname:
                        hostnames.append(u.hostname.lower())
                except Exception:
                    pass

        seen = set()
        unique = []
        for h in hostnames:
            if h not in seen:
                seen.add(h)
                unique.append(h)
        self.debug(f'urlscan.io: extracted {len(unique)} unique hostnames before filtering')

        for h in unique:
            hn = self.normalize(h)
            if self.is_in_scope(hn) and self.is_subdomain(hn) and self.is_valid_hostname(hn):
                subs.add(hn)
        self.debug(f'urlscan.io: collected {len(subs)} subdomains after filtering')
        return subs

    # --------------- Aggregation and output ---------------
    def collect_all_subdomains(self) -> set:
        self.debug('Starting subdomain collection across all sources')
        results = {}

        def run_source(name: str, func):
            self.debug(f'--- Running {name} collector ---')
            try:
                s = func()
                results[name] = s
                self.debug(f'--- {name} returned {len(s)} subdomains ---')
            except Exception as e:
                results[name] = set()
                self.debug(f'--- {name} failed: {e} ---')

        run_source('AlienVault OTX', self.fetch_alienvault)
        run_source('Cert Spotter', self.fetch_certspotter)
        run_source('ProjectDiscovery Chaos', self.fetch_chaos)
        run_source('crt.sh', self.fetch_crtsh)
        run_source('HackerTarget', self.fetch_hackertarget)
        run_source('subdomain.center', self.fetch_subdomain_center)
        run_source('urlscan.io', self.fetch_urlscan)

        all_subs_raw = set().union(*results.values())
        self.debug(f'Combined raw subdomains from all sources: {len(all_subs_raw)}')

        cleaned = set()
        for h in all_subs_raw:
            hn = self.normalize(h)
            if self.drop_wildcards and self.is_wildcard(hn):
                continue
            if not self.is_subdomain(hn):
                continue
            if not self.is_valid_hostname(hn):
                continue
            cleaned.add(hn)
        self.debug(f'After normalization and validation: {len(cleaned)}')

        cleaned_list = sorted(cleaned)
        cleaned_list = self.remove_numeric_exact_firstlabel(cleaned_list)
        cleaned = set(cleaned_list)
        self.debug(f'After removing numeric-only first-labels: {len(cleaned)}')
        return cleaned

    def write_output(self, subs: set):
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                for s in sorted(subs):
                    f.write(s + '\n')
            print(f'Saved {len(subs)} unique subdomains to {self.output_file}')
        except OSError as e:
            sys.stderr.write(f'Failed to write {self.output_file}: {e}\n')

    def run(self):
        subs = self.collect_all_subdomains()
        self.write_output(subs)

if __name__ == '__main__': 
    SubdomainHarvester().run()
