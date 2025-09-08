"""
Custom Host Header Injection Detection (Custom Jython Active Rule)
- Preserves method & body, skips DELETE
- Uses regex (including url-encoded forms) to detect injected host reflections
- Debug output: scanned URL, method, injected host, and alert when found
"""

from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata
import re

INJECTED_HOST = "bing.com"
EXCLUDED_METHODS = ["DELETE"]

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 1187567
name: Host Header Injection Detection (Custom Jython Active Rule)
description: Detects if an application is vulnerable to Host header injection or poisoning by sending manipulated Host headers and checking the response for reflections in Location, headers, or body.
solution: Validate and enforce the expected Host value at the edge. Do not trust request Host or X-Forwarded-* headers. Normalize headers before use and configure caches/CDNs correctly.
references:
  - https://portswigger.net/web-security/host-header
category: MISC
risk: MEDIUM
confidence: HIGH
cweId: 444
wascId: 20
alertTags:
  OWASP_2021_A05: Security Misconfiguration
otherInfo: Checks Location header first, then full headers and body (includes url-encoded checks).
status: alpha
""")


# Build search patterns (plain + scheme + port + path + url-encoded variants)
def _build_patterns(marker):
    patterns = set()
    m_esc = re.escape(marker)

    # plain host, host with port, scheme + host, scheme + host + path
    patterns.add(r"\b" + m_esc + r"\b")
    patterns.add(r"\b" + m_esc + r":[0-9]{1,5}\b")
    patterns.add(r"https?://"+m_esc+r"(?=[/\s\"'>]|$)")
    patterns.add(r"https?://"+m_esc+r":[0-9]{1,5}(?=[/\s\"'>]|$)")
    patterns.add(r"\b"+m_esc+r"(?=/)")

    # URL-encoded variants (try urllib.quote, fallback to Java URLEncoder)
    try:
        import urllib
        enc = urllib.quote(marker, '')
        enc_http = urllib.quote("http://" + marker, '')
        enc_https = urllib.quote("https://" + marker, '')
    except Exception:
        try:
            from java.net import URLEncoder
            enc = URLEncoder.encode(marker, "UTF-8")
            enc_http = URLEncoder.encode("http://" + marker, "UTF-8")
            enc_https = URLEncoder.encode("https://" + marker, "UTF-8")
        except Exception:
            enc = marker
            enc_http = "http%3A%2F%2F" + marker
            enc_https = "https%3A%2F%2F" + marker

    patterns.add(re.escape(enc))
    patterns.add(re.escape(enc_http))
    patterns.add(re.escape(enc_https))

    # return compiled regex list (ignore case, dot matches newline is not needed)
    return [re.compile(p, re.IGNORECASE) for p in patterns]


PATTERNS = _build_patterns(INJECTED_HOST)


def _search_patterns_in_text(patterns, text):
    if not text:
        return None
    for p in patterns:
        m = p.search(text)
        if m:
            return m
    return None


def _snippet(text, match_obj, ctx=60):
    if not text or not match_obj:
        return ""
    start = max(0, match_obj.start() - ctx)
    end = min(len(text), match_obj.end() + ctx)
    return text[start:end]


def scanNode(helper, msg):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        method = msg.getRequestHeader().getMethod()

        # Debug: scanned URL and method
        print("[SCAN] URL:", uri, "Method:", method, "InjectedHost:", INJECTED_HOST)

        # Skip excluded methods for safety
        if method and method.upper() in EXCLUDED_METHODS:
            print("[SKIP] Skipping method:", method, "for", uri)
            return

        # Clone original request (keeps method/body)
        newMsg = msg.cloneRequest()

        # Inject Host header only (preserve everything else)
        newMsg.getRequestHeader().setHeader("Host", INJECTED_HOST)

        # Ensure Content-Length matches body if present
        try:
            reqBody = newMsg.getRequestBody().toString()
            if reqBody:
                newMsg.getRequestHeader().setContentLength(len(reqBody))
        except Exception:
            # best effort; continue if we can't read/set body
            pass

        # Send request; do not follow redirects so Location header remains visible
        helper.sendAndReceive(newMsg, False, False)

        # Read headers and body as strings
        headers_str = newMsg.getResponseHeader().toString()
        body_str = newMsg.getResponseBody().toString()

        # First check Location header explicitly (line-by-line, case-insensitive)
        found = False
        evidence = ""
        loc_match_obj = None

        try:
            # Split headers in a robust way (handles \r\n or \n)
            for line in headers_str.splitlines():
                if line.strip() == "":
                    continue
                # check if this is a Location header line
                if line.lower().startswith("location:"):
                    # check all patterns against the line
                    m = _search_patterns_in_text(PATTERNS, line)
                    if m:
                        found = True
                        loc_match_obj = m
                        evidence = "Reflected in Location header:\n" + line.strip()
                        break
        except Exception:
            # ignore and continue to general search
            pass

        # If not found yet, search all headers
        if not found:
            m = _search_patterns_in_text(PATTERNS, headers_str)
            if m:
                found = True
                evidence = "Reflected in response headers (snippet):\n" + _snippet(headers_str, m, 120)

        # If still not found, search full response body
        if not found:
            m = _search_patterns_in_text(PATTERNS, body_str)
            if m:
                found = True
                evidence = "Reflected in response body (snippet):\n" + _snippet(body_str, m, 120)

        # Raise an alert if reflection found
        if found:
            alert = helper.newAlert()
            alert.setRisk(2)  # Medium
            alert.setConfidence(3)  # High
            alert.setName("Host Header Injection (CUSTOM)")
            alert.setDescription("The injected Host value '%s' was reflected by the application." % INJECTED_HOST)
            alert.setParam("Host")
            alert.setAttack("Host: " + INJECTED_HOST)
            # Limit evidence length
            ev = evidence if evidence else INJECTED_HOST
            if len(ev) > 2000:
                ev = ev[:2000] + "...(truncated)"
            alert.setEvidence(ev)
            alert.setOtherInfo("Reflection detected in headers or body.")
            alert.setSolution("Validate Host headers at the edge and avoid reflecting untrusted Host values.")
            alert.setCweId(444)
            alert.setWascId(20)
            alert.setMessage(newMsg)
            alert.raise()

            # Debug: print alert raised and evidence snippet
            print("[ALERT] Host Header Injection detected at:", uri)
            print("[ALERT] Evidence:", ev)
        else:
            # Debug: no reflection found
            print("[DEBUG] No reflection of injected host at:", uri)

    except Exception as e:
        # Print full exception for troubleshooting
        print("[ERROR] Exception in scanNode for %s: %s" % (str(uri), str(e)))


def scan(helper, msg, param, value):
    # Not used for this header-only active scan
    return
