"""
Custom Host Header Injection Detection Scan Rule for ZAP (Jython).
Checks Location header, all response headers, and full response body (including url-encoded forms).
"""

# Optional metadata (works if commonlib add-on is available)
try:
    from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata
    def getMetadata():
        return ScanRuleMetadata.fromYaml("""
id: 1189765
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
except:
    def getMetadata():
        return None

# --- Configuration ----------------------------------------------------------
# Pick a distinctive marker domain (change if you'd like to use a domain you control)
MALICIOUS_HOST = "zzzz-injected-host.evil"

# --- Helpers ---------------------------------------------------------------
def _make_search_patterns(marker):
    """Return list of lowercase patterns to search for (plain, schemes, port, url-encoded)."""
    try:
        import urllib
        quote = lambda s: urllib.quote(s, '')
    except Exception:
        # Fallback to Java URLEncoder
        try:
            from java.net import URLEncoder
            quote = lambda s: URLEncoder.encode(s, 'UTF-8')
        except Exception:
            quote = lambda s: s

    m = marker.lower()
    patterns = set()
    patterns.add(m)
    patterns.add("http://" + m)
    patterns.add("https://" + m)
    patterns.add(m + ":")  # host:port
    # url-encoded forms
    try:
        patterns.add(quote(m).lower())
        patterns.add(quote("http://" + m).lower())
    except:
        pass
    return list(patterns)

def _snippet_around(text, idx, length):
    """Return a context snippet from `text` around index idx for readability."""
    start = max(0, idx - 60)
    end = min(len(text), idx + length + 60)
    return text[start:end]

# --- Main scan -------------------------------------------------------------
def scanNode(helper, msg):
    try:
        method = msg.getRequestHeader().getMethod()
        uri = msg.getRequestHeader().getURI().toString()

        # Skip DELETE for safety
        if method and method.upper() == "DELETE":
            print("[SKIP] Skipping DELETE request for:", uri)
            return

        print("[SCAN] Target:", uri, "Method:", method)

        # Build search patterns once
        patterns = _make_search_patterns(MALICIOUS_HOST)

        # Clone original request and only change Host header
        newMsg = msg.cloneRequest()
        newMsg.getRequestHeader().setHeader("Host", MALICIOUS_HOST)

        # Preserve body (if present) and correct content-length
        try:
            orig_body = ""
            if msg.getRequestBody():
                orig_body = msg.getRequestBody().toString()
            if orig_body:
                newMsg.setRequestBody(orig_body)
                newMsg.getRequestHeader().setContentLength(len(orig_body))
        except Exception:
            # best-effort: continue without body if something goes wrong
            pass

        # Send request without following redirects (so Location header is visible)
        helper.sendAndReceive(newMsg, False, False)

        respHeader = newMsg.getResponseHeader()
        respBody = newMsg.getResponseBody().toString()
        respBodyLower = respBody.lower() if respBody else ""
        evidence = None
        evidence_snippet = None

        # 1) Explicitly check Location header first (most impactful)
        try:
            loc = respHeader.getHeader("Location")
            if loc:
                loc_lower = loc.lower()
                for p in patterns:
                    if p in loc_lower:
                        evidence = "Reflected in Location header"
                        evidence_snippet = loc
                        break
        except Exception:
            loc = None

        # 2) If not found, search full response headers
        if not evidence:
            try:
                headers_str = respHeader.toString()
                headers_lower = headers_str.lower()
                for p in patterns:
                    idx = headers_lower.find(p)
                    if idx >= 0:
                        evidence = "Reflected in response headers"
                        # give a readable snippet of the header lines containing the pattern
                        # we use the original header string (preserve case)
                        evidence_snippet = _snippet_around(headers_str, idx, len(p))
                        break
            except Exception:
                pass

        # 3) If still not found, search full response body
        if not evidence and respBodyLower:
            for p in patterns:
                idx = respBodyLower.find(p)
                if idx >= 0:
                    evidence = "Reflected in full response body"
                    evidence_snippet = _snippet_around(respBody, idx, len(p))
                    break

        # If we found evidence, raise an alert with a helpful snippet
        if evidence:
            alert = helper.newAlert()
            alert.setRisk(2)  # Medium
            alert.setConfidence(3)  # High
            alert.setName("Host Header Injection Detected (CUSTOM)")
            alert.setDescription(
                "The application appears vulnerable to Host header injection / poisoning. "
                "A user-supplied Host value was observed reflected by the application."
            )
            alert.setParam("Host")
            alert.setAttack("Host: " + MALICIOUS_HOST)
            # If snippet is large, keep it reasonably sized
            ev = evidence_snippet if evidence_snippet else MALICIOUS_HOST
            if ev and len(ev) > 1000:
                ev = ev[:1000] + "...(truncated)"
            alert.setEvidence(ev)
            alert.setOtherInfo("Detection point: " + evidence)
            alert.setSolution("Validate and enforce expected Host headers at the edge. Reject untrusted Host/X-Forwarded-* headers.")
            alert.setCweId(444)
            alert.setWascId(20)
            alert.setMessage(newMsg)
            alert.raise()
            print("[ALERT] Host header injection detected at " + uri + " (" + evidence + ")")

    except Exception as ex:
        print("[ERROR] Exception in scanNode:", str(ex))


def scan(helper, msg, param, value):
    # Not used for header-only checks
    return
