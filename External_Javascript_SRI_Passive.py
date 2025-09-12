"""
Passive Scan Rule (Jython 2.7) - Detect <script> tags missing SRI
"""

import re
from java.net import URL

DEBUG = True
MAX_BYTES = 2 * 1024 * 1024

# Risk / Confidence
RISK_INFO, RISK_LOW, RISK_MED, RISK_HIGH = 0, 1, 2, 3
CONFIDENCE_LOW, CONFIDENCE_MED, CONFIDENCE_HIGH = 1, 2, 3

SCRIPT_PATTERN = re.compile(
    r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL
)

def _debug(msg):
    if DEBUG:
        try:
            print(u"[SRI-Detector] %s" % msg)
        except:
            pass

def _raise(pscan, msg, src_attr, script_tag):
    try:
        pscan.newAlert()\
            .setRisk(RISK_MED)\
            .setConfidence(CONFIDENCE_HIGH)\
            .setName(u"Missing Subresource Integrity (SRI) - (CUSTOM)")\
            .setDescription(
                u"An external JavaScript resource is loaded without an 'integrity' attribute. "
                u"This makes the application vulnerable to supply chain attacks if the external resource is compromised."
            )\
            .setEvidence(script_tag)\
            .setParam(src_attr)\
            .setSolution(
                u"Ensure that external scripts include 'integrity' and 'crossorigin' attributes to enable Subresource Integrity (SRI)."
            )\
            .setReference(u"https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity")\
            .setCweId(345)\
            .setWascId(15)\
            .setMessage(msg)\
            .raise()
        _debug(u"Raised alert for: %s" % src_attr)
    except Exception as e:
        _debug(u"ERROR raising alert: %s" % e)

def scan(pscan, msg, src):
    try:
        if not msg.getResponseHeader().isHtml():
            return

        uri = msg.getRequestHeader().getURI().toString()
        base_url = URL(uri)
        base_host = base_url.getHost()
        _debug(u"Scanning %s (base host=%s)" % (uri, base_host))

        body = msg.getResponseBody().toString()
        if not body:
            return
        if len(body) > MAX_BYTES:
            body = body[:MAX_BYTES]

        scripts = SCRIPT_PATTERN.findall(body)
        for src_attr, _ in scripts:
            tag_match = re.search(
                r'<script\b[^>]*src\s*=\s*["\']' + re.escape(src_attr) + r'["\'][^>]*>',
                body,
                re.IGNORECASE
            )
            if not tag_match:
                continue

            script_tag = tag_match.group(0)

            # Skip if integrity already present
            if re.search(r'\bintegrity\s*=\s*["\']', script_tag, re.IGNORECASE):
                continue

            lower_src = src_attr.strip().lower()
            if lower_src.startswith(("data:", "blob:", "javascript:")):
                continue

            is_external = False
            full_url = src_attr
            if src_attr.startswith("//"):
                full_url = base_url.getProtocol() + ":" + src_attr

            try:
                parsed = URL(full_url)
                parsed_host = parsed.getHost()
                _debug(u"Parsed src=%s, host=%s" % (src_attr, parsed_host))
                if parsed_host and (not base_host or parsed_host != base_host):
                    is_external = True
            except Exception as e:
                _debug(u"Skipping invalid/relative src=%s (err=%s)" % (src_attr, e))
                is_external = False

            if is_external:
                _raise(pscan, msg, src_attr, script_tag)

        _debug(u"SRI scan done for: %s" % uri)

    except Exception as e:
        _debug(u"SRI passive scan exception: %s" % e)
