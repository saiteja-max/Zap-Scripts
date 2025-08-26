"""
Active Scan Rule (Jython, Python 2.7)
Title: External Script without Subresource Integrity (SRI)
Finds <script src=...> loaded from a different origin that do NOT include an `integrity` attribute.
"""

import re
from java.net import URI as JavaURI
from org.parosproxy.paros.network import HttpRequestHeader
from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

# ---- Config ----
RULE_NAME      = "External Script without Subresource Integrity (SRI)"
RISK           = 2  # 0: Info, 1: Low, 2: Medium, 3: High
CONFIDENCE     = 2  # 0: Low, 1: Medium, 2: High, 3: Certain
CWE_ID         = 353   # Missing Support for Integrity Check
WASC_ID        = 14    # Server Misconfiguration (closest mapping)
DEBUG          = False

# Regexes
SCRIPT_TAG = re.compile(r'<script\b[^>]*\bsrc\s*=\s*([\'"])(.*?)\1[^>]*>', re.I | re.M)
HAS_INTEGRITY = re.compile(r'\bintegrity\s*=\s*([\'"]).*?\1', re.I)

def getMetadata():
    """
    Provides metadata for ZAP UI.
    """
    return ScanRuleMetadata.fromYaml("""
id: 400035
name: External Script without Subresource Integrity (SRI)
description: Detects external script tags that do not implement Subresource Integrity (SRI).
solution: |
  Add an SRI integrity attribute and crossorigin="anonymous" to all external
  script tags, for example:
  
  <script src="https://cdn.example.com/lib.js"
          integrity="sha384-..."
          crossorigin="anonymous"></script>
  
  If the script is dynamic and SRI is impractical, consider self-hosting and pinning
  a known-good version, or use a trusted, controlled delivery path.
risk: Medium
confidence: Medium
cweId: 353
wascId: 14
category: MISC
alertTags:
  OWASP_2021_A08: "Software and Data Integrity Failures"
  OWASP_2017_A09: "Using Components with Known Vulnerabilities"
  WSTG-INPV-12: "Testing for Subresource Integrity"
""")

def _log(msg):
    if DEBUG:
        print("[SRI-Scan] %s" % msg)

def _same_origin(page_uri, target_url):
    try:
        if target_url.startswith("//"):
            target_url = page_uri.getScheme() + ":" + target_url
        if not (target_url.startswith("http://") or target_url.startswith("https://")):
            return True
        t = JavaURI(target_url)
        return (t.getScheme().lower() == page_uri.getScheme().lower() and
                t.getHost() and page_uri.getHost() and
                t.getHost().lower() == page_uri.getHost().lower() and
                (t.getPort() == page_uri.getPort() or
                 (t.getPort() == -1 and page_uri.getPort() in (-1, 80, 443)) or
                 (page_uri.getPort() == -1 and t.getPort() in (-1, 80, 443))))
    except:
        return True

def raiseAlert(helper, msg, url, evidence):
    desc = (
        "The page loads a third-party script without a Subresource Integrity (SRI) "
        "attribute. Without SRI, if the CDN or upstream source is compromised, the "
        "browser may execute tampered JavaScript, enabling supply-chain attacks."
    )

    sol = (
        "Add an SRI integrity attribute and crossorigin=\"anonymous\" to all external "
        "script tags.\n"
        "If the script is dynamic and SRI is impractical, consider self-hosting."
    )

    helper.raiseAlert(
        RISK, CONFIDENCE, RULE_NAME, desc,
        msg.getRequestHeader().getURI().toString(),
        "script", None, None,
        sol, evidence, CWE_ID, WASC_ID, msg
    )

def scanNode(helper, msg):
    try:
        new_msg = msg.cloneRequest()
        new_msg.getRequestHeader().setMethod(HttpRequestHeader.GET)
        helper.sendAndReceive(new_msg, False, False)
    except Exception as e:
        _log("Request error: %s" % e)
        return

    resp = new_msg.getResponseHeader()
    body = new_msg.getResponseBody().toString()

    if not resp or not resp.isText() or not body:
        return

    ctype = resp.getHeader("Content-Type") or ""
    if ("html" not in ctype.lower()) and ("xml" not in ctype.lower()):
        return

    page_uri = new_msg.getRequestHeader().getURI()
    _log("Scanning %s" % page_uri.toString())

    for m in SCRIPT_TAG.finditer(body):
        tag_html = m.group(0)
        src = m.group(2).strip()

        if HAS_INTEGRITY.search(tag_html):
            continue
        if _same_origin(page_uri, src):
            continue

        evidence = tag_html if len(tag_html) <= 512 else tag_html[:512] + "..."
        _log("Missing SRI on external script: %s" % src)
        raiseAlert(helper, new_msg, src, evidence)

def scan(helper, msg, param, value):
    return
