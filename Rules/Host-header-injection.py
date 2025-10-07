"""
Custom Host Header Injection Detection Active Scan Rule for ZAP (Jython).
"""

import re
from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 1198978
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
otherInfo: Checks Location header first, then full headers and body (includes regex-based checks).
status: alpha
""")

# --------------- CONFIG ---------------
INJECTED_HOST = "bing.com"
EXCLUDED_METHODS = ["DELETE"]
# --------------------------------------

def raise_alert(helper, attack, evidence, uri):
    (helper.newAlert()
        .setName("Host Header Injection (CUSTOM)")
        .setRisk(2)  # Medium
        .setConfidence(3)  # High
        .setDescription("The application reflects user-supplied Host header values in response headers or body. "
                        "This can lead to web cache poisoning, password reset poisoning, and other host header attacks.")
        .setParam("Host")
        .setAttack("Host: " + INJECTED_HOST)
        .setEvidence(evidence)
        .setCweId(444)
        .setWascId(20)
        .setMessage(attack)
        .raise())
    print("[DEBUG] ALERT RAISED at %s with evidence: %s" % (uri, evidence))

def scanNode(helper, msg):
    try:
        uri = msg.getRequestHeader().getURI()
        method = msg.getRequestHeader().getMethod()
        print("[DEBUG] scanNode() called for: %s %s" % (method, uri))

        # Skip dangerous/irrelevant methods
        if method.upper() in EXCLUDED_METHODS:
            return

        # Clone the request
        attack = msg.cloneRequest()

        # Inject Host header (overwrite if already present)
        attack.getRequestHeader().setHeader("Host", INJECTED_HOST)

        # Send the request
        helper.sendAndReceive(attack, False, False)

        # Get response
        resp_header = attack.getResponseHeader().toString()
        resp_body = attack.getResponseBody().toString()

        # --- Checks for reflection ---
        evidence = None

        # Check Location header
        loc = attack.getResponseHeader().getHeader("Location")
        if loc and INJECTED_HOST in loc:
            evidence = "Location: " + loc

        # Check other response headers
        elif INJECTED_HOST in resp_header:
            evidence = "Header Reflection: " + INJECTED_HOST

        # Check body using regex (meta tags, hidden fields, comments, anywhere)
        elif re.search(re.escape(INJECTED_HOST), resp_body, re.IGNORECASE):
            evidence = "Body Reflection: " + INJECTED_HOST

        # Raise alert if evidence found
        if evidence:
            raise_alert(helper, attack, evidence, uri)
        else:
            print("[DEBUG] No Host header reflection detected at %s" % uri)

    except Exception as e:
        print("[ERROR] Exception in scanNode:", str(e))


def scan(helper, msg, param, value):
    # Not used; scanning handled in scanNode
    pass
