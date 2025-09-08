"""
Custom Host Header Injection Detection Scan Rule for ZAP (Jython).
"""

from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata
import re

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 118987
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

# Payload host we inject
INJECTED_HOST = "bing.com"

def scanNode(helper, msg):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        method = msg.getRequestHeader().getMethod()
        print("[DEBUG] scanNode() called for:", uri, "method:", method)

        # Clone and inject Host header
        newMsg = msg.cloneRequest()
        newMsg.getRequestHeader().setHeader("Host", INJECTED_HOST)

        # Send request
        helper.sendAndReceive(newMsg, False, False)

        response_headers = newMsg.getResponseHeader().toString()
        response_body = newMsg.getResponseBody().toString()

        found_reflection = None

        # 1. Check Location header explicitly
        if re.search(r"Location:\s*https?://[^\\s]*" + re.escape(INJECTED_HOST), response_headers, re.IGNORECASE):
            found_reflection = "Location header"
        
        # 2. Check all headers
        elif INJECTED_HOST in response_headers:
            found_reflection = "Response headers"
        
        # 3. Check full body (hidden fields, meta tags, comments, etc.)
        elif INJECTED_HOST in response_body:
            found_reflection = "Response body"

        # Raise alert if found
        if found_reflection:
            alert = helper.newAlert()
            alert.setRisk(2)  # Medium
            alert.setConfidence(3)  # High
            alert.setName("Host Header Injection (CUSTOM)")
            alert.setDescription("The application reflects the injected Host header value in the " + found_reflection + ".")
            alert.setParam("Host")
            alert.setAttack("Host: " + INJECTED_HOST)
            alert.setEvidence(found_reflection)
            alert.setOtherInfo("Reflection detected in: " + found_reflection)
            alert.setSolution("Validate and enforce correct Host headers. Do not trust client-supplied values.")
            alert.setCweId(444)
            alert.setWascId(20)
            alert.setMessage(newMsg)
            alert.raise()
            print("[DEBUG] ALERT RAISED: Host Header Injection detected at " + uri + " in " + found_reflection)
        else:
            print("[DEBUG] No Host header reflection found at", uri)

    except Exception as e:
        print("[ERROR] Exception in scanNode:", str(e))


def scan(helper, msg, param, value):
    # Not needed for param-based scanning
    return
