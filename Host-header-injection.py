"""
Custom Host Header Injection Detection Scan Rule for ZAP (Jython).
"""

import re

def getMetadata():
    from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata
    return ScanRuleMetadata.fromYaml("""
id: 111878
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

# Payload to inject
INJECTED_HOST = "bing.com"

# Methods to scan (exclude DELETE)
HTTP_METHODS = ["GET", "POST", "PUT", "OPTIONS", "HEAD"]

def scanNode(helper, msg):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        print("[DEBUG] scanNode() called for:", uri)

        for method in HTTP_METHODS:
            newMsg = msg.cloneRequest()
            newMsg.getRequestHeader().setMethod(method)

            # Replace Host header (fixed here)
            newMsg.getRequestHeader().setHeader("Host", INJECTED_HOST)

            # Send request
            helper.sendAndReceive(newMsg, False, False)

            response_headers = newMsg.getResponseHeader().toString()
            response_body = newMsg.getResponseBody().toString()

            found_reflection = None

            # 1. Location header reflection
            if "Location:" in response_headers and INJECTED_HOST in response_headers:
                found_reflection = "Location header"

            # 2. Any header reflection
            elif INJECTED_HOST in response_headers:
                found_reflection = "Response headers"

            # 3. Body reflection (hidden fields, meta tags, comments, etc.)
            elif INJECTED_HOST in response_body:
                found_reflection = "Response body"

            if found_reflection:
                alert = helper.newAlert()
                alert.setRisk(2)  # Medium
                alert.setConfidence(3)  # High
                alert.setName("Host Header Injection (CUSTOM)")
                alert.setDescription("The application reflects a malicious Host header in its " + found_reflection + ".")
                alert.setParam("Host")
                alert.setAttack("Host: " + INJECTED_HOST)
                alert.setEvidence(found_reflection)
                alert.setOtherInfo("Host header injection detected in " + found_reflection + " using method: " + method)
                alert.setSolution("Validate and enforce the expected Host value at the edge. Normalize and sanitize Host headers.")
                alert.setCweId(444)
                alert.setWascId(20)
                alert.setMessage(newMsg)
                alert.raise()
                print("[DEBUG] ALERT RAISED: Host header reflected in", found_reflection, "via", method, "on", uri)
            else:
                print("[DEBUG] No reflection detected with method", method, "on", uri)

    except Exception as e:
        print("[ERROR] Exception in scanNode:", str(e))

def scan(helper, msg, param, value):
    # Not used in this script
    return
