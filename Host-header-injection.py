"""
Custom Host Header Injection Detection Active Scan Rule for ZAP (Jython).
Uses regex to detect reflections in headers and body.
"""

from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata
import re

INJECTED_HOST = "bing.com"
EXCLUDED_METHODS = ["DELETE"]

# Regex pattern to catch host reflection, URL-encoded, with optional protocol/port/path
HOST_REGEX = re.compile(r"(https?://)?%s(:\d+)?(/[\w\-\./?=&]*)?" % re.escape(INJECTED_HOST), re.IGNORECASE)

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 11189767
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
otherInfo: Uses regex to detect host reflections including URL-encoded and paths.
status: alpha
""")


def scanNode(helper, msg):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        method = msg.getRequestHeader().getMethod()

        if method.upper() in EXCLUDED_METHODS:
            return

        # Clone request
        newMsg = msg.cloneRequest()

        # Inject Host header
        newMsg.getRequestHeader().setHeader("Host", INJECTED_HOST)

        # Adjust Content-Length if body present
        if newMsg.getRequestBody() and newMsg.getRequestBody().length() > 0:
            newMsg.getRequestHeader().setContentLength(len(newMsg.getRequestBody().toString()))

        # Send request
        helper.sendAndReceive(newMsg, False, False)

        headers = newMsg.getResponseHeader().toString()
        body = newMsg.getResponseBody().toString()

        found = False
        evidence = ""

        # --- Step 1: Check Location header specifically ---
        location_match = re.search(r"(?i)^location:.*%s" % re.escape(INJECTED_HOST), headers, re.MULTILINE)
        if location_match:
            found = True
            evidence = "Reflected in Location header:\n" + location_match.group(0)

        # --- Step 2: Check all headers if not found yet ---
        if not found:
            header_match = HOST_REGEX.search(headers)
            if header_match:
                found = True
                evidence = "Reflected in Response Header:\n" + header_match.group(0)

        # --- Step 3: Check body ---
        if not found:
            body_match = HOST_REGEX.search(body)
            if body_match:
                found = True
                idx = body.find(body_match.group(0))
                snippet = body[max(0, idx-40): idx+40]
                evidence = "Reflected in Response Body (snippet):\n" + snippet

        # --- Raise alert if found ---
        if found:
            helper.newAlert()\
                .setRisk(2)\
                .setConfidence(3)\
                .setName("Host Header Injection (CUSTOM)")\
                .setDescription("Injected host '%s' reflected in response." % INJECTED_HOST)\
                .setParam("Host")\
                .setAttack("Host: " + INJECTED_HOST)\
                .setEvidence(evidence)\
                .setOtherInfo("Reflection found in headers or body.")\
                .setSolution("Validate Host headers and avoid reflecting them.")\
                .setCweId(444)\
                .setWascId(20)\
                .setMessage(newMsg)\
                .raise()
            print("[ALERT] Host Header Injection detected at:", uri)

    except Exception as e:
        print("[ERROR] Exception in scanNode:", str(e))


def scan(helper, msg, param, value):
    return
