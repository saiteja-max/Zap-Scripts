"""
Custom Host Header Injection Detection Active Scan Rule for ZAP (Jython).
"""

from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

INJECTED_HOST = "bing.com"
EXCLUDED_METHODS = ["DELETE"]

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 1197898
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
otherInfo: Checks Location header first, then full headers and body.
status: alpha
""")


def scanNode(helper, msg):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        method = msg.getRequestHeader().getMethod()

        print("[DEBUG] scanNode() called for:", uri)

        if method.upper() in EXCLUDED_METHODS:
            return

        # Clone original request
        newMsg = msg.cloneRequest()

        # Inject custom Host header
        newMsg.getRequestHeader().setHeader("Host", INJECTED_HOST)

        # Fix Content-Length for POST/PUT
        if newMsg.getRequestBody() and newMsg.getRequestBody().length() > 0:
            newMsg.getRequestHeader().setContentLength(len(newMsg.getRequestBody().toString()))

        # Send request
        helper.sendAndReceive(newMsg, False, False)

        response_headers = newMsg.getResponseHeader().toString().lower()
        response_body = newMsg.getResponseBody().toString()

        found = False
        evidence = ""

        # --- Step 1: Check Location header properly ---
        if "location:" in response_headers and INJECTED_HOST in response_headers:
            lines = response_headers.split("\r\n")
            for line in lines:
                if line.lower().startswith("location:") and INJECTED_HOST in line.lower():
                    evidence = "Reflected in Location header:\n" + line
                    found = True
                    break

        # --- Step 2: Check any other response header ---
        if not found and INJECTED_HOST in response_headers:
            lines = response_headers.split("\r\n")
            for line in lines:
                if INJECTED_HOST in line.lower():
                    evidence = "Reflected in Response Header:\n" + line
                    found = True
                    break

        # --- Step 3: Check full body ---
        if not found and INJECTED_HOST in response_body:
            idx = response_body.find(INJECTED_HOST)
            snippet = response_body[max(0, idx-40): idx+40]
            evidence = "Reflected in Response Body (snippet):\n" + snippet
            found = True

        # --- Raise alert ---
        if found:
            helper.newAlert()\
                .setRisk(2)\
                .setConfidence(3)\
                .setName("Host Header Injection (CUSTOM)")\
                .setDescription("The injected host value '" + INJECTED_HOST + "' was reflected in the response.")\
                .setParam("Host")\
                .setAttack("Host: " + INJECTED_HOST)\
                .setEvidence(evidence)\
                .setOtherInfo("Reflected in headers or body.")\
                .setSolution("Validate the Host header and avoid reflecting it in responses.")\
                .setCweId(444)\
                .setWascId(20)\
                .setMessage(newMsg)\
                .raise()
            print("[ALERT] Host Header Injection detected at:", uri, "Evidence:", evidence)

    except Exception as e:
        print("[ERROR] Exception in scanNode:", str(e))


def scan(helper, msg, param, value):
    # Not using parameter-based scanning here
    return
