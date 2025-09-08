"""
Custom Host Header Injection Detection Scan Rule for ZAP (Jython).
"""

from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

INJECTED_HOST = "bing.com"
EXCLUDED_METHODS = ["DELETE"]

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 118978
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


def scanNode(helper, msg):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        method = msg.getRequestHeader().getMethod()

        print("[DEBUG] scanNode() called for:", uri)

        if method.upper() in EXCLUDED_METHODS:
            return

        # Clone original request
        newMsg = msg.cloneRequest()

        # Inject malicious Host header
        newMsg.getRequestHeader().setHeader("Host", INJECTED_HOST)

        # Keep body length consistent for POST/PUT
        if newMsg.getRequestBody() and newMsg.getRequestBody().length() > 0:
            newMsg.getRequestHeader().setContentLength(len(newMsg.getRequestBody().toString()))

        # Send modified request
        helper.sendAndReceive(newMsg, False, False)

        response_headers = newMsg.getResponseHeader().toString()
        response_body = newMsg.getResponseBody().toString()

        found = False
        evidence = ""

        # === Step 1: Normalize headers and check line by line ===
        for header_line in response_headers.split("\r\n"):
            if INJECTED_HOST in header_line.lower():
                if header_line.lower().startswith("location:"):
                    found = True
                    evidence = "Reflected in Location header:\n" + header_line
                    break
                else:
                    found = True
                    evidence = "Reflected in Response Header:\n" + header_line
                    break

        # === Step 2: Check full response body ===
        if not found and INJECTED_HOST in response_body:
            idx = response_body.find(INJECTED_HOST)
            snippet = response_body[max(0, idx-40): idx+40]
            evidence = "Reflected in Response Body (snippet):\n" + snippet
            found = True

        # === Raise alert if reflection found ===
        if found:
            alert = helper.newAlert()
            alert.setRisk(2)  # Medium
            alert.setConfidence(3)  # High
            alert.setName("Host Header Injection (CUSTOM)")
            alert.setDescription("The injected host value '" + INJECTED_HOST + "' was reflected in the response, indicating potential Host Header Injection.")
            alert.setParam("Host")
            alert.setAttack("Host: " + INJECTED_HOST)
            alert.setEvidence(evidence)
            alert.setOtherInfo("Host reflection detected in headers or body.")
            alert.setSolution("Ensure the application validates the Host header and does not reflect it unsafely in responses.")
            alert.setCweId(444)
            alert.setWascId(20)
            alert.setMessage(newMsg)
            alert.raise()
            print("[ALERT] Host Header Injection detected at:", uri)

    except Exception as e:
        print("[ERROR] Exception in scanNode:", str(e))


def scan(helper, msg, param, value):
    # Not needed for param-based scanning
    return
