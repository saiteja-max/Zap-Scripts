"""
Custom Host Header Injection Detection Scan Rule for ZAP (Jython).
"""

try:
    from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

    def getMetadata():
        return ScanRuleMetadata.fromYaml("""
id: 118765
name: Host Header Injection Detection (Custom Jython Active Rule)
description: Detects if an application is vulnerable to Host header injection or poisoning by sending manipulated Host headers and checking the response for reflections or behavioral changes.
solution: Validate and enforce the expected Host value at the edge (reverse proxy / load balancer). Do not trust user-supplied Host or X-Forwarded-* headers. Normalize headers before use and configure caches/CDNs to key only on trusted values.
references:
  - https://portswigger.net/web-security/host-header
category: MISC
risk: MEDIUM
confidence: HIGH
cweId: 444
wascId: 20
alertTags:
  OWASP_2021_A05: Security Misconfiguration
  OWASP_2017_A06: Security Misconfiguration
otherInfo: Custom script-based detection of Host header injection / poisoning.
status: alpha
""")
except:
    def getMetadata():
        return None

MALICIOUS_HOST = "example.com"

def scanNode(helper, msg):
    try:
        method = msg.getRequestHeader().getMethod()
        uri = msg.getRequestHeader().getURI().toString()

        # Skip DELETE for safety
        if method.upper() == "DELETE":
            print("[SKIP] Skipping DELETE request for:", uri)
            return

        print("[SCAN] Target:", uri, "Method:", method)

        newMsg = msg.cloneRequest()

        # Replace Host header
        newMsg.getRequestHeader().setHeader("Host", MALICIOUS_HOST)

        # Preserve body if present (e.g., POST/PUT)
        if msg.getRequestBody() and msg.getRequestBody().length() > 0:
            newMsg.setRequestBody(msg.getRequestBody())
            newMsg.getRequestHeader().setContentLength(len(msg.getRequestBody()))

        # Send manipulated request
        helper.sendAndReceive(newMsg, False, False)

        response_headers = newMsg.getResponseHeader().toString()
        response_body = newMsg.getResponseBody().toString()

        evidence = None

        # 1. Check in response headers
        if MALICIOUS_HOST in response_headers:
            evidence = "Reflected in response headers"

        # 2. Check in full response body
        elif MALICIOUS_HOST in response_body:
            evidence = "Reflected in full response body"

        if evidence:
            alert = helper.newAlert()
            alert.setRisk(2)  # Medium
            alert.setConfidence(3)  # High
            alert.setName("Host Header Injection Detected (CUSTOM)")
            alert.setDescription(
                "The application appears vulnerable to Host header injection. "
                "The malicious Host value was reflected in the response.\n\n"
                "Evidence: " + evidence
            )
            alert.setParam("Host")
            alert.setAttack("Host: " + MALICIOUS_HOST)
            alert.setEvidence(MALICIOUS_HOST)
            alert.setOtherInfo("Host header replaced and reflected in response (" + evidence + ").")
            alert.setSolution("Validate and enforce expected Host headers. Reject unrecognized values.")
            alert.setCweId(444)
            alert.setWascId(20)
            alert.setMessage(newMsg)
            alert.raise()
            print("[ALERT] Host header injection detected at " + uri + " (" + evidence + ")")

    except Exception as e:
        print("[ERROR] Exception in scanNode:", str(e))


def scan(helper, msg, param, value):
    return
