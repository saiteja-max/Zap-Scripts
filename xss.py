"""
Custom Reflected XSS Detection Active Scan Rule for ZAP (Jython).
"""

from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 6000001
name: Reflected XSS Detection (Custom Jython Active Rule)
description: Attempts to detect reflected XSS in URL query parameters by injecting common payloads and checking for reflection in the response.
solution: Properly validate and encode all user-controlled input. Apply a strict Content Security Policy (CSP).
references:
  - https://owasp.org/www-community/attacks/xss/
  - https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
category: INJECTION
risk: HIGH
confidence: MEDIUM
cweId: 79
wascId: 8
alertTags:
  OWASP_2021_A03: Injection
  OWASP_2017_A07: Cross-Site Scripting (XSS)
otherInfo: Custom script-based detection of reflected XSS in query parameters.
status: alpha
""")

# Common XSS payloads
xss_payloads = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>"
]

def scan(helper, msg, param, value):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        print("[DEBUG] Active scan triggered for:", uri)

        # Only analyze HTTP(S) requests with query parameters
        if not uri.lower().startswith("http"):
            return
        if param is None:
            return

        for payload in xss_payloads:
            # Clone the original message
            attack = msg.cloneRequest()
            helper.setParam(attack, param, payload)

            # Send the attack request
            helper.sendAndReceive(attack, False)

            body = attack.getResponseBody().toString()

            # Simple reflection check
            if payload in body:
                (helper.newAlert()
                    .setName("Reflected XSS Detected")
                    .setRisk(3)              # High
                    .setConfidence(2)        # Medium
                    .setDescription("The application appears vulnerable to reflected XSS. Payload was injected into parameter and reflected in the response.")
                    .setParam(param)
                    .setAttack(payload)
                    .setEvidence(payload)
                    .setCweId(79)
                    .setWascId(8)
                    .setMessage(attack)
                    .raise())
                print("[DEBUG] ALERT RAISED: XSS detected with payload:", payload)
                break

    except Exception as e:
        print("[ERROR] Exception in Active Scan rule:", str(e))


def scanNode(helper, msg):
    # Active scan script requires scanNode(), but actual checks happen in scan()
    pass
