""" 
Custom Polyfill.io Detection Active Scan Rule for ZAP (Jython).
"""

from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 4000301
name: Polyfill.io Detection (Custom Jython Active Rule)
description: Detects usage of polyfill.io CDN which is no longer safe. Usage may result in malicious script injection due to supply chain risks.
solution: Remove polyfill.io references. Self-host polyfills or use safe libraries such as core-js or polyfill-library.
references:
  - https://sansec.io/research/polyfill-supply-chain-attack
  - https://github.com/Financial-Times/polyfill-library
category: MISC
risk: MEDIUM
confidence: HIGH
cweId: 829
wascId: 15
alertTags:
  OWASP_2021_A08: Software and Data Integrity Failures
  OWASP_2017_A09: Using Components with Known Vulnerabilities
otherInfo: Custom script-based detection of unsafe polyfill.io usage.
status: alpha
""")

def scan(helper, msg, param, value):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        print("[DEBUG] Active scan triggered for:", uri)

        # Only analyze HTTP(S) responses
        if not uri.lower().startswith("http"):
            return

        body = msg.getResponseBody().toString()

        # Vulnerability check: anywhere polyfill.io appears in response body
        if "polyfill.io" in body:
            (helper.newAlert()
                .setName("Polyfill.io Usage Detected")
                .setRisk(2)              # Medium
                .setConfidence(3)        # High
                .setDescription("The application includes references to polyfill.io, which is no longer safe. This may allow malicious script injection.")
                .setParam(param)
                .setAttack("polyfill.io reference in response")
                .setEvidence("Found: polyfill.io")
                .setCweId(829)
                .setWascId(15)
                .setMessage(msg)
                .raise())
            print("[DEBUG] ALERT RAISED: Polyfill.io detected in response body")

    except Exception as e:
        print("[ERROR] Exception in Active Scan rule:", str(e))


def scanNode(helper, msg):
    # Active scan script requires scanNode() but we delegate to scan()
    scan(helper, msg, None, None)
