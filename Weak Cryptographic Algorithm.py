"""
Custom Weak Algorithm Detection (SHA1) Active Scan Rule for ZAP (Jython).
"""

import re
from org.parosproxy.paros.network import HttpMessage
from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 4000304
name: Weak Algorithm Detection - SHA1 (Custom Jython Active Rule)
description: Detects usage of weak cryptographic algorithm SHA1 in HTTP responses.
solution: Replace weak algorithms (e.g., SHA1) with stronger alternatives such as SHA256 or SHA3.
references:
  - https://cwe.mitre.org/data/definitions/327.html
  - https://owasp.org/www-community/Weak_Cryptography
category: MISC
risk: MEDIUM
confidence: HIGH
cweId: 327
wascId: 101
alertTags:
  OWASP_2021_A02: Cryptographic Failures
  OWASP_2017_A03: Sensitive Data Exposure
otherInfo: Custom script-based detection of SHA1 usage in headers or body.
status: alpha
""")

def scan(helper, msg, param, value):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        print("[DEBUG] Active scan triggered for:", uri)

        # Force sending request to make sure response is populated
        helper.sendAndReceive(msg, False, True)

        body = msg.getResponseBody().toString()
        headers = msg.getResponseHeader().toString()

        print("[DEBUG] Response body length:", len(body))
        print("[DEBUG] Response headers length:", len(headers))

        target_text = headers + "\n" + body

        # Case-insensitive search for "sha1"
        match = re.search(r"sha1", target_text, re.IGNORECASE)
        if match:
            evidence = match.group(0)

            (helper.newAlert()
                .setName("Weak Algorithm SHA1 Detected")
                .setRisk(2)              # Medium
                .setConfidence(3)        # High
                .setDescription("The application response contains the weak algorithm 'SHA1', which is considered cryptographically insecure.")
                .setParam(param)
                .setAttack("Detected weak algorithm in response")
                .setEvidence(evidence)
                .setCweId(327)
                .setWascId(101)
                .setMessage(msg)
                .raise())
            print("[DEBUG] ALERT RAISED: SHA1 detected ->", evidence)

    except Exception as e:
        print("[ERROR] Exception in Active Scan rule:", str(e))

def scanNode(helper, msg):
    # Run detection for node-level scans
    scan(helper, msg, None, None)
