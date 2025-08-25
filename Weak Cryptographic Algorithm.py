"""
Custom ZAP Active Scan Rule (Jython) - Weak Cryptographic Algorithm Detection
"""

import re 
from org.parosproxy.paros.core.scanner import AbstractAppPlugin
from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 4000302
name: Weak Cryptographic Algorithm Detection (Custom Jython Active Rule)
description: Detects usage of weak or deprecated cryptographic signature algorithms (e.g., MD5, SHA-1, etc.) in HTTP responses.
solution: Replace weak algorithms with strong ones like SHA-256/512, SHA3, EdDSA, or RSA/ECDSA with >=2048-bit keys.
references:
  - https://owasp.org/www-community/vulnerabilities/Weak_Cryptography
  - https://cwe.mitre.org/data/definitions/327.html
category: CRYPTO
risk: HIGH
confidence: MEDIUM
cweId: 327
wascId: 124
alertTags:
  OWASP_2021_A02: Cryptographic Failures
status: alpha
""")

# List of weak algos to flag
WEAK_ALGORITHMS = [
    r"md2", r"md4", r"md5",
    r"sha[-_ ]?0", r"sha[-_ ]?1", r"sha1",
    r"sha1WithRSAEncryption",
    r"rsa[-_ ]?1024", r"dsa[-_ ]?sha1",
    r"des", r"3des", r"triple[-_ ]?des",
    r"rc2", r"rc4"
]

class WeakCryptoDetection(AbstractAppPlugin):

    def scanNode(self, parent, msg):
        msg = msg.cloneRequest()
        response_body = msg.getResponseBody().toString().lower()
        response_headers = msg.getResponseHeader().toString().lower()

        content_to_check = response_body + "\n" + response_headers
        findings = []

        for weak_algo in WEAK_ALGORITHMS:
            if re.search(weak_algo, content_to_check):
                findings.append(weak_algo)

        if findings:
            alert = self.newAlert()
            alert.setName("Weak Cryptographic Algorithm Detected")
            alert.setDescription(
                "The response discloses usage of weak cryptographic algorithm(s): "
                + ", ".join(findings)
            )
            alert.setSolution(
                "Migrate to strong algorithms such as SHA-256/512, SHA-3, EdDSA, "
                "or RSA/ECDSA with 2048+ bit keys."
            )
            alert.setEvidence(", ".join(findings))
            alert.setRisk(3)  # High
            alert.setConfidence(2)  # Medium
            alert.raise()
