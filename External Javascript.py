""" 
Custom External JavaScript without SRI Active Scan Rule for ZAP (Jython).
Python 2.7 compatible version with minimal debugging.
"""

import re
from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 4000310
name: External JavaScript without SRI (Custom Jython Active Rule)
description: Detects external <script> tags without Subresource Integrity (SRI). Without SRI, compromised third-party scripts may lead to supply-chain attacks.
solution: Always add an SRI integrity attribute and crossorigin="anonymous" to external script tags, or self-host the JavaScript.
references:
  - https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
  - https://owasp.org/www-community/controls/Subresource_Integrity
category: MISC
risk: MEDIUM
confidence: MEDIUM
cweId: 353
wascId: 15
alertTags:
  OWASP_2021_A08: Software and Data Integrity Failures
  OWASP_2017_A09: Using Components with Known Vulnerabilities
otherInfo: Custom script-based detection of external JavaScript files without SRI.
status: alpha
""")

def scan(helper, msg, param, value):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        print "[DEBUG] Script loaded successfully, starting scan for:", uri

        # Only analyze HTTP(S) responses
        if not uri.lower().startswith("http"):
            return

        body = msg.getResponseBody().toString()

        # Regex to find external <script src="..."> without integrity
        pattern = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"'][^>]*>", re.I)
        
        for match in pattern.finditer(body):
            src = match.group(1)
            script_tag = match.group(0)

            # Check if it's external and missing integrity
            if (src.startswith("http") or src.startswith("//")) and "integrity=" not in script_tag.lower():
                evidence = script_tag.strip()[:200]

                # Build alert
                alert = (helper.newAlert()
                    .setName("External JavaScript without SRI")
                    .setRisk(2)              # Medium
                    .setConfidence(2)        # Medium
                    .setDescription("The application loads an external script without an SRI attribute. Without SRI, tampered CDN or third-party scripts may lead to supply-chain compromise.")
                    .setParam(param)
                    .setAttack("Missing SRI on external script: " + src)
                    .setEvidence(evidence)
                    .setCweId(353)
                    .setWascId(15)
                    .setMessage(msg))
                
                # Add solution guidance
                alert.setSolution("Add integrity and crossorigin attributes: <script src='" + src + "' integrity='sha384-...' crossorigin='anonymous'></script>")
                
                # Raise the alert
                alert.raise()
                print "[DEBUG] ALERT RAISED: Missing SRI on external script ->", src

    except Exception as e:
        print "[ERROR] Exception in Active Scan rule:", str(e)


def scanNode(helper, msg):
    # Active scan script requires scanNode() but we delegate to scan()
    scan(helper, msg, None, None)
