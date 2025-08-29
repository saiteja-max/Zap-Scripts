"""
Custom External JavaScript SRI Detection Active Scan Rule for ZAP (Jython).
"""

import re
from java.net import URL
from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 4000509
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

# Core scan function
def scan(helper, msg, param, value):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        print("[DEBUG] Active scan triggered for:", uri)

        if not uri.lower().startswith("http"):
            return

        body = msg.getResponseBody().toString()
        base_url = URL(msg.getRequestHeader().getURI().toString())
        same_origin_prefix = base_url.getProtocol() + "://" + base_url.getHost()

        # Regex for <script src="...">
        script_pattern = re.compile(r'<script[^>]+src=["\'](.*?)["\'][^>]*>', re.IGNORECASE)

        for match in script_pattern.finditer(body):
            script_tag = match.group(0)
            js_file = match.group(1)

            has_integrity = "integrity=" in script_tag.lower()
            is_external = not js_file.startswith(same_origin_prefix)

            # Flag only if all 3 conditions are true
            if js_file and not has_integrity and is_external:
                (helper.newAlert()
                    .setName("Missing Subresource Integrity (SRI)")
                    .setRisk(2)              # Medium
                    .setConfidence(2)        # Medium
                    .setDescription("The external JavaScript file '" + js_file +
                                    "' is included without an integrity attribute. " +
                                    "This may allow malicious modifications if the script source is compromised.")
                    .setParam(js_file)
                    .setEvidence(script_tag)
                    .setCweId(353)
                    .setWascId(15)
                    .setMessage(msg)
                    .raise())
                print("[DEBUG] ALERT RAISED: Missing SRI for", js_file)

    except Exception as e:
        print("[ERROR] Exception in Active Scan rule:", str(e))

# Required by ZAP active scan scripts
def scanNode(helper, msg):
    scan(helper, msg, None, None)
