"""
Custom Active Scan Rule: External JavaScript without SRI Detection (Jython).
Works on ZAP (Python 2.7/Jython).
"""

import re
from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

# Rule metadata
RULE_NAME   = "External JavaScript without SRI"
RISK        = 2  # Medium
CONFIDENCE  = 2  # Medium
CWE_ID      = 353  # CWE: Missing SRI
WASC_ID     = 15   # Application Misconfiguration
DEBUG       = True

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 4000310
name: External JavaScript without SRI (Custom Jython Active Rule)
description: Detects external <script> tags without Subresource Integrity (SRI).
solution: Use Subresource Integrity (SRI) attributes when including external scripts.
category: MISC
risk: Medium
confidence: MISC
cweId: 353
wascId: 15
status: alpha
""")

print("[SRI-Scan] Script loaded successfully")

def raiseAlert(helper, msg, url, evidence):
    desc = (
        "The page loads a third-party script without a Subresource Integrity (SRI) "
        "attribute. Without SRI, if the CDN or upstream source is compromised, the "
        "browser may execute tampered JavaScript, enabling supply-chain attacks."
    )

    sol = (
        "Add an SRI integrity attribute and crossorigin=\"anonymous\" to all external "
        "script tags.\n"
        "If the script is dynamic and SRI is impractical, consider self-hosting."
    )

    if DEBUG:
        print("[SRI-Scan] ALERT: Missing SRI -> %s" % url)

    helper.raiseAlert(
        RISK, CONFIDENCE, RULE_NAME, desc,
        msg.getRequestHeader().getURI().toString(),
        "script", None, None,
        sol, evidence, CWE_ID, WASC_ID, msg
    )

def scanNode(helper, msg):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        if DEBUG:
            print("[SRI-Scan] scanNode invoked for: %s" % uri)

        # Make a safe copy of the message
        new_msg = msg.cloneRequest()
        helper.sendAndReceive(new_msg, False, False)

        body = new_msg.getResponseBody().toString()

        # Regex: external script without integrity
        pattern = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"'][^>]*>", re.I)
        for match in pattern.finditer(body):
            src = match.group(1)
            script_tag = match.group(0)

            if "http" in src and "integrity=" not in script_tag.lower():
                evidence = script_tag.strip()[:200]
                raiseAlert(helper, new_msg, src, evidence)

    except Exception as e:
        print("[SRI-Scan] ERROR in scanNode: %s" % str(e))

def scan(helper, msg, param, value):
    # Not needed for this rule
    return
