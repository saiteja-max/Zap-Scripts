""" 
Custom External JavaScript without SRI Active Scan Rule for ZAP (Jython).
Checks for external scripts missing integrity attributes.
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
        print "[DEBUG] Script loaded successfully, starting scan for: %s" % uri

        # Only analyze HTTP(S) responses
        if not uri or not uri.lower().startswith("http"):
            print "[DEBUG] Skipping non-HTTP(S) URI:", uri
            return

        # Read response body and content type
        body = msg.getResponseBody().toString() or ""
        content_type = msg.getResponseHeader().getHeader("Content-Type") or ""

        # Only scan HTML pages
        if "text/html" not in content_type.lower():
            print "[DEBUG] Skipping non-HTML content type:", content_type
            return

        print "[DEBUG] Scanning HTML content for SRI issues..."

        # Find all <script ... src="..."> tags (handles single/double quotes and arbitrary attributes)
        script_pattern = re.compile(r'<script\s+[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', re.I | re.M)
        script_matches = script_pattern.finditer(body)

        vulnerability_count = 0

        for match in script_matches:
            script_tag = match.group(0)
            src = match.group(1).strip()

            # Check if it's external (http, https, or protocol-relative //)
            is_external = src.startswith(('http://', 'https://', '//'))

            if is_external:
                # Determine if integrity attribute is present in the tag (case-insensitive)
                has_integrity = re.search(r'\bintegrity\s*=', script_tag, re.I) is not None
                has_crossorigin = re.search(r'\bcrossorigin\s*=', script_tag, re.I) is not None

                if not has_integrity:
                    print "[DEBUG] VULNERABILITY FOUND: External script without SRI -> %s" % src
                    # Raise an alert; pass param (may be None) and the exact script tag as evidence
                    raise_alert(helper, msg, param, src, script_tag, has_crossorigin)
                    vulnerability_count += 1
                else:
                    print "[DEBUG] Script has SRI (OK): %s" % src
            else:
                # Not considered external -> skip
                print "[DEBUG] Internal/relative script (skipping): %s" % src

        print "[DEBUG] Scan completed. Found %d vulnerabilities." % vulnerability_count

    except Exception as e:
        print "[ERROR] Exception in Active Scan rule:", str(e)
        import traceback
        traceback.print_exc()

def raise_alert(helper, msg, param, src, script_tag, has_crossorigin):
    """Helper method to raise alerts for SRI issues"""
    # Shorten evidence for alert display if extremely long
    evidence = script_tag if len(script_tag) <= 200 else script_tag[:200] + "..."

    alert = (helper.newAlert()
        .setName("External JavaScript without SRI")
        .setRisk(2)           # Medium
        .setConfidence(2)     # Medium
        .setDescription("The application loads an external script without a Subresource Integrity (SRI) attribute. "
                        "Without SRI, a compromised third-party script can lead to supply-chain attacks or arbitrary code execution in the context of the page.")
        .setParam(param)
        .setAttack("Missing SRI attribute on: " + src)
        .setEvidence(evidence)
        .setCweId(353)
        .setWascId(15)
        .setMessage(msg)
    )

    # Suggest adding integrity and crossorigin; mention crossorigin only if missing
    crossorigin_note = "" if has_crossorigin else " Also consider adding crossorigin=\"anonymous\"."
    solution = ("Add an integrity attribute with a proper hash to the external script, e.g. "
                "<script src=\"%s\" integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>." % src) + crossorigin_note

    alert.setSolution(solution)
    alert.raise()

def scanNode(helper, msg):
    """Required by ZAP - delegate to scan method for node scans"""
    scan(helper, msg, None, None)
