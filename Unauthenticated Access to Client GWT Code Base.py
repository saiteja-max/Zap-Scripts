"""
Custom Active Scan Rule for ZAP (Jython).

Checks for:
1. Missing Subresource Integrity (SRI) on external <script> tags.
2. Unauthenticated access to exposed Google Web Toolkit (GWT) client code (.nocache.js, .cache.js, deferred fragments).
"""

import re
from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

# ==================================================
# Metadata
# ==================================================
def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 4000311
name: Missing SRI / GWT Client Code Exposure (Custom Jython Rule)
description: Detects missing SRI on external JavaScript and unauthenticated access to GWT client-side code (.nocache.js, .cache.js, deferred fragments).
solution: 
  - Always add an integrity attribute and crossorigin="anonymous" to external script tags. 
  - Restrict access to GWT permutation/fragment files; do not expose client-side code without proper authentication.
references:
  - https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
  - https://owasp.org/www-community/controls/Subresource_Integrity
  - https://owasp.org/www-community/vulnerabilities/Exposed_GWT_Code
category: MISC
risk: MEDIUM
confidence: MEDIUM
cweId: 353
wascId: 15
alertTags:
  OWASP_2021_A08: Software and Data Integrity Failures
  OWASP_2017_A09: Using Components with Known Vulnerabilities
  OWASP_2021_A05: Security Misconfiguration
otherInfo: Custom detection of SRI issues and exposed GWT client code.
status: alpha
""")

# ==================================================
# Main scan entrypoint (ZAP calls this)
# ==================================================
def scanNode(helper, msg):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        print "[DEBUG] Custom scan triggered for:", uri

        # -------------------------------
        # Check 1: GWT code base exposure
        # -------------------------------
        gwt_patterns = (".nocache.js", ".cache.js", "/deferredjs/")
        if any(pat in uri.lower() for pat in gwt_patterns):
            print "[DEBUG] GWT client code detected:", uri
            raise_gwt_alert(helper, msg, uri)

        # -------------------------------
        # Check 2: External <script> without SRI
        # -------------------------------
        body = msg.getResponseBody().toString() or ""
        if not body:
            return

        script_pattern = re.compile(
            r'<script\s+[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>',
            re.I | re.M
        )

        matches = script_pattern.finditer(body)
        vuln_count = 0

        for match in matches:
            script_tag = match.group(0)
            src = match.group(1).strip()

            if src.startswith(("http://", "https://", "//")):
                has_integrity = re.search(r'\bintegrity\s*=', script_tag, re.I) is not None
                has_crossorigin = re.search(r'\bcrossorigin\s*=', script_tag, re.I) is not None

                if not has_integrity:
                    print "[DEBUG] Missing SRI detected for:", src
                    raise_sri_alert(helper, msg, src, script_tag, has_crossorigin)
                    vuln_count += 1
                else:
                    print "[DEBUG] Script has SRI OK:", src
            else:
                print "[DEBUG] Skipping internal script:", src

        present_summary(uri, vuln_count)

    except Exception as e:
        print "[ERROR] Exception in custom scan:", str(e)
        import traceback
        traceback.print_exc()

# ==================================================
# Alert raisers
# ==================================================
def raise_sri_alert(helper, msg, src, script_tag, has_crossorigin):
    evidence = script_tag if len(script_tag) <= 200 else script_tag[:200] + "..."

    alert = (helper.newAlert()
        .setName("Missing Subresource Integrity (SRI) on External Script")
        .setRisk(2)   # Medium
        .setConfidence(2)
        .setDescription("The application loads an external script without a Subresource Integrity (SRI) attribute. "
                        "Without SRI, compromised third-party scripts may execute malicious code.")
        .setAttack("Missing SRI attribute on: " + src)
        .setEvidence(evidence)
        .setCweId(353)   # CWE-353: Missing Authentication for Critical Function
        .setWascId(15)
        .setMessage(msg)
    )

    crossorigin_note = "" if has_crossorigin else " Also add crossorigin=\"anonymous\"."
    solution = ("Add integrity attribute with a valid hash, e.g.: "
                "<script src=\"%s\" integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>."
                % src) + crossorigin_note

    alert.setSolution(solution)
    alert.raise()

def raise_gwt_alert(helper, msg, uri):
    alert = (helper.newAlert()
        .setName("Unauthenticated Access to Client GWT Code Base")
        .setRisk(2)   # Medium
        .setConfidence(2)
        .setDescription("The application exposes Google Web Toolkit (GWT) client-side code "
                        "(.nocache.js, .cache.js, deferred fragments). "
                        "These files may leak service/method information, aiding attackers in enumeration.")
        .setAttack("Direct access to: " + uri)
        .setEvidence(uri)
        .setCweId(200)   # CWE-200: Information Exposure
        .setWascId(13)
        .setMessage(msg)
    )
    alert.setSolution("Restrict access to GWT permutation and fragment files. "
                      "Ensure these resources are not exposed to unauthenticated users.")
    alert.raise()

# ==================================================
# Summary Presenter
# ==================================================
def present_summary(uri, count):
    print "============================"
    print "[SUMMARY] Custom Scan Results"
    print "Target:", uri
    if count > 0:
        print "Vulnerable external scripts (missing SRI):", count
    else:
        print "No missing SRI issues detected."
    print "============================"
