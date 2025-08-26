""" 
Custom External JavaScript without SRI Active Scan Rule for ZAP (Jython).
Enhanced to detect dynamically loaded scripts and DOM-based SRI issues.
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
        response_headers = msg.getResponseHeader().toString()

        # Check 1: Look for script tags in HTML source
        pattern = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"'][^>]*>", re.I)
        found_vulnerabilities = False
        
        for match in pattern.finditer(body):
            src = match.group(1)
            script_tag = match.group(0)

            # Check if it's external and missing integrity
            if (src.startswith("http") or src.startswith("//")) and "integrity=" not in script_tag.lower():
                self.raise_alert(helper, msg, param, src, script_tag)
                found_vulnerabilities = True
                print "[DEBUG] ALERT RAISED: Missing SRI on external script ->", src

        # Check 2: Look for JavaScript code that might dynamically load scripts without SRI
        # Common patterns for dynamic script loading
        dynamic_patterns = [
            r"document\.createElement\(['\"]script['\"]\)",
            r"\.src\s*=\s*[^;]+;",
            r"appendChild\([^)]*script[^)]*\)",
            r"new\s+Script\([^)]*\)",
            r"\$\.getScript\([^)]*\)",
            r"loadJS\([^)]*\)",
            r"injectScript\([^)]*\)"
        ]
        
        for pattern_str in dynamic_patterns:
            if re.search(pattern_str, body, re.I):
                print "[DEBUG] Found potential dynamic script loading code"
                # If we find dynamic loading code, we should alert about potential SRI issues
                if not found_vulnerabilities:
                    self.raise_generic_alert(helper, msg, param, "Dynamic script loading detected without explicit SRI checks")
                    print "[DEBUG] ALERT RAISED: Dynamic script loading without explicit SRI checks"
                break

        # Check 3: Look for common CDN URLs that should have SRI
        common_cdns = [
            "cdnjs.cloudflare.com",
            "ajax.googleapis.com",
            "code.jquery.com",
            "maxcdn.bootstrapcdn.com",
            "cdn.jsdelivr.net",
            "unpkg.com",
            "stackpath.bootstrapcdn.com",
            "assets.adobedtm.com"  # Specifically for the Adobe DTM in your example
        ]
        
        for cdn in common_cdns:
            if cdn in body and "integrity=" not in body.lower():
                cdn_pattern = re.compile(r"<script[^>]+src=[\"'][^\"']*" + re.escape(cdn) + r"[^\"']*[\"'][^>]*>", re.I)
                if cdn_pattern.search(body):
                    print "[DEBUG] Found", cdn, "URL without SRI"
                    if not found_vulnerabilities:
                        self.raise_alert(helper, msg, param, cdn + " script", "CDN script without integrity")
                        print "[DEBUG] ALERT RAISED: Common CDN script without SRI ->", cdn

    except Exception as e:
        print "[ERROR] Exception in Active Scan rule:", str(e)

def raise_alert(self, helper, msg, param, src, script_tag):
    evidence = script_tag.strip()[:200] if isinstance(script_tag, basestring) else "External script without SRI"
    
    alert = (helper.newAlert()
        .setName("External JavaScript without SRI")
        .setRisk(2)
        .setConfidence(2)
        .setDescription("The application loads an external script without an SRI attribute. Without SRI, tampered CDN or third-party scripts may lead to supply-chain compromise.")
        .setParam(param)
        .setAttack("Missing SRI on external script: " + src)
        .setEvidence(evidence)
        .setCweId(353)
        .setWascId(15)
        .setMessage(msg))
    
    alert.setSolution("Add integrity and crossorigin attributes: <script src='" + src + "' integrity='sha384-...' crossorigin='anonymous'></script>")
    alert.raise()

def raise_generic_alert(self, helper, msg, param, reason):
    alert = (helper.newAlert()
        .setName("Potential SRI Bypass via Dynamic Script Loading")
        .setRisk(2)
        .setConfidence(1)  # Lower confidence for potential issues
        .setDescription("The application contains code that dynamically loads scripts, which may bypass SRI protections if not properly implemented.")
        .setParam(param)
        .setAttack(reason)
        .setEvidence("Dynamic script loading code detected")
        .setCweId(353)
        .setWascId(15)
        .setMessage(msg))
    
    alert.setSolution("Ensure all dynamically loaded scripts include SRI integrity checks programmatically.")
    alert.raise()

def scanNode(helper, msg):
    # Active scan script requires scanNode() but we delegate to scan()
    scan(helper, msg, None, None)
