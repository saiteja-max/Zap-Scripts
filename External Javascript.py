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
        print "[DEBUG] Script loaded successfully, starting scan for:", uri

        # Only analyze HTTP(S) responses
        if not uri.lower().startswith("http"):
            return

        body = msg.getResponseBody().toString()
        content_type = msg.getResponseHeader().getHeader("Content-Type") or ""
        
        # Only scan HTML pages
        if "text/html" not in content_type.lower():
            print "[DEBUG] Skipping non-HTML content type:", content_type
            return

        print "[DEBUG] Scanning HTML content for SRI issues..."

        # Find all script tags with src attributes
        script_pattern = re.compile(r'<script\s+[^>]*src\s*=\s*["\']([^"\']+)["\'][^>]*>', re.I | re.M)
        script_matches = script_pattern.finditer(body)
        
        vulnerability_count = 0
        
        for match in script_matches:
            script_tag = match.group(0)
            src = match.group(1)
            
            # Check if it's external (http, https, or protocol-relative)
            is_external = src.startswith(('http://', 'https://', '//'))
            
            if is_external:
                # Check if integrity attribute is missing
                has_integrity = 'integrity=' in script_tag.lower()
                
                if not has_integrity:
                    print "[DEBUG] VULNERABILITY FOUND: External script without SRI ->", src
                    self.raise_alert(helper, msg, param, src, script_tag)
                    vulnerability_count += 1
                else:
                    print "[DEBUG] Script has SRI (OK):", src
            else:
                print "[DEBUG] Internal script (skipping):", src

        print "[DEBUG] Scan completed. Found", vulnerability_count, "vulnerabilities."

    except Exception as e:
        print "[ERROR] Exception in Active Scan rule:", str(e)
        import traceback
        traceback.print_exc()

def raise_alert(self, helper, msg, param, src, script_tag):
    """Helper method to raise alerts for SRI issues"""
    evidence = script_tag[:100] + "..." if len(script_tag) > 100 else script_tag
    
    alert = (helper.newAlert()
        .setName("External JavaScript without SRI")
        .setRisk(2)  # Medium
        .setConfidence(2)  # Medium
        .setDescription("The application loads an external script without Subresource Integrity (SRI) attribute. This allows potential manipulation of third-party scripts leading to supply chain attacks.")
        .setParam(param)
        .setAttack("Missing SRI attribute on: " + src)
        .setEvidence(evidence)
        .setCweId(353)
        .setWascId(15)
        .setMessage(msg))
    
    alert.setSolution("Add integrity attribute: <script src='" + src + "' integrity='sha384-...' crossorigin='anonymous'></script>")
    alert.raise()

def scanNode(helper, msg):
    """Required by ZAP - delegate to scan method"""
    scan(helper, msg, None, None)
