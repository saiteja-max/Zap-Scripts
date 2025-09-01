"""
Passive Scan Rule (Jython) - Detect <script> tags missing SRI
"""

import re
from java.net import URL

script_pattern = re.compile(
    r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL
)

def scan(pscan, msg, src):
    try:
        if not msg.getResponseHeader().isHtml():
            return

        base_url = URL(msg.getRequestHeader().getURI().toString())
        body = msg.getResponseBody().toString()
        scripts = script_pattern.findall(body)

        if scripts:
            print("[DEBUG] Total external <script> tags found:", len(scripts))

            for src_attr, _ in scripts:
                script_tag_match = re.search(
                    r'<script\b[^>]*src\s*=\s*["\']' + re.escape(src_attr) + r'["\'][^>]*>',
                    body,
                    re.IGNORECASE
                )
                if not script_tag_match:
                    continue

                script_tag = script_tag_match.group(0)

                # Skip if already has integrity
                if re.search(r'\bintegrity\s*=\s*["\']', script_tag, re.IGNORECASE):
                    continue

                # Check if external
                is_external = True
                if src_attr.startswith("/") or src_attr.startswith(base_url.getProtocol() + "://" + base_url.getHost()):
                    is_external = False

                if is_external:
                    print("[ALERT] Missing integrity check on:", src_attr)

                    # Raise ZAP alert
                    pscan.raiseAlert(
                        2,  # Risk: Medium
                        2,  # Confidence: High
                        "Missing Subresource Integrity (SRI) Check",
                        "An external JavaScript resource is loaded without an 'integrity' attribute. "
                        "This makes the application vulnerable to supply chain attacks if the external resource is compromised.",
                        msg.getRequestHeader().getURI().toString(),  # Page URI
                        src_attr,  # Param (external script URL)
                        "",  # Attack (not used here)
                        "Script tag: " + script_tag,  # Other info
                        "Ensure that external scripts include 'integrity' and 'crossorigin' attributes to enable Subresource Integrity (SRI).",
                        script_tag,  # Evidence (the actual script tag)
                        345,  # CWE-345: Insufficient Verification of Data Authenticity
                        15,   # WASC-15: Application Misconfiguration
                        msg   # Original HTTP message
                    )

    except Exception as e:
        import traceback
        print("[ERROR] Passive scan exception:", e)
        traceback.print_exc()
