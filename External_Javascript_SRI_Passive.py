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
        content_type = msg.getResponseHeader().getHeader("Content-Type")
        if not content_type or "text/html" not in content_type.lower():
            return

        base_url = URL(msg.getRequestHeader().getURI().toString())
        body = msg.getResponseBody().toString()
        scripts = script_pattern.findall(body)

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

            # Skip if local script
            if src_attr.startswith("/") or src_attr.startswith(base_url.getProtocol() + "://" + base_url.getHost()):
                continue

            pscan.raiseAlert(
                2,  # Risk: Medium
                2,  # Confidence: High
                "Missing Subresource Integrity-SRI (CUSTOM)",
                "An external JavaScript resource is loaded without an 'integrity' attribute. "
                "This makes the application vulnerable to supply chain attacks if the external resource is compromised.",
                msg.getRequestHeader().getURI().toString(),
                src_attr,
                "",
                "Script tag: " + script_tag,
                "Ensure that external scripts include 'integrity' and 'crossorigin' attributes to enable Subresource Integrity (SRI).",
                script_tag,
                345,
                15,
                msg
            )

    except Exception as e:
        pscan.println("[ERROR] Passive scan exception: " + str(e))
