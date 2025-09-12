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
        # Only scan HTML
        if not msg.getResponseHeader().isHtml():
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

            # Skip non-http(s) or inline-like
            lower_src = src_attr.strip().lower()
            if lower_src.startswith(("data:", "blob:", "javascript:")):
                continue

            # Assume internal unless proven external
            is_external = False
            full_url = src_attr

            # Handle protocol-relative URLs like //cdn.example.com/file.js
            if src_attr.startswith("//"):
                full_url = base_url.getProtocol() + ":" + src_attr

            try:
                parsed = URL(full_url)
                parsed_host = parsed.getHost()
                # If host exists and differs, treat as external
                if parsed_host and parsed_host != base_url.getHost():
                    is_external = True
            except:
                # Relative path or invalid URL → treat as internal
                is_external = False

            if is_external:
                # Raise ZAP alert
                pscan.raiseAlert(
                    2,  # Risk: Medium
                    2,  # Confidence: High
                    "Missing Subresource Integrity-SRI (CUSTOM)",
                    "An external JavaScript resource is loaded without an 'integrity' attribute. "
                    "This makes the application vulnerable to supply chain attacks if the external resource is compromised.",
                    msg.getRequestHeader().getURI().toString(),  # URI
                    src_attr,  # Param
                    "",  # Attack
                    "Script tag: " + script_tag,  # Other info
                    "Ensure that external scripts include 'integrity' and 'crossorigin' attributes to enable Subresource Integrity (SRI).",
                    script_tag,  # Evidence
                    345,  # CWE
                    15,   # WASC
                    msg   # Message
                )

    except:
        # Suppress any error that would disable the script
        pass
