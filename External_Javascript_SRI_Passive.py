"""
Passive Scan Rule (Jython) - Detect <script> tags missing/invalid SRI
"""

import re
from java.net import URL

script_pattern = re.compile(
    r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>(?:.*?)</script>',
    re.IGNORECASE | re.DOTALL
)

integrity_token_re = re.compile(r'sha(?:256|384|512)-[A-Za-z0-9+/=]+')

def _effective_port(url):
    p = url.getPort()
    if p != -1:
        return p
    proto = url.getProtocol().lower()
    return 80 if proto == "http" else 443 if proto == "https" else -1

def _same_origin(url1, url2):
    try:
        return (url1.getProtocol().lower() == url2.getProtocol().lower()
                and url1.getHost().lower() == url2.getHost().lower()
                and _effective_port(url1) == _effective_port(url2))
    except:
        return False

def scan(msg, src):
    try:
        if not msg.getResponseHeader().isHtml():
            return

        base_url = URL(msg.getRequestHeader().getURI().toString())
        body = msg.getResponseBody().toString()
        scripts = script_pattern.findall(body)

        if scripts:
            for src_attr in [s[0] if isinstance(s, tuple) else s for s in scripts]:
                if not src_attr or src_attr.strip() == "":
                    continue

                src_attr = src_attr.strip().lower()
                if src_attr.startswith(("javascript:", "data:", "blob:")):
                    continue

                try:
                    abs_url = URL(base_url, src_attr)
                except:
                    continue

                if _same_origin(base_url, abs_url):
                    continue

                script_tag_match = re.search(
                    r'<script\b[^>]*\bsrc\s*=\s*["\']' + re.escape(src_attr) + r'["\'][^>]*>',
                    body, re.IGNORECASE
                )
                if not script_tag_match:
                    continue

                script_tag = script_tag_match.group(0)

                integrity_match = re.search(r'\bintegrity\s*=\s*["\']([^"\']+)["\']',
                                            script_tag, re.IGNORECASE)
                has_valid_integrity = False
                if integrity_match:
                    integrity_val = integrity_match.group(1).strip()
                    if integrity_val and integrity_token_re.search(integrity_val):
                        has_valid_integrity = True

                if not has_valid_integrity:
                    raiseAlert(
                        2,  # Risk: Medium
                        2,  # Confidence: High
                        "Missing or invalid Subresource Integrity (SRI) for external script (CUSTOM)",
                        ("This page loads an external JavaScript resource without a valid 'integrity' attribute. "
                         "Without SRI, integrity of the fetched resource can't be guaranteed."),
                        msg.getRequestHeader().getURI().toString(),
                        abs_url.toString(),
                        "",
                        "Script tag: " + script_tag,
                        "Add a valid 'integrity' (sha256/384/512) and 'crossorigin' attribute.",
                        script_tag,
                        345,
                        15,
                        msg
                    )

    except Exception as e:
        import traceback
        print("[ERROR] Passive scan exception:", e)
        traceback.print_exc()
