"""
Passive Scan Rule (Jython) - Detect <script> tags missing SRI
"""

import re
from java.net import URL

script_pattern = re.compile(
    r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>(?:.*?)</script>',
    re.IGNORECASE | re.DOTALL
)

# detect valid integrity token (sha256/384/512 followed by base64)
integrity_token_re = re.compile(r'sha(?:256|384|512)-[A-Za-z0-9+/=]+')

def _effective_port(url):
    p = url.getPort()
    if p != -1:
        return p
    proto = url.getProtocol().lower()
    if proto == "http":
        return 80
    if proto == "https":
        return 443
    # fallback if unknown scheme
    return -1

def _same_origin(url1, url2):
    try:
        return (url1.getProtocol().lower() == url2.getProtocol().lower()
                and url1.getHost().lower() == url2.getHost().lower()
                and _effective_port(url1) == _effective_port(url2))
    except:
        return False

def scan(pscan, msg, src):
    try:
        if not msg.getResponseHeader().isHtml():
            return

        base_url = URL(msg.getRequestHeader().getURI().toString())
        body = msg.getResponseBody().toString()
        scripts = script_pattern.findall(body)

        if scripts:
            print("[DEBUG] Total external <script> tag candidates found:", len(scripts))

            for src_attr in [s[0] if isinstance(s, tuple) else s for s in scripts]:
                # skip "inline" (shouldn't be present since we matched src) but keep safe
                if not src_attr or src_attr.strip() == "":
                    continue

                src_attr = src_attr.strip()

                # ignore javascript:, data:, blob: etc.
                lower_src = src_attr.lower()
                if lower_src.startswith("javascript:") or lower_src.startswith("data:") or lower_src.startswith("blob:"):
                    print("[DEBUG] Skipping non-http src:", src_attr)
                    continue

                # Resolve protocol-relative URLs and relative URLs against base
                try:
                    # If it's protocol-relative like //cdn..., URL(base, src) handles it for Java
                    abs_url = URL(base_url, src_attr)
                except Exception as e:
                    # If URL can't be parsed, skip it (avoid false positives)
                    print("[DEBUG] Could not resolve URL for src '%s': %s" % (src_attr, e))
                    continue

                # Determine if same-origin. If same origin -> do not flag (SRI is only meaningful for cross-origin resources)
                if _same_origin(base_url, abs_url):
                    print("[DEBUG] Same-origin script, skipping:", abs_url.toString())
                    continue

                # Find the specific script tag (the first one matching this src) to inspect attributes
                script_tag_match = re.search(
                    r'<script\b[^>]*\bsrc\s*=\s*["\']' + re.escape(src_attr) + r'["\'][^>]*>',
                    body,
                    re.IGNORECASE
                )
                if not script_tag_match:
                    # fallback: try matching by resolved absolute URL in case the page uses absolute URLs in HTML
                    script_tag_match = re.search(
                        r'<script\b[^>]*\bsrc\s*=\s*["\']' + re.escape(abs_url.toString()) + r'["\'][^>]*>',
                        body,
                        re.IGNORECASE
                    )
                    if not script_tag_match:
                        print("[DEBUG] Could not locate script tag text for src:", src_attr)
                        continue

                script_tag = script_tag_match.group(0)

                # Check integrity attribute existence and validity
                integrity_match = re.search(r'\bintegrity\s*=\s*["\']([^"\']+)["\']', script_tag, re.IGNORECASE)
                has_valid_integrity = False
                if integrity_match:
                    integrity_val = integrity_match.group(1).strip()
                    if integrity_val and integrity_token_re.search(integrity_val):
                        has_valid_integrity = True

                if not has_valid_integrity:
                    print("[ALERT] Missing/invalid integrity on external script:", abs_url.toString())

                    # Raise ZAP alert
                    pscan.raiseAlert(
                        2,  # Risk: Medium
                        2,  # Confidence: High
                        "Missing or invalid Subresource Integrity (SRI) for external script (CUSTOM)",
                        ("This page loads an external JavaScript resource without a valid 'integrity' attribute. "
                         "Without SRI, the integrity of the fetched resource can't be guaranteed and the page "
                         "is vulnerable to supply-chain compromises."),
                        msg.getRequestHeader().getURI().toString(),  # Page URI
                        abs_url.toString(),  # Param (external script URL)
                        "",  # Attack (not used here)
                        "Script tag: " + script_tag,  # Other info
                        "Add a valid 'integrity' attribute (e.g. sha384-...) and 'crossorigin' when loading cross-origin scripts.",
                        script_tag,  # Evidence (the actual script tag)
                        345,  # CWE-345 (Insufficient Verification of Data Authenticity) or choose CWE-1021 if you prefer
                        15,   # WASC-15: Application Misconfiguration
                        msg   # Original HTTP message
                    )

    except Exception as e:
        import traceback
        print("[ERROR] Passive scan exception:", e)
        traceback.print_exc()
