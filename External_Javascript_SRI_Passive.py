"""
Passive Scan Rule (Jython) - Detect <script> tags missing SRI
"""

import re
from java.net import URL

DEBUG = True

def _debug(msg):
    if DEBUG:
        try:
            print(u"[SRI-Detector] %s" % msg)
        except:
            pass

def scan(pscan, msg, src):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        ctype = msg.getResponseHeader().getHeader("Content-Type") or ""

        # Only check HTML responses
        if "text/html" not in ctype.lower() and not uri.lower().endswith(".html"):
            return

        base_url = URL(uri)
        body = msg.getResponseBody().toString()

        script_pattern = re.compile(
            r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>',
            re.IGNORECASE
        )
        scripts = script_pattern.findall(body)
        if not scripts:
            return

        for src_attr in scripts:
            # Get full script tag
            m = re.search(
                r'<script\b[^>]*src\s*=\s*["\']' + re.escape(src_attr) + r'["\'][^>]*>',
                body,
                re.IGNORECASE
            )
            if not m:
                continue

            script_tag = m.group(0)

            # Skip if integrity present
            if re.search(r'\bintegrity\s*=\s*["\']', script_tag, re.IGNORECASE):
                continue

            # Skip local scripts
            if src_attr.startswith("/") or src_attr.startswith(base_url.getProtocol() + "://" + base_url.getHost()):
                continue

            # Raise alert using builder API
            try:
                alert = pscan.newAlert()
                alert.setRisk(2) \
                     .setConfidence(2) \
                     .setName("Missing Subresource Integrity-SRI (CUSTOM)") \
                     .setDescription(
                         "An external JavaScript resource is loaded without an 'integrity' attribute. "
                         "This makes the application vulnerable to supply chain attacks if the external resource is compromised."
                     ) \
                     .setEvidence(script_tag) \
                     .setParam(src_attr) \
                     .setSolution("Ensure that external scripts include 'integrity' and 'crossorigin' attributes to enable Subresource Integrity (SRI).") \
                     .setReference("https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity") \
                     .setCweId(345) \
                     .setWascId(15) \
                     .setMessage(msg) \
                     .raise()
                _debug("Raised alert for script: %s" % src_attr)
            except Exception as e:
                _debug("ERROR raising alert: %s" % e)

    except Exception as e:
        _debug("Passive scan exception: %s" % e)
