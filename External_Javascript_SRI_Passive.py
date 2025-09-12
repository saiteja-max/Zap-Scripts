"""
Passive Scan Rule (Jython 2.7) - External JS without SRI
"""

import re
from java.net import URL
from org.parosproxy.paros.model import HistoryReference

DEBUG = True

# Regex to match <script src="...">
SCRIPT_PATTERN = re.compile(
    r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>',
    re.IGNORECASE
)

# ------------------------------------------------------
# History types this script should run on
# ------------------------------------------------------
def appliesToHistoryType(historyType):
    try:
        return historyType in [
            HistoryReference.TYPE_PROXIED,
            HistoryReference.TYPE_SPIDER,
            HistoryReference.TYPE_SPIDER_AJAX
        ]
    except:
        return True  # fallback if ZAP internals change


# ------------------------------------------------------
# Debug printing
# ------------------------------------------------------
def _debug(msg):
    if DEBUG:
        try:
            print("[SRI-Detector] %s" % msg)
        except:
            pass


# ------------------------------------------------------
# Passive Scan Main
# ------------------------------------------------------
def scan(ps, msg, src):
    try:
        if not msg.getResponseHeader().isHtml():
            return

        body = msg.getResponseBody().toString()
        base_url = URL(msg.getRequestHeader().getURI().toString())

        scripts = SCRIPT_PATTERN.findall(body)
        if not scripts:
            return

        for src_attr in scripts:
            # Ignore relative or same-origin scripts
            if (src_attr.startswith("/") or
                src_attr.startswith(base_url.getProtocol() + "://" + base_url.getHost())):
                continue

            # Only flag if remote (absolute external URL with domain)
            if not (src_attr.startswith("http://") or src_attr.startswith("https://")):
                continue

            # Extract full script tag
            m = re.search(
                r'<script\b[^>]*src\s*=\s*["\']' + re.escape(src_attr) + r'["\'][^>]*>',
                body, re.IGNORECASE
            )
            if not m:
                continue
            script_tag = m.group(0)

            # Skip if integrity attribute already present
            if re.search(r'\bintegrity\s*=\s*["\']', script_tag, re.IGNORECASE):
                continue

            # Raise alert
            alert = ps.newAlert()
            alert.setRisk(2)  # Medium
            alert.setConfidence(2)  # High
            alert.setName("Missing Subresource Integrity (SRI) on External Script (CUSTOM)")
            alert.setDescription(
                "An external JavaScript resource is loaded without an 'integrity' attribute. "
                "This makes the application vulnerable to supply chain attacks if the external resource is compromised."
            )
            alert.setEvidence(script_tag)
            alert.setParam(src_attr)
            alert.setOtherInfo("Script tag without SRI: %s" % script_tag)
            alert.setSolution(
                "Ensure all external scripts include 'integrity' and 'crossorigin' attributes to enable Subresource Integrity (SRI)."
            )
            alert.setReference("https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity")
            alert.setCweId(345)  # Insufficient Verification of Data Authenticity
            alert.setWascId(15)  # Application Misconfiguration
            alert.setMessage(msg)
            alert.raiseAlert()

            _debug("Raised alert for external script missing SRI: %s" % src_attr)

    except Exception as e:
        _debug("Passive scan exception: %s" % e)
