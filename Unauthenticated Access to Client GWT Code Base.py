"""
Unauthenticated Access to Client GWT Code Base Detection (Custom Jython Active Rule).
"""

import re
import urllib2
import traceback
from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata


def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 4000306
name: Unauthenticated Access to Client GWT Code Base
category: MISC
description: Detects unauthenticated access to client-side GWT code base which may expose sensitive methods and services.
cweId: 639
wascId: 2
""")


def scan(ascan, msg, param, value):
    try:
        url = msg.getRequestHeader().getURI().toString()
        if not (url.endswith(".nocache.js") or url.endswith(".cache.js")):
            return

        ascan.getLogger().info("[DEBUG] Scanning GWT file: " + url)
        response = fetch(url)
        if not response:
            return

        R_VAR = "[a-zA-Z][a-zA-Z0-9_]*"
        frag_patterns = [
            re.compile("^" + R_VAR + "\\.runAsyncCallback.*"),
            re.compile("^" + R_VAR + "\\.onSuccess.*"),
            re.compile("^" + R_VAR + "\\.AsyncCallback.*"),
            re.compile("^" + R_VAR + "\\.Callback.*")
        ]

        vulnerable = False
        for pattern in frag_patterns:
            if pattern.search(response):
                vulnerable = True
                break

        if vulnerable:
            try:
                ascan.raiseAlert(
                    3,  # Risk: High
                    2,  # Confidence: Medium
                    "Unauthenticated Access to Client GWT Code Base",
                    "The application exposes GWT client-side code base which may reveal sensitive classes, methods, and services.",
                    url,
                    param,
                    value,
                    response[0:200],
                    "Review and restrict public access to GWT .nocache.js/.cache.js files.",
                    "Ensure proper authentication and limit exposure of GWT code base.",
                    639,
                    2,
                    msg
                )
            except Exception as ae:
                ascan.getLogger().warn("[ERROR] Failed to raise alert:\n" + traceback.format_exc())

    except Exception as e:
        ascan.getLogger().warn("[ERROR] Exception in scan():\n" + traceback.format_exc())


def fetch(url):
    try:
        req = urllib2.Request(url)
        resp = urllib2.urlopen(req, timeout=10)
        if "text" in resp.headers.get("Content-Type", ""):
            return resp.read()
    except Exception:
        import traceback
        print("[ERROR] Exception in fetch():\n" + traceback.format_exc())
        return None
    return None
