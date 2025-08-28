"""
Unauthenticated Access to Client GWT Code Base Detection (Custom Jython Active Rule).
"""

import re
import urllib2
import traceback
from java.lang import Throwable
from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata


def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 4000302
name: Unauthenticated Access to Client GWT Code Base
category: Injection
description: Detects unauthenticated access to client-side GWT code base which may expose sensitive methods and services.
cweId: 639
wascId: 2
""")


def log_full_exception(ascan, e, context=""):
    try:
        # Log error summary
        ascan.getLogger().error("[ERROR] Exception in %s: %s" % (context, str(e)))

        # Python traceback if Jython triggered it
        try:
            tb = traceback.format_exc()
            if tb:
                ascan.getLogger().error("[PYTHON TRACEBACK]\n" + tb)
        except:
            pass

        # If it's a Java exception, unwrap recursively
        if isinstance(e, Throwable):
            cause = e
            depth = 0
            while cause is not None and depth < 5:  # limit depth
                ascan.getLogger().error("[JAVA Exception][depth=%d] %s" % (depth, str(cause)))
                cause.printStackTrace()  # Full Java stack trace to ZAP logs
                cause = cause.getCause()
                depth += 1
    except Exception as le:
        print("[FATAL LOGGER ERROR] Could not log exception: %s" % str(le))


def scan(ascan, msg, param, value):
    try:
        url = msg.getRequestHeader().getURI().toString()
        if not (url.endswith(".nocache.js") or url.endswith(".cache.js")):
            return

        ascan.getLogger().info("[DEBUG] Scanning GWT file: " + url)
        response = fetch(ascan, url)
        if not response:
            return

        R_VAR = "[a-zA-Z][a-zA-Z0-9_]*"
        frag_patterns = [
            re.compile("^" + R_VAR + "\\.runAsyncCallback.*"),
            re.compile("^" + R_VAR + "\\.onSuccess.*"),
            re.compile("^" + R_VAR + "\\.AsyncCallback.*"),
            re.compile("^" + R_VAR + "\\.Callback.*")
        ]

        vulnerable = any(pattern.search(response) for pattern in frag_patterns)

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
                log_full_exception(ascan, ae, "raiseAlert()")

    except Exception as e:
        log_full_exception(ascan, e, "scan()")


def fetch(ascan, url):
    try:
        req = urllib2.Request(url)
        resp = urllib2.urlopen(req, timeout=10)
        if "text" in resp.headers.get("Content-Type", ""):
            return resp.read()
    except Exception as e:
        log_full_exception(ascan, e, "fetch()")
        return None
    return None
