"""
Client-side Google Web Toolkit (GWT) Detector (Passive Scan, Jython 2.7)

- Only checks .html and .js responses (by content-type and URL extension).
- Flags GWT bootstrap and compiled artifacts like .nocache.js, .cache.js, .cache.html.
- Detects DevMode usage (gwt.codesvr, __gwt_codeServerPort).
- Prints debug logs to ZAP output for traceability.
"""

from org.parosproxy.paros.network import HttpMessage
from org.parosproxy.paros.core.scanner import Alert
from java.util import Arrays

DEBUG = True
MAX_BYTES = 2 * 1024 * 1024  # safeguard large responses

# Risk/Confidence
RISK_INFO, RISK_LOW, RISK_MED, RISK_HIGH = 0, 1, 2, 3
CONFIDENCE_LOW, CONFIDENCE_MED, CONFIDENCE_HIGH = 1, 2, 3

# Regex patterns for GWT artifacts
PATTERNS = [
    (r'(?:^|[^A-Za-z0-9_])gwt\.codesvr\s*=', 
     u"GWT DevMode Parameter Detected (gwt.codesvr)",
     u"Indicates GWT DevMode/CodeServer enabled. Should not appear in production.",
     RISK_MED, CONFIDENCE_MED),

    (r'__gwt_codeServerPort',
     u"GWT DevMode CodeServer Port Variable",
     u"Found '__gwt_codeServerPort', used for GWT DevMode debugging.",
     RISK_MED, CONFIDENCE_MED),

    (r'\.nocache\.js\b',
     u"GWT Bootstrap Script (.nocache.js)",
     u"GWT bootstrap script detected. Confirms GWT client usage.",
     RISK_LOW, CONFIDENCE_MED),

    (r'\.cache\.(?:js|html)\b',
     u"GWT Compiled Artifact (.cache.js/.cache.html)",
     u"GWT compiled permutation artifact detected. Confirms GWT client usage.",
     RISK_LOW, CONFIDENCE_MED),

    (r'\b(?:__gwt_onLoad|gwtOnLoad)\b',
     u"GWT Bootstrap Function Detected",
     u"GWT bootstrap onLoad function found.",
     RISK_INFO, CONFIDENCE_MED),

    (r'\b__gwt_jsonp__\b',
     u"GWT JSONP Callback Detected",
     u"GWT JSONP callback '__gwt_jsonp__' found.",
     RISK_INFO, CONFIDENCE_MED),

    (r'\bcom\.google\.gwt\b',
     u"GWT Namespace Reference",
     u"Reference to 'com.google.gwt' found, suggesting GWT client code.",
     RISK_INFO, CONFIDENCE_MED),
]

def _debug(msg):
    if DEBUG:
        try:
            print(u"[GWT-Detector] %s" % msg)
        except:
            pass

def _first_snippet(body, offset, radius=80):
    start = max(0, offset - radius)
    end = min(len(body), offset + radius)
    return body[start:end].replace(u"\r", u" ").replace(u"\n", u" ")

def _raise(pscan, msg, name, desc, evidence, risk, confidence):
    try:
        alert = pscan.newAlert()
        alert.setRisk(risk)\
             .setConfidence(confidence)\
             .setName(name)\
             .setDescription(desc)\
             .setEvidence(evidence)\
             .setParam(msg.getRequestHeader().getURI().toString())\
             .setSolution(u"Remove DevMode flags, avoid exposing debug builds, ensure no secrets in bundles.")\
             .setReference(u"https://www.gwtproject.org/")\
             .setCweId(200)\
             .setWascId(13)\
             .setMessage(msg)\
             .raise()
        _debug(u"Raised alert: %s | risk=%d | evidence=%s" % (name, risk, evidence))
    except Exception as e:
        _debug(u"ERROR raising alert: %s" % e)

def scan(pscan, msg, src):
    try:
        uri = msg.getRequestHeader().getURI().toString().lower()
        ctype = msg.getResponseHeader().getHeader("Content-Type") or ""

        # Only check HTML/JS responses
        if not (".html" in uri or ".js" in uri or "text/html" in ctype or "javascript" in ctype):
            _debug(u"Skipping non-HTML/JS: %s" % uri)
            return

        body = msg.getResponseBody().toString()
        if not body:
            return
        if len(body) > MAX_BYTES:
            body = body[:MAX_BYTES]

        import re
        for (pattern, name, desc, risk, confidence) in PATTERNS:
            for m in re.finditer(pattern, body, flags=re.IGNORECASE):
                ev = _first_snippet(body, m.start())
                _raise(pscan, msg, name, desc, ev, risk, confidence)

        _debug(u"Scan done for: %s" % uri)

    except Exception as e:
        _debug(u"Passive scan exception: %s" % e)
