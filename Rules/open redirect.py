"""
Custom Open Redirect Scan Rule for ZAP (Jython).
"""

import random
from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata
from org.apache.commons.httpclient import URI as HttpClientURI

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 40002
name: Open Redirect (Custom Jython Rule)
description: Checks for Open Redirection vulnerabilities by appending payloads to request paths or parameters and analyzing responses.
solution: Validate and sanitize all user-supplied URLs and redirect targets. Use allow-lists of safe domains/paths and avoid directly reflecting user input in redirects.
references:
  - https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards
  - https://portswigger.net/web-security/open-redirection
category: MISC
risk: HIGH
confidence: HIGH
cweId: 601
wascId: 38
alertTags:
  OWASP_2021_A01: Broken Access Control
  OWASP_2017_A10: Unvalidated Redirects and Forwards
otherInfo: Custom script-based Open Redirect detection rule.
status: alpha
""")

# Payload allowlist
PAYLOADS = [
    "://welcome.gsselect.com.example.com/",
    "//evil.example.com/",
    "/\\evil.example.com/",
    "https://evil.example.com"
    "://welcome.gsselect.com.example.com/"
]

def scanNode(helper, msg):
    try:
        uri = msg.getRequestHeader().getURI()
        print("[DEBUG] scanNode() called for:", uri.toString())
    except:
        print("[ERROR] Unable to extract URI from message")
        return

    base_scheme = uri.getScheme()
    base_host = uri.getHost()
    base_port = uri.getPort()
    base_path = uri.getPath() or "/"   # handle None safely

    for payload in PAYLOADS:
        attack_msg = msg.cloneRequest()

        # Build attack URI
        raw_attack_uri = base_scheme + "://" + base_host
        if base_port != -1:
            raw_attack_uri += ":" + str(base_port)
        raw_attack_uri += base_path + "?" + payload

        print("[DEBUG] Raw attack URI:", raw_attack_uri)

        try:
            attack_uri = HttpClientURI(raw_attack_uri, False)
            attack_msg.getRequestHeader().setURI(attack_uri)
            helper.sendAndReceive(attack_msg, False, False)

            location_header = attack_msg.getResponseHeader().getHeader("Location")
            print("[DEBUG] Location header:", location_header)

            # Detection: payload reflected in Location
            if location_header and payload.strip("/") in location_header:
                helper.newAlert() \
                    .setName("Open Redirection (CUSTOM)") \
                    .setRisk(3) \
                    .setConfidence(3) \
                    .setDescription("Open Redirect detected via Location header reflection.") \
                    .setParam("Path") \
                    .setAttack(payload) \
                    .setEvidence(location_header) \
                    .setCweId(601) \
                    .setWascId(38) \
                    .setMessage(attack_msg) \
                    .raise()
                print("[DEBUG] ALERT RAISED: Payload found in Location header")

        except Exception as e:
            print("[ERROR] Exception while sending:", str(e))


def scan(helper, msg, param, value):
    # Optional: param-based redirects
    return
