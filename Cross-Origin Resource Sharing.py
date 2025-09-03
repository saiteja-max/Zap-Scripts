"""
Custom CORS Misconfiguration Active Scan Rule for ZAP (Jython).
"""

from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 93892
name: CORS Misconfiguration Detection (Custom Jython Active Rule)
description: Detects common CORS misconfigurations such as wildcard origins, reflected origins, and unsafe combinations with credentials.
solution: Restrict Access-Control-Allow-Origin to trusted domains. Avoid using '*' with Access-Control-Allow-Credentials. Ensure only explicitly trusted origins are allowed.
references:
  - https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
category: MISC
risk: MEDIUM
confidence: MEDIUM
cweId: 942
wascId: 14
alertTags:
  OWASP_2021_A05: Security Misconfiguration
  OWASP_2017_A06: Security Misconfiguration
otherInfo: Custom script-based detection of CORS misconfigurations in HTTP responses.
status: beta
""")

# ------------ CONFIGURATION ------------
WHITELIST = [
    "trusted.example.com",
    "static.cdn.example",
    "localhost",
    "127.0.0.1"
]

ATTACKER_ORIGINS = [
    "http://evil.example",
    "http://attacker.com",
    "null"
]
# ---------------------------------------

def is_whitelisted(host):
    if not host:
        return False
    host = host.lower()
    for w in WHITELIST:
        w = w.lower()
        # exact match or subdomain match
        if host == w or host.endswith("." + w.lstrip("*.")):
            return True
    return False

def raise_alert(helper, attack, name, desc, risk, evidence, param=None, origin=None):
    (helper.newAlert()
        .setName(name)
        .setRisk(risk)   # 0=Info, 1=Low, 2=Medium, 3=High
        .setConfidence(2)  # Medium
        .setDescription(desc)
        .setParam(param if param else "")
        .setAttack(origin if origin else "")
        .setEvidence(evidence)
        .setCweId(942)
        .setWascId(14)
        .setMessage(attack)
        .raise())

def scanNode(helper, msg):
    try:
        uri = msg.getRequestHeader().getURI()
        host = uri.getHost()

        if is_whitelisted(host):
            print("[CORS-SCAN] Skipping whitelisted host:", host)
            return

        for origin in ATTACKER_ORIGINS:
            attack = msg.cloneRequest()
            attack.getRequestHeader().setHeader("Origin", origin)

            helper.sendAndReceive(attack, False)
            resp = attack.getResponseHeader()

            acao = resp.getHeader("Access-Control-Allow-Origin")
            acac = resp.getHeader("Access-Control-Allow-Credentials")

            if not acao:
                continue

            # Condition 1: ACAO * + credentials
            if acao == "*" and acac and acac.lower() == "true":
                raise_alert(
                    helper, attack,
                    "CORS Misconfiguration: ACAO * with Credentials (CUSTOM)",
                    "The server responds with Access-Control-Allow-Origin: * and also allows credentials. "
                    "This exposes sensitive responses to any origin.",
                    3,
                    "ACAO: * ; ACAC: true",
                    origin=origin
                )
                continue

            # Condition 2: Reflected Origin
            if acao.lower() == origin.lower():
                risk = 2
                desc = "The server reflects the Origin in ACAO, which can allow attacker-controlled domains."
                if acac and acac.lower() == "true":
                    risk = 3
                    desc += " With credentials enabled, this is a critical issue."
                raise_alert(
                    helper, attack,
                    "CORS Misconfiguration: Reflected Origin (CUSTOM)",
                    desc,
                    risk,
                    "ACAO: %s ; ACAC: %s" % (acao, acac),
                    origin=origin
                )
                continue

            # Condition 3: Null Origin accepted
            if origin == "null" and (acao == "null" or acao == "*"):
                raise_alert(
                    helper, attack,
                    "CORS Misconfiguration: Accepts Null Origin (CUSTOM)",
                    "The server allows 'null' as an origin. This can be abused via sandboxed iframes or file:// contexts.",
                    2,
                    "Origin: null ; ACAO: %s" % acao,
                    origin=origin
                )
                continue

            # Condition 4: ACAO * (low informational)
            if acao == "*":
                raise_alert(
                    helper, attack,
                    "CORS Misconfiguration: Wildcard Origin (CUSTOM)",
                    "The server responds with Access-Control-Allow-Origin: *. "
                    "While not always exploitable, this may expose sensitive endpoints if combined with cookies or tokens.",
                    1,
                    "ACAO: *",
                    origin=origin
                )

    except Exception as e:
        print("[CORS-SCAN][ERROR] Exception in CORS Active Scan rule:", str(e))


def scan(helper, msg, param, value):
    # Not used; all logic runs in scanNode
    pass
