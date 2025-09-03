"""
Custom CORS Misconfiguration Active Scan Rule for ZAP (Jython).
"""

from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 6000002
name: CORS Misconfiguration Detection (Custom Jython Active Rule)
description: Detects common CORS misconfigurations such as wildcard origins, reflected origins, and unsafe combinations with credentials.
solution: Restrict Access-Control-Allow-Origin to trusted domains. Avoid using '*' with Access-Control-Allow-Credentials. Always return 'Vary: Origin' when dynamic ACAO values are used.
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
status: alpha
""")

# ------------ CONFIGURATION ------------
# Domains to skip from detection (trusted/whitelist)
WHITELIST = [
    "trusted.example.com",
    "static.cdn.example",
    "localhost",
    "127.0.0.1"
]

# Origins to test against the server
ATTACKER_ORIGINS = [
    "http://evil.example",
    "http://attacker.com",
    "null"
]
# ---------------------------------------

def is_whitelisted(host):
    if host is None:
        return False
    for w in WHITELIST:
        if w.lower() in host.lower():
            return True
    return False

def scan(helper, msg, param, value):
    try:
        uri = msg.getRequestHeader().getURI()
        host = uri.getHost()

        if is_whitelisted(host):
            print("[DEBUG] Skipping whitelisted host:", host)
            return

        for origin in ATTACKER_ORIGINS:
            attack = msg.cloneRequest()
            attack.getRequestHeader().setHeader("Origin", origin)

            helper.sendAndReceive(attack, False)
            resp = attack.getResponseHeader()

            acao = resp.getHeader("Access-Control-Allow-Origin")
            acac = resp.getHeader("Access-Control-Allow-Credentials")
            vary = resp.getHeader("Vary")

            # Condition 1: ACAO * + credentials
            if acao == "*" and acac and acac.lower() == "true":
                (helper.newAlert()
                    .setName("CORS Misconfiguration: ACAO * with Credentials (CUSTOM)")
                    .setRisk(3)   # High
                    .setConfidence(2)
                    .setDescription("The server responds with Access-Control-Allow-Origin: * and also allows credentials. This exposes sensitive responses to any origin.")
                    .setParam(param)
                    .setAttack(origin)
                    .setEvidence("ACAO: * ; ACAC: true")
                    .setCweId(942)
                    .setWascId(14)
                    .setMessage(attack)
                    .raise())
                continue

            # Condition 2: Reflected Origin
            if acao and acao.lower() == origin.lower():
                risk = 2
                desc = "The server reflects Origin in ACAO, which can allow attacker-controlled domains."
                if acac and acac.lower() == "true":
                    risk = 3
                    desc += " With credentials enabled, this is a critical issue."
                (helper.newAlert()
                    .setName("CORS Misconfiguration: Reflected Origin (CUSTOM)")
                    .setRisk(risk)
                    .setConfidence(2)
                    .setDescription(desc)
                    .setParam(param)
                    .setAttack(origin)
                    .setEvidence("ACAO: %s ; ACAC: %s" % (acao, acac))
                    .setCweId(942)
                    .setWascId(14)
                    .setMessage(attack)
                    .raise())
                continue

            # Condition 3: Missing Vary: Origin
            if acao and acao != "*" and acao.startswith("http") and (not vary or "origin" not in vary.lower()):
                (helper.newAlert()
                    .setName("CORS Misconfiguration: Missing Vary Header (CUSTOM)")
                    .setRisk(2)
                    .setConfidence(2)
                    .setDescription("The server responds with dynamic ACAO but does not set 'Vary: Origin'. This can cause cache poisoning or data leaks between origins.")
                    .setParam(param)
                    .setAttack(origin)
                    .setEvidence("ACAO: %s ; Vary: %s" % (acao, vary))
                    .setCweId(942)
                    .setWascId(14)
                    .setMessage(attack)
                    .raise())
                continue

            # Condition 4: ACAO * (low-risk informational)
            if acao == "*":
                (helper.newAlert()
                    .setName("CORS Misconfiguration: Wildcard Origin (CUSTOM)")
                    .setRisk(1)   # Low
                    .setConfidence(2)
                    .setDescription("The server responds with Access-Control-Allow-Origin: *. While not always exploitable, this may expose sensitive endpoints if combined with cookies or tokens.")
                    .setParam(param)
                    .setAttack(origin)
                    .setEvidence("ACAO: *")
                    .setCweId(942)
                    .setWascId(14)
                    .setMessage(attack)
                    .raise())

    except Exception as e:
        print("[ERROR] Exception in CORS Active Scan rule:", str(e))


def scanNode(helper, msg):
    # Not used here, but required by ZAP scripting API
    pass
