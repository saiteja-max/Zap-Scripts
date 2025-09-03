""" 
Custom GraphQL Introspection Detection Scan Rule for ZAP (Jython).
"""

from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 4000302
name: GraphQL Introspection Detection (Custom Jython Active Rule)
description: Detects if a GraphQL endpoint has introspection enabled by sending an introspection query and checking for schema details in the response.
solution: Disable or restrict GraphQL introspection queries in production. Only allow introspection in non-production environments.
references:
  - https://graphql.org/learn/introspection/
  - https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
category: MISC
risk: MEDIUM
confidence: HIGH
cweId: 200
wascId: 13
alertTags:
  OWASP_2021_A05: Security Misconfiguration
  OWASP_2017_A06: Security Misconfiguration
otherInfo: Custom script-based detection of GraphQL introspection queries.
status: alpha
""")

# Maximum requests allowed
MAX_REQUESTS = 1

# Introspection query payload
INTROSPECTION_QUERY = '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name } }} fragment FullType on __Type { kind name fields { name } }"}'

def scanNode(helper, msg):
    try:
        uri = msg.getRequestHeader().getURI().toString()
        print("[DEBUG] scanNode() called for:", uri)

        if not uri.lower().endswith("/graphql"):
            return

        newMsg = msg.cloneRequest()
        newMsg.getRequestHeader().setMethod("POST")
        newMsg.getRequestHeader().setHeader("Content-Type", "application/json")
        newMsg.setRequestBody(INTROSPECTION_QUERY)

        helper.sendAndReceive(newMsg, False, False)
        response_body = newMsg.getResponseBody().toString()

        if "__schema" in response_body or "\"types\"" in response_body:
            alert = helper.newAlert()
            alert.setRisk(2)  # Medium
            alert.setConfidence(3)  # High
            alert.setName("GraphQL Introspection Enabled (CUSTOM)")
            alert.setDescription("The GraphQL endpoint responded to an introspection query, exposing schema details.")
            alert.setParam("GraphQL Introspection Query")
            alert.setAttack("POST /graphql with introspection query")
            alert.setEvidence("__schema")
            alert.setOtherInfo("GraphQL introspection should be disabled in production environments.")
            alert.setSolution("Disable or restrict GraphQL introspection queries in production.")
            alert.setCweId(200)
            alert.setWascId(13)
            alert.setMessage(newMsg)
            alert.raise()
            print("[DEBUG] ALERT RAISED: GraphQL introspection enabled at " + uri)
        else:
            print("[DEBUG] No introspection data at " + uri)

    except Exception as e:
        print("[ERROR] Exception in scanNode:", str(e))


def scan(helper, msg, param, value):
    # Not needed for param-based scanning
    return
