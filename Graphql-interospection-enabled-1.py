"""
Custom GraphQL Introspection Detection Rule for ZAP (Jython).
Detects GraphQL endpoints (not only /graphql) and checks if introspection is enabled.
"""

import org.parosproxy.paros.network.HttpMessage as HttpMessage
from org.parosproxy.paros.core.scanner import AbstractPlugin
from org.parosproxy.paros.core.scanner import Plugin
from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 4000302
name: GraphQL Introspection Detection (Custom Jython Active Rule)
description: Detects GraphQL endpoints and checks if introspection queries are enabled.
solution: Disable GraphQL introspection in production or restrict access to trusted users.
references:
  - https://graphql.org/learn/introspection/
  - https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
category: MISC
risk: MEDIUM
confidence: HIGH
cweId: 200
wascId: 45
alertTags:
  OWASP_2021_A05: Security Misconfiguration
  OWASP_2017_A06: Security Misconfiguration
otherInfo: Custom script-based detection of GraphQL introspection exposure.
status: alpha
""")

class GraphQLIntrospectionScanRule(AbstractPlugin):

    introspection_query = '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name locations args { ...InputValue } } } } fragment FullType on __Type { kind name fields(includeDeprecated: true) { name args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}'

    def __init__(self):
        self.id = 4000302

    def getId(self):
        return self.id

    def getName(self):
        return "GraphQL Introspection Detection (Custom)"

    def scanNode(self, as, msg):
        try:
            url = msg.getRequestHeader().getURI().toString()
            method = msg.getRequestHeader().getMethod()
            body = msg.getRequestBody().toString()
            content_type = msg.getRequestHeader().getHeader("Content-Type")

            print("[DEBUG] scanNode() called for:", url)

            # --- Heuristic detection ---
            looks_like_graphql = False
            if method.upper() == "POST" and content_type and "application/json" in content_type.lower():
                if "query" in body or "mutation" in body:
                    looks_like_graphql = True

            # Fallback: if URL looks like graphql-ish
            if any(x in url.lower() for x in ["/graphql", "/gql", "/api/query", "/playground"]):
                looks_like_graphql = True

            if not looks_like_graphql:
                return

            # --- Send introspection query ---
            newMsg = msg.cloneRequest()
            newMsg.getRequestBody().setBody(self.introspection_query)
            newMsg.getRequestHeader().setContentLength(len(self.introspection_query))

            as.sendAndReceive(newMsg, False, False)

            response = newMsg.getResponseBody().toString()

            if "__schema" in response:
                # Raise alert for enabled introspection
                self.newAlert()
                    .setRisk(2)  # Medium
                    .setConfidence(3)  # High
                    .setName("GraphQL Introspection Enabled")
                    .setDescription("GraphQL introspection is enabled at: " + url)
                    .setSolution("Disable introspection in production environments or restrict to admin-only access.")
                    .setEvidence("__schema")
                    .setOtherInfo("Full response:\n" + response[:500])
                    .setMessage(newMsg)
                    .raise()
                print("[DEBUG] ALERT RAISED: GraphQL introspection enabled at", url)

            elif "errors" in response and ("query" in response or "Cannot query field" in response):
                # GraphQL detected but introspection disabled
                self.newAlert()
                    .setRisk(0)  # Informational
                    .setConfidence(2)  # Medium
                    .setName("GraphQL Detected (Introspection Disabled)")
                    .setDescription("GraphQL endpoint detected at: " + url + " but introspection appears disabled.")
                    .setSolution("Review GraphQL security best practices, limit access, and enforce query cost analysis.")
                    .setEvidence(response[:200])
                    .setOtherInfo("This endpoint responded like a GraphQL API but did not allow introspection.")
                    .setMessage(newMsg)
                    .raise()
                print("[DEBUG] INFO: GraphQL detected but introspection disabled at", url)

        except Exception as e:
            print("[ERROR] Exception in GraphQLIntrospectionScanRule:", e)
