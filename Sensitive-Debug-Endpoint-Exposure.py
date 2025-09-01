"""
Custom Passive Script: Sensitive Debug Endpoint Exposure
Works in: OWASP ZAP (Jython 2.7)
Type: Passive Scan Rule
"""

debug_endpoints = [
    # Java / Spring Boot
    "/actuator", "/actuator/env", "/actuator/beans", "/actuator/heapdump",
    "/actuator/metrics", "/actuator/mappings", "/jolokia", "/h2-console",

    # Python Flask/Django/FastAPI
    "/debug", "/console", "/__debug__/", "/admin/",
    "/docs", "/redoc", "/openapi.json",

    # Node.js / Express / NestJS
    "/errors", "/express/status", "/swagger-ui", "/api-json",

    # Ruby on Rails
    "/rails/info/routes", "/rails/info/properties", "/active_storage/blobs",

    # PHP Laravel / Symfony
    "/telescope", "/horizon", "/.env", "/vendor/", "/config.php", "/app_dev.php",

    # .NET / ASP.NET
    "/swagger", "/swagger/ui", "/swagger.json", "/elmah.axd",
    "/health", "/trace.axd",

    # Go
    "/debug/pprof", "/debug/pprof/goroutine", "/debug/pprof/heap",
    "/debug/pprof/cmdline", "/debug/pprof/trace", "/debug/pprof/threadcreate", "/debug/pprof/profile", 
    "/debug/pprof/mutex", "/debug/pprof/block", "/debug/pprof/allocs", "/metrics",

    # Generic
    "/status", "/ping", "/api-docs"
]

def scan(ps, msg, src):
    try:
        url = msg.getRequestHeader().getURI().toString()

        for endpoint in debug_endpoints:
            if endpoint in url:
                print("[DEBUG] Sensitive Debug Endpoint found: {} in {}".format(endpoint, url))

                ps.raiseAlert(
                    1,  # risk: Low
                    3,  # confidence: Confirmed
                    "Sensitive Debug Endpoint Exposure",  # name
                    "The application exposes a sensitive debug endpoint: " + endpoint,  # description
                    url,  # uri
                    endpoint,  # param
                    "",  # attack
                    "Debug/monitoring endpoint was requested in the URL.",  # otherInfo
                    "Remove or secure debug endpoints in production.",  # solution
                    endpoint,  # evidence
                    200,  # CWE-200: Information Exposure
                    13,   # WASC-13: Information Leakage
                    msg   # HttpMessage
                )
    except Exception as e:
        print("[ERROR] Exception in Passive Script: {}".format(str(e)))
