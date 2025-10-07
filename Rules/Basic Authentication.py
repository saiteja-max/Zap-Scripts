"""
Custom Passive Scan Script for Detecting Basic Authentication in Request Headers
Description: Flags the presence of Basic Authentication in the Authorization header.
"""

from org.parosproxy.paros.network import HttpMessage
from org.zaproxy.zap.extension.pscan import PluginPassiveScanner

def scan(pscan, msg, src):
    try:
        # Get request headers
        request_header = msg.getRequestHeader()
        auth_header = request_header.getHeader("Authorization")

        if auth_header and auth_header.lower().startswith("basic "):
            # Raise an alert
            pscan.raiseAlert(
                2,  # risk: 0=info,1=low,2=medium,3=high
                2,  # confidence: 0=low,1=medium,2=high,3=confirmed
                "Basic Authentication Detected",  # name
                "The request contains Basic Authentication credentials in the Authorization header.",  # description
                msg.getRequestHeader().getURI().toString(),  # uri
                "N/A",  # param
                "Authorization Header",  # attack
                "Basic Authentication transmits credentials in Base64 encoding, which is easily reversible. This could expose sensitive information if sent over HTTP or weak TLS.",  # other info
                "Use stronger authentication methods (e.g., OAuth, token-based auth) and ensure all requests use HTTPS.",  # solution
                auth_header,  # evidence
                0,  # CWE-ID (e.g., 522: Insufficiently Protected Credentials)
                1000,  # WASC-ID (e.g., 2: Authentication)
                msg  # HTTP message
            )

    except Exception as e:
        print("[ERROR] Passive Script Exception: " + str(e))
