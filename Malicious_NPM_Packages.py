"""
Passive Scan Rule (Jython) - Detect Affected NPM Packages in Responses
"""

import re

# List of known affected npm packages
affected_pkgs = [
    "ansi-styles", "debug", "backslash", "chalk-template",
    "supports-hyperlinks", "has-ansi", "simple-swizzle",
    "color-string", "error-ex", "color-name", "is-arrayish",
    "slice-ansi", "color-convert", "wrap-ansi", "ansi-regex",
    "supports-color", "strip-ansi", "chalk"
]

# Expanded regex patterns for suspicious function signatures / variables
suspicious_patterns = [
    r"chalk\.[a-zA-Z]+\(",    # chalk.red(), chalk.blue(), etc.
    r"ansiRegex\s*\(",        # ansi-regex
    r"supportsColor",         # supports-color
    r"stripAnsi",             # strip-ansi
    r"wrapAnsi",              # wrap-ansi
    r"sliceAnsi",             # slice-ansi
    r"colorString",           # color-string
    r"colorConvert",          # color-convert
    r"ansiStyles",            # ansi-styles
    r"hasAnsi",               # has-ansi
    r"supportsHyperlinks",    # supports-hyperlinks
    r"simpleSwizzle",         # simple-swizzle
    r"colorName",             # color-name
    r"isArrayish",            # is-arrayish
    r"errorEx",               # error-ex
    r"chalkTemplate"          # chalk-template
]

def scan(pscan, msg, src):
    try:
        # Only scan HTML or JavaScript responses
        content_type = msg.getResponseHeader().getHeader("Content-Type")
        if not (msg.getResponseHeader().isHtml() or (content_type and "javascript" in content_type.lower())):
            return

        body = msg.getResponseBody().toString()
        url = msg.getRequestHeader().getURI().toString()

        alerts_raised = 0

        # --- 1) Check for direct package mentions ---
        for pkg in affected_pkgs:
            if pkg.lower() in body.lower() or pkg.lower() in url.lower():
                print("[ALERT] Affected npm package found:", pkg, "in", url)

                pscan.raiseAlert(
                    2,  # Risk: Medium
                    2,  # Confidence: Medium
                    "Usage of Potentially Compromised NPM Package (CUSTOM)",
                    "The application appears to reference or include the npm package: " + pkg,
                    url,  # URI
                    pkg,  # Param (package name)
                    "",   # Attack
                    "Package reference detected in response body or URL.",  # Other info
                    "Review dependency tree and ensure patched versions of this package are used.",
                    pkg,  # Evidence
                    829,  # CWE-829: Inclusion of Functionality from Untrusted Control Sphere
                    15,   # WASC-15: Application Misconfiguration
                    msg   # Original message
                )
                alerts_raised += 1

        # --- 2) Check for suspicious JS signatures ---
        for pattern in suspicious_patterns:
            match = re.search(pattern, body)
            if match:
                evidence = match.group(0)
                print("[ALERT] Suspicious JS signature detected:", evidence, "in", url)

                pscan.raiseAlert(
                    2,  # Risk: Medium
                    3,  # Confidence: High
                    "JavaScript Signature of Affected NPM Package (CUSTOM)",
                    "The application response contains a function signature matching a known affected npm package.",
                    url,
                    "",   # Param
                    "",   # Attack
                    "Signature matched: " + evidence,
                    "Review dependencies and ensure patched versions of npm packages are in use.",
                    evidence,
                    829,  # CWE-829
                    15,   # WASC-15
                    msg
                )
                alerts_raised += 1

        if alerts_raised > 0:
            print("[DEBUG] Total alerts raised:", alerts_raised)

    except Exception as e:
        import traceback
        print("[ERROR] Passive scan exception:", e)
        traceback.print_exc()
