import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from core.analyzer import analyze_stack
from core.curl_fallback import fallback_curl_request

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def check_security_web(url):
    result = []
    required_headers = [
        "X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy",
        "X-Content-Type-Options", "Strict-Transport-Security",
        "Referrer-Policy", "Permissions-Policy", "Cross-Origin-Resource-Policy",
        "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
        "Access-Control-Allow-Origin", "Cache-Control", "Pragma", "Expires",
        "Content-Disposition", "Server", "X-Powered-By"
    ]

    try:
        response = requests.get(url, verify=False, timeout=30)
        headers = response.headers

        tech_info = analyze_stack(headers)
        result.append(("Technology Stack", tech_info))

        found_headers = []
        missing_headers = []
        sensitive_info = []

        for header in required_headers:
            if header in headers:
                if header in ["Server", "X-Powered-By"]:
                    sensitive_info.append(f"\u26A0\ufe0f {header}: Found → Consider hiding")
                else:
                    found_headers.append(f"\u2705 {header}: Found")
            else:
                if header in ["Server", "X-Powered-By"]:
                    found_headers.append(f"\u2705 {header}: Not Found → Good")
                else:
                    missing_headers.append(f"\u274C {header}: Not Found")

        cookie_results = []
        cookies = headers.get("Set-Cookie", "")
        if cookies:
            cookie_results.append(f"Secure: {'\u2705' if 'Secure' in cookies else '\u274C'}")
            cookie_results.append(f"HttpOnly: {'\u2705' if 'HttpOnly' in cookies else '\u274C'}")
            cookie_results.append(f"SameSite: {'\u2705' if 'SameSite' in cookies else '\u274C'}")
        else:
            cookie_results.append("\u274C Set-Cookie: Not Found")

        risks = []
        if "Content-Security-Policy" not in headers:
            risks.append("\U0001F6A8 Missing CSP → Risk of XSS")
        if "Strict-Transport-Security" not in headers:
            risks.append("\U0001F6A8 Missing HSTS → Risk of HTTPS downgrade")
        if "Server" in headers:
            risks.append("\U0001F6A8 Server info exposed")
        if "X-Powered-By" in headers:
            risks.append("\U0001F6A8 X-Powered-By exposed")

        result.extend([
            ("Security Headers (Found)", found_headers),
            ("Security Headers (Missing)", missing_headers),
            ("Cookies", cookie_results),
            ("Risks", risks)
        ])

    except Exception as e:
        result.append(("Error", [str(e)]))
        fallback = fallback_curl_request(url, required_headers)
        result.append(("Fallback Curl", fallback))

    return result