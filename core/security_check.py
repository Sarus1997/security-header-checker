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
                    sensitive_info.append(f"⚠️ {header}: Found → {headers.get(header)} → Consider hiding")
                else:
                    found_headers.append(f"✅ {header}: Found")
            else:
                if header in ["Server", "X-Powered-By"]:
                    found_headers.append(f"✅ {header}: Not Found → Good")
                else:
                    missing_headers.append(f"❌ {header}: Not Found")

        cookie_results = []
        cookies = headers.get("Set-Cookie", "")
        if cookies:
            cookie_results.append(f"Secure: {'✅' if 'Secure' in cookies else '❌'}")
            cookie_results.append(f"HttpOnly: {'✅' if 'HttpOnly' in cookies else '❌'}")
            cookie_results.append(f"SameSite: {'✅' if 'SameSite' in cookies else '❌'}")
        else:
            cookie_results.append("❌ Set-Cookie: Not Found")

        risks = []
        if "Content-Security-Policy" not in headers:
            risks.append("🔴 Missing CSP → Risk of XSS")
        if "Strict-Transport-Security" not in headers:
            risks.append("🔴 Missing HSTS → Risk of HTTPS downgrade")
        if "Server" in headers:
            risks.append("🔴 Server info exposed → Could allow targeted attacks")
        if "X-Powered-By" in headers:
            risks.append("🔴 X-Powered-By exposed → Can reveal backend technology")

        result.extend([
            ("Security Headers (Found)", found_headers + sensitive_info),
            ("Security Headers (Missing)", missing_headers),
            ("Cookies", cookie_results),
            ("Risks", risks)
        ])

    except Exception as e:
        result.append(("Error", [str(e)]))
        fallback = fallback_curl_request(url, required_headers)
        result.append(("Fallback Curl", fallback))

    return result
