import subprocess

def fallback_curl_request(url, headers):
    results = []
    try:
        output = subprocess.run(["curl", "-I", "--insecure", url], capture_output=True, text=True)
        header_text = output.stdout
        for header in headers:
            if any(header.lower() in line.lower() for line in header_text.splitlines()):
                results.append(f"\u2705 {header}: Found")
            else:
                results.append(f"\u274C {header}: Not Found")
    except Exception as e:
        results.append(f"Curl error: {e}")
    return results