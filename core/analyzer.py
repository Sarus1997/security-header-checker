def analyze_stack(headers):
    tech_info = []
    server = headers.get("Server", "")
    x_powered_by = headers.get("X-Powered-By", "")

    if "apache" in server.lower():
        tech_info.append("\U0001F9F1 Server: Apache")
    elif "nginx" in server.lower():
        tech_info.append("\U0001F9F1 Server: Nginx")
    elif "iis" in server.lower():
        tech_info.append("\U0001F9F1 Server: Microsoft IIS")
    elif "cloudflare" in server.lower():
        tech_info.append("\U0001F9F1 CDN/Proxy: Cloudflare")
    elif server:
        tech_info.append(f"\U0001F9F1 Server: {server}")

    if "express" in x_powered_by.lower():
        tech_info.append("\u2699\ufe0f Framework: Express (Node.js)")
    elif "php" in x_powered_by.lower():
        tech_info.append("\u2699\ufe0f Language: PHP")
    elif "asp.net" in x_powered_by.lower():
        tech_info.append("\u2699\ufe0f Framework: ASP.NET")
    elif x_powered_by:
        tech_info.append(f"\u2699\ufe0f Powered by: {x_powered_by}")

    return tech_info