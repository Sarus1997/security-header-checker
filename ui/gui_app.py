def launch_gui():
    import customtkinter as ctk
    from core.security_check import check_security_web

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    app = ctk.CTk()
    app.title("Security Header Checker")
    app.geometry("800x700")

    def run_check():
        url = url_entry.get()
        result_textbox.delete("1.0", ctk.END)
        if not url.startswith("http"):
            url = "https://" + url

        results = check_security_web(url)

        result_textbox.insert(ctk.END, "=" * 60 + "\n")
        result_textbox.insert(ctk.END, f"🔍 Checking Security Headers for: {url}\n")
        result_textbox.insert(ctk.END, "=" * 60 + "\n\n")

        for section, lines in results:
            section_title = {
                "Technology Stack": "🧠 Technology Stack:",
                "Security Headers (Found)": "🛡️ Security Headers (Found):",
                "Security Headers (Missing)": "🛡️ Security Headers (Missing):",
                "Cookies": "🍪 Cookie Security Check:",
                "Risks": "🚨 Potential Security Risks:",
                "Error": "❌ Error:",
                "Fallback Curl": "🔄 Fallback Curl Results:"
            }.get(section, section)

            result_textbox.insert(ctk.END, f"{section_title}\n")
            result_textbox.insert(ctk.END, "-" * 60 + "\n")
            for line in lines:
                result_textbox.insert(ctk.END, f"{line}\n")
            result_textbox.insert(ctk.END, "-" * 60 + "\n\n")

        result_textbox.insert(ctk.END, "=" * 60 + "\n")

    # --- UI Layout ---
    url_label = ctk.CTkLabel(app, text="Enter URL:")
    url_label.pack(pady=10)

    url_entry = ctk.CTkEntry(app, width=500)
    url_entry.pack(pady=5)

    check_button = ctk.CTkButton(app, text="Check Security", command=run_check)
    check_button.pack(pady=10)

    result_textbox = ctk.CTkTextbox(app, width=750, height=500)
    result_textbox.pack(pady=10)

    app.mainloop()
