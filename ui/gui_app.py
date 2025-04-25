import customtkinter as ctk
from core.security_check import check_security_web

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def launch_gui():
    app = ctk.CTk()
    app.title("Security Header Checker")
    app.geometry("700x600")

    def run_check():
        url = url_entry.get()
        result_textbox.delete("1.0", ctk.END)
        if not url.startswith("http"):
            url = "https://" + url
        results = check_security_web(url)
        for section, lines in results:
            result_textbox.insert(ctk.END, f"\n=== {section} ===\n")
            for line in lines:
                result_textbox.insert(ctk.END, f"{line}\n")

    url_label = ctk.CTkLabel(app, text="Enter URL:")
    url_label.pack(pady=10)
    url_entry = ctk.CTkEntry(app, width=500)
    url_entry.pack(pady=5)
    check_button = ctk.CTkButton(app, text="Check Security", command=run_check)
    check_button.pack(pady=10)

    result_textbox = ctk.CTkTextbox(app, width=650, height=450)
    result_textbox.pack(pady=10)

    app.mainloop()