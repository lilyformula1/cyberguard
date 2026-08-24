import customtkinter as ctk

app = ctk.CTk()
app.title("CyberGuard")
app.geometry("1000x650")

title = ctk.CTkLabel(
    app,
    text="🛡 CYBERGUARD",
    font=("Arial", 32, "bold")
)

title.pack(pady=40)

app.mainloop()