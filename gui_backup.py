import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import sys


# ============================================================
# CYBERBOOM THEME
# ============================================================

BG = "#080D14"
PANEL = "#0F1722"
PANEL_2 = "#121D2A"
BORDER = "#1E3445"
TEXT = "#E8F1F7"
MUTED = "#7F98A8"
CYAN = "#00E5FF"
GREEN = "#00FF9C"
RED = "#FF3B6B"
YELLOW = "#FFD166"


# ============================================================
# FILE SELECTION
# ============================================================

selected_file = None


def choose_file():
    global selected_file

    file_path = filedialog.askopenfilename(
        title="Select file to analyze",
        filetypes=[
            ("Executable files", "*.exe;*.dll;*.sys"),
            ("All files", "*.*")
        ]
    )

    if file_path:
        selected_file = file_path

        file_label.config(
            text=file_path,
            fg=TEXT
        )

        status_label.config(
            text="● SAMPLE LOADED",
            fg=GREEN
        )


# ============================================================
# RUN FULL ANALYSIS
# ============================================================

def run_full_analysis():

    if not selected_file:
        messagebox.showwarning(
            "No Sample Selected",
            "Please select a file before running the analysis."
        )
        return

    status_label.config(
        text="● ANALYZING SAMPLE...",
        fg=YELLOW
    )

    root.update()

    try:

        result = subprocess.run(
            [sys.executable, "cyberguard.py"],
            input=selected_file + "\n",
            text=True,
            capture_output=True
        )

        output = result.stdout

        if result.stderr:
            output += "\n\nERRORS:\n" + result.stderr

        show_results(output)

        status_label.config(
            text="● ANALYSIS COMPLETE",
            fg=GREEN
        )

    except Exception as error:

        status_label.config(
            text="● ANALYSIS FAILED",
            fg=RED
        )

        messagebox.showerror(
            "CyberBoom Error",
            str(error)
        )


# ============================================================
# RESULTS WINDOW
# ============================================================

def show_results(output):

    results_window = tk.Toplevel(root)

    results_window.title(
        "CyberBoom — Analysis Results"
    )

    results_window.geometry(
        "1050x720"
    )

    results_window.configure(
        bg=BG
    )

    title = tk.Label(
        results_window,
        text="💥 CYBERBOOM — ANALYSIS RESULTS",
        bg=BG,
        fg=CYAN,
        font=("Segoe UI", 20, "bold")
    )

    title.pack(
        anchor="w",
        padx=25,
        pady=(20, 5)
    )

    subtitle = tk.Label(
        results_window,
        text="Static Malware Analysis Report",
        bg=BG,
        fg=MUTED,
        font=("Segoe UI", 10)
    )

    subtitle.pack(
        anchor="w",
        padx=27
    )

    text_frame = tk.Frame(
        results_window,
        bg=PANEL,
        highlightbackground=BORDER,
        highlightthickness=1
    )

    text_frame.pack(
        fill="both",
        expand=True,
        padx=25,
        pady=20
    )

    scrollbar = tk.Scrollbar(
        text_frame
    )

    scrollbar.pack(
        side="right",
        fill="y"
    )

    output_box = tk.Text(
        text_frame,
        bg="#070B11",
        fg=TEXT,
        insertbackground=TEXT,
        font=("Consolas", 10),
        wrap="none",
        yscrollcommand=scrollbar.set
    )

    output_box.pack(
        fill="both",
        expand=True,
        padx=10,
        pady=10
    )

    scrollbar.config(
        command=output_box.yview
    )

    output_box.insert(
        "1.0",
        output
    )

    output_box.config(
        state="disabled"
    )


# ============================================================
# MAIN WINDOW
# ============================================================

root = tk.Tk()

root.title(
    "CyberBoom — Static Malware Analysis"
)

root.geometry(
    "1200x750"
)

root.minsize(
    1000,
    650
)

root.configure(
    bg=BG
)


# ============================================================
# HEADER
# ============================================================

header = tk.Frame(
    root,
    bg=BG,
    height=80
)

header.pack(
    fill="x",
    padx=30,
    pady=(20, 0)
)

brand = tk.Label(
    header,
    text="💥 CYBERBOOM",
    bg=BG,
    fg=CYAN,
    font=("Segoe UI", 26, "bold")
)

brand.pack(
    side="left"
)

subtitle = tk.Label(
    header,
    text="  STATIC MALWARE ANALYSIS PLATFORM",
    bg=BG,
    fg=MUTED,
    font=("Segoe UI", 10, "bold")
)

subtitle.pack(
    side="left",
    pady=(10, 0)
)

status_label = tk.Label(
    header,
    text="● SYSTEM READY",
    bg=BG,
    fg=GREEN,
    font=("Segoe UI", 10, "bold")
)

status_label.pack(
    side="right",
    pady=(10, 0)
)


# ============================================================
# MAIN LAYOUT
# ============================================================

main = tk.Frame(
    root,
    bg=BG
)

main.pack(
    fill="both",
    expand=True,
    padx=30,
    pady=15
)


# ============================================================
# SIDEBAR
# ============================================================

sidebar = tk.Frame(
    main,
    bg=PANEL,
    width=220,
    highlightbackground=BORDER,
    highlightthickness=1
)

sidebar.pack(
    side="left",
    fill="y",
    padx=(0, 15)
)

sidebar.pack_propagate(False)


sidebar_title = tk.Label(
    sidebar,
    text="ANALYSIS",
    bg=PANEL,
    fg=MUTED,
    font=("Segoe UI", 9, "bold")
)

sidebar_title.pack(
    anchor="w",
    padx=20,
    pady=(25, 15)
)


sidebar_items = [
    "◉  Dashboard",
    "◈  PE Analysis",
    "⚠  API Detection",
    "◇  String Scanner",
    "◉  Entropy",
    "◆  Hash Analysis",
    "⚡  Risk Assessment"
]


for item in sidebar_items:

    tk.Label(
        sidebar,
        text=item,
        bg=PANEL,
        fg=TEXT,
        font=("Segoe UI", 11),
        anchor="w",
        padx=20,
        pady=12
    ).pack(
        fill="x"
    )


# ============================================================
# CONTENT AREA
# ============================================================

content = tk.Frame(
    main,
    bg=BG
)

content.pack(
    side="left",
    fill="both",
    expand=True
)


# ============================================================
# SAMPLE PANEL
# ============================================================

sample_panel = tk.Frame(
    content,
    bg=PANEL,
    highlightbackground=BORDER,
    highlightthickness=1
)

sample_panel.pack(
    fill="x",
    pady=(0, 15)
)


tk.Label(
    sample_panel,
    text="SAMPLE ANALYSIS",
    bg=PANEL,
    fg=CYAN,
    font=("Segoe UI", 10, "bold")
).pack(
    anchor="w",
    padx=20,
    pady=(18, 5)
)


tk.Label(
    sample_panel,
    text="Select a Windows executable for static analysis",
    bg=PANEL,
    fg=MUTED,
    font=("Segoe UI", 9)
).pack(
    anchor="w",
    padx=20
)


file_area = tk.Frame(
    sample_panel,
    bg=PANEL_2,
    highlightbackground=BORDER,
    highlightthickness=1
)

file_area.pack(
    fill="x",
    padx=20,
    pady=15
)


file_label = tk.Label(
    file_area,
    text="📁  No sample selected",
    bg=PANEL_2,
    fg=MUTED,
    font=("Segoe UI", 10),
    anchor="w"
)

file_label.pack(
    side="left",
    fill="x",
    expand=True,
    padx=15,
    pady=14
)


browse_button = tk.Button(
    file_area,
    text="SELECT FILE",
    command=choose_file,
    bg=CYAN,
    fg=BG,
    activebackground=GREEN,
    activeforeground=BG,
    relief="flat",
    font=("Segoe UI", 9, "bold"),
    padx=18,
    pady=8,
    cursor="hand2"
)

browse_button.pack(
    side="right",
    padx=10
)


# ============================================================
# ANALYSIS MODULES
# ============================================================

tk.Label(
    content,
    text="ANALYSIS MODULES",
    bg=BG,
    fg=MUTED,
    font=("Segoe UI", 9, "bold")
).pack(
    anchor="w",
    pady=(0, 8)
)


cards = tk.Frame(
    content,
    bg=BG
)

cards.pack(
    fill="x"
)


modules = [
    ("🧬", "PE ANALYSIS", "Headers & Sections"),
    ("⚠", "API DETECTION", "Suspicious APIs"),
    ("🔤", "STRING SCANNER", "Threat Indicators"),
    ("📊", "ENTROPY", "Packing Indicators"),
    ("🔐", "HASH ANALYSIS", "MD5 / SHA1 / SHA256"),
    ("⚡", "RISK ENGINE", "Threat Assessment")
]


for i, (icon, title, description) in enumerate(modules):

    row = i // 3
    column = i % 3

    card = tk.Frame(
        cards,
        bg=PANEL,
        highlightbackground=BORDER,
        highlightthickness=1,
        height=100
    )

    card.grid(
        row=row,
        column=column,
        padx=5,
        pady=5,
        sticky="nsew"
    )

    tk.Label(
        card,
        text=icon,
        bg=PANEL,
        fg=CYAN,
        font=("Segoe UI", 20)
    ).pack(
        anchor="w",
        padx=15,
        pady=(10, 0)
    )

    tk.Label(
        card,
        text=title,
        bg=PANEL,
        fg=TEXT,
        font=("Segoe UI", 9, "bold")
    ).pack(
        anchor="w",
        padx=15
    )

    tk.Label(
        card,
        text=description,
        bg=PANEL,
        fg=MUTED,
        font=("Segoe UI", 8)
    ).pack(
        anchor="w",
        padx=15
    )


for column in range(3):

    cards.grid_columnconfigure(
        column,
        weight=1
    )


# ============================================================
# RISK DASHBOARD
# ============================================================

risk_panel = tk.Frame(
    content,
    bg=PANEL,
    highlightbackground=BORDER,
    highlightthickness=1
)

risk_panel.pack(
    fill="x",
    pady=15
)


tk.Label(
    risk_panel,
    text="CURRENT RISK ASSESSMENT",
    bg=PANEL,
    fg=MUTED,
    font=("Segoe UI", 9, "bold")
).pack(
    anchor="w",
    padx=20,
    pady=(15, 5)
)


risk_row = tk.Frame(
    risk_panel,
    bg=PANEL
)

risk_row.pack(
    fill="x",
    padx=20,
    pady=(0, 15)
)


tk.Label(
    risk_row,
    text="-- / 100",
    bg=PANEL,
    fg=YELLOW,
    font=("Segoe UI", 25, "bold")
).pack(
    side="left"
)


tk.Label(
    risk_row,
    text="  ANALYSIS NOT RUN",
    bg=PANEL,
    fg=MUTED,
    font=("Segoe UI", 10, "bold")
).pack(
    side="left",
    pady=(8, 0)
)


# ============================================================
# FULL ANALYSIS BUTTON
# ============================================================

full_scan = tk.Button(
    content,
    text="⚡  RUN FULL ANALYSIS",
    command=run_full_analysis,
    bg=GREEN,
    fg=BG,
    activebackground=CYAN,
    activeforeground=BG,
    relief="flat",
    font=("Segoe UI", 13, "bold"),
    padx=30,
    pady=14,
    cursor="hand2"
)

full_scan.pack(
    fill="x"
)


# ============================================================
# FOOTER
# ============================================================

footer = tk.Label(
    root,
    text="CYBERBOOM v1.0   •   Static Analysis Engine   •   Malware Research",
    bg=BG,
    fg=MUTED,
    font=("Segoe UI", 8)
)

footer.pack(
    pady=(0, 10)
)


# ============================================================
# START APPLICATION
# ============================================================

root.mainloop()