import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import sys
from pathlib import Path
import re
import os


# ============================================================
# CYBERBOOM THEME
# ============================================================

BG = "#080D14"
PANEL = "#0F1722"
PANEL_2 = "#121D2A"
PANEL_3 = "#182535"
BORDER = "#1E3445"

TEXT = "#E8F1F7"
MUTED = "#7F98A8"

CYAN = "#00E5FF"
GREEN = "#00FF9C"
RED = "#FF3B6B"
YELLOW = "#FFD166"
WHITE = "#FFFFFF"


# ============================================================
# GLOBAL STATE
# ============================================================

selected_file = None
last_output = ""
last_analysis_title = ""


# ============================================================
# FILE SELECTION
# ============================================================

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

        update_sample_info()


def update_sample_info():
    if not selected_file:
        return

    try:
        path = Path(selected_file)

        size = path.stat().st_size

        if size >= 1024 * 1024:
            size_text = f"{size / (1024 * 1024):.2f} MB"
        elif size >= 1024:
            size_text = f"{size / 1024:.2f} KB"
        else:
            size_text = f"{size} bytes"

        sample_info.config(
            text=f"FILE  •  {path.name}     SIZE  •  {size_text}"
        )

    except Exception:
        pass


# ============================================================
# RUN ANALYSIS - FIXED FOR EXE
# ============================================================

def run_analysis(mode, title):
    global last_output
    global last_analysis_title

    if not selected_file:
        messagebox.showwarning(
            "No Sample Selected",
            "Please select a file before running the analysis."
        )
        return

    status_label.config(
        text=f"● RUNNING {title.upper()}...",
        fg=YELLOW
    )

    root.update()

    try:
        # ============================================================
        # FIX: Check if running as EXE or Python script
        # ============================================================
        
        if getattr(sys, 'frozen', False):
            # ---------- RUNNING AS EXE ----------
            # Get the directory where the EXE is located
            exe_dir = Path(sys.executable).parent
            
            # Path to cyberguard.py bundled with the EXE
            engine_path = exe_dir / "cyberguard.py"
            
            # If not found in exe_dir, try current directory
            if not engine_path.exists():
                engine_path = Path.cwd() / "cyberguard.py"
            
            # If still not found, try the directory where the EXE was built
            if not engine_path.exists():
                # This is for when running from dist folder
                engine_path = Path(__file__).parent / "cyberguard.py"
            
            # Use Python executable to run cyberguard.py
            python_exe = sys.executable
            
            result = subprocess.run(
                [
                    python_exe,
                    str(engine_path),
                    selected_file,
                    mode
                ],
                text=True,
                capture_output=True
            )
            
        else:
            # ---------- RUNNING AS PYTHON SCRIPT ----------
            engine_path = Path(__file__).parent / "cyberguard.py"
            
            result = subprocess.run(
                [
                    sys.executable,
                    str(engine_path),
                    selected_file,
                    mode
                ],
                text=True,
                capture_output=True
            )

        output = result.stdout.strip()

        if result.stderr:
            output += "\n\nERRORS:\n" + result.stderr.strip()

        if not output:
            output = "No analysis output was returned."

        last_output = output
        last_analysis_title = title

        show_results(output, title)

        update_risk_dashboard(output)

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
# ANALYSIS FUNCTIONS
# ============================================================

def run_pe():
    run_analysis("pe", "PE Analysis")


def run_api():
    run_analysis("api", "API Detection")


def run_strings():
    run_analysis("strings", "String Scanner")


def run_entropy():
    run_analysis("entropy", "Entropy Analysis")


def run_hash():
    run_analysis("hash", "Hash Analysis")


def run_risk():
    run_analysis("risk", "Risk Engine")


def run_full_analysis():
    run_analysis("full", "Full Analysis")


# ============================================================
# RISK DASHBOARD
# ============================================================

def update_risk_dashboard(output):
    match = re.search(
        r"Risk Score\s*:\s*(\d+)\s*/\s*100",
        output,
        re.IGNORECASE
    )

    level_match = re.search(
        r"Risk Level\s*:\s*(HIGH|MEDIUM|LOW)",
        output,
        re.IGNORECASE
    )

    if not match:
        return

    score = int(match.group(1))

    if level_match:
        level = level_match.group(1).upper()
    else:
        if score >= 70:
            level = "HIGH"
        elif score >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

    if level == "HIGH":
        risk_color = RED
        status = "HIGH RISK"
    elif level == "MEDIUM":
        risk_color = YELLOW
        status = "MEDIUM RISK"
    else:
        risk_color = GREEN
        status = "LOW RISK"

    risk_score_label.config(
        text=f"{score} / 100",
        fg=risk_color
    )

    risk_status_label.config(
        text=f"  {status}",
        fg=risk_color
    )

    risk_bar.delete("all")

    width = max(1, int((score / 100) * 500))

    risk_bar.create_rectangle(
        0,
        0,
        width,
        12,
        fill=risk_color,
        outline=""
    )


# ============================================================
# DASHBOARD
# ============================================================

def show_dashboard():
    status_label.config(
        text="● DASHBOARD",
        fg=CYAN
    )

    if selected_file:
        sample_info.config(
            text=f"FILE  •  {Path(selected_file).name}"
        )
    else:
        sample_info.config(
            text="NO SAMPLE LOADED"
        )


# ============================================================
# SIDEBAR HOVER
# ============================================================

def sidebar_hover(widget, enter=True):
    if enter:
        widget.config(
            bg=PANEL_3,
            fg=CYAN
        )
    else:
        widget.config(
            bg=PANEL,
            fg=TEXT
        )


# ============================================================
# RESULTS WINDOW
# ============================================================

def show_results(output, analysis_title):
    results_window = tk.Toplevel(root)

    results_window.title(
        f"CyberBoom — {analysis_title}"
    )

    results_window.geometry(
        "1100x750"
    )

    results_window.minsize(
        900,
        600
    )

    results_window.configure(
        bg=BG
    )

    # HEADER
    header = tk.Frame(
        results_window,
        bg=BG
    )

    header.pack(
        fill="x",
        padx=28,
        pady=(22, 5)
    )

    tk.Label(
        header,
        text="💥 CYBERBOOM",
        bg=BG,
        fg=CYAN,
        font=("Segoe UI", 20, "bold")
    ).pack(
        side="left"
    )

    tk.Label(
        header,
        text=f"  /  {analysis_title.upper()}",
        bg=BG,
        fg=TEXT,
        font=("Segoe UI", 14, "bold")
    ).pack(
        side="left",
        pady=(4, 0)
    )

    # SAMPLE INFO
    if selected_file:
        filename = Path(selected_file).name
    else:
        filename = "Unknown Sample"

    tk.Label(
        results_window,
        text=f"Static Malware Analysis  •  {filename}",
        bg=BG,
        fg=MUTED,
        font=("Segoe UI", 9)
    ).pack(
        anchor="w",
        padx=30
    )

    # RESULTS PANEL
    result_panel = tk.Frame(
        results_window,
        bg=PANEL,
        highlightbackground=BORDER,
        highlightthickness=1
    )

    result_panel.pack(
        fill="both",
        expand=True,
        padx=28,
        pady=18
    )

    # SCROLLBAR
    scrollbar = tk.Scrollbar(
        result_panel
    )

    scrollbar.pack(
        side="right",
        fill="y"
    )

    # OUTPUT
    output_box = tk.Text(
        result_panel,
        bg=PANEL_2,
        fg=TEXT,
        insertbackground=TEXT,
        selectbackground=CYAN,
        selectforeground=BG,
        font=("Consolas", 10),
        wrap="none",
        padx=18,
        pady=18,
        spacing1=2,
        spacing3=2,
        relief="flat",
        borderwidth=0,
        yscrollcommand=scrollbar.set
    )

    output_box.pack(
        fill="both",
        expand=True,
        padx=8,
        pady=8
    )

    scrollbar.config(
        command=output_box.yview
    )

    # TEXT STYLES
    output_box.tag_config(
        "section",
        foreground=CYAN,
        font=("Consolas", 11, "bold"),
        spacing1=12,
        spacing3=6
    )

    output_box.tag_config(
        "warning",
        foreground=RED,
        font=("Consolas", 10, "bold")
    )

    output_box.tag_config(
        "success",
        foreground=GREEN,
        font=("Consolas", 10, "bold")
    )

    output_box.tag_config(
        "yellow",
        foreground=YELLOW,
        font=("Consolas", 10, "bold")
    )

    output_box.tag_config(
        "label",
        foreground="#8FDFFF"
    )

    output_box.tag_config(
        "normal",
        foreground=TEXT
    )

    # INSERT FORMATTED OUTPUT
    section_names = [
        "HASH ANALYSIS",
        "STRING ANALYSIS",
        "PE ANALYSIS",
        "API DETECTION",
        "ENTROPY ANALYSIS",
        "RISK ASSESSMENT"
    ]

    for line in output.splitlines():
        stripped = line.strip()

        if stripped in section_names:
            output_box.insert(
                "end",
                f"\n{line}\n",
                "section"
            )

        elif "[!]" in line:
            output_box.insert(
                "end",
                line + "\n",
                "warning"
            )

        elif "Risk Level" in line:
            if "HIGH" in line.upper():
                tag = "warning"
            elif "MEDIUM" in line.upper():
                tag = "yellow"
            else:
                tag = "success"

            output_box.insert(
                "end",
                line + "\n",
                tag
            )

        elif "Risk Score" in line:
            output_box.insert(
                "end",
                line + "\n",
                "yellow"
            )

        elif line.startswith("MD5") or \
             line.startswith("SHA1") or \
             line.startswith("SHA256"):
            output_box.insert(
                "end",
                line + "\n",
                "label"
            )

        elif line.startswith("  ") and ":" in line:
            output_box.insert(
                "end",
                line + "\n",
                "normal"
            )

        else:
            output_box.insert(
                "end",
                line + "\n",
                "normal"
            )

    output_box.config(
        state="disabled"
    )

    # CLOSE BUTTON
    tk.Button(
        results_window,
        text="CLOSE",
        command=results_window.destroy,
        bg=PANEL_3,
        fg=TEXT,
        activebackground=CYAN,
        activeforeground=BG,
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=25,
        pady=8,
        cursor="hand2"
    ).pack(
        pady=(0, 18)
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
    bg=BG
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


tk.Label(
    sidebar,
    text="ANALYSIS",
    bg=PANEL,
    fg=MUTED,
    font=("Segoe UI", 9, "bold")
).pack(
    anchor="w",
    padx=20,
    pady=(25, 15)
)


sidebar_items = [
    ("◉  Dashboard", show_dashboard),
    ("◈  PE Analysis", run_pe),
    ("⚠  API Detection", run_api),
    ("◇  String Scanner", run_strings),
    ("◉  Entropy", run_entropy),
    ("◆  Hash Analysis", run_hash),
    ("⚡  Risk Assessment", run_risk)
]


for text, command in sidebar_items:
    item = tk.Label(
        sidebar,
        text=text,
        bg=PANEL,
        fg=TEXT,
        font=("Segoe UI", 11),
        anchor="w",
        padx=20,
        pady=12,
        cursor="hand2"
    )

    item.pack(
        fill="x"
    )

    item.bind(
        "<Button-1>",
        lambda event, cmd=command: cmd()
    )

    item.bind(
        "<Enter>",
        lambda event, w=item: sidebar_hover(w, True)
    )

    item.bind(
        "<Leave>",
        lambda event, w=item: sidebar_hover(w, False)
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
    pady=10
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


sample_info = tk.Label(
    sample_panel,
    text="NO SAMPLE LOADED",
    bg=PANEL,
    fg=MUTED,
    font=("Consolas", 8)
)

sample_info.pack(
    anchor="w",
    padx=20,
    pady=(0, 12)
)


# ============================================================
# ANALYSIS MODULES TITLE
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
    ("🧬", "PE ANALYSIS", "Headers & Sections", run_pe),
    ("⚠", "API DETECTION", "Suspicious APIs", run_api),
    ("🔤", "STRING SCANNER", "Threat Indicators", run_strings),
    ("📊", "ENTROPY", "Packing Indicators", run_entropy),
    ("🔐", "HASH ANALYSIS", "MD5 / SHA1 / SHA256", run_hash),
    ("⚡", "RISK ENGINE", "Threat Assessment", run_risk)
]


for i, (icon, title, description, command) in enumerate(modules):
    row = i // 3
    column = i % 3

    card = tk.Frame(
        cards,
        bg=PANEL,
        highlightbackground=BORDER,
        highlightthickness=1,
        height=105,
        cursor="hand2"
    )

    card.grid(
        row=row,
        column=column,
        padx=5,
        pady=5,
        sticky="nsew"
    )

    def card_click(event, cmd=command):
        cmd()

    card.bind(
        "<Button-1>",
        card_click
    )

    icon_label = tk.Label(
        card,
        text=icon,
        bg=PANEL,
        fg=CYAN,
        font=("Segoe UI", 20),
        cursor="hand2"
    )

    icon_label.pack(
        anchor="w",
        padx=15,
        pady=(10, 0)
    )

    title_label = tk.Label(
        card,
        text=title,
        bg=PANEL,
        fg=TEXT,
        font=("Segoe UI", 9, "bold"),
        cursor="hand2"
    )

    title_label.pack(
        anchor="w",
        padx=15
    )

    description_label = tk.Label(
        card,
        text=description,
        bg=PANEL,
        fg=MUTED,
        font=("Segoe UI", 8),
        cursor="hand2"
    )

    description_label.pack(
        anchor="w",
        padx=15
    )

    for widget in (
        icon_label,
        title_label,
        description_label
    ):
        widget.bind(
            "<Button-1>",
            card_click
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
    pady=(0, 8)
)


risk_score_label = tk.Label(
    risk_row,
    text="-- / 100",
    bg=PANEL,
    fg=YELLOW,
    font=("Segoe UI", 25, "bold")
)

risk_score_label.pack(
    side="left"
)


risk_status_label = tk.Label(
    risk_row,
    text="  ANALYSIS NOT RUN",
    bg=PANEL,
    fg=MUTED,
    font=("Segoe UI", 10, "bold")
)

risk_status_label.pack(
    side="left",
    pady=(8, 0)
)


# Risk progress bar
risk_bar_frame = tk.Frame(
    risk_panel,
    bg=PANEL_2,
    height=12
)

risk_bar_frame.pack(
    fill="x",
    padx=20,
    pady=(0, 15)
)

risk_bar = tk.Canvas(
    risk_bar_frame,
    height=12,
    bg=PANEL_2,
    highlightthickness=0
)

risk_bar.pack(
    fill="x"
)


# ============================================================
# FULL ANALYSIS
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