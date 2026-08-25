import hashlib
import math
from pathlib import Path
import pefile

SUSPICIOUS_APIS = {
    "IsDebuggerPresent": "Anti-Debugging",
    "CheckRemoteDebuggerPresent": "Anti-Debugging",
    "VirtualAlloc": "Memory Allocation",
    "VirtualProtect": "Memory Protection",
    "WriteProcessMemory": "Process Memory Manipulation",
    "CreateRemoteThread": "Remote Thread Creation",
    "OpenProcess": "Process Access",
    "LoadLibraryA": "Dynamic Loading",
    "LoadLibraryW": "Dynamic Loading",
    "LoadLibraryExA": "Dynamic Loading",
    "LoadLibraryExW": "Dynamic Loading",
    "WinExec": "Command Execution",
    "ShellExecuteA": "Command/Shell Execution",
    "ShellExecuteW": "Command/Shell Execution",
    "URLDownloadToFileA": "File Download",
    "URLDownloadToFileW": "File Download",
    "RegSetValueExA": "Registry Modification",
    "RegSetValueExW": "Registry Modification",
}

SUSPICIOUS_STRING_KEYWORDS = [
    "powershell", "cmd.exe", "wscript", "cscript", "password", "passwd",
    "cookie", "appdata", "startup", "runonce", "http://", "https://", "ftp://",
]


def calculate_entropy(data):
    if not data:
        return 0.0
    frequency = {}
    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in frequency.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def calculate_hashes(file_path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def extract_strings(file_path, min_length=4):
    with open(file_path, "rb") as f:
        data = f.read()
    strings = []
    current = ""
    for byte in data:
        if 32 <= byte <= 126:
            current += chr(byte)
        else:
            if len(current) >= min_length:
                strings.append(current)
            current = ""
    if len(current) >= min_length:
        strings.append(current)
    return strings


def find_suspicious_strings(strings):
    found = []
    for string in strings:
        low = string.lower()
        if any(keyword in low for keyword in SUSPICIOUS_STRING_KEYWORDS):
            found.append(string)
    return found


def inspect_pe(file_path):
    pe = pefile.PE(file_path)
    machine = pe.FILE_HEADER.Machine
    if machine == 0x8664:
        architecture = "x64"
    elif machine == 0x14C:
        architecture = "x86"
    else:
        architecture = f"Unknown (0x{machine:X})"

    sections = []
    entropy_sections = []
    imports = []
    suspicious_apis = []

    for section in pe.sections:
        name = section.Name.decode(errors="ignore").rstrip("\x00")
        entropy = calculate_entropy(section.get_data())
        sections.append((name, entropy, section.SizeOfRawData))
        if entropy >= 7.0:
            entropy_sections.append(name)

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore")
            dll_imports = []
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode(errors="ignore")
                    dll_imports.append(name)
                    if name in SUSPICIOUS_APIS:
                        suspicious_apis.append((name, SUSPICIOUS_APIS[name], dll))
                else:
                    dll_imports.append(f"Ordinal {imp.ordinal}")
            imports.append((dll, dll_imports))

    result = {
        "architecture": architecture,
        "entry_point": f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}",
        "image_base": f"0x{pe.OPTIONAL_HEADER.ImageBase:X}",
        "sections": sections,
        "imports": imports,
        "suspicious_apis": suspicious_apis,
        "high_entropy_sections": entropy_sections,
    }
    pe.close()
    return result


def risk_score(suspicious_apis, suspicious_strings, high_entropy_sections):
    score = min(
        min(len(suspicious_apis) * 10, 40)
        + min(len(suspicious_strings) * 5, 30)
        + min(len(high_entropy_sections) * 15, 30),
        100,
    )
    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level


def analyze(file_path, mode="full"):
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError("File not found.")

    mode = mode.lower()
    output = []
    md5 = sha1 = sha256 = None
    strings = []
    suspicious_strings = []
    pe_data = None

    output += [
        "CYBERGUARD — STATIC MALWARE ANALYSIS",
        "=" * 72,
        f"Sample : {path.name}",
        f"Size   : {path.stat().st_size:,} bytes",
        "",
    ]

    if mode in ("full", "hash"):
        md5, sha1, sha256 = calculate_hashes(path)
        output += [
            "HASH ANALYSIS",
            "-" * 72,
            f"MD5    : {md5}",
            f"SHA1   : {sha1}",
            f"SHA256 : {sha256}",
            "",
        ]

    if mode in ("full", "strings", "risk"):
        strings = extract_strings(path)
        suspicious_strings = find_suspicious_strings(strings)

    if mode in ("full", "strings"):
        output += [
            "STRING ANALYSIS",
            "-" * 72,
            f"Total printable strings : {len(strings):,}",
            f"Suspicious indicators   : {len(suspicious_strings)}",
            "",
        ]
        for s in suspicious_strings[:100]:
            output.append(f"[!] {s}")
        output.append("")

    if mode in ("full", "pe", "api", "entropy", "risk"):
        try:
            pe_data = inspect_pe(path)
        except pefile.PEFormatError:
            output += ["PE ANALYSIS", "-" * 72, "Not a valid Windows PE file.", ""]
            pe_data = None

    if pe_data and mode in ("full", "pe"):
        output += [
            "PE ANALYSIS",
            "-" * 72,
            f"Architecture : {pe_data['architecture']}",
            f"Entry Point  : {pe_data['entry_point']}",
            f"Image Base   : {pe_data['image_base']}",
            f"Sections     : {len(pe_data['sections'])}",
            "",
            "Sections:",
        ]
        for name, entropy, raw_size in pe_data["sections"]:
            output.append(f"  {name:<10} Raw Size: {raw_size:>8,}  Entropy: {entropy:.2f}")
        output.append("")

    if pe_data and mode in ("full", "api"):
        output += ["API DETECTION", "-" * 72]
        if pe_data["suspicious_apis"]:
            for name, category, dll in pe_data["suspicious_apis"]:
                output.append(f"[!] {name}  |  {category}  |  {dll}")
        else:
            output.append("No predefined suspicious API indicators found.")
        output.append("")

    if pe_data and mode in ("full", "entropy"):
        output += ["ENTROPY ANALYSIS", "-" * 72]
        for name, entropy, _ in pe_data["sections"]:
            marker = "  [!] HIGH ENTROPY" if entropy >= 7.0 else ""
            output.append(f"{name:<10} Entropy: {entropy:.2f}{marker}")
        output.append("")

    if mode in ("full", "risk"):
        apis = pe_data["suspicious_apis"] if pe_data else []
        high_entropy = pe_data["high_entropy_sections"] if pe_data else []
        score, level = risk_score(apis, suspicious_strings, high_entropy)
        output += [
            "RISK ASSESSMENT",
            "-" * 72,
            f"Risk Score : {score}/100",
            f"Risk Level : {level}",
            "",
            "Indicators:",
            f"  Suspicious APIs       : {len(apis)}",
            f"  Suspicious strings    : {len(suspicious_strings)}",
            f"  High-entropy sections : {len(high_entropy)}",
            "",
        ]

    return "\n".join(output)

if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 2:
        file_path = sys.argv[1]
        mode = sys.argv[2] if len(sys.argv) >= 3 else "full"
    else:
        file_path = input("Enter the path of the file to analyze: ").strip()
        mode = "full"

    try:
        print(analyze(file_path, mode))
    except Exception as e:
        print(f"ERROR: {e}")