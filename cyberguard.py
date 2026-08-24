import hashlib
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
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "password",
    "passwd",
    "cookie",
    "appdata",
    "startup",
    "runonce",
    "http://",
    "https://",
    "ftp://",
]

def extract_strings(file_path, min_length=4):
    with open(file_path, "rb") as file:
        data = file.read()

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

def calculate_hashes(file_path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)

        machine = pe.FILE_HEADER.Machine

        if machine == 0x8664:
            architecture = "x64"
        elif machine == 0x14C:
            architecture = "x86"
        else:
            architecture = f"Unknown (0x{machine:X})"

        print("\n=== PE Analysis ===")
        print("File Type    : Windows PE")
        print(f"Architecture : {architecture}")
        print(f"Entry Point  : 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
        print(f"Image Base   : 0x{pe.OPTIONAL_HEADER.ImageBase:X}")
        print(f"Sections     : {len(pe.sections)}")

        print("\nSections:")
        for section in pe.sections:
            name = section.Name.decode(errors="ignore").rstrip("\x00")
            print(f"  {name}")

        print("\n=== Imported DLLs ===")

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="ignore")
                print(f"\n{dll_name}")

                for imp in entry.imports:
                    if imp.name:
                        function_name = imp.name.decode(errors="ignore")
                        print(f"  - {function_name}")
                    else:
                        print(f"  - Ordinal {imp.ordinal}")
                else:
                 print("No imports found.")

        print("\n=== Suspicious API Indicators ===")

        suspicious_found = []

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        function_name = imp.name.decode(errors="ignore")

                        if function_name in SUSPICIOUS_APIS:
                            category = SUSPICIOUS_APIS[function_name]
                            suspicious_found.append((function_name, category))

        if suspicious_found:
            for function_name, category in suspicious_found:
                print(f"[!] {function_name}")
                print(f"    Category: {category}")
        else:
            print("No predefined suspicious API indicators found.")

        pe.close()

    except pefile.PEFormatError:
        print("\nFile Type    : Not a valid Windows PE file")


file_path = input("Enter the path of the file to analyze: ")
path = Path(file_path)

if not path.is_file():
    print("File not found.")
else:
    md5, sha1, sha256 = calculate_hashes(path)

    print("\n=== CyberGuard File Analysis ===")
    print(f"File Name : {path.name}")
    print(f"File Size : {path.stat().st_size} bytes")
    print(f"MD5      : {md5}")
    print(f"SHA1     : {sha1}")
    print(f"SHA256   : {sha256}")

    analyze_pe(path)

    strings = extract_strings(path)

    print("\n=== Strings Analysis ===")
    print(f"Total strings found: {len(strings)}")

    interesting_strings = []

    for string in strings:
        lower_string = string.lower()

        for keyword in SUSPICIOUS_STRING_KEYWORDS:
            if keyword in lower_string:
                interesting_strings.append(string)
                break

    print("\n=== Interesting String Indicators ===")

    if interesting_strings:
        for string in interesting_strings[:50]:
            print(f"[!] {string}")
    else:
        print("No interesting string indicators found.")
