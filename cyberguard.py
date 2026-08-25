import hashlib
import math
import re
import sys
from pathlib import Path

import pefile


# ============================================================
# CYBERGUARD — STATIC MALWARE ANALYSIS ENGINE
# ============================================================


# ============================================================
# SUSPICIOUS API DATABASE
# ============================================================

SUSPICIOUS_APIS = {
    # Anti-Debugging
    "IsDebuggerPresent": "Anti-Debugging",
    "CheckRemoteDebuggerPresent": "Anti-Debugging",
    "NtQueryInformationProcess": "Anti-Debugging",
    "OutputDebugStringA": "Anti-Debugging",
    "OutputDebugStringW": "Anti-Debugging",

    # Process / Injection
    "OpenProcess": "Process Access",
    "WriteProcessMemory": "Process Injection",
    "ReadProcessMemory": "Process Memory Access",
    "CreateRemoteThread": "Remote Thread Creation",
    "CreateRemoteThreadEx": "Remote Thread Creation",
    "VirtualAllocEx": "Remote Memory Allocation",
    "VirtualProtectEx": "Remote Memory Protection",
    "QueueUserAPC": "APC Injection",
    "NtWriteVirtualMemory": "Process Injection",
    "NtCreateThreadEx": "Remote Thread Creation",

    # Memory
    "VirtualAlloc": "Memory Allocation",
    "VirtualProtect": "Memory Protection",
    "VirtualFree": "Memory Management",
    "HeapAlloc": "Memory Allocation",

    # Dynamic Loading
    "LoadLibraryA": "Dynamic Loading",
    "LoadLibraryW": "Dynamic Loading",
    "LoadLibraryExA": "Dynamic Loading",
    "LoadLibraryExW": "Dynamic Loading",
    "GetProcAddress": "Dynamic API Resolution",

    # Command / Execution
    "WinExec": "Command Execution",
    "ShellExecuteA": "Command/Shell Execution",
    "ShellExecuteW": "Command/Shell Execution",
    "ShellExecuteExA": "Command/Shell Execution",
    "ShellExecuteExW": "Command/Shell Execution",
    "CreateProcessA": "Process Creation",
    "CreateProcessW": "Process Creation",

    # Download / Network
    "URLDownloadToFileA": "File Download",
    "URLDownloadToFileW": "File Download",
    "InternetOpenA": "Internet Communication",
    "InternetOpenW": "Internet Communication",
    "InternetOpenUrlA": "Internet Communication",
    "InternetOpenUrlW": "Internet Communication",
    "InternetConnectA": "Internet Communication",
    "InternetConnectW": "Internet Communication",
    "HttpOpenRequestA": "HTTP Communication",
    "HttpOpenRequestW": "HTTP Communication",
    "HttpSendRequestA": "HTTP Communication",
    "HttpSendRequestW": "HTTP Communication",
    "WinHttpOpen": "HTTP Communication",
    "WinHttpConnect": "HTTP Communication",
    "WinHttpOpenRequest": "HTTP Communication",
    "WinHttpSendRequest": "HTTP Communication",

    # Registry / Persistence
    "RegCreateKeyA": "Registry Modification",
    "RegCreateKeyW": "Registry Modification",
    "RegCreateKeyExA": "Registry Modification",
    "RegCreateKeyExW": "Registry Modification",
    "RegSetValueExA": "Registry Modification",
    "RegSetValueExW": "Registry Modification",
    "RegOpenKeyA": "Registry Access",
    "RegOpenKeyW": "Registry Access",
    "RegOpenKeyExA": "Registry Access",
    "RegOpenKeyExW": "Registry Access",

    # File System
    "CreateFileA": "File Access",
    "CreateFileW": "File Access",
    "DeleteFileA": "File Deletion",
    "DeleteFileW": "File Deletion",
    "CopyFileA": "File Copy",
    "CopyFileW": "File Copy",
    "MoveFileA": "File Move",
    "MoveFileW": "File Move",

    # Service / Persistence
    "OpenSCManagerA": "Service Management",
    "OpenSCManagerW": "Service Management",
    "CreateServiceA": "Service Creation",
    "CreateServiceW": "Service Creation",
    "StartServiceA": "Service Execution",
    "StartServiceW": "Service Execution",

    # Token / Privileges
    "OpenProcessToken": "Token Access",
    "OpenThreadToken": "Token Access",
    "AdjustTokenPrivileges": "Privilege Manipulation",
    "LookupPrivilegeValueA": "Privilege Discovery",
    "LookupPrivilegeValueW": "Privilege Discovery",
}


# ============================================================
# STRING INDICATOR DATABASE
# ============================================================

STRING_KEYWORDS = {
    "Credential Indicators": [
        "password",
        "passwd",
        "credential",
        "credentials",
        "login",
        "username",
        "userpass",
        "secret",
        "apikey",
        "api_key",
        "token",
    ],

    "Browser / Cookie Indicators": [
        "chrome",
        "msedge",
        "edge",
        "firefox",
        "brave",
        "opera",
        "cookies",
        "cookie",
        "login data",
        "web data",
        "local state",
        "browser",
    ],

    "Persistence Indicators": [
        "startup",
        "runonce",
        "currentversion\\run",
        "\\startup\\",
        "schtasks",
        "scheduled task",
        "service",
    ],

    "Command / Script Indicators": [
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "bitsadmin",
        "certutil",
    ],

    "Network Indicators": [
        "http://",
        "https://",
        "ftp://",
        "socket",
        "user-agent",
        "wininet",
        "winhttp",
    ],

    "File System Indicators": [
        "appdata",
        "temp",
        "system32",
        "programdata",
        "desktop",
        "downloads",
    ],

    "Encryption / Obfuscation Indicators": [
        "crypt",
        "encrypt",
        "decrypt",
        "base64",
        "xor",
        "rc4",
        "aes",
    ],
}


URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE
)

IP_PATTERN = re.compile(
    r"\b(?:"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\."
    r"){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)


# ============================================================
# ENTROPY
# ============================================================

def calculate_entropy(data):
    if not data:
        return 0.0

    frequency = {}

    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1

    entropy = 0.0
    length = len(data)

    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def entropy_label(entropy):
    if entropy >= 7.5:
        return "VERY HIGH — possible packing/obfuscation"
    elif entropy >= 7.0:
        return "HIGH — possible packing/obfuscation"
    elif entropy >= 6.0:
        return "ELEVATED"
    else:
        return "NORMAL"


# ============================================================
# HASH ANALYSIS
# ============================================================

def calculate_hashes(file_path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return (
        md5.hexdigest(),
        sha1.hexdigest(),
        sha256.hexdigest(),
    )


# ============================================================
# STRING EXTRACTION
# ============================================================

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


def find_string_indicators(strings):
    categories = {
        category: []
        for category in STRING_KEYWORDS
    }

    urls = []
    ips = []

    seen_urls = set()
    seen_ips = set()

    for string in strings:
        low = string.lower()

        # Keyword categories
        for category, keywords in STRING_KEYWORDS.items():

            if any(keyword in low for keyword in keywords):

                if string not in categories[category]:
                    categories[category].append(string)

        # URLs
        for match in URL_PATTERN.findall(string):
            if match not in seen_urls:
                seen_urls.add(match)
                urls.append(match)

        # IP addresses
        for match in IP_PATTERN.findall(string):
            if match not in seen_ips:
                seen_ips.add(match)
                ips.append(match)

    return categories, urls, ips


# ============================================================
# PE ANALYSIS
# ============================================================

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
    high_entropy_sections = []

    for section in pe.sections:

        name = section.Name.decode(
            errors="ignore"
        ).rstrip("\x00")

        entropy = calculate_entropy(
            section.get_data()
        )

        raw_size = section.SizeOfRawData

        characteristics = section.Characteristics

        executable = bool(
            characteristics & 0x20000000
        )

        writable = bool(
            characteristics & 0x80000000
        )

        readable = bool(
            characteristics & 0x40000000
        )

        section_info = {
            "name": name,
            "entropy": entropy,
            "raw_size": raw_size,
            "executable": executable,
            "writable": writable,
            "readable": readable,
        }

        sections.append(section_info)

        if entropy >= 7.0:
            high_entropy_sections.append(name)

    imports = []
    suspicious_apis = []

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):

        for entry in pe.DIRECTORY_ENTRY_IMPORT:

            dll = entry.dll.decode(
                errors="ignore"
            )

            dll_imports = []

            for imp in entry.imports:

                if imp.name:

                    name = imp.name.decode(
                        errors="ignore"
                    )

                    dll_imports.append(name)

                    if name in SUSPICIOUS_APIS:

                        suspicious_apis.append(
                            (
                                name,
                                SUSPICIOUS_APIS[name],
                                dll,
                            )
                        )

                else:

                    dll_imports.append(
                        f"Ordinal {imp.ordinal}"
                    )

            imports.append(
                (
                    dll,
                    dll_imports
                )
            )

    timestamp = pe.FILE_HEADER.TimeDateStamp

    try:
        compile_time = pefile.get_pep_timestamp(
            timestamp
        )
    except Exception:
        compile_time = str(timestamp)

    subsystem_map = {
        2: "Windows GUI",
        3: "Windows Console",
        9: "Windows CE GUI",
    }

    subsystem = subsystem_map.get(
        pe.OPTIONAL_HEADER.Subsystem,
        f"Unknown ({pe.OPTIONAL_HEADER.Subsystem})"
    )

    result = {
        "architecture": architecture,

        "entry_point":
            f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}",

        "image_base":
            f"0x{pe.OPTIONAL_HEADER.ImageBase:X}",

        "sections": sections,

        "imports": imports,

        "suspicious_apis":
            suspicious_apis,

        "high_entropy_sections":
            high_entropy_sections,

        "compile_time":
            compile_time,

        "subsystem":
            subsystem,

        "number_of_imported_dlls":
            len(imports),

        "number_of_imports":
            sum(
                len(items)
                for _, items in imports
            ),
    }

    pe.close()

    return result


# ============================================================
# API CATEGORIZATION
# ============================================================

def group_apis(suspicious_apis):

    grouped = {}

    for name, category, dll in suspicious_apis:

        grouped.setdefault(
            category,
            []
        ).append(
            {
                "name": name,
                "dll": dll,
            }
        )

    return grouped


# ============================================================
# RISK ENGINE
# ============================================================

def calculate_risk(
    suspicious_apis,
    string_categories,
    urls,
    ips,
    high_entropy_sections,
):

    score = 0
    reasons = []

    # API contribution
    api_count = len(suspicious_apis)

    if api_count:
        api_points = min(api_count * 5, 30)
        score += api_points

        reasons.append(
            (
                api_points,
                f"{api_count} suspicious API indicator(s) detected"
            )
        )

    # High-risk API categories
    api_categories = {
        category
        for _, category, _ in suspicious_apis
    }

    injection_categories = {
        "Process Injection",
        "Remote Thread Creation",
        "Remote Memory Allocation",
        "APC Injection",
        "Process Memory Access",
    }

    injection_hits = (
        api_categories &
        injection_categories
    )

    if injection_hits:

        score += 15

        reasons.append(
            (
                15,
                "Process manipulation/injection capabilities detected"
            )
        )

    # Credential indicators
    credential_count = len(
        string_categories.get(
            "Credential Indicators",
            []
        )
    )

    if credential_count:

        points = min(
            credential_count * 3,
            15
        )

        score += points

        reasons.append(
            (
                points,
                f"{credential_count} credential-related string indicator(s)"
            )
        )

    # Browser indicators
    browser_count = len(
        string_categories.get(
            "Browser / Cookie Indicators",
            []
        )
    )

    if browser_count:

        points = min(
            browser_count * 2,
            10
        )

        score += points

        reasons.append(
            (
                points,
                f"{browser_count} browser/cookie indicator(s)"
            )
        )

    # Persistence
    persistence_count = len(
        string_categories.get(
            "Persistence Indicators",
            []
        )
    )

    if persistence_count:

        points = min(
            persistence_count * 3,
            15
        )

        score += points

        reasons.append(
            (
                points,
                f"{persistence_count} persistence indicator(s)"
            )
        )

    # Network
    network_count = (
        len(urls) +
        len(ips) +
        len(
            string_categories.get(
                "Network Indicators",
                []
            )
        )
    )

    if network_count:

        points = min(
            network_count * 2,
            10
        )

        score += points

        reasons.append(
            (
                points,
                f"{network_count} network indicator(s)"
            )
        )

    # Entropy
    if high_entropy_sections:

        points = min(
            len(high_entropy_sections) * 10,
            20
        )

        score += points

        reasons.append(
            (
                points,
                "High-entropy PE section(s) detected"
            )
        )

    score = min(score, 100)

    if score >= 70:
        level = "HIGH"

    elif score >= 40:
        level = "MEDIUM"

    else:
        level = "LOW"

    if level == "HIGH":

        assessment = (
            "Multiple static indicators suggest "
            "potentially malicious behavior. "
            "Further dynamic analysis is recommended."
        )

    elif level == "MEDIUM":

        assessment = (
            "Several suspicious static indicators "
            "were identified. Additional analysis "
            "is recommended."
        )

    else:

        assessment = (
            "Limited suspicious indicators were "
            "identified by the current static rules. "
            "This does not prove the sample is benign."
        )

    reasons.sort(
        key=lambda item: item[0],
        reverse=True
    )

    return (
        score,
        level,
        reasons,
        assessment,
    )


# ============================================================
# MAIN ANALYSIS
# ============================================================

def analyze(file_path, mode="full"):

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            "File not found."
        )

    mode = mode.lower()

    output = []

    strings = []
    string_categories = {}
    urls = []
    ips = []

    pe_data = None

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    output += [
        "CYBERGUARD — STATIC MALWARE ANALYSIS",
        "=" * 76,
        f"Sample : {path.name}",
        f"Size   : {path.stat().st_size:,} bytes",
        "",
    ]

    # --------------------------------------------------------
    # HASH
    # --------------------------------------------------------

    if mode in ("full", "hash"):

        md5, sha1, sha256 = calculate_hashes(
            path
        )

        output += [
            "HASH ANALYSIS",
            "-" * 76,
            f"MD5    : {md5}",
            f"SHA1   : {sha1}",
            f"SHA256 : {sha256}",
            "",
        ]

    # --------------------------------------------------------
    # STRINGS
    # --------------------------------------------------------

    if mode in ("full", "strings", "risk"):

        strings = extract_strings(path)

        (
            string_categories,
            urls,
            ips,
        ) = find_string_indicators(strings)

    if mode in ("full", "strings"):

        total_indicators = sum(
            len(values)
            for values in string_categories.values()
        )

        output += [
            "STRING ANALYSIS",
            "-" * 76,
            f"Total printable strings : {len(strings):,}",
            f"Categorized indicators  : {total_indicators:,}",
            f"URLs detected            : {len(urls)}",
            f"IP addresses detected    : {len(ips)}",
            "",
        ]

        for category, values in string_categories.items():

            if not values:
                continue

            output += [
                f"[{category}]",
                "-" * 50,
            ]

            for value in values[:50]:
                output.append(
                    f"  [!] {value}"
                )

            if len(values) > 50:

                output.append(
                    f"  ... {len(values) - 50} more"
                )

            output.append("")

        if urls:

            output += [
                "[URLs]",
                "-" * 50,
            ]

            for url in urls[:100]:
                output.append(
                    f"  [!] {url}"
                )

            output.append("")

        if ips:

            output += [
                "[IP ADDRESSES]",
                "-" * 50,
            ]

            for ip in ips[:100]:
                output.append(
                    f"  [!] {ip}"
                )

            output.append("")

    # --------------------------------------------------------
    # PE
    # --------------------------------------------------------

    if mode in (
        "full",
        "pe",
        "api",
        "entropy",
        "risk",
    ):

        try:

            pe_data = inspect_pe(path)

        except pefile.PEFormatError:

            output += [
                "PE ANALYSIS",
                "-" * 76,
                "Not a valid Windows PE file.",
                "",
            ]

            pe_data = None

    if pe_data and mode in ("full", "pe"):

        output += [
            "PE ANALYSIS",
            "-" * 76,
            f"Architecture       : {pe_data['architecture']}",
            f"Entry Point        : {pe_data['entry_point']}",
            f"Image Base         : {pe_data['image_base']}",
            f"Subsystem           : {pe_data['subsystem']}",
            f"Compile Timestamp   : {pe_data['compile_time']}",
            f"Imported DLLs       : {pe_data['number_of_imported_dlls']}",
            f"Total Imports       : {pe_data['number_of_imports']}",
            f"Sections             : {len(pe_data['sections'])}",
            "",
            "SECTIONS",
            "-" * 76,
        ]

        for section in pe_data["sections"]:

            permissions = ""

            if section["readable"]:
                permissions += "R"

            if section["writable"]:
                permissions += "W"

            if section["executable"]:
                permissions += "X"

            output.append(
                f"{section['name']:<10} "
                f"Size: {section['raw_size']:>9,}  "
                f"Entropy: {section['entropy']:.2f}  "
                f"Permissions: {permissions}"
            )

        output.append("")

    # --------------------------------------------------------
    # API
    # --------------------------------------------------------

    if pe_data and mode in ("full", "api"):

        suspicious = pe_data[
            "suspicious_apis"
        ]

        grouped = group_apis(
            suspicious
        )

        output += [
            "API DETECTION",
            "-" * 76,
            f"Total imported APIs     : {pe_data['number_of_imports']}",
            f"Suspicious APIs         : {len(suspicious)}",
            f"Suspicious categories   : {len(grouped)}",
            "",
        ]

        if grouped:

            for category, values in sorted(
                grouped.items()
            ):

                output += [
                    f"[{category}]",
                    "-" * 50,
                ]

                seen = set()

                for item in values:

                    key = (
                        item["name"],
                        item["dll"]
                    )

                    if key in seen:
                        continue

                    seen.add(key)

                    output.append(
                        f"  [!] {item['name']:<28} "
                        f"DLL: {item['dll']}"
                    )

                output.append("")

        else:

            output += [
                "No predefined suspicious API indicators found.",
                "",
            ]

    # --------------------------------------------------------
    # ENTROPY
    # --------------------------------------------------------

    if pe_data and mode in ("full", "entropy"):

        output += [
            "ENTROPY ANALYSIS",
            "-" * 76,
        ]

        for section in pe_data["sections"]:

            entropy = section["entropy"]

            output.append(
                f"{section['name']:<10} "
                f"Entropy: {entropy:.2f}  "
                f"{entropy_label(entropy)}"
            )

        output.append("")

        if pe_data["high_entropy_sections"]:

            output += [
                "HIGH ENTROPY SECTIONS",
                "-" * 76,
            ]

            for name in pe_data[
                "high_entropy_sections"
            ]:
                output.append(
                    f"  [!] {name}"
                )

            output.append("")

        else:

            output += [
                "No sections exceeded the high-entropy threshold.",
                "",
            ]

    # --------------------------------------------------------
    # RISK
    # --------------------------------------------------------

    if mode in ("full", "risk"):

        suspicious_apis = (
            pe_data["suspicious_apis"]
            if pe_data
            else []
        )

        high_entropy = (
            pe_data["high_entropy_sections"]
            if pe_data
            else []
        )

        (
            score,
            level,
            reasons,
            assessment,
        ) = calculate_risk(
            suspicious_apis,
            string_categories,
            urls,
            ips,
            high_entropy,
        )

        output += [
            "RISK ASSESSMENT",
            "-" * 76,
            f"Risk Score : {score}/100",
            f"Risk Level : {level}",
            "",
            "INDICATORS",
            "-" * 76,
            f"Suspicious APIs        : {len(suspicious_apis)}",
            f"Credential indicators  : "
            f"{len(string_categories.get('Credential Indicators', []))}",
            f"Browser indicators     : "
            f"{len(string_categories.get('Browser / Cookie Indicators', []))}",
            f"Persistence indicators : "
            f"{len(string_categories.get('Persistence Indicators', []))}",
            f"Network indicators     : {len(urls) + len(ips)}",
            f"High-entropy sections  : {len(high_entropy)}",
            "",
            "RISK CONTRIBUTORS",
            "-" * 76,
        ]

        if reasons:

            for points, reason in reasons:

                output.append(
                    f"+{points:02d}  {reason}"
                )

        else:

            output.append(
                "No significant indicators were identified."
            )

        output += [
            "",
            "ASSESSMENT",
            "-" * 76,
            assessment,
            "",
        ]

    return "\n".join(output)


# ============================================================
# COMMAND LINE ENTRY POINT
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) >= 2:

        file_path = sys.argv[1]

        mode = (
            sys.argv[2]
            if len(sys.argv) >= 3
            else "full"
        )

    else:

        file_path = input(
            "Enter the path of the file to analyze: "
        ).strip()

        mode = "full"

    try:

        print(
            analyze(
                file_path,
                mode
            )
        )

    except Exception as error:

        print(
            f"ERROR: {error}"
        )