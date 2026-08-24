import hashlib
from pathlib import Path
import pefile


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