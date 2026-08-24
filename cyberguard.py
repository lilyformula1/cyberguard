import hashlib
from pathlib import Path


def calculate_hashes(file_path):
    file_path = Path(file_path)

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


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