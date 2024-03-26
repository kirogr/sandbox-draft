import hashlib
import pefile
from mappings import *


def get_characteristics(flags, characteristics_mapping):
    characteristics = []
    for flag, characteristic in characteristics_mapping.items():
        if flags & flag:
            characteristics.append(characteristic)
    return characteristics

def analyze_program(file_path):
    analysis_report = {}
    try:
        pe = pefile.PE(file_path)

        metadata = {
            "PE_Header": {
                "Machine": pe.FILE_HEADER.Machine,
                "TimeDateStamp": pe.FILE_HEADER.TimeDateStamp,
                "EntryPoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                "FileCharacteristics": get_characteristics(pe.FILE_HEADER.Characteristics, file_characteristics_mapping),
                "DllCharacteristics": get_characteristics(pe.OPTIONAL_HEADER.DllCharacteristics, dll_characteristics_mapping)
            },
            "Imports": {}
        }

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8")
            metadata["Imports"][dll_name] = [func.name.decode("utf-8") for func in entry.imports]

        analysis_report["metadata"] = metadata

        with open(file_path, "rb") as f:
            content = f.read()
            sha1 = hashlib.sha1(content).hexdigest()
            sha256 = hashlib.sha256(content).hexdigest()
            sha512 = hashlib.sha512(content).hexdigest()
            md5 = hashlib.md5(content).hexdigest()

        analysis_report["file_hashes"] = {
            "sha1": sha1,
            "sha256": sha256,
            "sha512": sha512,
            "md5": md5
        }

    except Exception as e:
        analysis_report["error"] = str(e)

    return analysis_report

if __name__ == "__main__":
    file_path = r"ConsoleApp1.exe"
    analysis_result = analyze_program(file_path)
    print(analysis_result)
