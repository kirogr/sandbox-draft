import os
import sys
import json
import hashlib
import base64
from io import BytesIO
import pytz
from filetype import guess
from PIL import Image, UnidentifiedImageError
from PyPDF2 import PdfReader
import pefile
from mappings import *
from datetime import datetime
from asn1crypto import cms
import win32ui, win32gui, win32api, win32con
import io
import requests

def get_characteristics(flags, characteristics_mapping):
    return [characteristic for flag, characteristic in characteristics_mapping.items() if flags & flag]

def get_subsystem(pe):
    subsystem_mapping = {0: 'Unknown', 1: 'Native', 2: 'Windows GUI', 3: 'Windows CUI'}
    return subsystem_mapping.get(pe.OPTIONAL_HEADER.Subsystem, 'Unknown')

def file_type(filepath):
    kind = guess(filepath)
    return kind.mime if kind else 'unknown'

def extract_signature_info(pe):
    if not hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
        return {'is_signed': False, 'details': 'No signature found.'}

    signature_data = []
    security = pe.DIRECTORY_ENTRY_SECURITY[0]
    data = security.struct.data

    content_info = cms.ContentInfo.load(data)
    signed_data = content_info['content']

    for signer_info in signed_data['signer_infos']:
        signer_certificates = signed_data['certificates']
        for cert in signer_certificates:
            certificate = cert.chosen

        issuer = certificate.issuer.human_friendly
        subject = certificate.subject.human_friendly

        signing_time = None
        for attribute in signer_info['signed_attrs']:
            if attribute['type'].dotted == '1.2.840.113549.1.9.5':
                signing_time = attribute['values'][0].native

        signature_data.append({
            'issuer': issuer,
            'subject': subject,
            'signing_time': signing_time
        })

    return {
        'is_signed': True,
        'signatures': signature_data
    }

def extract_icon(filepath):
    large, small = win32gui.ExtractIconEx(filepath, 0)
    if not large:
        return None

    icon = large[0] if large else small[0]

    # Convert the HICON to a PIL image
    hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
    hbmp = win32ui.CreateBitmap()
    hbmp.CreateCompatibleBitmap(hdc, 32, 32)
    hdc = hdc.CreateCompatibleDC()

    hdc.SelectObject(hbmp)
    hdc.DrawIcon((0,0), icon)
    bmpstr = hbmp.GetBitmapBits(True)

    img = Image.frombuffer(
        'RGBA',
        (32,32),
        bmpstr, 'raw', 'BGRA', 0, 1
    )
    win32gui.DestroyIcon(icon)

    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    encoded_string = base64.b64encode(buffered.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{encoded_string}"

def get_virustotal_score(file_path):
    api_key = 'API_KEY'
    url = 'https://www.virustotal.com/api/v3/files/upload_url'

    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    upload_url = response.json()['data']

    files = {'file': (file_path, open(file_path, 'rb'))}
    upload_response = requests.post(upload_url, headers=headers, files=files)
    id = upload_response.json()['data']['id']

    report_url = f'https://www.virustotal.com/api/v3/analyses/{id}'
    report_response = requests.get(report_url, headers=headers)
    stats = report_response.json()['data']['attributes']['stats']

    malicious_count = stats.get('malicious', 0)
    total_vendors = sum(stats.values())

    score = 10 * malicious_count / total_vendors if total_vendors else 1
    return min(max(1, round(score)), 10)

def analyze_pe(file_path):
    pe = pefile.PE(file_path)
    machine_type_hex = pe.FILE_HEADER.Machine
    machine_label = MACHINE_TYPES.get(machine_type_hex, "UNKNOWN")

    timestamp = pe.FILE_HEADER.TimeDateStamp
    date_time_utc = datetime.utcfromtimestamp(timestamp).replace(tzinfo=pytz.utc).strftime('%Y-%m-%d %H:%M:%S %Z')

    imports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll and any(func.name for func in entry.imports if func.name is not None):
                dll_name = entry.dll.decode('utf-8')
                imports[dll_name] = [func.name.decode('utf-8') for func in entry.imports if func.name is not None]

    pdb_paths = []
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
            if hasattr(debug_entry.entry, 'PdbFileName') and debug_entry.entry.PdbFileName:
                pdb_path = debug_entry.entry.PdbFileName.decode('utf-8').rstrip('\x00')
                pdb_paths.append(pdb_path)

    pe_metadata = {
        'PE_Header': {
            'Machine': machine_label + f" ({hex(pe.FILE_HEADER.Machine)})",
            'TimeDateStamp': f"{timestamp} ({date_time_utc})",
            'EntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'FileCharacteristics': get_characteristics(pe.FILE_HEADER.Characteristics, file_characteristics_mapping),
            'DllCharacteristics': get_characteristics(pe.OPTIONAL_HEADER.DllCharacteristics, dll_characteristics_mapping)
        },
        'Imports': imports,
        'PDB_Paths': pdb_paths,
        'Subsystem': get_subsystem(pe),
        'Signature': extract_signature_info(pe),
    }
    return pe_metadata

def analyze_pdf(file_path):
    reader = PdfReader(file_path)
    return {
        'PDF_Metadata': {
            'number_of_pages': len(reader.pages),
            'info': reader.metadata
        }
    }

def analyze_image(file_path):
    with Image.open(file_path) as img:
        return {
            'Image_Metadata': {
                'format': img.format,
                'size': img.size,
                'mode': img.mode
            }
        }

def analyze_generic(file_path):
    return {'Generic_File': 'No specific analysis available'}

def analyze_file(file_path):
    analysis_report = {
        'App': {
            'filename': os.path.basename(file_path),
            'size': os.path.getsize(file_path),
            'kind': 'File',
            'icon': extract_icon(file_path),
            'vt_score': get_virustotal_score(file_path),
            'extension': os.path.splitext(file_path)[1]
        },
        'File_Hashes': calculate_hashes(file_path)
    }

    filetype = file_type(file_path)

    if filetype == 'application/x-msdownload':
        analysis_report.update(analyze_pe(file_path))
    elif filetype == 'application/pdf':
        analysis_report.update(analyze_pdf(file_path))
    elif filetype.startswith('image/'):
        analysis_report.update(analyze_image(file_path))
    else:
        analysis_report.update(analyze_generic(file_path))

    return json.dumps(analysis_report, indent=2)

def calculate_hashes(file_path):
    with open(file_path, "rb") as f:
        content = f.read()
        return {
            "sha1": hashlib.sha1(content).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
            "sha512": hashlib.sha512(content).hexdigest(),
            "md5": hashlib.md5(content).hexdigest()
        }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[!] Error: No file path provided.")
        sys.exit(1)

    file_path = sys.argv[1]
    print(analyze_file(file_path))
