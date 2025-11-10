import os
import sys
import json
import math
import sqlite3
import ctypes
import pefile
import argparse
from ctypes import wintypes

DB_NAME = "binary_info.db"

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a bytes sequence."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for count in counts:
        if count:
            p_x = count / len(data)
            entropy -= p_x * math.log2(p_x)
    return entropy

def get_section_entropy(filepath):
    """Extract entropy per section from a PE binary."""
    try:
        pe = pefile.PE(filepath, fast_load=True)
        sections = []
        entropies = []
        for s in pe.sections:
            name = s.Name.decode(errors="ignore").strip("\x00")
            e = calculate_entropy(s.get_data())
            sections.append({"name": name, "entropy": e})
            entropies.append(e)
        pe.close()
        avg = sum(entropies) / len(entropies) if entropies else 0.0
        return json.dumps(sections, ensure_ascii=False), avg
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False), None

def get_file_version_info(filepath):
    """Extract version information from a Windows PE binary using Win32 API."""
    size = ctypes.windll.version.GetFileVersionInfoSizeW(filepath, None)
    if not size:
        return {}

    res = ctypes.create_string_buffer(size)
    ctypes.windll.version.GetFileVersionInfoW(filepath, 0, size, res)

    # Get translation table
    lptr = ctypes.c_void_p()
    lsize = wintypes.UINT()
    r = ctypes.windll.version.VerQueryValueW(
        res, u"\\VarFileInfo\\Translation", ctypes.byref(lptr), ctypes.byref(lsize)
    )
    if not r or not lsize.value:
        return {}

    lang, codepage = ctypes.cast(lptr.value, ctypes.POINTER(wintypes.WORD))[0:2]

    fields = [
        "CompanyName",
        "FileDescription",
        "FileVersion",
        "InternalName",
        "LegalCopyright",
        "OriginalFilename",
        "ProductName",
        "ProductVersion",
        "Comments",
    ]

    info = {}
    for field in fields:
        sub_block = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\{field}"
        val_ptr = ctypes.c_wchar_p()
        val_size = wintypes.UINT()
        if ctypes.windll.version.VerQueryValueW(
            res, sub_block, ctypes.byref(val_ptr), ctypes.byref(val_size)
        ):
            if val_ptr.value:
                info[field] = val_ptr.value.strip()

    return info

def init_db(db_path):
    """Create SQLite table if not exists."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS binaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT UNIQUE,
            company_name TEXT,
            file_description TEXT,
            file_version TEXT,
            internal_name TEXT,
            copyright TEXT,
            original_filename TEXT,
            product_name TEXT,
            product_version TEXT,
            comments TEXT,
            section_entropy_json TEXT,
            avg_entropy REAL
        );
    """
    )
    conn.commit()
    return conn


def insert_record(conn, path, info, section_entropy_json, avg_entropy):
    """Insert or replace a record in the database."""
    c = conn.cursor()
    c.execute(
        """
        INSERT OR REPLACE INTO binaries (
            path, company_name, file_description, file_version,
            internal_name, copyright, original_filename,
            product_name, product_version, comments,
            section_entropy_json, avg_entropy
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """,
        (
            path,
            info.get("CompanyName"),
            info.get("FileDescription"),
            info.get("FileVersion"),
            info.get("InternalName"),
            info.get("LegalCopyright"),
            info.get("OriginalFilename"),
            info.get("ProductName"),
            info.get("ProductVersion"),
            info.get("Comments"),
            section_entropy_json,
            avg_entropy,
        ),
    )
    conn.commit()

def process_file(filepath, conn):
    """
    Process a single binary: get info, get entropy, and insert into DB.
    """
    print(f"Scanning: {filepath}")
    try:
        info = get_file_version_info(filepath)
        section_entropy_json, avg_entropy = get_section_entropy(filepath)
        insert_record(conn, filepath, info, section_entropy_json, avg_entropy)
    except Exception as e:
        print(f"  Error processing {filepath}: {e}")

def scan_folder(folder_path, db_path=DB_NAME):
    """Scan folder for binaries and store their metadata and entropy in SQLite."""
    conn = init_db(db_path)
    extensions = (".exe", ".dll", ".cpl")

    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith(extensions):
                full_path = os.path.join(root, file)
                process_file(full_path, conn)

    conn.close()
    print(f"\n✅ Scan complete. Data saved to: {os.path.abspath(db_path)}")

def scan_single_file(filepath, db_path=DB_NAME):
    """Scan a single binary and store its metadata and entropy in SQLite."""
    conn = init_db(db_path)
    process_file(filepath, conn)
    conn.close()
    print(f"\n✅ Scan complete. Data saved to: {os.path.abspath(db_path)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scan Windows binaries for Version Info and Section Entropy.",
        epilog="The provided path can be a single file or a directory to scan recursively."
    )
    parser.add_argument(
        "scan_path",
        metavar="PATH",
        type=str,
        help="Path to the directory or single file to scan."
    )
    parser.add_argument(
        "-db", "--database",
        metavar="DB_PATH",
        type=str,
        default=DB_NAME,
        help=f"Path to the SQLite database file (default: {DB_NAME})"
    )
    args = parser.parse_args()
    
    path_to_scan = args.scan_path
    db_path = args.database

    if os.path.isdir(path_to_scan):
        print(f"Scanning directory: {path_to_scan}")
        print(f"Saving results to: {os.path.abspath(db_path)}")
        scan_folder(path_to_scan, db_path)
    elif os.path.isfile(path_to_scan):
        print(f"Scanning single file: {path_to_scan}")
        print(f"Saving results to: {os.path.abspath(db_path)}")
        scan_single_file(path_to_scan, db_path)
    else:
        print(f"Error: '{path_to_scan}' is not a valid directory or file.")
        sys.exit(1)