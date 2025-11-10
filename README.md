# PY-SPECTOR

A simple Python tool to scan Windows PE files for version information and section entropy. Data is logged to an SQLite database, which can then be queried for analysis.

## Features

* Scans `.exe`, `.dll`, and `.cpl` files recursively from a given path.
* Extracts full `VS_VERSIONINFO` (Company, Product, Copyright, etc.).
* Calculates Shannon entropy for each PE section (useful for finding packed/encrypted data).
* Logs all findings to a portable `SQLite` database.
* Includes a query tool to find common anomalies.

## Installation

1.  Clone the repository:
    ```sh
    git clone https://github.com/Herkkomehtala/PY-SPECTOR
    cd PY-SPECTOR
    ```
2.  Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## 📊 Usage

Using the tool is a two-step process: first, you scan a directory to build the database, and second, you query that database.

### Step 1: Scan and Create Database

Use `bin_analyzer.py` to scan a target. The database file will be created in your project directory.

**Scan an entire directory:**
```sh
# Scan C:\Windows and save results to 'windows_scan.db'
python bin_analyzer.py "C:\Windows" -db windows_scan.db

# Or scan a single file:

# Scan notepad.exe and use the default 'binary_info.db'
python bin_analyzer.py "C:\Windows\System32\notepad.exe"
```

### Step 2: Query the Database

Use the `queries/query_tool.py` script to run pre-defined analyses on your database.

**Find files with high average entropy (such as packed binaries):**  

```sh
# Use the default threshold of 7.5
python queries/query_tool.py -db windows_scan.db high_entropy

# Specify a custom threshold
python queries/query_tool.py -db windows_scan.db high_entropy --threshold 6.0
--- Querying Database: C:\Users\user\PE-SPECTOR\binary_info.db ---
[*] Querying for files with avg. entropy > 6.0...

  --- Found 2 matching files ---
  ('Path', 'Avg. Entropy', 'Company', 'Product')
  ----------------------------------------------------------------------
  ('C:\\Windows\\System32\\AppV\\AppVStreamingUX.exe', '6.8989', 'Microsoft Corporation', 'Microsoft® Windows® Operating System')
  ('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe', '6.3187', 'Microsoft Corporation', 'Microsoft® Windows® Operating System')
```

**Find files with missing version info:**

```sh
python queries/query_tool.py -db windows_scan.db missing_info
--- Querying Database: C:\Users\user\PE-SPECTOR\binary_info.db ---
[*] Querying for files with missing version info...

  --- Found 91 matching files ---
  ('Path', 'Avg. Entropy')
  ----------------------------------------------------------------------
  ('C:\\Windows\\System32\\Windows.UI.Input.Inking.Analysis.dll', '5.5738')
  ('C:\\Windows\\System32\\DMRCDecoder.dll', '5.5322')
  [...]
```

**Find files with a packed .text section:**

```sh
python queries/query_tool.py -db windows_scan.db text_section --threshold 7.0
--- Querying Database: C:\Users\user\PE-SPECTOR\binary_info.db ---

  --- Found 10 matching files ---
  ('Path', '.text Entropy', 'Product')
  ----------------------------------------------------------------------
  ('C:\\Windows\\System32\\en-GB\\fhuxpresentation.Resources.dll', '7.7455', 'Microsoft (R) Windows (R) Operating System')
  ('C:\\Windows\\System32\\en\\fhuxpresentation.Resources.dll', '7.7432', 'Microsoft (R) Windows (R) Operating System')
  [...]
```

### Advanced Usage (Manual SQL)

The `queries/sql/` folder contains the raw SQL for the pre-defined queries. You can use a tool like [DB Browser for SQLite](https://sqlitebrowser.org/) to open your .db file and run these queries manually or write your own.

### Why?

I've been using this tool in a few blue team/forensic CTF's to get quick data on all the binaries in the system. Recently I've also been using this tool to get a baseline for what types of binaries are on a base Windows machine to better masquarade red team payloads. After noticing the utility of the tool, I decided to release it. Maybe someone will find use for it as well.