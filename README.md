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
python queries/query_tool.py -db windows_scan.db high_entropy --threshold 7.8
```

**Find files with missing version info:**

```sh
python queries/query_tool.py -db windows_scan.db missing_info
```

**Find files with a packed .text section:**

```sh
python queries/query_tool.py -db windows_scan.db text_section --threshold 7.0
```

### Advanced Usage (Manual SQL)

The `queries/sql/` folder contains the raw SQL for the pre-defined queries. You can use a tool like [DB Browser for SQLite](https://sqlitebrowser.org/) to open your .db file and run these queries manually or write your own.