import sqlite3
import argparse
import sys
import os

DEFAULT_DB_NAME = "binary_info.db"

def print_results(results, headers):
    """
    Helper function to pretty-print query results to the console.
    
    Args:
        results (list): A list of tuples, where each tuple is a row.
        headers (str): A string representing the column headers.
    """
    if not results:
        print("  -> No results found for this query.")
        return

    print(f"\n  --- Found {len(results)} matching files ---")
    print(f"  {headers}")
    print("  " + "-" * 70)
    
    for row in results:
        formatted_row = []
        for item in row:
            if isinstance(item, float):
                formatted_row.append(f"{item:.4f}")
            else:
                formatted_row.append(str(item))
        print(f"  {tuple(formatted_row)}")

def query_high_entropy(conn, threshold=7.5):
    """
    Finds all files with an average entropy over a given threshold.
    """
    print(f"[*] Querying for files with avg. entropy > {threshold}...")
    c = conn.cursor()
    query = """
        SELECT path, avg_entropy, company_name, product_name
        FROM binaries
        WHERE avg_entropy > ?
        ORDER BY avg_entropy DESC;
    """
    c.execute(query, (threshold,))
    results = c.fetchall()
    print_results(results, headers="('Path', 'Avg. Entropy', 'Company', 'Product')")

def query_missing_info(conn):
    """
    Finds files with NULL/missing version info fields.
    """
    print(f"[*] Querying for files with missing version info...")
    c = conn.cursor()
    query = """
        SELECT path, avg_entropy
        FROM binaries
        WHERE company_name IS NULL
           OR file_description IS NULL
           OR product_name IS NULL
        ORDER BY avg_entropy DESC;
    """
    c.execute(query)
    results = c.fetchall()
    print_results(results, headers="('Path', 'Avg. Entropy')")

def query_high_entropy_text_section(conn, threshold=7.0):
    """
    Finds files with a high-entropy .text section.
    """
    print(f"[*] Querying for files with .text section entropy > {threshold}...")
    c = conn.cursor()
    
    # This query uses the json_each and json_extract functions in SQLite
    # Make sure your SQLite version isn't too old.
    query = """
        SELECT
            b.path,
            json_extract(j.value, '$.entropy') AS text_entropy,
            b.product_name
        FROM
            binaries b,
            json_each(b.section_entropy_json) j
        WHERE
            json_extract(j.value, '$.name') = '.text'
            AND json_extract(j.value, '$.entropy') > ?
        ORDER BY
            text_entropy DESC;
    """
    try:
        c.execute(query, (threshold,))
        results = c.fetchall()
        print_results(results, headers="('Path', '.text Entropy', 'Product')")
    except sqlite3.OperationalError as e:
        print(f"\n  [!] SQL ERROR: {e}")
        print("  [!] This query failed. Your version of SQLite might be too old")
        print("  [!] or it lacks the JSON1 extension (required for this query).")


def main():
    """
    Parses arguments and routes to the correct query function.
    """
    parser = argparse.ArgumentParser(
        description="Query the binary_info.db.",
        epilog="Example: python query_tool.py -db my_scan.db high_entropy -t 7.8"
    )
    
    parser.add_argument(
        "-db", "--database",
        metavar="DB_PATH",
        type=str,
        default=DEFAULT_DB_NAME,
        help=f"Path to the SQLite database file (default: {DEFAULT_DB_NAME})"
    )
    
    subparsers = parser.add_subparsers(
        dest="query", 
        required=True,
        help="The query to run."
    )

    p_high = subparsers.add_parser(
        "high_entropy", 
        help="Find files with high avg. entropy (packed/encrypted)."
    )
    p_high.add_argument(
        "-t", "--threshold", 
        type=float, 
        default=7.5,
        help="Entropy threshold (0.0 to 8.0, default: 7.5)"
    )
    
    p_miss = subparsers.add_parser(
        "missing_info", 
        help="Find files with missing version info (suspicious)."
    )

    p_text = subparsers.add_parser(
        "text_section", 
        help="Find files with high .text section entropy (packed)."
    )
    p_text.add_argument(
        "-t", "--threshold", 
        type=float, 
        default=7.0,
        help="Entropy threshold (0.0 to 8.0, default: 7.0)"
    )

    args = parser.parse_args()
    
    db_path = args.database
    
    if not os.path.exists(db_path):
        print(f"Error: Database file not found at '{os.path.abspath(db_path)}'")
        print("Please run the bin_analyzer.py script first, or specify")
        print("the correct path using the -db / --database argument.")
        sys.exit(1)

    try:
        conn = sqlite3.connect(db_path)
    except sqlite3.Error as e:
        print(f"Error connecting to database '{db_path}': {e}")
        sys.exit(1)

    print(f"--- Querying Database: {os.path.abspath(db_path)} ---")

    if args.query == "high_entropy":
        query_high_entropy(conn, args.threshold)
    
    elif args.query == "missing_info":
        query_missing_info(conn)

    elif args.query == "text_section":
        query_high_entropy_text_section(conn, args.threshold)

    print("\n--- Query complete ---")
    conn.close()

if __name__ == "__main__":
    main()