#!/usr/bin/env python3
"""
Export WeChat Encrypted Database to Unencrypted SQLite
Simple script to convert encrypted EnMicroMsg.db to plain SQLite database
"""

import sys
from pathlib import Path
from pysqlcipher3 import dbapi2 as sqlite


def export_decrypted_database(encrypted_db, password, output_db):
    """
    Export encrypted WeChat database to unencrypted SQLite file

    Args:
        encrypted_db: Path to encrypted EnMicroMsg.db
        password: Database password (7-char hex from Frida)
        output_db: Path for output unencrypted database
    """

    print("=" * 80)
    print("WeChat Database Decryption Export Tool")
    print("=" * 80)

    # Validate input file
    if not Path(encrypted_db).exists():
        print(f"[!] Error: Input database not found: {encrypted_db}")
        return False

    input_size = Path(encrypted_db).stat().st_size / 1024 / 1024
    print(f"\n[*] Input database: {encrypted_db}")
    print(f"[*] Input size: {input_size:.2f} MB")
    print(f"[*] Password: {password}")
    print(f"[*] Output database: {output_db}")

    # Check if output exists
    if Path(output_db).exists():
        print(f"\n[!] Warning: Output file already exists: {output_db}")
        response = input("Overwrite? (y/n): ").strip().lower()
        if response != 'y':
            print("[!] Export cancelled")
            return False
        Path(output_db).unlink()
        print("[+] Deleted existing file")

    try:
        # Connect to encrypted database
        print("\n[*] Connecting to encrypted database...")
        conn = sqlite.connect(encrypted_db)
        cursor = conn.cursor()

        # Set WCDB decryption parameters
        cursor.execute(f"PRAGMA key = '{password}'")
        cursor.execute("PRAGMA cipher_use_hmac = OFF")
        cursor.execute("PRAGMA cipher_page_size = 1024")
        cursor.execute("PRAGMA kdf_iter = 4000")
        cursor.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA1")
        cursor.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1")

        # Verify decryption
        cursor.execute("SELECT count(*) FROM sqlite_master")
        table_count = cursor.fetchone()[0]
        print(f"[+] Database decrypted successfully")
        print(f"[+] Found {table_count} tables/indexes")

        # Attach unencrypted database
        print(f"\n[*] Creating unencrypted database: {output_db}")
        cursor.execute(f"ATTACH DATABASE '{output_db}' AS plaintext KEY ''")
        print("[+] Attached plaintext database")

        # Export all data
        print("[*] Exporting data (this may take a while for large databases)...")
        cursor.execute("SELECT sqlcipher_export('plaintext')")
        print("[+] Data export complete")

        # Detach
        cursor.execute("DETACH DATABASE plaintext")
        conn.close()
        print("[+] Database detached and closed")

        # Verify output
        if Path(output_db).exists():
            output_size = Path(output_db).stat().st_size / 1024 / 1024
            print("\n" + "=" * 80)
            print("SUCCESS!")
            print("=" * 80)
            print(f"[+] Decrypted database exported successfully!")
            print(f"[+] Output file: {output_db}")
            print(f"[+] Output size: {output_size:.2f} MB")
            print(f"\n[+] You can now open this file with standard SQLite tools:")
            print(f"    sqlite3 {output_db}")
            print(f"    DB Browser for SQLite")
            print(f"    Python sqlite3 module")
            return True
        else:
            print("\n[!] Error: Output file was not created")
            return False

    except Exception as e:
        print(f"\n[!] Error during export: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main function with command line argument support"""

    # Default values (can be overridden by command line arguments)
    default_encrypted_db = "EnMicroMsg.db"
    default_password = "874986d"  # Update this to your password
    default_output_db = "EnMicroMsg_decrypted.db"

    # Parse command line arguments
    if len(sys.argv) > 1:
        encrypted_db = sys.argv[1]
    else:
        encrypted_db = default_encrypted_db

    if len(sys.argv) > 2:
        password = sys.argv[2]
    else:
        password = default_password

    if len(sys.argv) > 3:
        output_db = sys.argv[3]
    else:
        output_db = default_output_db

    # Show usage if help requested
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']:
        print("WeChat Database Decryption Export Tool")
        print("\nUsage:")
        print(f"  python {sys.argv[0]} [encrypted_db] [password] [output_db]")
        print("\nExamples:")
        print(f"  python {sys.argv[0]}")
        print(f"  python {sys.argv[0]} EnMicroMsg.db 874986d")
        print(f"  python {sys.argv[0]} EnMicroMsg.db 874986d decrypted.db")
        print("\nDefault values:")
        print(f"  encrypted_db: {default_encrypted_db}")
        print(f"  password: {default_password}")
        print(f"  output_db: {default_output_db}")
        return

    # Run export
    success = export_decrypted_database(encrypted_db, password, output_db)

    if success:
        print("\n[+] Done!")
        sys.exit(0)
    else:
        print("\n[!] Export failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
