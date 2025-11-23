#!/usr/bin/env python3
"""
WeChat Database Decryption Tool
Simple tool to pull and decrypt WeChat EnMicroMsg.db database
"""

import subprocess
from pathlib import Path
from pysqlcipher3 import dbapi2 as sqlite


def pull_database_from_device(remote_path=None, local_path="EnMicroMsg.db"):
    """
    Pull EnMicroMsg.db from Android device using adb

    Args:
        remote_path: Path on device (auto-detected if None)
        local_path: Local destination path

    Returns:
        Path to pulled database or None if failed
    """
    print("[*] Pulling database from Android device...")

    if not remote_path:
        # Auto-detect database path
        cmd = 'adb shell su -c "find /data/data/com.tencent.mm/MicroMsg -name EnMicroMsg.db"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0 and result.stdout.strip():
            paths = result.stdout.strip().split('\n')
            # Filter out backup/recovery paths, get the main database
            main_paths = [p for p in paths if 'recovery' not in p and 'backup' not in p]
            if main_paths:
                remote_path = main_paths[0]
                print(f"[+] Found database: {remote_path}")
            else:
                remote_path = paths[0]
        else:
            print("[!] Cannot find database. Please specify path manually.")
            return None

    # Pull the database
    local_path = Path(local_path)
    cmd = f'adb shell su -c "cat {remote_path}" > {local_path}'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if local_path.exists() and local_path.stat().st_size > 0:
        size_mb = local_path.stat().st_size / 1024 / 1024
        print(f"[+] Database pulled successfully: {local_path}")
        print(f"[+] Size: {size_mb:.2f} MB")
        return str(local_path)
    else:
        print("[!] Failed to pull database")
        return None


def test_decryption(db_path, password):
    """
    Test if database can be decrypted with given password

    Args:
        db_path: Path to encrypted database
        password: Decryption password

    Returns:
        True if decryption successful, False otherwise
    """
    try:
        conn = sqlite.connect(db_path)
        cursor = conn.cursor()

        # Set WCDB decryption parameters
        cursor.execute(f"PRAGMA key = '{password}'")
        cursor.execute("PRAGMA cipher_use_hmac = OFF")
        cursor.execute("PRAGMA cipher_page_size = 1024")
        cursor.execute("PRAGMA kdf_iter = 4000")
        cursor.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA1")
        cursor.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1")

        # Test decryption
        cursor.execute("SELECT count(*) FROM sqlite_master")
        count = cursor.fetchone()[0]

        conn.close()
        return True, count

    except Exception as e:
        return False, str(e)


def export_decrypted_database(encrypted_db, password, output_db="EnMicroMsg_decrypted.db"):
    """
    Export encrypted database to unencrypted SQLite file

    Args:
        encrypted_db: Path to encrypted database
        password: Decryption password
        output_db: Output path for decrypted database

    Returns:
        True if export successful, False otherwise
    """
    print(f"[*] Exporting decrypted database...")
    print(f"[*] Input: {encrypted_db}")
    print(f"[*] Output: {output_db}")
    print(f"[*] Password: {password}")

    # Check if output exists
    if Path(output_db).exists():
        print(f"[!] {output_db} already exists, deleting...")
        Path(output_db).unlink()

    try:
        # Connect to encrypted database
        conn = sqlite.connect(encrypted_db)
        cursor = conn.cursor()

        # Set decryption parameters
        cursor.execute(f"PRAGMA key = '{password}'")
        cursor.execute("PRAGMA cipher_use_hmac = OFF")
        cursor.execute("PRAGMA cipher_page_size = 1024")
        cursor.execute("PRAGMA kdf_iter = 4000")
        cursor.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA1")
        cursor.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1")

        # Verify decryption
        cursor.execute("SELECT count(*) FROM sqlite_master")
        table_count = cursor.fetchone()[0]
        print(f"[+] Found {table_count} tables/indexes")

        # Export to unencrypted database
        cursor.execute(f"ATTACH DATABASE '{output_db}' AS plaintext KEY ''")
        cursor.execute("SELECT sqlcipher_export('plaintext')")
        cursor.execute("DETACH DATABASE plaintext")

        conn.close()

        # Verify output
        if Path(output_db).exists():
            size_mb = Path(output_db).stat().st_size / 1024 / 1024
            print(f"[+] Export successful!")
            print(f"[+] Decrypted database: {output_db}")
            print(f"[+] Size: {size_mb:.2f} MB")
            return True
        else:
            print("[!] Export failed - output file not created")
            return False

    except Exception as e:
        print(f"[!] Error: {e}")
        return False


def main():
    """Main decryption workflow"""
    import sys

    print("=" * 80)
    print("WeChat Database Decryption Tool")
    print("=" * 80)

    # Parse arguments
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python decrypt.py <password> [encrypted_db] [output_db]")
        print("\nExamples:")
        print("  python decrypt.py 874986d")
        print("  python decrypt.py 874986d EnMicroMsg.db decrypted.db")
        print("\nSteps:")
        print("  1. Extract password: cd decryption && frida -U -n WeChat -l wechatdbpass.js")
        print("  2. Run this script with the password")
        return

    password = sys.argv[1]
    encrypted_db = sys.argv[2] if len(sys.argv) > 2 else "EnMicroMsg.db"
    output_db = sys.argv[3] if len(sys.argv) > 3 else "EnMicroMsg_decrypted.db"

    # Step 1: Pull database if not exists
    if not Path(encrypted_db).exists():
        print(f"\n[1] Database not found locally: {encrypted_db}")
        print("[1] Attempting to pull from device...")
        db_path = pull_database_from_device(local_path=encrypted_db)
        if not db_path:
            print("[!] Failed. Please pull database manually:")
            print('    adb pull /data/data/com.tencent.mm/MicroMsg/[hash]/EnMicroMsg.db')
            return
    else:
        print(f"\n[1] Using existing database: {encrypted_db}")

    # Step 2: Test decryption
    print(f"\n[2] Testing decryption...")
    success, result = test_decryption(encrypted_db, password)

    if not success:
        print(f"[!] Decryption failed: {result}")
        print("[!] Check if password is correct")
        return

    print(f"[+] Decryption successful! Found {result} tables/indexes")

    # Step 3: Export decrypted database
    print(f"\n[3] Exporting decrypted database...")
    if export_decrypted_database(encrypted_db, password, output_db):
        print("\n" + "=" * 80)
        print("SUCCESS!")
        print("=" * 80)
        print(f"\nDecrypted database: {output_db}")
        print("\nYou can now use it with standard SQLite tools:")
        print(f"  python read_db.py {output_db}")
        print(f"  sqlite3 {output_db}")
    else:
        print("\n[!] Export failed")


if __name__ == "__main__":
    main()
