#!/usr/bin/env python3
"""
WeChat Database Reader
Read and display data from decrypted WeChat database
"""

import sys
import sqlite3
from pathlib import Path
from datetime import datetime


def read_messages(db_path, limit=50):
    """Read recent messages from database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print(f"\n{'='*80}")
    print(f"RECENT MESSAGES (Last {limit})")
    print('='*80)

    cursor.execute("""
        SELECT
            msgId,
            type,
            isSend,
            createTime,
            talker,
            content
        FROM message
        ORDER BY createTime DESC
        LIMIT ?
    """, (limit,))

    messages = cursor.fetchall()
    print(f"Found {len(messages)} messages\n")

    for msg_id, msg_type, is_send, create_time, talker, content in messages:
        try:
            dt = datetime.fromtimestamp(create_time / 1000)
            time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            time_str = str(create_time)

        direction = "→ Sent" if is_send == 1 else "← Received"

        print(f"[{time_str}] {direction}")
        print(f"Chat: {talker}")

        # Message type names
        type_names = {
            1: "Text", 3: "Image", 34: "Voice", 43: "Video",
            47: "Emoji", 49: "Link/App", 10000: "System"
        }
        print(f"Type: {type_names.get(msg_type, f'Type {msg_type}')}")

        if msg_type == 1 and content:
            display_content = content if len(content) <= 200 else content[:200] + "..."
            print(f"Content: {display_content}")

        print("-" * 80)

    conn.close()


def read_contacts(db_path, limit=50):
    """Read contacts from database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print(f"\n{'='*80}")
    print(f"CONTACTS")
    print('='*80)

    cursor.execute("""
        SELECT
            username,
            alias,
            conRemark,
            nickname,
            type
        FROM rcontact
        WHERE username NOT LIKE '%@chatroom'
        AND username NOT LIKE 'gh_%'
        ORDER BY nickname
        LIMIT ?
    """, (limit,))

    contacts = cursor.fetchall()
    print(f"Found {len(contacts)} contacts\n")

    for username, alias, remark, nickname, contact_type in contacts:
        display_name = remark or nickname or alias or username
        print(f"  - {display_name}")
        if username != display_name:
            print(f"    ID: {username}")
        print()

    conn.close()


def read_chatrooms(db_path):
    """Read group chats from database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print(f"\n{'='*80}")
    print(f"GROUP CHATS")
    print('='*80)

    cursor.execute("""
        SELECT
            chatroomname,
            memberlist,
            displayname,
            roomowner
        FROM chatroom
        LIMIT 50
    """)

    chatrooms = cursor.fetchall()
    print(f"Found {len(chatrooms)} group chats\n")

    for room_name, members, display_name, owner in chatrooms:
        member_count = len(members.split(';')) if members else 0
        print(f"  - {display_name or room_name}")
        print(f"    Room ID: {room_name}")
        print(f"    Members: {member_count}")
        print(f"    Owner: {owner}")
        print()

    conn.close()


def get_statistics(db_path):
    """Get database statistics"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print(f"\n{'='*80}")
    print(f"DATABASE STATISTICS")
    print('='*80)

    # Message count by type
    cursor.execute("""
        SELECT type, COUNT(*) as count
        FROM message
        GROUP BY type
        ORDER BY count DESC
    """)

    print("\nMessage count by type:")
    type_names = {
        1: "Text", 3: "Image", 34: "Voice", 43: "Video",
        47: "Emoji", 49: "Link/App", 10000: "System"
    }
    for msg_type, count in cursor.fetchall():
        type_name = type_names.get(msg_type, f"Type {msg_type}")
        print(f"  {type_name}: {count}")

    # Total counts
    cursor.execute("SELECT COUNT(*) FROM message")
    total_messages = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM rcontact")
    total_contacts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM rconversation")
    total_conversations = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM chatroom")
    total_chatrooms = cursor.fetchone()[0]

    print(f"\nTotal messages: {total_messages}")
    print(f"Total contacts: {total_contacts}")
    print(f"Total conversations: {total_conversations}")
    print(f"Total group chats: {total_chatrooms}")

    conn.close()


def list_tables(db_path):
    """List all tables in database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print(f"\n{'='*80}")
    print(f"DATABASE TABLES")
    print('='*80)

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = cursor.fetchall()

    print(f"\nFound {len(tables)} tables:")
    for (table_name,) in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        count = cursor.fetchone()[0]
        print(f"  {table_name}: {count} rows")

    conn.close()


def export_messages_csv(db_path, output_file="messages.csv", limit=1000):
    """Export messages to CSV file"""
    import csv

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print(f"\n[*] Exporting messages to {output_file}...")

    cursor.execute("""
        SELECT
            msgId,
            msgSvrId,
            type,
            status,
            isSend,
            createTime,
            talker,
            content
        FROM message
        ORDER BY createTime ASC
        LIMIT ?
    """, (limit,))

    with open(output_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['msgId', 'msgSvrId', 'type', 'status', 'isSend', 'createTime', 'talker', 'content'])
        writer.writerows(cursor.fetchall())

    conn.close()
    print(f"[+] Exported {limit} messages to {output_file}")


def interactive_sql(db_path):
    """Interactive SQL query interface"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print(f"\n{'='*80}")
    print("Interactive SQL Query Mode")
    print('='*80)
    print("Enter SQL queries (or 'exit' to quit)")
    print("Examples:")
    print("  SELECT COUNT(*) FROM message")
    print("  SELECT * FROM rcontact WHERE nickname LIKE '%John%'")
    print('='*80)

    while True:
        try:
            query = input("\nSQL> ").strip()

            if query.lower() in ['exit', 'quit', 'q']:
                break

            if not query:
                continue

            cursor.execute(query)

            if query.upper().startswith('SELECT'):
                results = cursor.fetchall()
                print(f"\nResults: {len(results)} rows")
                for row in results[:20]:  # Limit display
                    print(row)
                if len(results) > 20:
                    print(f"... and {len(results) - 20} more rows")
            else:
                print("Query executed successfully")

        except KeyboardInterrupt:
            print("\n[!] Interrupted")
            break
        except Exception as e:
            print(f"[!] Error: {e}")

    conn.close()


def main():
    """Main function with menu interface"""

    if len(sys.argv) < 2:
        print("WeChat Database Reader")
        print("\nUsage:")
        print("  python read_db.py <database_path> [option]")
        print("\nOptions:")
        print("  messages        - Read recent messages (default)")
        print("  contacts        - Read contacts")
        print("  chatrooms       - Read group chats")
        print("  stats           - Show statistics")
        print("  tables          - List all tables")
        print("  export          - Export messages to CSV")
        print("  sql             - Interactive SQL query mode")
        print("\nExamples:")
        print("  python read_db.py EnMicroMsg_decrypted.db")
        print("  python read_db.py EnMicroMsg_decrypted.db contacts")
        print("  python read_db.py EnMicroMsg_decrypted.db sql")
        return

    db_path = sys.argv[1]

    if not Path(db_path).exists():
        print(f"[!] Database not found: {db_path}")
        return

    # Get action
    action = sys.argv[2].lower() if len(sys.argv) > 2 else "messages"

    print("=" * 80)
    print("WeChat Database Reader")
    print("=" * 80)
    print(f"Database: {db_path}")
    print(f"Size: {Path(db_path).stat().st_size / 1024 / 1024:.2f} MB")

    # Execute action
    if action == "messages":
        read_messages(db_path, limit=50)
    elif action == "contacts":
        read_contacts(db_path, limit=50)
    elif action == "chatrooms":
        read_chatrooms(db_path)
    elif action == "stats":
        get_statistics(db_path)
    elif action == "tables":
        list_tables(db_path)
    elif action == "export":
        export_messages_csv(db_path)
    elif action == "sql":
        interactive_sql(db_path)
    else:
        print(f"[!] Unknown action: {action}")
        print("Available actions: messages, contacts, chatrooms, stats, tables, export, sql")


if __name__ == "__main__":
    main()
