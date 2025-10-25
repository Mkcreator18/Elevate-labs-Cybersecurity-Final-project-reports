import sqlite3
import os
from config import DB_FILE

def init_db():
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
        
        # Remove any existing database file
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
        
        # Create new database with proper permissions
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                length INTEGER,
                flags TEXT
            )
        """)
        conn.commit()
        conn.close()
        
        # Set file permissions
        if os.name == 'nt':  # Windows
            import ctypes
            try:
                # Try to set full control for current user
                import win32security
                import ntsecuritycon
                user = win32security.GetUserName(win32security.NameSamCompatible)
                sd = win32security.GetFileSecurity(DB_FILE, win32security.DACL_SECURITY_INFORMATION)
                dacl = win32security.ACL()
                dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user)
                sd.SetSecurityDescriptorDacl(1, dacl, 0)
                win32security.SetFileSecurity(DB_FILE, win32security.DACL_SECURITY_INFORMATION, sd)
            except:
                # If win32security fails, try basic chmod
                os.chmod(DB_FILE, 0o666)
        else:
            # Unix/Linux
            os.chmod(DB_FILE, 0o666)
            
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise

def log_packet(src_ip, dst_ip, src_port, dst_port, protocol, length, flags):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Convert flags to string if it's not None
        flags_str = str(flags) if flags is not None else None
        
        cursor.execute("""
            INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, length, flags)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (src_ip, dst_ip, src_port, dst_port, protocol, length, flags_str))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging packet: {e}")
        # Try to reconnect and retry once
        try:
            init_db()  # Reinitialize database
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, length, flags)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (src_ip, dst_ip, src_port, dst_port, protocol, length, flags_str))
            conn.commit()
            conn.close()
        except Exception as e2:
            print(f"Failed to retry logging packet: {e2}")

def get_traffic_summary():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT src_ip, COUNT(*) FROM packets GROUP BY src_ip")
        summary = cursor.fetchall()
        conn.close()
        return summary
    except Exception as e:
        print(f"Error getting traffic summary: {e}")
        return []
