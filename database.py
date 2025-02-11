import sqlite3
import hashlib

DB_NAME = "passwords.db"

def init_db():
    """Initialize the database and create necessary tables."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create passwords table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)
    
    # Create settings table to store the secret PIN
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pin TEXT NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()

def save_password(account, username, encrypted_password):
    """Save encrypted password to the database."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO passwords (account, username, password) VALUES (?, ?, ?)", 
                       (account, username, encrypted_password))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database Error: {e}")
    finally:
        conn.close()

def get_all_passwords():
    """Retrieve all stored passwords."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT account, username, password FROM passwords")
    records = cursor.fetchall()
    conn.close()
    return records

def delete_password(account):
    """Delete a password entry from the database."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM passwords WHERE account = ?", (account,))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database Error: {e}")
    finally:
        conn.close()

def search_passwords(query):
    """Search for password entries matching an account name."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT account, username, password FROM passwords WHERE account LIKE ?", (f"%{query}%",))
    records = cursor.fetchall()
    conn.close()
    return records

def set_pin(pin):
    """Set or update the secret PIN (hashed)."""
    hashed_pin = hashlib.sha256(pin.encode()).hexdigest()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM settings")  # Remove existing PIN
    cursor.execute("INSERT INTO settings (pin) VALUES (?)", (hashed_pin,))
    
    conn.commit()
    conn.close()

def verify_pin(pin):
    """Verify entered PIN with stored hashed PIN."""
    hashed_pin = hashlib.sha256(pin.encode()).hexdigest()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT pin FROM settings")
    stored_pin = cursor.fetchone()
    
    conn.close()
    
    if stored_pin is None:
        return False  # If no PIN is set, reject access
    
    return stored_pin[0] == hashed_pin

# Initialize database on first run
init_db()
