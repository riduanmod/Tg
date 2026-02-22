import sqlite3
import threading
from datetime import datetime, timedelta

DB_FILE = 'bot_data.db'
db_lock = threading.RLock() # FIXED: Changed to RLock to prevent deadlocks

def get_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db_lock:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Tables
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (user_id INTEGER PRIMARY KEY, username TEXT, first_name TEXT, join_date TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS channels (id INTEGER PRIMARY KEY AUTOINCREMENT, channel_username TEXT UNIQUE)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS subscriptions (user_id INTEGER PRIMARY KEY, expire_date DATETIME)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_stats (user_id INTEGER PRIMARY KEY, accounts_submitted INTEGER DEFAULT 0)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS bot_config (key TEXT PRIMARY KEY, value INTEGER)''')
        
        # Default Config (1 Account = 3 Days)
        cursor.execute("INSERT OR IGNORE INTO bot_config (key, value) VALUES ('req_accounts', 1)")
        cursor.execute("INSERT OR IGNORE INTO bot_config (key, value) VALUES ('reward_days', 3)")
        
        conn.commit()
        conn.close()

# --- USER MANAGEMENT ---
def add_user(user):
    try:
        with db_lock:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM users WHERE user_id = ?", (user.id,))
            if cursor.fetchone() is None:
                join_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("INSERT INTO users (user_id, username, first_name, join_date) VALUES (?, ?, ?, ?)", (user.id, user.username, user.first_name, join_date))
                cursor.execute("INSERT OR IGNORE INTO user_stats (user_id, accounts_submitted) VALUES (?, 0)", (user.id,))
                conn.commit()
            conn.close()
    except Exception as e: print(f"DB Error: {e}")

def get_all_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users")
    users = [row['user_id'] for row in cursor.fetchall()]
    conn.close()
    return users

def get_total_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    conn.close()
    return count

# --- CHANNEL MANAGEMENT ---
def add_channel(username):
    try:
        conn = get_connection()
        conn.cursor().execute("INSERT OR IGNORE INTO channels (channel_username) VALUES (?)", (username,))
        conn.commit()
        conn.close()
        return True
    except: return False

def remove_channel(username):
    conn = get_connection()
    conn.cursor().execute("DELETE FROM channels WHERE channel_username = ?", (username,))
    conn.commit()
    conn.close()

def get_channels():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT channel_username FROM channels")
    channels = [row['channel_username'] for row in cursor.fetchall()]
    conn.close()
    return channels

# --- SUBSCRIPTION & ACCESS MANAGEMENT ---
def check_subscription(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT expire_date FROM subscriptions WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        expire_date = datetime.strptime(row['expire_date'], "%Y-%m-%d %H:%M:%S")
        if datetime.now() < expire_date:
            return True, expire_date
    return False, None

def grant_access(user_id, days):
    with db_lock:
        conn = get_connection()
        cursor = conn.cursor()
        new_expire = datetime.now() + timedelta(days=days)
        expire_str = new_expire.strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT OR REPLACE INTO subscriptions (user_id, expire_date) VALUES (?, ?)", (user_id, expire_str))
        conn.commit()
        conn.close()
        return expire_str

# --- ACCOUNT SUBMISSION LOGIC ---
def get_config():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM bot_config")
    conf = {row['key']: row['value'] for row in cursor.fetchall()}
    conn.close()
    return conf

def update_config(req_acc, reward_days):
    with db_lock:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE bot_config SET value = ? WHERE key = 'req_accounts'", (req_acc,))
        cursor.execute("UPDATE bot_config SET value = ? WHERE key = 'reward_days'", (reward_days,))
        conn.commit()
        conn.close()

def increment_submitted_account(user_id):
    with db_lock:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Ensure user exists in user_stats
        cursor.execute("INSERT OR IGNORE INTO user_stats (user_id, accounts_submitted) VALUES (?, 0)", (user_id,))
        
        # Increment
        cursor.execute("UPDATE user_stats SET accounts_submitted = accounts_submitted + 1 WHERE user_id = ?", (user_id,))
        cursor.execute("SELECT accounts_submitted FROM user_stats WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        count = row['accounts_submitted'] if row else 1
        conn.commit()
        conn.close()
        
        # Check if user deserves reward
        config = get_config()
        if count >= config['req_accounts']:
            grant_access(user_id, config['reward_days'])
            
            # Reset count after reward
            conn = get_connection()
            conn.cursor().execute("UPDATE user_stats SET accounts_submitted = 0 WHERE user_id = ?", (user_id,))
            conn.commit()
            conn.close()
            return True, config['reward_days']
            
        return False, config['req_accounts'] - count
