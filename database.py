import sqlite3
import logging

# Configure logging for database operations.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DB_NAME = 'users.db'

#Function initializes a database and creates a table
def init_db():
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')
        conn.commit()
    except Exception as e:
        logging.error("Database initialization error: %s", e)
        raise
    finally:
        if conn:
            conn.close()

#Adds a new user to the database and returns false if it already exists
def add_user(username: str, password_hash: str) -> bool:
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        logging.info("Username %s already exists.", username)
        return False
    except Exception as e:
        logging.error("Error adding user: %s", e)
        return False
    finally:
        if conn:
            conn.close()

#Checks if username and password match in the database. Returns True if valid and False if not.
def verify_user(username: str, password_hash: str) -> bool:
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE username=?', (username,))
        row = c.fetchone()
        return row is not None and row[0] == password_hash
    except Exception as e:
        logging.error("Error verifying user: %s", e)
        return False
    finally:
        if conn:
            conn.close()

#Retruns a list of all registered users from the database
def get_all_users() -> list:
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('SELECT username FROM users')
        users = [row[0] for row in c.fetchall()]
        return users
    except Exception as e:
        logging.error("Error retrieving users: %s", e)
        return []
    finally:
        if conn:
            conn.close()


