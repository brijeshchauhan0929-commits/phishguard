import os
import sqlite3
import pymysql
import json
from werkzeug.security import generate_password_hash
from config import Config

_using_mysql = False
_mysql_checked = False

def check_mysql_connection():
    """Attempts to connect to MySQL server once and caches the result."""
    global _mysql_checked, _using_mysql
    if _mysql_checked:
        return _using_mysql

    _mysql_checked = True
    try:
        conn = pymysql.connect(
            host=Config.MYSQL_HOST,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            port=Config.MYSQL_PORT,
            connect_timeout=1
        )
        conn.close()
        _using_mysql = True
        return True
    except Exception:
        _using_mysql = False
        return False

def get_db():
    """Returns an active database connection (MySQL if available, otherwise SQLite)."""
    global _using_mysql
    if _using_mysql:
        try:
            conn = pymysql.connect(
                host=Config.MYSQL_HOST,
                user=Config.MYSQL_USER,
                password=Config.MYSQL_PASSWORD,
                database=Config.MYSQL_DB,
                port=Config.MYSQL_PORT,
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=True
            )
            return conn
        except Exception:
            _using_mysql = False
    
    # SQLite connection with dict-like row access
    conn = sqlite3.connect(Config.SQLITE_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def execute_db(query, args=()):
    """Executes an INSERT/UPDATE/DELETE query and returns the last inserted ID."""
    conn = get_db()
    cursor = conn.cursor()
    try:
        if isinstance(conn, sqlite3.Connection):
            # Adapt MySQL placeholders %s to SQLite ?
            sqlite_query = query.replace('%s', '?')
            cursor.execute(sqlite_query, args)
            conn.commit()
            last_id = cursor.lastrowid
        else:
            cursor.execute(query, args)
            last_id = cursor.lastrowid
        return last_id
    finally:
        cursor.close()
        conn.close()

def query_db(query, args=(), one=False):
    """Executes a SELECT query and returns rows as dictionaries."""
    conn = get_db()
    cursor = conn.cursor()
    try:
        if isinstance(conn, sqlite3.Connection):
            sqlite_query = query.replace('%s', '?')
            cursor.execute(sqlite_query, args)
            rv = cursor.fetchall()
            # Convert sqlite3.Row to dict
            result = [dict(row) for row in rv]
        else:
            cursor.execute(query, args)
            result = cursor.fetchall()
            if result and isinstance(result[0], tuple):
                # In case cursor is not dict cursor
                desc = [d[0] for d in cursor.description]
                result = [dict(zip(desc, r)) for r in result]
        return (result[0] if result else None) if one else result
    finally:
        cursor.close()
        conn.close()

def init_db():
    """Initializes the database schema and seeds default data."""
    global _using_mysql
    if check_mysql_connection():
        try:
            # Create MySQL database if not exists
            conn = pymysql.connect(
                host=Config.MYSQL_HOST,
                user=Config.MYSQL_USER,
                password=Config.MYSQL_PASSWORD,
                port=Config.MYSQL_PORT
            )
            with conn.cursor() as cur:
                cur.execute(f"CREATE DATABASE IF NOT EXISTS `{Config.MYSQL_DB}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
            conn.close()
            _using_mysql = True
            
            # Execute MySQL schema
            schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.sql')
            if os.path.exists(schema_path):
                with open(schema_path, 'r', encoding='utf-8') as f:
                    schema_sql = f.read()
                db_conn = get_db()
                with db_conn.cursor() as cur:
                    for statement in schema_sql.split(';'):
                        stmt = statement.strip()
                        if stmt and not stmt.upper().startswith("CREATE DATABASE") and not stmt.upper().startswith("USE"):
                            cur.execute(stmt)
                db_conn.close()
            print("[PHISHGUARD] Connected to MySQL successfully.")
        except Exception as e:
            print(f"[PHISHGUARD] MySQL init failed ({e}), falling back to SQLite.")
            _using_mysql = False
    else:
        print("[PHISHGUARD] MySQL not detected. Utilizing local SQLite database engine.")
        _using_mysql = False

    if not _using_mysql:
        # SQLite schema initialization
        conn = sqlite3.connect(Config.SQLITE_DB_PATH)
        cur = conn.cursor()
        cur.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS url_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NULL,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            passed_count INTEGER DEFAULT 0,
            concern_count INTEGER DEFAULT 0,
            indicators_json TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS email_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NULL,
            sender TEXT NOT NULL,
            subject TEXT NOT NULL,
            body_snippet TEXT,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            concern_count INTEGER DEFAULT 0,
            indicators_json TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS quiz_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NULL,
            score INTEGER NOT NULL,
            total_questions INTEGER NOT NULL,
            percentage REAL NOT NULL,
            performance_rating TEXT NOT NULL,
            answers_json TEXT,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NULL,
            activity_type TEXT NOT NULL,
            description TEXT NOT NULL,
            ip_address TEXT DEFAULT '127.0.0.1',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        ''')
        conn.commit()
        conn.close()

    seed_default_data()

def seed_default_data():
    """Seeds default student user and realistic initial threat intelligence logs."""
    user = query_db("SELECT id FROM users WHERE email = %s", ('brijesh@phishguard.local',), one=True)
    if not user:
        pw_hash = generate_password_hash('password123')
        user_id = execute_db(
            "INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, %s)",
            (Config.STUDENT_NAME, 'brijesh@phishguard.local', pw_hash, 'admin')
        )
        
        # Seed realistic demonstration scans for Chauhan Brijesh Ramayan
        sample_scans = [
            (
                user_id,
                'https://accounts.google.com/signin/v2/identifier',
                'accounts.google.com',
                12,
                'LOW RISK',
                5,
                0,
                json.dumps([
                    {'name': 'HTTPS Protocol', 'status': 'pass', 'description': 'Secure SSL/TLS certificate detected'},
                    {'name': 'Official Domain Structure', 'status': 'pass', 'description': 'Legitimate Google authentication domain'},
                    {'name': 'No IP Hostname', 'status': 'pass', 'description': 'Standard domain name resolution'}
                ]),
                'Safe to proceed. Valid official authentication service.'
            ),
            (
                user_id,
                'http://paypa1-security-verification.xyz/login.php?user=alert',
                'paypa1-security-verification.xyz',
                92,
                'PHISHING LIKELY',
                0,
                5,
                json.dumps([
                    {'name': 'Brand Spoofing (Typosquatting)', 'status': 'danger', 'description': 'Targeting PayPal with altered character substitution'},
                    {'name': 'Insecure Protocol', 'status': 'danger', 'description': 'No HTTPS encryption detected'},
                    {'name': 'Suspicious High-Risk TLD', 'status': 'warning', 'description': '.xyz is frequently associated with disposable phishing kits'},
                    {'name': 'Urgent Credential Keywords', 'status': 'warning', 'description': 'Found "security", "verification", and "login" in path'}
                ]),
                'CRITICAL: Do not navigate to this site or submit any credentials. High likelihood of credential harvesting.'
            ),
            (
                user_id,
                'https://bit.ly/3x8Qz9A-claim-reward',
                'bit.ly',
                58,
                'SUSPICIOUS',
                2,
                2,
                json.dumps([
                    {'name': 'URL Shortener Service', 'status': 'warning', 'description': 'Destination destination is masked by redirection service'},
                    {'name': 'Enticement Keyword', 'status': 'warning', 'description': 'Contains "claim-reward" phrasing frequently used in lure campaigns'},
                    {'name': 'HTTPS Protocol', 'status': 'pass', 'description': 'Transport layer encryption active'}
                ]),
                'Exercise caution. Verify destination target using a link expander before entering credentials.'
            )
        ]

        for s in sample_scans:
            execute_db(
                """INSERT INTO url_scans 
                (user_id, url, domain, risk_score, risk_level, passed_count, concern_count, indicators_json, recommendation) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                s
            )

        # Seed sample email scan
        execute_db(
            """INSERT INTO email_scans
            (user_id, sender, subject, body_snippet, risk_score, risk_level, concern_count, indicators_json, recommendation)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                user_id,
                'security@notice-bank-alert.com',
                'URGENT: Unauthorized Account Access Detected - Action Required in 24 Hours',
                'Dear Customer, We have detected unauthorized attempts to access your online banking profile from a foreign IP address. Your account has been temporarily restricted. Click the link below to verify your identity and restore full access immediately or your funds will remain frozen.',
                88,
                'PHISHING LIKELY',
                4,
                json.dumps([
                    {'name': 'Psychological Urgency', 'status': 'danger', 'description': 'Imposes a false 24-hour deadline to induce panic'},
                    {'name': 'Generic Salutation', 'status': 'warning', 'description': '"Dear Customer" used instead of customer name'},
                    {'name': 'Credential Harvesting Lure', 'status': 'danger', 'description': 'Prompts user to click and verify account identity'},
                    {'name': 'Threat of Negative Consequence', 'status': 'danger', 'description': 'Threatens funds freezing if immediate action is not taken'}
                ]),
                'Do not click any links or download attachments. Report this email as phishing to your security administrator.'
            )
        )

        # Seed initial quiz result
        execute_db(
            """INSERT INTO quiz_results
            (user_id, score, total_questions, percentage, performance_rating, answers_json)
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (
                user_id,
                9,
                10,
                90.0,
                'Cyber Defender (Expert)',
                json.dumps({'correct': 9, 'incorrect': 1})
            )
        )

        # Seed initial activity log
        execute_db(
            """INSERT INTO activity_logs (user_id, activity_type, description)
            VALUES (%s, %s, %s)""",
            (user_id, 'SYSTEM_INIT', 'PhishGuard threat intelligence profile initialized')
        )
