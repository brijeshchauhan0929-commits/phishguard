import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'phishguard-ultra-secure-key-2026-mini-pj')
    
    # MySQL Database Settings
    MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
    MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
    MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
    MYSQL_DB = os.environ.get('MYSQL_DB', 'phishguard_db')
    
    # SQLite Fallback Path (Supports Local, Render/Railway, and Netlify Serverless environments)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    bundled_db = os.path.join(base_dir, 'phishguard.db')
    
    is_serverless = bool(os.environ.get('NETLIFY') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME') or os.environ.get('LAMBDA_TASK_ROOT'))
    if is_serverless:
        tmp_db = '/tmp/phishguard.db'
        if not os.path.exists(tmp_db) and os.path.exists(bundled_db):
            try:
                import shutil
                shutil.copy2(bundled_db, tmp_db)
            except Exception:
                pass
        SQLITE_DB_PATH = os.environ.get('SQLITE_DB_PATH', tmp_db)
    else:
        SQLITE_DB_PATH = os.environ.get('SQLITE_DB_PATH', bundled_db)
    
    # App Information
    APP_NAME = "PHISHGUARD"
    APP_SUBTITLE = "Phishing Attack Detection & Awareness System"
    STUDENT_NAME = "Chauhan Brijesh Ramayan"
    MENTOR_NAME = "Jagruti Raut"
    PROJECT_TYPE = "College Mini Project"
