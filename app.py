import os
import json
import csv
import io
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, Response, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
import database
from detectors import URLPhishingDetector, EmailThreatDetector

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database schema and default seeds on startup
with app.app_context():
    database.init_db()

url_detector = URLPhishingDetector()
email_detector = EmailThreatDetector()

# ============================================================================
# Authentication Helper Decorator
# ============================================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please authenticate to access the operations dashboard.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# SECTION 1 — LANDING PAGE CONTROLLER
# ============================================================================
@app.route('/')
def landing():
    return render_template('landing.html')

# ============================================================================
# SECTION 2 — URL PHISHING SCANNER
# ============================================================================
@app.route('/scanner', methods=['GET', 'POST'])
def scanner_view():
    raw_url = None
    if request.method == 'POST':
        raw_url = request.form.get('url', '').strip()
    elif request.method == 'GET' and 'url' in request.args:
        raw_url = request.args.get('url', '').strip()

    if raw_url:
        result = url_detector.analyze(raw_url)
        user_id = session.get('user_id')

        # Persist scan result to database
        try:
            indicators_json = json.dumps(result['indicators'])
            database.execute_db(
                """INSERT INTO url_scans 
                (user_id, url, domain, risk_score, risk_level, passed_count, concern_count, indicators_json, recommendation)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    user_id,
                    result['url'],
                    result['domain'],
                    result['risk_score'],
                    result['risk_level'],
                    result['passed_count'],
                    result['concern_count'],
                    indicators_json,
                    result['recommendation']
                )
            )
            if user_id:
                database.execute_db(
                    "INSERT INTO activity_logs (user_id, activity_type, description) VALUES (%s, %s, %s)",
                    (user_id, 'URL_SCAN', f"Scanned URL: {result['domain']} (Risk Score: {result['risk_score']})")
                )
        except Exception as e:
            print(f"[PHISHGUARD DB ERROR] URL Scan persistence failed: {e}")

        return render_template('scanner_result.html', result=result)

    return render_template('scanner.html')

# ============================================================================
# SECTION 3 — EMAIL THREAT ANALYZER
# ============================================================================
@app.route('/email', methods=['GET', 'POST'])
def email_view():
    if request.method == 'POST':
        sender = request.form.get('sender', '').strip()
        subject = request.form.get('subject', '').strip()
        body = request.form.get('body', '').strip()

        if not sender or not subject or not body:
            flash('Please complete all required email fields for analysis.', 'warning')
            return render_template('email_analyzer.html')

        result = email_detector.analyze(sender, subject, body)
        user_id = session.get('user_id')

        # Persist scan to database
        try:
            indicators_json = json.dumps(result['indicators'])
            database.execute_db(
                """INSERT INTO email_scans
                (user_id, sender, subject, body_snippet, risk_score, risk_level, concern_count, indicators_json, recommendation)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    user_id,
                    result['sender'],
                    result['subject'],
                    result['body_snippet'],
                    result['risk_score'],
                    result['risk_level'],
                    result['concern_count'],
                    indicators_json,
                    result['recommendation']
                )
            )
            if user_id:
                database.execute_db(
                    "INSERT INTO activity_logs (user_id, activity_type, description) VALUES (%s, %s, %s)",
                    (user_id, 'EMAIL_SCAN', f"Analyzed email: {result['subject'][:40]} (Score: {result['risk_score']})")
                )
        except Exception as e:
            print(f"[PHISHGUARD DB ERROR] Email Scan persistence failed: {e}")

        return render_template('email_result.html', result=result)

    return render_template('email_analyzer.html')

# ============================================================================
# AJAX Telemetry API Endpoints (For Live Interactive Previews)
# ============================================================================
@app.route('/api/scan/url', methods=['POST'])
def api_scan_url():
    data = request.get_json() or {}
    target_url = data.get('url', '').strip()
    if not target_url:
        return jsonify({'error': 'No URL provided'}), 400

    result = url_detector.analyze(target_url)
    user_id = session.get('user_id')
    try:
        indicators_json = json.dumps(result['indicators'])
        database.execute_db(
            """INSERT INTO url_scans 
            (user_id, url, domain, risk_score, risk_level, passed_count, concern_count, indicators_json, recommendation)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                user_id,
                result['url'],
                result['domain'],
                result['risk_score'],
                result['risk_level'],
                result['passed_count'],
                result['concern_count'],
                indicators_json,
                result['recommendation']
            )
        )
    except Exception as e:
        print(f"[PHISHGUARD DB ERROR] URL Scan API persistence failed: {e}")

    return jsonify(result)

@app.route('/api/scan/email', methods=['POST'])
def api_scan_email():
    data = request.get_json() or {}
    sender = data.get('sender', '').strip()
    subject = data.get('subject', '').strip()
    body = data.get('body', '').strip()

    if not sender or not subject or not body:
        return jsonify({'error': 'Missing email fields'}), 400

    result = email_detector.analyze(sender, subject, body)
    return jsonify(result)

# ============================================================================
# SECTION 4 — AWARENESS & EDUCATION HUB
# ============================================================================
@app.route('/awareness')
def awareness_view():
    return render_template('awareness.html')

# ============================================================================
# SECTION 5 — INTERACTIVE QUIZ & API
# ============================================================================
@app.route('/quiz')
def quiz_view():
    return render_template('quiz.html')

@app.route('/api/quiz/submit', methods=['POST'])
def submit_quiz_api():
    data = request.get_json() or {}
    score = int(data.get('score', 0))
    total = int(data.get('total', 10))
    percentage = float(data.get('percentage', 0.0))
    rating = data.get('rating', 'Completed')
    answers_json = json.dumps(data.get('answers', []))
    user_id = session.get('user_id')

    try:
        database.execute_db(
            """INSERT INTO quiz_results 
            (user_id, score, total_questions, percentage, performance_rating, answers_json)
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (user_id, score, total, percentage, rating, answers_json)
        )
        if user_id:
            database.execute_db(
                "INSERT INTO activity_logs (user_id, activity_type, description) VALUES (%s, %s, %s)",
                (user_id, 'QUIZ_COMPLETED', f"Completed Awareness Quiz: {score}/{total} ({percentage}%) - {rating}")
            )
        return jsonify({'status': 'success', 'message': 'Quiz telemetry recorded'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ============================================================================
# SECTION 6 — APPLICATION DASHBOARD (LOGGED IN)
# ============================================================================
@app.route('/dashboard')
@login_required
def dashboard_view():
    user_id = session.get('user_id')
    user_name = session.get('user_name', 'Analyst')
    first_name = user_name.split()[0] if user_name else 'Analyst'

    # Compute time-of-day greeting
    current_hour = datetime.now().hour
    if current_hour < 12:
        greeting = "Good morning"
    elif current_hour < 17:
        greeting = "Good afternoon"
    else:
        greeting = "Good evening"

    # Aggregate Statistics
    url_scans = database.query_db("SELECT risk_level, risk_score FROM url_scans WHERE user_id = %s", (user_id,))
    email_scans = database.query_db("SELECT risk_level, risk_score FROM email_scans WHERE user_id = %s", (user_id,))

    total_scans = len(url_scans) + len(email_scans)
    safe_scans = sum(1 for s in (url_scans + email_scans) if s['risk_level'] == 'LOW RISK')
    suspicious_scans = sum(1 for s in (url_scans + email_scans) if s['risk_level'] in ['SUSPICIOUS', 'POSSIBLE PHISHING'])
    high_risk_scans = sum(1 for s in (url_scans + email_scans) if s['risk_level'] == 'PHISHING LIKELY')

    stats = {
        'total': total_scans,
        'safe': safe_scans,
        'suspicious': suspicious_scans,
        'high_risk': high_risk_scans
    }

    # Fetch Recent Activity (merged URLs + Emails)
    recent_urls = database.query_db(
        "SELECT id, 'URL' as type, url as target, risk_score as score, risk_level as level, created_at FROM url_scans WHERE user_id = %s ORDER BY created_at DESC LIMIT 6",
        (user_id,)
    )
    recent_emails = database.query_db(
        "SELECT id, 'Email' as type, subject as target, risk_score as score, risk_level as level, created_at FROM email_scans WHERE user_id = %s ORDER BY created_at DESC LIMIT 6",
        (user_id,)
    )

    combined_activity = sorted(
        recent_urls + recent_emails,
        key=lambda x: str(x['created_at']),
        reverse=True
    )[:8]

    return render_template(
        'dashboard.html',
        first_name=first_name,
        greeting=greeting,
        stats=stats,
        recent_activity=combined_activity
    )

# ============================================================================
# SECTION 7 — SECURITY AUDIT REPORTS
# ============================================================================
@app.route('/reports')
def reports_view():
    filter_type = request.args.get('filter', '').lower()
    search_q = request.args.get('q', '').strip()
    user_id = session.get('user_id')

    # Base Queries
    url_items = database.query_db(
        "SELECT id, 'URL' as type, url as target, risk_score, risk_level, concern_count, created_at FROM url_scans ORDER BY created_at DESC LIMIT 50"
    )
    email_items = database.query_db(
        "SELECT id, 'Email' as type, subject as target, risk_score, risk_level, concern_count, created_at FROM email_scans ORDER BY created_at DESC LIMIT 50"
    )

    all_logs = sorted(url_items + email_items, key=lambda x: str(x['created_at']), reverse=True)

    # Compute Filter Counts
    all_count = len(all_logs)
    safe_count = sum(1 for x in all_logs if x['risk_level'] == 'LOW RISK')
    suspicious_count = sum(1 for x in all_logs if x['risk_level'] in ['SUSPICIOUS', 'POSSIBLE PHISHING'])
    danger_count = sum(1 for x in all_logs if x['risk_level'] == 'PHISHING LIKELY')

    # Apply Filtering
    filtered = all_logs
    if filter_type == 'safe':
        filtered = [x for x in filtered if x['risk_level'] == 'LOW RISK']
    elif filter_type == 'suspicious':
        filtered = [x for x in filtered if x['risk_level'] in ['SUSPICIOUS', 'POSSIBLE PHISHING']]
    elif filter_type == 'danger':
        filtered = [x for x in filtered if x['risk_level'] == 'PHISHING LIKELY']

    # Apply Search Query
    if search_q:
        filtered = [x for x in filtered if search_q.lower() in x['target'].lower()]

    return render_template(
        'reports.html',
        logs=filtered,
        current_filter=filter_type,
        search_query=search_q,
        all_count=all_count,
        safe_count=safe_count,
        suspicious_count=suspicious_count,
        danger_count=danger_count
    )

@app.route('/reports/export')
def export_reports_csv():
    url_items = database.query_db(
        "SELECT id, 'URL' as type, url as target, domain, risk_score, risk_level, concern_count, created_at FROM url_scans ORDER BY created_at DESC"
    )
    email_items = database.query_db(
        "SELECT id, 'Email' as type, subject as target, sender as domain, risk_score, risk_level, concern_count, created_at FROM email_scans ORDER BY created_at DESC"
    )

    combined = sorted(url_items + email_items, key=lambda x: str(x['created_at']), reverse=True)

    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['Record ID', 'Vector Type', 'Target / URL', 'Domain / Sender', 'Risk Score', 'Classification', 'Flagged Concerns', 'Timestamp'])

    for row in combined:
        writer.writerow([
            row['id'],
            row['type'],
            row['target'],
            row['domain'],
            row['risk_score'],
            row['risk_level'],
            row['concern_count'],
            row['created_at']
        ])

    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=phishguard_threat_telemetry_report.csv"}
    )

@app.route('/project-report')
@app.route('/documentation')
def documentation_view():
    """Serves the comprehensive academic documentation report with diagrams and pie charts."""
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'PHISHGUARD_PROJECT_REPORT.html')

# ============================================================================
# SECTION 8 — USER AUTHENTICATION & PROFILE
# ============================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('dashboard_view'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        user = database.query_db("SELECT * FROM users WHERE email = %s", (email,), one=True)
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_email'] = user['email']
            session['user_role'] = user.get('role', 'user')

            flash(f"Welcome back, {user['name']}. Operations terminal active.", 'success')
            next_url = request.args.get('next')
            return redirect(next_url or url_for('dashboard_view'))
        else:
            flash('Invalid email or password credentials. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        return redirect(url_for('dashboard_view'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        if len(password) < 6:
            flash('Password must contain at least 6 characters.', 'warning')
            return render_template('register.html')

        existing = database.query_db("SELECT id FROM users WHERE email = %s", (email,), one=True)
        if existing:
            flash('An account with this email address already exists. Please sign in.', 'warning')
            return redirect(url_for('login'))

        pw_hash = generate_password_hash(password)
        user_id = database.execute_db(
            "INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, %s)",
            (name, email, pw_hash, 'user')
        )

        session['user_id'] = user_id
        session['user_name'] = name
        session['user_email'] = email
        session['user_role'] = 'user'

        database.execute_db(
            "INSERT INTO activity_logs (user_id, activity_type, description) VALUES (%s, %s, %s)",
            (user_id, 'USER_REGISTER', f"New account created for {name} ({email})")
        )

        flash('Your defense profile has been established successfully. Welcome to PhishGuard!', 'success')
        return redirect(url_for('dashboard_view'))

    return render_template('register.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile_view():
    user_id = session.get('user_id')
    user = database.query_db("SELECT * FROM users WHERE id = %s", (user_id,), one=True)

    if request.method == 'POST':
        new_password = request.form.get('new_password', '').strip()
        if len(new_password) < 6:
            flash('New password must contain at least 6 characters.', 'warning')
        else:
            pw_hash = generate_password_hash(new_password)
            database.execute_db("UPDATE users SET password_hash = %s WHERE id = %s", (pw_hash, user_id))
            flash('Credentials updated successfully.', 'success')

    # Count user's specific records
    url_count_row = database.query_db("SELECT COUNT(*) as c FROM url_scans WHERE user_id = %s", (user_id,), one=True)
    quiz_count_row = database.query_db("SELECT COUNT(*) as c FROM quiz_results WHERE user_id = %s", (user_id,), one=True)

    url_count = url_count_row['c'] if url_count_row else 0
    quiz_count = quiz_count_row['c'] if quiz_count_row else 0

    return render_template('profile.html', user=user, url_count=url_count, quiz_count=quiz_count)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been securely signed out.', 'info')
    return redirect(url_for('landing'))

# ============================================================================
# Error Handlers
# ============================================================================
@app.errorhandler(404)
def page_not_found(e):
    return render_template('base.html', content="""
      <div class="container text-center" style="padding: 100px 0;">
        <h1 style="font-size: 4rem; font-weight: 800; color: var(--primary);">404</h1>
        <p style="font-size: 1.2rem; color: var(--text-muted); margin-bottom: 24px;">The requested security endpoint could not be resolved.</p>
        <a href="/" class="btn btn-primary">Return to Operations Portal</a>
      </div>
    """), 404

if __name__ == '__main__':
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() in ('true', '1')
    print(f"[PHISHGUARD] Starting application server on http://{host}:{port}")
    print(f"[PHISHGUARD] Student Developer: {Config.STUDENT_NAME}")
    print(f"[PHISHGUARD] Project Mentor: {Config.MENTOR_NAME}")
    app.run(debug=debug, host=host, port=port)
