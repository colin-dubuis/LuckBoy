import json
import os
import hmac
import hashlib
import traceback
from datetime import datetime
from functools import wraps

from pathlib import Path

import git
from dotenv import load_dotenv
from git.exc import GitCommandError, InvalidGitRepositoryError, NoSuchPathError  # added

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


# Load .env deterministically from the directory of this file
ENV_PATH = Path(__file__).resolve().parent / '.env'
load_dotenv(dotenv_path=str(ENV_PATH), override=False)

def require_env(key: str) -> str:
    val = os.getenv(key)
    if not val:
        raise RuntimeError(f"Missing environment variable: {key}")
    return val
app = Flask(__name__)
application = app  # WSGI entrypoint

# Session secret (use env if set)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-insecure-change-me')

DB_HOST = require_env('DB_HOST')
DB_USER = require_env('DB_USER')
DB_PASSWORD = require_env('DB_PASSWORD')
DB_NAME = require_env('DB_NAME')

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
)
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_recycle': 280}
db = SQLAlchemy(app)

# Auth setup
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'

# Map existing users table (no schema change)
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def check_password(self, password: str) -> bool:
        try:
            return bcrypt.check_password_hash(self.password_hash, password)
        except Exception:
            return False

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

# ---------------- Error logging utilities ----------------
def log_error_to_json(error, context=None):
    """
    Log errors to a JSON file with timestamp and details.
    """
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file = os.path.join(log_dir, "errors.json")

    error_data = {
        "timestamp": datetime.now().isoformat(),
        "error_type": type(error).__name__,
        "error_message": str(error),
        "traceback": traceback.format_exc(),
        "request_url": request.url if request else None,
        "request_method": request.method if request else None,
        "ip_address": request.remote_addr if request else None,
        "context": context or {}
    }

    errors = []
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                content = f.read()
                if content:
                    errors = json.loads(content)
        except (json.JSONDecodeError, IOError):
            errors = []

    errors.append(error_data)

    try:
        with open(log_file, 'w') as f:
            json.dump(errors, f, indent=2, default=str)
        return True
    except Exception as write_error:
        print(f"Failed to write to log file: {write_error}")
        print(f"Original error: {error_data}")
        return False


def handle_errors(func):
    """
    Decorator to automatically catch and log errors in routes.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            log_error_to_json(e, context={"function": func.__name__})
            return {"error": "An error occurred", "message": str(e)}, 500
    return wrapper


@app.errorhandler(Exception)
def handle_exception(e):
    """
    Global error handler for Flask app.
    """
    log_error_to_json(e)
    return {"error": "Internal Server Error", "message": str(e)}, 500


#--------------Email------------------
# --- new route: test SendGrid email ---
@app.route('/test-email', methods=['GET', 'POST'])
@login_required
@handle_errors
def test_email():
    # Simple form to submit a recipient; prefill with current user's email
    if request.method == 'GET':
        default_to = getattr(current_user, 'email', '') or ''
        return f"""
        <!doctype html>
        <html><head><title>SendGrid Test</title></head>
        <body style="font-family: sans-serif; padding: 20px;">
            <h1>SendGrid Test</h1>
            <form method="POST">
                <label>To email:</label>
                <input name="to" type="email" required value="{default_to}" />
                <button type="submit">Send test email</button>
            </form>
            <p><a href="/">Back to Home</a></p>
        </body></html>
        """

    # POST: send the email
    to = (request.form.get('to') or '').strip()
    if not to:
        return {"error": "Missing 'to' address"}, 400

    api_key = os.getenv('SENDGRID_API_KEY')
    if not api_key:
        return {"error": "Missing SENDGRID_API_KEY"}, 500

    from_email = os.getenv('MAIL_FROM', 'no-reply@example.com')

    message = Mail(
        from_email=from_email,
        to_emails=to,
        subject='SendGrid test from Flask',
        html_content='<strong>If you see this, SendGrid works.</strong>'
    )

    try:
        sg = SendGridAPIClient(api_key)

        # Optional EU data residency
        region = (os.getenv('SENDGRID_REGION') or '').lower()
        if region in ('eu', 'eu1', 'eu_region'):
            try:
                sg.set_sendgrid_data_residency("eu")
            except Exception:
                # Non-fatal; continue without regional setting
                pass

        resp = sg.send(message)
        return {
            "status_code": resp.status_code,
            "note": "If status_code is 202, SendGrid accepted the email."
        }, 200
    except Exception as e:
        log_error_to_json(e, context={"route": "test_email", "to": to})
        return {"error": "SendGrid send failed", "message": str(e)}, 500

#-------------- Auth -----------------

@app.route('/users')
@handle_errors
@login_required
def show_users():
    try:
        # Simple SQL query
        result = db.session.execute(db.text("SELECT id, username, email FROM users"))
        users = result.fetchall()

        html = "<h1>👥 Users in Database</h1>"
        if users:
            for user in users:
                html += f"<p>🔸 ID: {user[0]} | Username: <strong>{user[1]}</strong> | Email: {user[2]}</p>"
        else:
            html += "<p>No users found</p>"

        html += '<br><a href="/">← Back to Home</a>'
        return html
    except Exception as e:
        return f"❌ Database Error: {str(e)}"



# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    username = (request.form.get('username') or '').strip()
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''

    if not username or not email or not password:
        flash('All fields are required.', 'danger')
        return redirect(url_for('register'))

    # Check uniqueness
    existing = db.session.execute(
        db.select(User).where((User.username == username) | (User.email == email))
    ).scalars().first()
    if existing:
        flash('Username or email already in use.', 'danger')
        return redirect(url_for('register'))

    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username, email=email, password_hash=pw_hash)
    db.session.add(user)
    db.session.commit()
    flash('Account created. You can now log in.', 'success')
    return redirect(url_for('login'))

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''

    user = db.session.execute(
        db.select(User).where(User.username == username)
    ).scalars().first()

    if not user or not user.check_password(password):
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))

    login_user(user)
    flash('Welcome back!', 'success')
    return redirect(url_for('home'))

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ------------------------
# Routes
# ------------------------

@app.route('/favicon.ico')
def favicon():
    # No content; avoids 404s in logs
    return '', 204, {'Content-Type': 'image/x-icon'}

# ---------------- Webhook routes ----------------
@app.route('/git', methods=['POST'])
@handle_errors
def github_webhook():
    # Handle event type first
    event = request.headers.get('X-GitHub-Event', '')
    if event == 'ping':
        return 'pong', 200
    if event and event != 'push':
        return 'ignored (not a push event)', 200

    # Optional signature verification
    secret = os.getenv('WEBHOOK_SECRET')
    if secret:
        signature = request.headers.get('X-Hub-Signature-256', '')
        mac = hmac.new(secret.encode('utf-8'), msg=request.data, digestmod=hashlib.sha256)
        expected_signature = 'sha256=' + mac.hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            return {"error": "Invalid signature"}, 401

    # Only act on the configured branch (default: main)
    payload = request.get_json(silent=True) or {}
    target_branch = os.getenv('GIT_BRANCH', 'main')
    if payload.get('ref') and payload['ref'] != f'refs/heads/{target_branch}':
        return f"ignored (ref {payload.get('ref')} != refs/heads/{target_branch})", 200

    repo_path = os.getenv('REPO_PATH', os.path.expanduser('~/mysite'))

    # Open repository safely
    try:
        repo = git.Repo(repo_path)
    except (InvalidGitRepositoryError, NoSuchPathError) as e:
        log_error_to_json(e, context={"stage": "open_repo", "repo_path": repo_path})
        return {"error": "Invalid repository path", "repo_path": repo_path}, 500

    # Update repository: fetch + checkout + hard reset
    try:
        origin = next((r for r in repo.remotes if r.name == 'origin'), None)
        if origin is None:
            return {"error": "Remote 'origin' not found"}, 500

        # Fetch latest changes
        origin.fetch(prune=True)

        # Determine current branch; handle detached HEAD
        try:
            current_branch = repo.active_branch.name
        except Exception:
            current_branch = None

        # Ensure we are on the target branch locally
        if target_branch not in repo.heads:
            # Create local branch tracking origin/<branch>
            repo.git.checkout('-B', target_branch, f'origin/{target_branch}')
        elif current_branch != target_branch:
            repo.git.checkout(target_branch)

        # Force sync with origin/<branch> to avoid merge conflicts/prompts
        repo.git.reset('--hard', f'origin/{target_branch}')

        return 'OK', 200
    except GitCommandError as e:
        # Log stdout/stderr if available
        log_error_to_json(e, context={
            "stage": "git_update",
            "stderr": getattr(e, 'stderr', ''),
            "stdout": getattr(e, 'stdout', ''),
            "repo_path": repo_path,
            "branch": target_branch,
        })
        return {"error": "Git update failed", "message": str(e)}, 500
    except Exception as e:
        log_error_to_json(e, context={"stage": "git_update_unknown", "repo_path": repo_path})
        return {"error": "Unexpected error during git update", "message": str(e)}, 500


# ---------------- Demo/diagnostic routes ----------------


@app.route('/view-errors')
def view_errors():
    log_file = os.path.join("logs", "errors.json")
    if not os.path.exists(log_file):
        return """
        <h1>📋 No Errors Logged Yet</h1>
        <p>The error log file doesn't exist yet.</p>
        <a href="/">Back to Home</a>
        """

    try:
        with open(log_file, 'r') as f:
            content = f.read()
            errors = json.loads(content) if content else []
    except Exception as e:
        return f"""
        <h1>❌ Error Reading Log File</h1>
        <p>Could not read the log file: {str(e)}</p>
        <a href="/">Back to Home</a>
        """

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Error Logs</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
            h1 { color: #333; }
            .error-count { background: #ff6b6b; color: white; padding: 10px; border-radius: 5px; margin: 10px 0; }
            .error-item { background: white; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 10px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .error-header { color: #d32f2f; font-weight: bold; margin-bottom: 10px; }
            .error-details { background: #f8f8f8; padding: 10px; border-radius: 3px; margin: 10px 0; font-family: monospace; white-space: pre-wrap; word-wrap: break-word; }
            .timestamp { color: #666; font-size: 14px; }
            .clear-btn { background: #ff4444; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; margin: 10px 0; }
            .clear-btn:hover { background: #cc0000; }
            .refresh-btn { background: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; margin: 10px 5px; }
            .refresh-btn:hover { background: #45a049; }
        </style>
    </head>
    <body>
        <h1>🔴 Error Logs</h1>
    """

    if not errors:
        html += """
        <div class="error-count">✅ No errors logged</div>
        <a href="/" class="refresh-btn">Back to Home</a>
        """
    else:
        html += f"""
        <div class="error-count">⚠️ Total Errors: {len(errors)}</div>
        <a href="/view-errors" class="refresh-btn">🔄 Refresh</a>
        <a href="/clear-errors" class="clear-btn">🗑️ Clear All Errors</a>
        """
        for error in reversed(errors[-50:]):
            html += f"""
            <div class="error-item">
                <div class="error-header">{error.get('error_type', 'Unknown Error')}</div>
                <div class="timestamp">📅 {error.get('timestamp', 'No timestamp')}</div>
                <p><strong>Message:</strong> {error.get('error_message', 'No message')}</p>
                <p><strong>URL:</strong> {error.get('request_url', 'N/A')}</p>
                <p><strong>Method:</strong> {error.get('request_method', 'N/A')}</p>
                <p><strong>IP:</strong> {error.get('ip_address', 'N/A')}</p>
                <details>
                    <summary style="cursor: pointer; color: #1976d2;"><strong>View Full Traceback</strong></summary>
                    <div class="error-details">{error.get('traceback', 'No traceback')}</div>
                </details>
            </div>
            """

    html += "</body></html>"
    return html

@app.route('/clear-errors')
def clear_errors():
    log_file = os.path.join("logs", "errors.json")
    try:
        with open(log_file, 'w') as f:
            json.dump([], f)
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Errors Cleared</title></head>
        <body>
            <div style="background:#4CAF50;color:white;padding:20px;border-radius:5px;display:inline-block;">
                <h2>✅ All errors have been cleared!</h2>
            </div>
            <br><a href="/view-errors">Back to Error Logs</a>
        </body>
        </html>
        """
    except Exception as e:
        return f"""
        <h1>❌ Could not clear errors</h1>
        <p>Error: {str(e)}</p>
        <a href="/view-errors">Back to Error Logs</a>
        """

@app.route('/LuckyBoy')
def luckyBoy():
    html = """
    <h1> Site underconstruction </h1>
    <p><a href="/">← Back to Home</a></p>
    """
    return html

# Helper injected into all templates: floating Home button
@app.context_processor
def inject_helpers():
    def home_button():
        return f'''
        <a href="{url_for('home')}"
           class="fixed bottom-4 left-4 inline-flex items-center gap-2 rounded-md bg-indigo-600 px-3 py-2 text-white shadow hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm"
           title="Back to Home">
           ⬅ Home
        </a>
        '''
    return dict(home_button=home_button)

# ---------------- Home ----------------
@app.route('/')
@login_required
def home():
    # Build a list of routes automatically (exclude 'static')
    routes = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint == 'static':
            continue
        methods = sorted(m for m in rule.methods if m in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH'))
        routes.append({
            "rule": rule.rule,
            "endpoint": rule.endpoint,
            "methods": methods
        })
    routes.sort(key=lambda r: (r["rule"], r["endpoint"]))
    return render_template('home.html', routes=routes)
