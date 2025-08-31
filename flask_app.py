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

import secrets
from datetime import datetime, timedelta
from uuid import uuid4  # added


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

    error_id = uuid4().hex[:10]  # short correlation id
    error_data = {
        "error_id": error_id,
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
        return error_id  # changed: return correlation id
    except Exception as write_error:
        print(f"Failed to write to log file: {write_error}")
        print(f"Original error: {error_data}")
        return None


def handle_errors(func):
    """
    Decorator to automatically catch and log errors in routes.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            err_id = log_error_to_json(e, context={"function": func.__name__})
            return {"error": "An error occurred", "message": str(e), "error_id": err_id}, 500
    return wrapper


@app.errorhandler(Exception)
def handle_exception(e):
    """
    Global error handler for Flask app.
    """
    err_id = log_error_to_json(e)
    return {"error": "Internal Server Error", "message": str(e), "error_id": err_id}, 500


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
        err = RuntimeError("SENDGRID_API_KEY is missing")
        err_id = log_error_to_json(err, context={"route": "test_email"})
        return {"error": "Missing SENDGRID_API_KEY", "error_id": err_id}, 500

    from_email = os.getenv('MAIL_FROM', 'no-reply@example.com')

    message = Mail(
        from_email=from_email,
        to_emails=to,
        subject='SendGrid test from Flask',
        html_content='<strong>If you see this, SendGrid works.</strong>'
    )

    try:
        sg = SendGridAPIClient(api_key)
        region = (os.getenv('SENDGRID_REGION') or '').lower()
        if region in ('eu', 'eu1', 'eu_region'):
            try:
                sg.set_sendgrid_data_residency("eu")
            except Exception:
                pass

        resp = sg.send(message)
        body_raw = getattr(resp, 'body', b'')
        body_str = body_raw.decode() if isinstance(body_raw, (bytes, bytearray)) else str(body_raw or '')
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers or {}),
            "body": body_str[:500],
            "note": "202 means accepted by SendGrid."
        }, 200
    except Exception as e:
        err_id = log_error_to_json(e, context={"route": "test_email", "to": to, "sendgrid_detail": getattr(e, 'body', None)})
        return {
            "error": "SendGrid send failed",
            "message": str(e),
            "sendgrid_detail": (getattr(e, 'body', b'').decode(errors='ignore')
                                if isinstance(getattr(e, 'body', None), (bytes, bytearray))
                                else str(getattr(e, 'body', None))),
            "error_id": err_id
        }, 500

#-------------- Auth -----------------
# python
class EmailVerification(db.Model):
    __tablename__ = 'email_verifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    user = db.relationship('User', backref=db.backref('verifications', lazy='dynamic'))


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



# Ensure the new table exists (no-op if already created)
@app.before_request
def _ensure_tables():
    if not getattr(app, '_db_ready', False):
        db.create_all()
        app._db_ready = True

def is_user_verified(user_id: int) -> bool:
    row = db.session.execute(
        db.select(EmailVerification.id)
          .where(EmailVerification.user_id == user_id, EmailVerification.used_at.isnot(None))
          .limit(1)
    ).first()
    return bool(row)

def _new_verification_token(user) -> str:
    token = secrets.token_urlsafe(32)
    ev = EmailVerification(
        user_id=user.id,
        token=token,
        expires_at=datetime.utcnow() + timedelta(minutes=5),
    )
    db.session.add(ev)
    db.session.commit()
    return token

def send_verification_email(to_email: str, token: str):
    api_key = os.getenv('SENDGRID_API_KEY')
    if not api_key:
        raise RuntimeError('SENDGRID_API_KEY is missing')

    from_email = os.getenv('MAIL_FROM', 'no-reply@example.com')
    verify_url = url_for('verify_email', token=token, _external=True)

    message = Mail(
        from_email=from_email,
        to_emails=to_email,
        subject='Verify your email (expires in 5 minutes)',
        html_content=f'''
            <p>Click to verify your email (valid 5 minutes):</p>
            <p><a href="{verify_url}">{verify_url}</a></p>
            <p>If you did not sign up, ignore this email.</p>
        '''
    )

    sg = SendGridAPIClient(api_key)
    region = (os.getenv('SENDGRID_REGION') or '').lower()
    if region in ('eu', 'eu1', 'eu_region'):
        try:
            sg.set_sendgrid_data_residency("eu")
        except Exception:
            pass

    try:
        resp = sg.send(message)
        body_raw = getattr(resp, 'body', b'')
        body_str = body_raw.decode() if isinstance(body_raw, (bytes, bytearray)) else str(body_raw or '')
        if resp.status_code not in (200, 202):
            raise RuntimeError(f"SendGrid send failed (status={resp.status_code}): {body_str[:300]}")
        return {"status_code": resp.status_code, "headers": dict(resp.headers or {}), "body": body_str[:500]}
    except Exception as e:
        err_detail = getattr(e, 'body', None)
        if isinstance(err_detail, (bytes, bytearray)):
            err_detail = err_detail.decode(errors='ignore')
        raise RuntimeError(f"SendGrid error: {str(e)}; detail: {str(err_detail)[:500] if err_detail else 'n/a'}") from e

@app.route('/verify-email', methods=['GET'])
@handle_errors
def verify_email():
    token = (request.args.get('token') or '').strip()
    if not token:
        # log and surface correlation id
        err_id = log_error_to_json(ValueError('Missing token'), context={'route': 'verify_email'})
        flash(f'Missing token. Error ID: {err_id}', 'danger')
        return redirect(url_for('login'))

    ev = db.session.execute(
        db.select(EmailVerification).where(EmailVerification.token == token)
    ).scalars().first()

    if not ev:
        err_id = log_error_to_json(ValueError('Invalid token'), context={'route': 'verify_email', 'token_preview': token[:6]})
        flash(f'Invalid token. Error ID: {err_id}', 'danger')
        return redirect(url_for('login'))

    now = datetime.utcnow()
    if ev.used_at is not None:
        err_id = log_error_to_json(ValueError('Token already used'), context={'route': 'verify_email', 'ev_id': ev.id})
        flash(f'Token already used. Error ID: {err_id}', 'warning')
        return redirect(url_for('login'))
    if now > ev.expires_at:
        err_id = log_error_to_json(ValueError('Token expired'), context={'route': 'verify_email', 'ev_id': ev.id, 'expired_at': ev.expires_at.isoformat()})
        flash(f'Token expired. Error ID: {err_id}. Log in to request a new link.', 'danger')
        return redirect(url_for('login'))

    ev.used_at = now
    db.session.commit()
    flash('Email verified. You can now log in.', 'success')
    return redirect(url_for('login'))

# Update: Register route – send verification email and require verification
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

    try:
        token = _new_verification_token(user)
        send_info = send_verification_email(user.email, token)
        flash(f'Account created. Check your inbox to verify your email (valid 5 minutes). [SendGrid {send_info.get("status_code")}]', 'success')
    except Exception as e:
        err_id = log_error_to_json(e, context={'stage': 'send_verification', 'email': email, 'user_id': user.id})
        safe_msg = str(e)[:200]
        flash(f'Account created, but sending the verification email failed. Error ID: {err_id}. Cause: {safe_msg}', 'warning')

    return redirect(url_for('login'))

# Update: Login route – block until verified and resend a token
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

    if not is_user_verified(user.id):
        try:
            token = _new_verification_token(user)
            send_info = send_verification_email(user.email, token)
            flash(f'Please verify your email. A new verification link was sent (valid 5 minutes). [SendGrid {send_info.get("status_code")}]', 'warning')
        except Exception as e:
            err_id = log_error_to_json(e, context={'stage': 'resend_verification', 'user_id': user.id})
            safe_msg = str(e)[:200]
            flash(f'Your email is not verified and resending the link failed. Error ID: {err_id}. Cause: {safe_msg}', 'danger')
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
