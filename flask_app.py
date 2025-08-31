import json
import os
import hmac
import hashlib
import traceback
from datetime import datetime
from functools import wraps

import git
from dotenv import load_dotenv
from git.exc import GitCommandError, InvalidGitRepositoryError, NoSuchPathError  # added

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
application = app  # WSGI entrypoint

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


#-------------- Auth -----------------
# MySQL configuration
app.config['MYSQL_HOST'] = os.getenv("DB_HOST")
app.config['MYSQL_USER'] = os.getenv("DB_USER")
app.config['MYSQL_PASSWORD'] = os.getenv("DB_PASSWORD")
app.config['MYSQL_DB'] = os.getenv("DB_NAME")

mysql = MySQL(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, username, email FROM users WHERE id=%s", (user_id,))
    result = cur.fetchone()
    if result:
        return User(*result)
    return None

# ------------------------
# Routes
# ------------------------

@app.route('/register', methods=['GET', 'POST'])
@handle_errors
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        cur = mysql.connection.cursor()
        try:
            cur.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                        (username, email, pw_hash))
            mysql.connection.commit()
            flash("User registered successfully!", "success")
            return redirect(url_for('login'))
        except:
            flash("Username or email already exists!", "danger")
            return redirect(url_for('register'))
    return render_template('templates/register.html')


@app.route('/login', methods=['GET', 'POST'])
@handle_errors
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT id, username, email, password_hash FROM users WHERE username=%s", (username,))
        result = cur.fetchone()
        if result and bcrypt.check_password_hash(result[3], password):
            user = User(result[0], result[1], result[2])
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials!", "danger")
            return redirect(url_for('login'))

    return render_template('templates/login.html')


@app.route('/dashboard')
@handle_errors
@login_required
def dashboard():
    return f"Hello, {current_user.username}! This is your dashboard."


@app.route('/logout')
@handle_errors
@login_required
def logout():
    logout_user()
    flash("Logged out!", "info")
    return redirect(url_for('login'))

# Load variables from .env (locally) or PA env panel
load_dotenv()


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

# Backward-compatible endpoint (optional)
@app.route('/update_server', methods=['POST'])
@handle_errors
def update_server():
    # Reuse the same logic
    return github_webhook()

# ---------------- Demo/diagnostic routes ----------------
@app.route('/test')
@handle_errors
def test_route():
    return {"message": "Success"}

@app.route('/error')
@handle_errors
def error_route():
    _ = 1 / 0  # intentional error
    return {"result": _}

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
    """
    return html

# ---------------- Home ----------------
@app.route('/')
def home():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
      <title>Home</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { margin-bottom: 10px; }
        h3 { margin-top: 20px; }
        .link { display: inline-block; margin: 6px 0; }
      </style>
    </head>
    <body>
      <h1>Hello Webhook2</h1>
    
      <h3>Pages</h3>
      <p class="link"><a href="/">Home</a></p>
      <p class="link"><a href="/register">Register</a></p>
      <p class="link"><a href="/login">Login</a></p>
      <p class="link"><a href="/dashboard">Dashboard</a></p>
      <p class="link"><a href="/logout">Logout</a></p>
      <p class="link"><a href="/LuckyBoy">LuckyBoy</a></p>
    
      <h3>Diagnostics</h3>
      <p class="link"><a href="/test">Test (JSON)</a></p>
      <p class="link"><a href="/error">Trigger Error</a></p>
      <p class="link"><a href="/view-errors">View Errors</a></p>
      <p class="link"><a href="/clear-errors">Clear Errors</a></p>
    
      <h3>Webhooks</h3>
      <p>POST-only endpoints (not clickable): /git, /update_server</p>
    </body>
    </html>
    """
    return html