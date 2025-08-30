import json
import os
import hmac
import hashlib
import traceback
from datetime import datetime
from functools import wraps

from flask import Flask, request
import git
from dotenv import load_dotenv

app = Flask(__name__)
application = app  # WSGI entrypoint

# Load variables from .env (locally) or PA env panel
load_dotenv()

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

# ---------------- Webhook routes ----------------
@app.route('/git', methods=['POST'])
@handle_errors
def github_webhook():
    # GitHub ping
    if request.headers.get('X-GitHub-Event') == 'ping':
        return 'pong', 200

    # Optional signature verification
    secret = os.getenv('WEBHOOK_SECRET')
    if secret:
        signature = request.headers.get('X-Hub-Signature-256', '')
        mac = hmac.new(secret.encode('utf-8'), msg=request.data, digestmod=hashlib.sha256)
        expected_signature = 'sha256=' + mac.hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            return {"error": "Invalid signature"}, 401

    repo_path = os.getenv('REPO_PATH', os.path.expanduser('~/mysite'))
    repo = git.Repo(repo_path)
    origin = repo.remotes.origin
    origin.pull()
    return 'OK', 200

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

# ---------------- Home ----------------
@app.route('/')
def home():
    return ('<h1> Hello Webhook2 </h1> <p><a href="view-errors" class="refresh-btn">See Errors</a> </p> <p><a href="test" class="refresh-btn">Create Errors</a> </p>"')