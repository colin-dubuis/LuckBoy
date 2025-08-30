import hmac
import hashlib
from flask import Flask, request, abort
import git
from dotenv import load_dotenv
import os

app = Flask(__name__)

# Load variables from .env
load_dotenv()
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET').encode()  # convert to bytes

@app.route('/update_server', methods=['POST'])
def webhook():
    # Get signature from GitHub header
    signature = request.headers.get('X-Hub-Signature-256')
    if signature is None:
        abort(400, 'Signature missing')

    # Compute HMAC SHA256 of payload
    mac = hmac.new(WEBHOOK_SECRET, msg=request.data, digestmod=hashlib.sha256)
    expected_signature = 'sha256=' + mac.hexdigest()

    # Compare GitHub signature with expected signature
    if not hmac.compare_digest(signature, expected_signature):
        abort(400, 'Invalid signature')

    # If signature is valid, pull the repo
    repo = git.Repo('/home/Warbird65/mysite')
    origin = repo.remotes.origin
    origin.pull()
    return 'Updated PythonAnywhere successfully', 200

@app.route('/')
def home():
    return "Hello Webhook"