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
    if request.method == 'POST':
        repo = git.Repo('./myproject')
        origin = repo.remotes.origin
        repo.create_head('master',origin.refs.master).set_tracking_branch(origin.refs.master).checkout()
        origin.pull()
        return '', 200
    else:
        return '', 400

@app.route('/')
def home():
    return "Hello Webhook1"