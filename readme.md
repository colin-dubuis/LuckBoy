# Instagram‑Lite with Flask, Cloudflare R2 & PythonAnywhere

A lightweight social‑media clone where users can register, upload a photo with a caption, and comment on others’ posts. The stack is deliberately simple so you can get a working MVP quickly, then iterate on features such as likes, pagination, or a SPA front‑end.

## Table of Contents
- [Project Overview](#project-overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Setup and Local Development](#setup-and-local-development)
- [Deploy to PythonAnywhere](#deploy-to-pythonanywhere)
- [Cloudflare R2 Integration](#cloudflare-r2-integration)
- [Database Schema](#database-schema)
- [Running Tests](#running-tests)
- [Folder Structure](#folder-structure)
- [Future Improvements](#future-improvements)
- [License](#license)

## Project Overview
The application mimics the core flow of Instagram:
- Users create an account (email + password).
- Authenticated users can upload a picture (stored in Cloudflare R2) with an optional caption.
- All posts appear on a public feed.
- Logged‑in users can leave comments on any post.

Everything runs on Flask, uses Flask‑Login for authentication, Flask‑SQLAlchemy for ORM, and boto3 to talk to Cloudflare R2 (S3‑compatible).

## Features
| Status | Feature                         | Description                                                                 |
| :----: | --------------------------------| ---------------------------------------------------------------------------- |
| ✅     | User registration & login       | Secure password hashing with Werkzeug.                                       |
| ✅     | Image upload                    | Files are streamed to an R2 bucket; the public URL is saved in the DB.      |
| ✅     | Public feed                     | Posts displayed in reverse chronological order with captions and comments.   |
| ✅     | Comments                        | Simple text comments linked to users and posts.                              |
| ✅     | GitHub webhook → auto‑deploy    | Pushes to main trigger a git pull on PythonAnywhere.                         |
| ⚙️     | Responsive UI                   | Minimal CSS via Tailwind (CDN).                                              |
| 📝     | Pagination / Likes / Notifications | Planned future enhancements.                                              |

## Tech Stack
| Layer          | Technology                                                                 |
| -------------- | -------------------------------------------------------------------------- |
| Backend        | Python 3.11, Flask, Flask‑Login, Flask‑SQLAlchemy, Flask‑Migrate           |
| Database       | SQLite (dev) or MySQL (PythonAnywhere)                                     |
| Object storage | Cloudflare R2 (S3‑compatible) via boto3                                    |
| Front‑end      | Jinja2 templates, Tailwind CSS (CDN)                                       |
| Deployment     | PythonAnywhere (WSGI), GitHub webhook for CI‑style deployment              |
| Version control| Git + GitHub                                                               |

## Prerequisites
- Python ≥ 3.10 installed locally
- Git command line client
- GitHub account (repo + webhook)
- PythonAnywhere account (free tier is fine)
- Cloudflare account with an R2 bucket
- Optional: virtualenv or conda for isolated dependencies

## Setup and Local Development
1) Clone the repo
```bash
git clone https://github.com/<your-username>/instagram-lite.git
cd instagram-lite
```

2) Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
```

3) Install dependencies
```bash
pip install -r requirements.txt
```

4) Set environment variables (create .env or export manually)
```bash
export FLASK_APP=app.py
export FLASK_ENV=development
export SECRET_KEY=$(openssl rand -hex 32)          # used by Flask sessions
export R2_ENDPOINT_URL="https://<account-id>.r2.cloudflarestorage.com"
export R2_ACCESS_KEY_ID="<your-access-key>"
export R2_SECRET_ACCESS_KEY="<your-secret>"
export DATABASE_URL="sqlite:///app.db"             # or MySQL URI for PA
```

5) Initialise the database
```bash
flask db upgrade
```

6) Run the development server
```bash
flask run
```

Open http://127.0.0.1:5000 in your browser. You should see the landing page, be able to register, log in, and upload a test image.

## Deploy to PythonAnywhere
1) Create a new web app (choose Flask).

2) Clone the repo into your home directory (e.g., `~/instagram-lite`).

3) Create a virtualenv on PythonAnywhere and install the same `requirements.txt`.

4) Add environment variables via the Web → Environment variables panel (R2 keys, SECRET_KEY, DATABASE_URL).

5) Configure WSGI – edit the generated `flask_app.py` to point at `app.py`.

6) Set up a webhook on GitHub:
- Repository → Settings → Webhooks → Add webhook
- Payload URL: `https://<your-username>.pythonanywhere.com/git`
- Content type: `application/json`
- Choose “Just the push event”.

7) Create a deploy script (`deploy.sh`) in the project root (make it executable):
```bash
#!/bin/bash
set -euo pipefail
cd ~/instagram-lite
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
flask db upgrade
touch /var/www/<your-username>_pythonanywhere_com_wsgi.py   # forces reload
```

Test the pipeline – push a change to `main`; the webhook should trigger the script and reload the site. Check the Error log on PythonAnywhere if anything fails.

## Cloudflare R2 Integration
### Bucket creation
- Log in to Cloudflare → R2 → Buckets → Create bucket (e.g., `instagram-lite-photos`).
- Note the Account ID (used in the endpoint URL).

### Credentials
- R2 → API Tokens → Create token with Read/Write permissions for the bucket.
- Store the Access Key ID and Secret Access Key as env vars (`R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`).

### Upload helper (`utils/r2.py`)
```python
import os
import boto3
from botocore.client import Config
from werkzeug.utils import secure_filename

def get_r2_client():
    return boto3.client(
        "s3",
        endpoint_url=os.getenv("R2_ENDPOINT_URL"),
        aws_access_key_id=os.getenv("R2_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("R2_SECRET_ACCESS_KEY"),
        config=Config(signature_version="s3v4"),
        region_name="auto",  # optional for R2
    )

def upload_to_r2(file_storage, bucket_name):
    client = get_r2_client()
    filename = secure_filename(file_storage.filename)
    client.upload_fileobj(
        Fileobj=file_storage,
        Bucket=bucket_name,
        Key=filename,
        ExtraArgs={"ACL": "public-read"}   # or omit and use signed URLs
    )
    return f"{os.getenv('R2_ENDPOINT_URL')}/{bucket_name}/{filename}"
```

The function returns the public URL, which you store in the `Post.image_url` column.

## Database Schema
```
User
 ├─ id (PK)
 ├─ email (unique)
 ├─ password_hash
 └─ created_at

Post
 ├─ id (PK)
 ├─ user_id (FK → User.id)
 ├─ caption (TEXT)
 ├─ image_url (STRING)
 └─ created_at

Comment
 ├─ id (PK)
 ├─ post_id (FK → Post.id)
 ├─ user_id (FK → User.id)
 ├─ body (TEXT)
 └─ created_at
```

Migrations are handled with Flask‑Migrate (`flask db init`, `flask db migrate`, `flask db upgrade`).

## Running Tests
A minimal test suite lives under `tests/`. It uses pytest and Flask’s test client.
```bash
pip install pytest
pytest
```

Typical tests cover:
- Registration & login flow
- Image upload (mocked boto3 client)
- Feed rendering and comment creation

## Folder Structure
```
instagram-lite/
│
├─ app.py                 # Flask app factory, routes
├─ config.py              # Configuration classes (dev/prod)
├─ models.py              # SQLAlchemy models
├─ utils/
│   └─ r2.py              # R2 upload helper
│
├─ templates/
│   ├─ base.html
│   ├─ feed.html
│   └─ upload.html
│
├─ static/
│   ├─ css/
│   │   └─ style.css
│   └─ js/
│
├─ migrations/            # Flask‑Migrate files
├─ tests/
│   └─ test_basic.py
│
├─ requirements.txt
├─ .gitignore
└─ README.md
```

## Future Improvements
- Pagination / infinite scroll – limit feed to N posts per request
- Likes & reactions – separate table linking users ↔ posts
- Signed URLs for private R2 objects – improve security
- Dockerfile – containerised development & easier deployment to other hosts
- Frontend SPA – React/Vue with a Flask REST API
- Email verification & password reset

## License
This project is released under the MIT License – feel free to fork, modify, and deploy it as you wish.

Happy coding! If you run into trouble with the webhook, R2 credentials, or any other piece, open an issue in the repository.
