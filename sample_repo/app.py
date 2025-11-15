import os
import logging
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify, abort, send_from_directory
from werkzeug.utils import secure_filename

#!/usr/bin/env python3
"""
Simple example Flask app suitable for an open-source sample repository.
Purpose: basic endpoints, file upload, small auth check. Designed to be simple
and safe for experimentation (no eval/exec or other dangerous patterns).
"""



# Configuration
APP_ROOT = Path(__file__).parent
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", APP_ROOT / "uploads"))
UPLOAD_DIR.mkdir(exist_ok=True, parents=True)
ALLOWED_EXTENSIONS = {"txt", "md", "png", "jpg", "jpeg", "gif"}
MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB max upload
API_TOKEN = os.getenv("API_TOKEN")  # optional token for simple auth

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sample_app")


# Helpers
def allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def require_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not API_TOKEN:
            return f(*args, **kwargs)  # not configured, open endpoint
        auth = request.headers.get("Authorization", "")
        parts = auth.split()
        if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1] == API_TOKEN:
            return f(*args, **kwargs)
        logger.warning("Unauthorized access attempt from %s", request.remote_addr)
        abort(401)
    return wrapper


# Routes
@app.route("/", methods=["GET"])
def index():
    return jsonify(
        {
            "name": "sample-app",
            "description": "Minimal Flask example for repository testing",
            "endpoints": {
                "GET /": "this info",
                "GET /health": "health check",
                "POST /echo": "echo JSON payload (safe)",
                "POST /upload": "upload a small file",
                "GET /files/<filename>": "download uploaded file",
            },
        }
    )


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/echo", methods=["POST"])
@require_token
def echo():
    # Accept JSON and return a sanitized subset
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "expected JSON object"}), 400
    # Only echo string, number, bool types and limit sizes
    safe = {}
    for k, v in data.items():
        if isinstance(v, (str, int, float, bool)):
            s = str(v)
            if len(s) > 1000:
                s = s[:1000]
            safe[k] = s
    return jsonify({"echo": safe})


@app.route("/upload", methods=["POST"])
@require_token
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "no file part"}), 400
    file = request.files["file"]
    # file.filename can be None according to type checkers; normalize to empty string
    filename_raw = file.filename or ""
    if filename_raw == "":
        return jsonify({"error": "no selected file"}), 400
    if not allowed_file(filename_raw):
        return jsonify({"error": "file type not allowed"}), 400

    filename = secure_filename(filename_raw)
    if not filename:
        return jsonify({"error": "invalid filename after sanitization"}), 400
    target = UPLOAD_DIR / filename

    # Avoid overwriting existing file by appending a counter
    counter = 0
    if "." in filename:
        base, ext = filename.rsplit(".", 1)
    else:
        base, ext = filename, ""

    while target.exists():
        counter += 1
        if ext:
            filename = f"{base}-{counter}.{ext}"
        else:
            filename = f"{base}-{counter}"
        target = UPLOAD_DIR / filename

    file.save(target)
    logger.info("Saved upload to %s", target)
    return jsonify({"filename": filename}), 201


@app.route("/files/<path:filename>", methods=["GET"])
@require_token
def get_file(filename):
    # Use secure_filename to reduce path traversal risk, but also check existence
    filename = secure_filename(filename)
    target = UPLOAD_DIR / filename
    if not target.exists() or not target.is_file():
        return jsonify({"error": "file not found"}), 404
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=True)


# Simple CLI for local dev
if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    logger.info("Starting sample app on %s:%d (debug=%s)", host, port, debug)
    app.run(host=host, port=port, debug=debug)