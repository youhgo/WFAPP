import json
import os
import sys
import uuid  # Replaced random.randint
import traceback
from werkzeug.utils import secure_filename  # Crucial addition for security
from flask import Blueprint, request, url_for, jsonify
from flask_login import login_required
from worker import celery

parse_api = Blueprint('parse_api', __name__)
WAPP_API = "https://wapp.localhost"
SHARED_FOLDER_PATH = "/python-docker/shared_files/"
DEPOT_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "depot")
WORKING_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "work")
LOG_FOLDER_PATH = os.path.join(WORKING_FOLDER_PATH, "execution_logs")

os.makedirs(DEPOT_FOLDER_PATH, exist_ok=True)
os.makedirs(WORKING_FOLDER_PATH, exist_ok=True)
os.makedirs(LOG_FOLDER_PATH, exist_ok=True)

# Allowed extensions (additional security)
ALLOWED_EXTENSIONS = {'.zip', '.7z', '.tar', '.gz'}


@parse_api.route('/parse_archive', methods=['POST'])
@login_required
def parse_archive():
    try:
        # 1. Validate file presence
        if 'file' not in request.files:
            return jsonify({"error": "No file provided in the request"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "Filename is empty"}), 400

        # Optional but recommended: Check extension
        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({"error": f"Extension {ext} not allowed"}), 400

        # 2. Securing and renaming
        # secure_filename removes dangerous characters (spaces, /, \, etc.)
        safe_filename = secure_filename(file.filename)

        # uuid4 generates a guaranteed unique identifier (e.g., 550e8400-e29b-41d4-a716-446655440000)
        # We can take only the first 8 characters to not lengthen the name too much
        unique_prefix = uuid.uuid4().hex[:8]
        file_name = f"{unique_prefix}__{file.filename}"

        file_path = os.path.join(DEPOT_FOLDER_PATH, file_name)
        file.save(file_path)

        # 3. Validate JSON data
        if 'json' not in request.form:
            return jsonify({"error": "The 'json' field is missing from the form"}), 400

        try:
            content = json.loads(request.form['json'])
        except json.JSONDecodeError:
            return jsonify({"error": "The 'json' field contains an invalid format"}), 400

        # 4. Send to Celery
        task = celery.send_task("tasks.parse_archive", args=[content, file_name], queue="parse")

        status_uri = url_for('wapp_api.get_task_status', task_id=task.id)
        run_uri = url_for('wapp_api.running_log', task_id=task.id)

        response = {
            "message": "Your analysis request has been sent to the queue",
            "taskId": str(task.id),
            "statusUrl": f"{WAPP_API}{status_uri}",
            "runLogUrl": f"{WAPP_API}{run_uri}"
        }

        # Using 202 (Accepted) code suitable for asynchronous tasks
        return jsonify(response), 202

    except Exception as e:
        # We log the technical error for the admin, but return a generic 500 error to the client
        sys.stderr.write(f"\n[CRITICAL ERROR] parse_archive: {traceback.format_exc()}\n")
        return jsonify({"error": "An internal error occurred while processing the request"}), 500