import json
import os
import sys
import time
import traceback
from flask import Blueprint, request, url_for, jsonify
from flask_login import login_required
from worker import celery
from random import randint
from extensions import db, login_manager
from models import User

parse_api = Blueprint('parse_api', __name__)
WAPP_API = "https://wapp.localhost"
SHARED_FOLDER_PATH = "/python-docker/shared_files/"
DEPOT_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "depot")
WORKING_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "work")
LOG_FOLDER_PATH = os.path.join(WORKING_FOLDER_PATH, "execution_logs")

os.makedirs(DEPOT_FOLDER_PATH, exist_ok=True)
os.makedirs(WORKING_FOLDER_PATH, exist_ok=True)
os.makedirs(LOG_FOLDER_PATH, exist_ok=True)


@parse_api.route('/parse_archive', methods=['POST'])
@login_required
def parse_archive():
    try:
        rand = randint(1000, 5000)
        file = request.files['file']
        file_name = file.filename + "__{}".format(rand)
        file_path = os.path.join(DEPOT_FOLDER_PATH, file_name)
        file.save(file_path)

        content = json.loads(request.form['json'])
        task = celery.send_task("tasks.parse_archive", args=[content, file_name], kwargs={}, queue="parse")

        status_uri = url_for('wapp_api.get_task_status', task_id=task.id)
        run_uri = url_for('wapp_api.running_log', task_id=task.id)

        response = {
            "message": "your parsing request has been send to queue",
            "taskId": "{}".format(task.id),
            "statusUrl": "{}{}".format(WAPP_API, status_uri),
            "runLogUrl": "{}{}".format(WAPP_API, run_uri)
        }
        time.sleep(1)
        return jsonify(response), 200
    except Exception:
        sys.stderr.write("\nerror : {}\n".format(traceback.format_exc()))
        return jsonify({"error": "Your request seems bad"})
