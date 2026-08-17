import sys
from datetime import datetime
import os

from flask import Blueprint, Response, jsonify, render_template, request, send_from_directory, abort
from flask_login import login_user, logout_user, login_required, current_user
from worker import celery
from extensions import db, login_manager
from models import User   # ✅ Import model

wapp_api = Blueprint('wapp_api', __name__)
SHARED_FOLDER_PATH = "/python-docker/shared_files/"
DB_FOLDER_PATH = "/python-docker/db/"
DEPOT_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "depot")
WORKING_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "work")
LOG_FOLDER_PATH = os.path.join(WORKING_FOLDER_PATH, "execution_logs")
RESOURCES_FOLDER_PATH = "/python-docker/ressources"


# Protected admin page
@wapp_api.route("/admin/users")
@login_required
def users_admin():
    # Check new is_admin field
    if not current_user.is_admin:
        return jsonify({"message": "Access forbidden"}), 403
    return render_template("users.html")


# API to fetch the list of users
@wapp_api.route("/api/users", methods=["GET"])
@login_required
def list_users():
    if not current_user.is_admin:
        return jsonify({"message": "Access forbidden"}), 403
    users = User.query.all()
    # Include admin status in the response
    return jsonify([{"id": u.id, "username": u.username, "is_admin": u.is_admin} for u in users])


# API to update a user
@wapp_api.route("/api/users/<int:user_id>", methods=["PUT"])
@login_required
def update_user(user_id):
    if not current_user.is_admin:
        return jsonify({"message": "Access forbidden"}), 403
    data = request.get_json()
    user = User.query.get_or_404(user_id)
    if "username" in data:
        user.username = data["username"]
    if "password" in data:
        user.set_password(data["password"])
    # Add logic to update the admin status
    if "is_admin" in data:
        user.is_admin = data["is_admin"]
    db.session.commit()
    return jsonify({"message": "User updated"})


# API to delete a user
@wapp_api.route("/api/users/<int:user_id>", methods=["DELETE"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({"message": "Access forbidden"}), 403
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted"})

# Make sure to apply the same logic to other admin routes.


@wapp_api.route("/index")
@login_required
def gui_index():
    return render_template('index.html')


@wapp_api.route("/login_page")
def login_page():
    return render_template("login.html")


# User loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@wapp_api.route('/api/register', methods=['POST'])
@login_required
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"message": "Username already exists"}), 409

    new_user = User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201


@wapp_api.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        login_user(user)
        return jsonify({"message": "Logged in successfully"}), 200
    else:
        return jsonify({"message": "Invalid username or password"}), 401


@wapp_api.route('/api/logout', methods=['POST'])
@login_required
def logout():
    """Logs out the current user and redirects them to the login page."""
    logout_user()
    return jsonify({"message": "Successfully logged out"}), 200


@wapp_api.route("/")
def index():
    dt_string = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    response = {
        "message": "Welcome to Windows Forensic Artefact Parser Project",
        "status": "OK",
        "serveurTime": "{}".format(dt_string)
    }
    return jsonify(response)

@wapp_api.route('/api/stop_task/<task_id>', methods=['POST'])
@login_required
def stop_single_task(task_id):
    try:
        celery.control.revoke(task_id, terminate=True, signal='SIGKILL')
        response = {
            "message": f"Task {task_id} killed.",
            "status": "OK"
        }
        return jsonify(response)
    except Exception as e:
        response = {
            "message": f"An error occurred: {str(e)}",
            "status": "ERROR"
        }
        return jsonify(response), 500


@wapp_api.route('/api/get_running_tasks')
@login_required
def get_running_tasks():
    all_nodes = celery.control.inspect()
    response = {
        "active": all_nodes.active(),
        "killedTasks": []
    }
    return response


def stop_task(task_list):
    l_killed_tasks = []
    for task_info in task_list:
        task_id = task_info.get('id', "")
        if task_id:
            celery.control.revoke(task_id, terminate=True, signal='SIGKILL')
            l_killed_tasks.append(task_id)
    return l_killed_tasks


@wapp_api.route('/api/get_running_tasks_parse')
@login_required
def get_parser_tasks():
    all_nodes = celery.control.inspect()
    worker_parser_name = get_parser_worker_name(all_nodes)
    worker_parser_tasks = all_nodes.active().get(worker_parser_name, [])
    return worker_parser_tasks


def get_parser_worker_name(all_nodes):
    for node in all_nodes.active().keys():
        if "parser" in node:
            return node

@wapp_api.route('/api/get_parser_worker_name')
@login_required
def get_parser_worker_name_api():
    all_nodes = celery.control.inspect()
    return jsonify(get_parser_worker_name(all_nodes))


@wapp_api.route('/api/get_worker_details')
@login_required
def get_worker_details_api():
    all_nodes = celery.control.inspect()
    return jsonify(all_nodes.stats())


@wapp_api.route('/api/get_task_status/<task_id>')
@login_required
def get_task_status(task_id):
    task = celery.AsyncResult(task_id)
    response = {
        "task_id": task.id,
        "task_status": task.status,
        "task_result": task.result if task.result else "Still running"
    }
    return jsonify(response)


@wapp_api.route('/api/running_log/<task_id>')
@login_required
def running_log(task_id):
    log_file = os.path.join(LOG_FOLDER_PATH, f"{task_id}_running.log")
    try:
        with open(log_file, "r") as f:
            return Response(f.read(), mimetype='text/plain')
    except IOError:
        return jsonify({"ERROR": "Log file not found", "TASKID": task_id}), 404
    except Exception as e:
        return jsonify({"ERROR": str(e), "TASKID": task_id}), 500


@wapp_api.route('/api/download/dfir-orc-full')
@login_required
def download_dfir_orc_classic():
    try:
        orc_classic_path = os.path.join(RESOURCES_FOLDER_PATH, "config_classic")
        print("Trying to send:", os.path.join(orc_classic_path, 'DFIR-Orc.exe'), file=sys.stderr)
        return send_from_directory(
            directory=orc_classic_path,
            path="DFIR-Orc.exe",
            as_attachment=True
        )
    except FileNotFoundError:
        abort(404, description="DFIR-Orc.exe not found in resources folder.")
    except Exception as e:
        print(f"Error during download: {e}", file=sys.stderr)
        abort(500, description="Internal Server Error during download.")


@wapp_api.route('/api/download/dfir-orc-offlinemode')
@login_required
def download_dfir_orc_offline():
    try:
        orc_offline_path = os.path.join(RESOURCES_FOLDER_PATH, "config_offline")
        print("Trying to send:", os.path.join(RESOURCES_FOLDER_PATH, 'DFIR-Orc_offline.exe'), file=sys.stderr)
        return send_from_directory(
            directory=orc_offline_path,
            path="DFIR-Orc_offline.exe",
            as_attachment=True
        )
    except FileNotFoundError:
        abort(404, description="DFIR-Orc_offline.exe not found in resources folder.")
    except Exception as e:
        print(f"Error during download: {e}", file=sys.stderr)
        abort(500, description="Internal Server Error during download.")


@wapp_api.route('/api/download/dfir-orc-wmem')
@login_required
def download_dfir_orc_wmemory():
    try:
        orc_wmem_path = os.path.join(RESOURCES_FOLDER_PATH, "config_wmemory")
        print("Trying to send:", os.path.join(orc_wmem_path, 'DFIR-Orc_wmem.exe'), file=sys.stderr)
        return send_from_directory(
            directory=orc_wmem_path,
            path="DFIR-Orc_wmem.exe",
            as_attachment=True
        )
    except FileNotFoundError:
        abort(404, description="DFIR-Orc_wmem.exe not found in resources folder.")
    except Exception as e:
        print(f"Error during download: {e}", file=sys.stderr)
        abort(500, description="Internal Server Error during download.")


@wapp_api.route('/api/debug/list_resources')
@login_required
def list_resources_api():
    try:
        contents = os.listdir(RESOURCES_FOLDER_PATH)
        files = [f for f in contents if os.path.isfile(os.path.join(RESOURCES_FOLDER_PATH, f))]
        directories = [d for d in contents if os.path.isdir(os.path.join(RESOURCES_FOLDER_PATH, d))]
        response = {
            "status": "OK",
            "path_checked": RESOURCES_FOLDER_PATH,
            "contents": {
                "files": files,
                "directories": directories
            }
        }
        return jsonify(response)
    except FileNotFoundError:
        response = {
            "status": "ERROR",
            "message": f"The directory {RESOURCES_FOLDER_PATH} was not found."
        }
        return jsonify(response), 404
    except Exception as e:
        response = {
            "status": "ERROR",
            "message": f"An error occurred: {str(e)}"
        }
        return jsonify(response), 500

import re

import ast

def extract_plugin_info(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=file_path)
    except Exception as e:
        print(f"AST Error reading {file_path}: {e}", file=sys.stderr)
        return None

    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            is_plugin = False
            plugin_name = None
            plugin_type = None
            
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and getattr(decorator.func, 'id', '') in ['register_pipeline', 'register_preprocessor', 'register_postprocessor']:
                    is_plugin = True
                    func_id = getattr(decorator.func, 'id', '')
                    if func_id == 'register_preprocessor': plugin_type = 'preprocessor'
                    elif func_id == 'register_pipeline': plugin_type = 'pipeline'
                    elif func_id == 'register_postprocessor': plugin_type = 'postprocessor'
                    
                    if decorator.args and isinstance(decorator.args[0], ast.Constant):
                        plugin_name = decorator.args[0].value
                    elif decorator.keywords:
                        for kw in decorator.keywords:
                            if kw.arg == 'name' and isinstance(kw.value, ast.Constant):
                                plugin_name = kw.value.value
            
            if is_plugin and plugin_name:
                description = ast.get_docstring(node)
                if description:
                    description = description.strip()
                else:
                    description = "No description available."
                    
                recommended = True
                for item in node.body:
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            if getattr(target, 'id', '') == 'recommended':
                                if isinstance(item.value, ast.Constant):
                                    recommended = item.value.value
                return {
                    "name": plugin_name,
                    "description": description,
                    "recommended": recommended,
                    "type": plugin_type
                }
    return None

@wapp_api.route('/api/pipelines', methods=['GET'])
@login_required
def get_pipelines():
    dirs = [
        "/python-docker/WAPP_MODULE/preprocessors",
        "/python-docker/WAPP_MODULE/modules",
        "/python-docker/WAPP_MODULE/postprocessors"
    ]
    pipelines = []
    
    for d in dirs:
        try:
            if os.path.exists(d):
                for file_name in os.listdir(d):
                    if file_name.endswith('.py') and not file_name.startswith('__'):
                        file_path = os.path.join(d, file_name)
                        info = extract_plugin_info(file_path)
                        if info:
                            pipelines.append(info)
        except Exception as e:
            print(f"Error scanning directory {d}: {e}", file=sys.stderr)
            
    return jsonify({"status": "OK", "pipelines": pipelines})

