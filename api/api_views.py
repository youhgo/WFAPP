import sys
from datetime import datetime
import os

from flask import Blueprint, Response, jsonify, render_template, request, send_from_directory, abort
from flask_login import login_user, logout_user, login_required, current_user
from worker import celery
from extensions import db, login_manager
from models import User   # ✅ Import du modèle

wapp_api = Blueprint('wapp_api', __name__)
SHARED_FOLDER_PATH = "/python-docker/shared_files/"
DB_FOLDER_PATH = "/python-docker/db/"
DEPOT_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "depot")
WORKING_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "work")
LOG_FOLDER_PATH = os.path.join(WORKING_FOLDER_PATH, "execution_logs")
RESOURCES_FOLDER_PATH = "/python-docker/ressources"


# Page d’admin protégée
@wapp_api.route("/admin/users")
@login_required
def users_admin():
    # Vérification du nouveau champ is_admin
    if not current_user.is_admin:
        return jsonify({"message": "Access forbidden"}), 403
    return render_template("users.html")


# API pour récupérer la liste des utilisateurs
@wapp_api.route("/api/users", methods=["GET"])
@login_required
def list_users():
    if not current_user.is_admin:
        return jsonify({"message": "Access forbidden"}), 403
    from models import User
    users = User.query.all()
    # Inclure le statut d'administrateur dans la réponse
    return jsonify([{"id": u.id, "username": u.username, "is_admin": u.is_admin} for u in users])


# API pour modifier un user
@wapp_api.route("/api/users/<int:user_id>", methods=["PUT"])
@login_required
def update_user(user_id):
    if not current_user.is_admin:
        return jsonify({"message": "Access forbidden"}), 403
    from models import User, db
    data = request.get_json()
    user = User.query.get_or_404(user_id)
    if "username" in data:
        user.username = data["username"]
    if "password" in data:
        user.set_password(data["password"])
    # Ajoutez la logique pour mettre à jour le statut d'administrateur
    if "is_admin" in data:
        user.is_admin = data["is_admin"]
    db.session.commit()
    return jsonify({"message": "User updated"})


# API pour supprimer un user
@wapp_api.route("/api/users/<int:user_id>", methods=["DELETE"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({"message": "Access forbidden"}), 403
    from models import User, db
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted"})

# Assurez-vous d'appliquer la même logique pour les autres routes admin.


@wapp_api.route("/index")
@login_required
def gui_index():
    return render_template('index.html')


@wapp_api.route("/login_page")
def login_page():
    return render_template("login.html")


# Fonction de chargement des utilisateurs
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
    """Déconnecte l'utilisateur actuel et le redirige vers la page de connexion."""
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


@wapp_api.route('/api/download/dfir-orc')
@login_required
def download_dfir_orc():
    try:
        print("Trying to send:", os.path.join(RESOURCES_FOLDER_PATH, 'DFIR-Orc.exe'), file=sys.stderr)
        return send_from_directory(
            directory=RESOURCES_FOLDER_PATH,
            path="DFIR-Orc.exe",
            as_attachment=True
        )
    except FileNotFoundError:
        abort(404, description="DFIR-Orc.exe not found in resources folder.")
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
