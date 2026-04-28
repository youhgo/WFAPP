import json
import os
import sys
import uuid  # Remplacement de random.randint
import traceback
from werkzeug.utils import secure_filename  # Ajout crucial pour la sécurité
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

# Extensions autorisées (sécurité supplémentaire)
ALLOWED_EXTENSIONS = {'.zip', '.7z', '.tar', '.gz'}


@parse_api.route('/parse_archive', methods=['POST'])
@login_required
def parse_archive():
    try:
        # 1. Validation de la présence du fichier
        if 'file' not in request.files:
            return jsonify({"error": "Aucun fichier fourni dans la requête"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "Le nom du fichier est vide"}), 400

        # Optionnel mais recommandé : Vérifier l'extension
        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({"error": f"Extension {ext} non autorisée"}), 400

        # 2. Sécurisation et renommage
        # secure_filename enlève les caractères dangereux (espaces, / , \, etc.)
        safe_filename = secure_filename(file.filename)

        # uuid4 génère un identifiant unique garanti (ex: 550e8400-e29b-41d4-a716-446655440000)
        # On peut ne prendre que les 8 premiers caractères pour ne pas trop rallonger le nom
        unique_prefix = uuid.uuid4().hex[:8]
        file_name = f"{unique_prefix}__{file.filename}"

        file_path = os.path.join(DEPOT_FOLDER_PATH, file_name)
        file.save(file_path)

        # 3. Validation des données JSON
        if 'json' not in request.form:
            return jsonify({"error": "Le champ 'json' est manquant dans le formulaire"}), 400

        try:
            content = json.loads(request.form['json'])
        except json.JSONDecodeError:
            return jsonify({"error": "Le champ 'json' contient un format invalide"}), 400

        # 4. Envoi à Celery
        task = celery.send_task("tasks.parse_archive", args=[content, file_name], queue="parse")

        status_uri = url_for('wapp_api.get_task_status', task_id=task.id)
        run_uri = url_for('wapp_api.running_log', task_id=task.id)

        response = {
            "message": "Votre demande d'analyse a été envoyée dans la file d'attente",
            "taskId": str(task.id),
            "statusUrl": f"{WAPP_API}{status_uri}",
            "runLogUrl": f"{WAPP_API}{run_uri}"
        }

        # Utilisation du code 202 (Accepted) adapté aux tâches asynchrones
        return jsonify(response), 202

    except Exception as e:
        # On logue l'erreur technique pour l'admin, mais on renvoie une erreur 500 générique au client
        sys.stderr.write(f"\n[CRITICAL ERROR] parse_archive: {traceback.format_exc()}\n")
        return jsonify({"error": "Une erreur interne est survenue lors du traitement de la requête"}), 500