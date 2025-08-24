import sys
import traceback
from flask import Blueprint, Response, jsonify, render_template, request, send_from_directory, abort, send_file
from worker import celery
import celery.states as states
from datetime import datetime
import os
import json
from random import randint

wapp_api = Blueprint('wapp_api', __name__)
SHARED_FOLDER_PATH = "/python-docker/shared_files/"
DEPOT_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "depot")
WORKING_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "work")
LOG_FOLDER_PATH = os.path.join(WORKING_FOLDER_PATH, "execution_logs")
# Define the path to the resources directory using the absolute path from your debug output
RESOURCES_FOLDER_PATH = "/python-docker/ressources"


@wapp_api.route("/")
def index():
    """
    api function to welcom user and check if co is ok
    :return:
    :rtype:
    """
    """
    api function to check health
    :return: OK
    :rtype: json dict
    """
    dt_string = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    response = {
        "message": "Welcome to Windows Forensic Artefact Parser Project",
        "status": "OK",
        "serveurTime": "{}".format(dt_string)
    }
    return jsonify(response)


@wapp_api.route("/index")
def gui_index():
    """
    api function to welcom user and check if co is ok
    :return:
    :rtype:
    """
    """
    api function to check health
    :return: OK
    :rtype: json dict
    """
    return render_template('index.html')


@wapp_api.route('/api/stop_task/<task_id>', methods=['POST'])
def stop_single_task(task_id):
    """
    api function to kill task
    :param task_id: task id that will been killed
    :type task_id: str
    :return: list of tasks id that have been killed
    :rtype: list
    """
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
def get_running_tasks():
    """
    api function to get all running tasks
    :return: dict of active tasks
    :rtype: dict
    """
    all_nodes = celery.control.inspect()
    response = {
        "active": all_nodes.active(),
        "killedTasks": []
    }
    return response


def stop_task(task_list):
    """
    function to kill tasks by it's id

    :param task_list: list of tasks id that will been killed
    :type task_list: list
    :return: list of tasks id that have been killed
    :rtype: list
    """
    l_killed_tasks = []
    for task_info in task_list:
        task_id = task_info.get('id', "")
        if task_id:
            celery.control.revoke(task_id, terminate=True, signal='SIGKILL')
            l_killed_tasks.append(task_id)
    return l_killed_tasks


@wapp_api.route('/api/get_running_tasks_parse')
def get_parser_tasks():
    """
    api function to get tasks related to parser module
    :return: list of tasks id
    :rtype: list
    """
    all_nodes = celery.control.inspect()
    worker_parser_name = get_parser_worker_name(all_nodes)
    worker_parser_tasks = all_nodes.active().get(worker_parser_name, [])
    return worker_parser_tasks

def get_parser_worker_name(all_nodes):
    """
    function to get the worker id that process the parsing tasks
    :param all_nodes: all celery node
    :type all_nodes: dict
    :return: worker id
    :rtype: str
    """
    for node in all_nodes.active().keys():
        if "parser" in node:
            return node

@wapp_api.route('/api/get_parser_worker_name')
def get_parser_worker_name_api():
    """
    api function to get the worker id that process the parsing tasks
    :return: worker id
    :rtype: str
    """
    all_nodes = celery.control.inspect()
    return jsonify(get_parser_worker_name(all_nodes))

@wapp_api.route('/api/get_worker_details')
def get_worker_details_api():
    """
    api function to get the worker id that process the parsing tasks
    :return: worker details
    :rtype: dict
    """
    all_nodes = celery.control.inspect()
    return jsonify(all_nodes.stats())

@wapp_api.route('/api/get_task_status/<task_id>')
def get_task_status(task_id):
    """
    api function to get task status
    :param task_id: task id
    :type task_id: str
    :return: task status
    :rtype: dict
    """
    task = celery.AsyncResult(task_id)
    response = {
        "task_id": task.id,
        "task_status": task.status,
        "task_result": task.result if task.result else "Still running"
    }
    return jsonify(response)

@wapp_api.route('/api/running_log/<task_id>')
def running_log(task_id):
    """
    api function to get running log
    :param task_id: task id
    :type task_id: str
    :return: log file
    :rtype: str
    """
    log_file = os.path.join(LOG_FOLDER_PATH, f"{task_id}_running.log")
    try:
        with open(log_file, "r") as f:
            return Response(f.read(), mimetype='text/plain')
    except IOError:
        return jsonify({"ERROR": "Log file not found", "TASKID": task_id}), 404
    except Exception as e:
        return jsonify({"ERROR": str(e), "TASKID": task_id}), 500

@wapp_api.route('/api/download/dfir-orc')
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
def list_resources_api():
    """
    API function to list the contents of the 'resources' directory for debugging.
    """
    try:
        # List all files and directories in the target folder
        contents = os.listdir(RESOURCES_FOLDER_PATH)
        # Separate files from directories for a cleaner output
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

'''
@wapp_api.route('/api/parse/parse_archive', methods=['POST'])
def parse_archive():
    """
    api function to parse archive
    :return: task id
    :rtype: dict
    """
    file_to_parse = request.files['file']
    json_data = json.loads(request.form['json'])
    case_name = json_data['caseName']
    machine_name = json_data['machineName']
    file_path = os.path.join(DEPOT_FOLDER_PATH, file_to_parse.filename)
    file_to_parse.save(file_path)
    task = celery.send_task('worker.parse_archive', args=[file_path, case_name, machine_name])
    response = {
        "taskId": task.id,
        "statusUrl": f"/api/get_task_status/{task.id}",
        "runLogUrl": f"/api/running_log/{task.id}"
    }
    return jsonify(response)
'''
