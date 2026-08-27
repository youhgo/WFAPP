# WFAPP API Usage Guide

This guide details how to interact with the WFAPP REST API programmatically. You can use this API to automate the forensic analysis pipeline, monitor processing tasks, check logs, retrieve plugin metadata, and natively ingest DFIR-ORC BITS uploads.

---

## 1. Authentication

The WFAPP API uses token-based authentication via an API Key. You must include your API key in every request using either the `X-API-Key` or `Authorization` header.

To get your API key, log into the Web GUI as an administrator, or check your profile settings. 

### Authentication Header Examples
You can use either format in your HTTP requests:
- `X-API-Key: YOUR_API_KEY`
- `Authorization: Bearer YOUR_API_KEY`

### Verify Authentication
To verify that your API key is valid and fetch your user details (including your current API key):
* **URL:** `/api/me`
* **Method:** `GET`

```bash
curl -X GET https://wapp.localhost/api/me \
   -H "X-API-Key: YOUR_API_KEY"
```

### Manage Your API Key
You can revoke your current API key or generate a new one.

* **URL:** `/api/me/api_key`
* **Method:** `POST`
* **Headers:** `Content-Type: application/json`, `X-API-Key: YOUR_API_KEY` (or via cookie if logged in to the GUI)
* **Payload:** `{"action": "generate"}` or `{"action": "revoke"}`

```bash
curl -X POST https://wapp.localhost/api/me/api_key \
   -H "Content-Type: application/json" \
   -H "X-API-Key: YOUR_API_KEY" \
   -d '{"action": "generate"}'
```

---

## 2. DFIR-ORC Native BITS Upload

WFAPP now features a built-in endpoint that emulates a BITS (Background Intelligent Transfer Service) server. This allows DFIR-ORC to natively upload its generated archive directly to the API, which will instantly and automatically trigger the parsing pipeline.

### DFIR-ORC Configuration
To configure DFIR-ORC to upload its output archive to WFAPP, modify your DFIR-ORC XML configuration file (`Upload` section) to use the `BITS` method targeting the new `/upload_orc_bits` endpoint.

You can specify the `caseName` (and optionally `machineName`) directly in the URL as query parameters to logically group your investigation results.

```xml
<Upload>
  <UploadMethod>BITS</UploadMethod>
  <Post>https://wapp.localhost/api/parse/upload_orc_bits?caseName=MyCustomCase</Post>
</Upload>
```

When DFIR-ORC executes, it will automatically fragment the file and stream it to the API. Once the upload finishes, WFAPP will automatically start parsing the archive under the specified case name.

---

## 3. Submitting a Forensic Archive Manually

If you prefer to manually submit an archive via standard HTTP POST, you can use the standard parsing endpoint.

* **URL:** `/api/parse/parse_archive`
* **Method:** `POST`
* **Headers:** `Content-Type: multipart/form-data`, `X-API-Key: YOUR_API_KEY`
* **Form-data Parameters:**
 - `file`: The binary archive file.
 - `json`: A stringified JSON object containing the execution configuration.

### Configuration Payload Structure
The `json` form parameter accepts the following properties:
- `archiveType`: The type of forensic archive (`"ORC"`, `"KAPE"`, or `"UAC"`).
- `caseName`: The name of the investigation case.
- `machineName`: The host name of the target machine.
- `ogreMode`: Execution mode for DFIR-Ogre (`"orc"` for full parsing or `"timeline"` for CSV timeline).
- `parser_config`: A dictionary mapping module names to `1` (enabled) or `0` (disabled), such as `"ogre_preprocessor"`, `"ogre_mft"`, `"ogre_disk"`, `"ogre_event"`, `"ogre_prefetch"`, `"ogre_srum"`, `"ogre_generic"`, etc.

*Note on Selective Extraction:* When using `"ORC"` archives, `OrcExtractor` automatically analyzes active pipelines in `parser_config` and selectively extracts only the specific files required by enabled pipelines (avoiding decompression of unused nested `.7z` archives like `Event.7z` or `UserHives.7z`).

### Submission Example (curl)
```bash
curl -X POST https://wapp.localhost/api/parse/parse_archive \
   -H "X-API-Key: YOUR_API_KEY" \
   -F "file=@/path/to/evidence_archive.7z" \
   -F 'json={
     "archiveType": "ORC",
     "caseName": "Case_Study_01",
     "machineName": "DESKTOP-5491A",
     "ogreMode": "orc",
     "parser_config": {
       "ogre_preprocessor": 1,
       "ogre_mft": 1,
       "ogre_disk": 1,
       "ogre_event": 1,
       "ogre_prefetch": 1,
       "ogre_srum": 1,
       "ogre_generic": 1
     }
   }'
```

### Response (202 Accepted)
```json
{
 "message": "Your analysis request has been sent to the queue",
 "taskId": "1d8b8db0-77a8-4223-9566-6b2169528be6",
 "statusUrl": "https://wapp.localhost/api/get_task_status/1d8b8db0-77a8-4223-9566-6b2169528be6",
 "runLogUrl": "https://wapp.localhost/api/running_log/1d8b8db0-77a8-4223-9566-6b2169528be6"
}
```

---

## 4. Monitoring Tasks

### Check Task Status
Retrieve the status of a specific background task.

* **URL:** `/api/get_task_status/<task_id>`
* **Method:** `GET`
* **Headers:** `X-API-Key: YOUR_API_KEY`

```bash
curl -X GET https://wapp.localhost/api/get_task_status/1d8b8db0-77a8-4223-9566-6b2169528be6 \
   -H "X-API-Key: YOUR_API_KEY"
```

### Retrieve Live Running Logs
Get raw running logs of the active parser task.

* **URL:** `/api/running_log/<task_id>`
* **Method:** `GET`

```bash
curl -X GET https://wapp.localhost/api/running_log/1d8b8db0-77a8-4223-9566-6b2169528be6 \
   -H "X-API-Key: YOUR_API_KEY"
```

---

## 5. Controlling Tasks

### Stop a Running Task
Revokes and terminates a Celery task that is currently executing.

* **URL:** `/api/stop_task/<task_id>`
* **Method:** `POST`

```bash
curl -X POST https://wapp.localhost/api/stop_task/1d8b8db0-77a8-4223-9566-6b2169528be6 \
   -H "X-API-Key: YOUR_API_KEY"
```

---

## 6. Querying Available Plugins

Retrieve a list of all registered preprocessors, pipelines, and postprocessors.

* **URL:** `/api/pipelines`
* **Method:** `GET`

```bash
curl -X GET https://wapp.localhost/api/pipelines \
   -H "X-API-Key: YOUR_API_KEY"
```

---

## 7. Managing DFIR-Ogre Configuration (YAML)

You can query and update DFIR-Ogre mapping configurations in `ogre.yaml` on-the-fly.

### List All Ogre Mappings
* **URL:** `/api/ogre_yaml_plugins`
* **Method:** `GET`

```bash
curl -X GET https://wapp.localhost/api/ogre_yaml_plugins \
   -H "X-API-Key: YOUR_API_KEY"
```

Response:
```json
{
  "status": "OK",
  "plugins": {
    "amcache_program_xml": true,
    "autoruns": true,
    "browser_history": true,
    "ntfsinfo": true,
    "user_assist": true
  }
}
```

### Enable/Disable an Ogre Mapping
* **URL:** `/api/ogre_yaml_plugins`
* **Method:** `POST`
* **Payload:** `{"label": "amcache_program_xml", "enable": false}`

```bash
curl -X POST https://wapp.localhost/api/ogre_yaml_plugins \
   -H "Content-Type: application/json" \
   -H "X-API-Key: YOUR_API_KEY" \
   -d '{"label": "amcache_program_xml", "enable": false}'
```

