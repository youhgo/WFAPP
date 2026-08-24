# Artefact Parser Project (APP): SIEM Configuration

This guide provides instructions on how to setup APP to send parsed events to your SIEM.

Note: APP currently supports ELK and Wazuh.

### Key Links

* **APP Repository:** <https://github.com/youhgo/WFAPP>

* **Documentation:** [Installation Guide](INSTALLATION_GUIDE.md) | [GUI Guide](GUI_GUIDE.md) | [Results Architecture](RESULTS_GUIDE.md)

## Configuring Access

In order to send data to the SIEM, you need to configure the `.env` file at the root of the project and setup the correct data.

Note : Modify **ONLY** values and not Keys.

### 1. ELK Configuration

```env
ELK_HOST="localhost" # ELK API IP/Domain address
ELK_PORT=9200 # ELK PORT default is 9200
ELK_USER="elastic" # username for elastic, default is "elastic"
ELK_PASSWD="changeme" # password for that user, default is "changeme"
ES_VERIFYSSL=0 # 1 to verify SSL certificates
ES_CHUNKSIZE=500 # Number of events per bulk upload
```

### 2. Wazuh Configuration

```env
WAZUH_HOST="https://wazuh.indexer" # Wazuh Indexer IP/Domain address
WAZUH_PORT=9200 # Wazuh Indexer PORT
WAZUH_USER="admin" # username for Wazuh indexer
WAZUH_PASSWD="SecretPassword" # password for Wazuh indexer
WAZUH_TIMEOUT=120 # API connection timeout
WAZUH_MODE="streaming" # Upload mode
WAZUH_NBTHREAD=4 # Number of concurrent threads
WAZUH_CHUNKSIZE=10000 # Number of events per bulk upload
WAZUH_VERIFYSSL=0 # 1 to verify SSL certificates
```

---

## Connecting to a Local Dockerized SIEM

If your SIEM (Elasticsearch, Wazuh, etc.) is running locally on the same host using Docker, you can connect WFAPP directly to it using a shared Docker network named `shared_sec_net`.

### 1. Create the Shared Network

If the network does not already exist, you must create it manually before starting the application to avoid errors:

```bash
docker network create shared_sec_net
```

*(Ensure that your SIEM's `docker-compose.yml` is also configured to connect to this `shared_sec_net` external network).*

### 2. Launch WFAPP with the SIEM Compose File

By default, WFAPP runs in an isolated network. To launch it with the SIEM connectivity enabled, use the provided alternative Docker Compose file:

```bash
docker compose -f docker-compose_with_docker_siem.yml up --build -d
```

This will attach the WFAPP workers to the `shared_sec_net` network, allowing them to communicate natively with your SIEM containers using their container names (e.g., `ELK_HOST="elasticsearch"`).

---



## Standalone Timeline Ingestion

If you already have a prepared `timeline.json` (e.g., generated manually or from an older WFAPP run) and want to push it directly to your SIEM without rerunning the entire extraction pipeline, you can use the standalone uploaders.

These scripts are fully autonomous, include robust type/timestamp sanitization, and can be executed directly.

### For Elasticsearch

```bash
docker exec -it wapp_worker-1 python /python-docker/WAPP_MODULE/utils/plaso2ELK/plaso_2_siem.py \
  -t /python-docker/shared_files/depot/timeline.json \
  -c "my_case" \
  -m "my_machine" \
  --es-hosts "https://elasticsearch:9200" \
  --es-user "elastic" \
  --es-pass "password"
```

### For Wazuh Indexer

```bash
docker exec -it wapp_worker-1 python /python-docker/WAPP_MODULE/utils/plaso2ELK/plaso_to_wazuh.py \
  -t /python-docker/shared_files/depot/timeline.json \
  -c "my_case" \
  -m "my_machine" \
  --es-hosts "https://wazuh.indexer:9200" \
  --es-user "admin" \
  --es-pass "SecretPassword"
```
