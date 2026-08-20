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
