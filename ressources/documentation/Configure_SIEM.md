#  Artifact Parser (WAPP) Project: SIEM Configuration

This guide provides instructions on how to setup APP to send plaso timeline to your SIEM.

Note: APP only support ELK and SPLUNK at the moment

### 📌 Key Links

* **WAPP Repository:** <https://github.com/youhgo/WFAPP>

* **Documentation:** [Installation Guide](https://github.com/youhgo/WFAPP/blob/master/ressources/documentation/how_to_install.md) | [Usage Guide](https://github.com/youhgo/WFAPP/blob/master/ressources/documentation/how_to_use.md) | [Results Architecture](https://github.com/youhgo/WFAPP/blob/master/ressources/documentation/Explaining_the_results.md)

## Configuring Access

in order to send data to the SIEM, you need to configure the .env file, at the root of the project and setup correct datas.

Note :  Modify **ONLY** values and not Keys.

```env
ELK_HOST=192.168.1.1 # ELK APi IP/Domain address
ELK_PORT=9200 # ELK PORT default is 9200
ELK_USER="elastic" # username for elastic, default is "elastic"
ELK_PASSWD="changeme" # passowrd for that user default is "changeme"
SPLUNK_HOST=192.168.1.1 # Splunk API IP/Domain address
SPLUNK_PORT=8089 # SPLUNK PORT default is 9200
SPLUNK_TOKEN="TOKEN" # SPLUNK JWT token to allow connection
```


