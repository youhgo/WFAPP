# Artefact Parser Project (APP): SIEM Configuration

This guide provides instructions on how to setup APP to send parsed events to your SIEM.

Note: APP currently supports ELK and Wazuh.

### Key Links

* **APP Repository:** <https://github.com/youhgo/WFAPP>

* **Documentation:** [Installation Guide](installation.md) | [GUI Guide](GUI_GUIDE.md) | [Results Architecture](Explaining_the_results.md)

## Configuring Access

In order to send data to the SIEM, you need to configure the `.env` file at the root of the project and setup the correct data.

Note : Modify **ONLY** values and not Keys.

```env
ELK_HOST=192.168.1.1 # ELK API IP/Domain address
ELK_PORT=9200 # ELK PORT default is 9200
ELK_USER="elastic" # username for elastic, default is "elastic"
ELK_PASSWD="changeme" # password for that user, default is "changeme"
```


