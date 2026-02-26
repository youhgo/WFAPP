# Forensic Artifacts Uploader (ELK & Wazuh)

Ce projet propose un pipeline automatisé en Python pour parser des artefacts forensiques généré par l'outil [WAPP](https://github.com/youhgo/wfapp) 
et les ingérer vers un cluster Elasticsearch ou Wazuh SIEM (OpenSearch).

Il parcourt récursivement le répertoire des résultats produits par WAPP, 
identifie les artefacts via des expressions régulières, les traite  et les envoie par lots (bulk) vers la destination choisie.

## Fonctionnalités principales

- Scripts dédiés pour Elasticsearch (App_2_elk.py) et Wazuh Indexer/OpenSearch (App_2_wazuh.py).
- Identifie les fichiers à traiter (ex: .*\.evtx\.json$, mft.json, Amcache.hve_regpy.json, etc.).
- Possibilité de ne traiter que certains types d'artefacts (ex: uniquement le réseau ou le registre) via l'argument --type.
- Envoi en masse (chunk_size) paramétrable. Le script supporte un mode d'envoi en streaming ou en parallèle (multithreading).
-  Configure automatiquement les templates d'index pour optimiser le mapping des champs 




## Dépendences 

Vous aurez besoin des bibliothèques officielles pour Elastic et OpenSearch :

```Bash
pip install elasticsearch opensearch-py
```

## Utilisation

Les deux scripts  partagent une syntaxe très similaire.

| Catégorie | Paramètre | Description | Valeur par défaut / Exemple |
| :--- | :--- | :--- | :--- |
| **Obligatoire** | `-c, --case-name` | Nom du cas (utilisé pour nommer l'index). | - |
| **Obligatoire** | `-m, --machine-name` | Nom de la machine analysée (utilisé pour nommer l'index). | - |
| **Obligatoire** | `-s, --source-dir` | Chemin du répertoire contenant les artefacts à scanner. | - |
| **Optionnel (Général)** | `-t, --type` | Types d'artefacts à ingérer (séparés par des virgules). Options : `process`, `hive`/`registry`, `network`, `disk`, `evtx`, `lnk`, ou `all`. | `all` |
| **Optionnel (Général)** | `--es-hosts` | URL(s) du cluster. | `https://localhost:9200` |
| **Optionnel (Général)** | `--es-user` | Nom d'utilisateur. | `admin` (Wazuh), `elastic` (ELK) |
| **Optionnel (Général)** | `--es-pass` | Mot de passe. | `SecretPassword` (Wazuh), `changeme` (ELK) |
| **Optionnel (Général)** | `--chunk-size` | Nombre de documents envoyés par lot. | `5000` (Wazuh), `15000` (ELK) |
| **Optionnel (Général)** | `--no-verify-ssl` | Désactive la vérification des certificats SSL (utile pour les environnements de test). | `False` (Vérification active par défaut) |
| **Spécifique (Wazuh)** | `--mode` | Mode d'envoi vers Wazuh Indexer (`parallel` ou `streaming`). | `parallel` |
| **Spécifique (Wazuh)** | `--thread-count` | Nombre de threads si le mode est `parallel`. | `4` |
| **Spécifique (Wazuh)** | `--es-timeout` | Temps d'attente maximum pour la connexion. | `60s` |

# Exemples de commandes

1. Ingestion complète vers un serveur ELK en ignorant le SSL :

```Bash
python3 App_2_elk.py -c "Incident_001" -m "SRV-WEB-01" -s "/chemin/vers/artefacts" --es-hosts "https://192.168.1.50:9200" --es-pass "monmotdepasse" --no-verify-ssl
```

2. Ingestion ciblée (uniquement Registre et Réseau) vers Wazuh Indexer :

```Bash
python3 App_2_wazuh.py -c "Compromission_AD" -m "DC-01" -s "/donnees/extraites" -t "registry,network" --es-hosts "https://wazuh-indexer:9200" --no-verify-ssl
```

3. Ingestion optimisée vers Wazuh (Parallel bulk avec 8 threads) :

```Bash
python3 App_2_wazuh.py -c "Investigation" -m "PC-USER1" -s "/dump" --mode parallel --thread-count 8 --chunk-size 10000
```


## Structure des Index 

Les index sont nommés selon le format suivant :

**wapp_<case_name>_<machine_name>_<type_artefact>**

Exemple : `wapp_incident_001_srv_web_01_registry`
