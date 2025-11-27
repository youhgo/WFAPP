# Processeur d'Artefacts Forensiques pour ELK

## TODO
Add more EVTX specific parsing


## Description
Ce projet est un script Python modulaire conçu pour parser une grande variété d'artefacts forensiques issus de systèmes Windows. Il normalise les données extraites dans un format structuré (proche de l'Elastic Common Schema - ECS) et les envoie en masse vers une instance Elasticsearch pour une analyse centralisée via Kibana.
L'outil est conçu pour être performant, en utilisant un traitement en flux continu (streaming) pour gérer des fichiers de très grande taille avec une faible consommation de mémoire.

## Fonctionnalités
Architecture Modulaire : Chaque type d'artefact est géré par sa propre classe de processeur, ce qui rend le code facile à maintenir et à étendre.
Détection Intelligente de Format : Le script détecte automatiquement les différents formats de fichiers (JSON complet vs. JSON Lines, différents types de CSV, texte ou XML).
Normalisation des Données : Les données sont mappées vers des champs ECS pour faciliter la corrélation et l'analyse dans Kibana.
Gestion Automatique des Index : Crée automatiquement des templates d'index dans Elasticsearch pour garantir le bon mapping des champs, notamment les timestamps.
Ingestion Performante : Utilise l'API streaming_bulk d'Elasticsearch pour un envoi efficace et une faible empreinte mémoire. 

## Prérequis
Python 3.x
Les librairies Python nécessaires. Installez-les via pip :
```bash
pip install elasticsearch xmltodict
```

## Utilisation
Le script s'exécute en ligne de commande. Vous devez spécifier un nom de cas, un nom de machine, et les fichiers d'artefacts que vous souhaitez traiter.
Syntaxe:
`python3 main.py --case-name <nom_du_cas> --machine-name <nom_de_la_machine> [options]`

Exemple Complet
```bash
python3 main.py \
    --case-name "mycase" \
    --machine-name "mymachine" \
    --evtx-files /artefacts/Security.jsonl /artefacts/System.jsonl \
    --disk-files /artefacts/mft_export.json /artefacts/usn_journal.csv \
    --processes-files /artefacts/autoruns.csv /artefacts/processes1.csv /artefacts/Process_Autoruns.xml \
    --network-files /artefacts/netstat.txt /artefacts/DNS_records.txt \
    --registry-files /artefacts/SAM.jsonl \
    --lnk-files /artefacts/lnk_files.json \
    --es-hosts "https://192.168.1.100:9200" \
    --es-user "elastic" \
    --es-pass "changeme"
```


## Artefacts Supportés
Le tableau ci-dessous détaille chaque type d'artefact supporté, l'outil recommandé pour le générer, et le format de fichier attendu.

 Argument en Ligne de Commande | Outil de Génération Suggéré             | Commande Exemple                                                            | Format Attendu               |
|-------------------------------|-----------------------------------------|-----------------------------------------------------------------------------|------------------------------|
| --evtx-files                  | https://github.com/0xrawsec/golang-evtx | evtx_dump.py Security.evtx > Security.jsonl                                 | JSON Lines (.json)           |
| --disk-files                  | https://github.com/rowingdude/analyzeMFT                        | analyzeMFT.py -f C:\$MFT -o mft.json --json                                 | JSON Complet (liste) (.json) |
| --disk-files                  | Outil d'export USN (ex: ORC)            |                                                                             | CSV (.csv)                   |
| --processes-files             | autoruns.exe (Sysinternals)             | autoruns.exe -a * -c * > autoruns.csv                                       | CSV (.csv)                   |
| --processes-files             | Export DFIR ORC                         | autoruns.exe -a * -x > autoruns.xml                                         | XML (.xml)                   |
| --processes-files             | PowerShell (WMI)                        | Get-WmiObject -Class Win32_Process \| Export-Csv -NoTypeInfo processes1.csv | CSV (.csv)                   |
| --processes-files             | PowerShell (Get-Process)                | Get-Process  \| Select-Object * Export-Csv -NoTypeInfo processes2.csv       | CSV (.csv)                   |
| --network-files               | netstat                                 | netstat -anob > netstat.txt                                                 | Texte (.txt)                 |
| --network-files               | tcpvcon.exe (Sysinternals)              | tcpvcon.exe -a > tcpvcon.txt                                                | Texte (.txt)                 |
| --network-files               | arp                                     | arp -a > arp_cache.txt                                                      | Texte (.txt)                 |
| --network-files               | PowerShell (DNS)                        | Get-DnsServerResourceRecord -ZoneName . > DNS_records.txt                   | Texte (.txt)                 |
| --registry-files              | https://github.com/msuhanov/yarp        | ... > registry_export.jsonl                                                 | JSON Lines (.json)           |
| --amcache-files               | https://github.com/msuhanov/yarp        | ... > amcache_export.jsonl                                                  | JSON Lines (.json)           |
| --lnk-files                   | lnkParse3 py                            | ... > lnk_files.json                                                        | JSON Lines (.json)           |

## Try It YourSelf

You will find some data to ingest in the folder data_sample.
For elastic i use this docker based one : [ElastDocker](https://github.com/sherifabdlnaby/elastdocker)


