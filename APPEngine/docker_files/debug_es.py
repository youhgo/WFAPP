from elasticsearch import Elasticsearch
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Supprimer les warnings SSL pour y voir plus clair
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

# Configuration issue de votre .env
ES_HOST = "https://elasticsearch:9200"
ES_USER = "elastic"
ES_PASS = "changeme"

print(f"--- TEST DE CONNEXION VERS {ES_HOST} ---")

try:
    # On tente une connexion simple, sans pool complexe
    client = Elasticsearch(
        [ES_HOST],
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False,
        request_timeout=5
    )

    # 1. Test Ping
    if client.ping():
        print("[OK] Ping réussi !")
    else:
        print("[KO] Ping échoué (le serveur est joignable mais refuse le ping).")

    # 2. Test Info (GET /)
    info = client.info()
    print("\n[OK] Informations du cluster récupérées :")
    print(f"     Nom : {info['name']}")
    print(f"     Cluster : {info['cluster_name']}")
    print(f"     Version : {info['version']['number']}")

except Exception as e:
    print(f"\n[ERREUR FATALE] Impossible de se connecter :")
    print(e)
finally:
    if 'client' in locals():
        client.close()
    print("\n--- FIN DU TEST ---")