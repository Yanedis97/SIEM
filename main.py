from sqlalchemy.orm import Session
from database import SessionLocal
from auth import create_user, authenticate_user
from elasticsearch import Elasticsearch
from utils import elasticsearch
from utils import normalize  # Para la normalización de logs
from utils import nxlog  # Para configurar NXLog
import time
import rules  # Archivo donde están las reglas de correlación


# Conexión a Elasticsearch
es = Elasticsearch(["localhost:9200"])

# Índice de logs en Elasticsearch
INDEX = "logs-*"

# Intervalo para leer los logs (en segundos)
READ_INTERVAL = 60

# Último timestamp procesado (puede iniciarse como 'now-1d' o leerlo de la base de datos)
last_timestamp = "now-1d"

# Lista de dispositivos para reglas específicas
FILTERED_DEVICES = ["device1", "device2", "192.168.1.10"]

# Configuración de reglas con sus dispositivos específicos o None para aplicar a todos
RULES_CONFIG = {
    "brute_force": {
        "function": rules.check_brute_force,
        "devices": FILTERED_DEVICES,
        "log_size": 100
    },
    "privilege_changes": {
        "function": rules.check_privilege_changes,
        "devices": None,  # Se aplica a todos los dispositivos
        "log_size": 200
    },
    "anomalous_traffic": {
        "function": rules.check_anomalous_traffic,
        "devices": FILTERED_DEVICES,
        "log_size": 50
    },
    # Agregar más reglas con sus configuraciones aquí...
}


def fetch_logs(es, index, last_timestamp, filtered_devices=None, size=100):
    """
    Obtiene los logs de Elasticsearch a partir de un timestamp dado y opcionalmente filtra por dispositivos.
    """
    query = {
        "size": size,
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gt": last_timestamp
                            }
                        }
                    }
                ]
            }
        },
        "sort": [
            {"@timestamp": {"order": "asc"}}
        ]
    }

    if filtered_devices:
        query["query"]["bool"]["must"].append({
            "terms": {
                "device_id.keyword": filtered_devices  # Asegúrate que este campo coincide con tus logs
            }
        })

    response = es.search(index=index, body=query)
    logs = response['hits']['hits']
    return logs


def process_rules(es, last_timestamp):
    """
    Procesa los logs según las configuraciones definidas en RULES_CONFIG.
    """
    for rule_name, config in RULES_CONFIG.items():
        print(f"Procesando regla: {rule_name}")

        # Obtener logs según configuración de la regla
        logs = fetch_logs(
            es=es,
            index=INDEX,
            last_timestamp=last_timestamp,
            filtered_devices=config["devices"],
            size=config["log_size"]
        )
        
        # Llamar a la función de la regla con los logs obtenidos
        config["function"](logs)


def normalize_and_save_logs(es):
    """
    Inicia la normalización y el guardado de logs en Elasticsearch.
    """
    normalize.start_monitoring('C:\\logs', es)  # Pasa la instancia de Elasticsearch aquí


def main():
    global last_timestamp

    # Crear una sesión para interactuar con la base de datos
    db: Session = SessionLocal()

    # Configurar NXLog al inicio
    nxlog.configure_nxlog()  # Asumiendo que esta función está en nxlog.py

    # Ejemplo de registro de un nuevo usuario
    username = "testuser"
    password = "password123"
    user = create_user(db, username, password)
    print(f"Usuario creado: {user.username}")

    # Ejemplo de autenticación de usuario
    auth_user = authenticate_user(db, username, password)
    if auth_user:
        print(f"Usuario autenticado: {auth_user.username}")
    else:
        print("Fallo en la autenticación")

    # Iniciar la normalización y guardado de logs en un hilo separado
    normalize_and_save_logs(es)

    # Lógica de lectura de logs y reglas de correlación
    try:
        while True:
            # Leer nuevos logs de Elasticsearch y procesar reglas
            process_rules(es, last_timestamp)

            # Actualizar el timestamp al último log procesado
            latest_logs = fetch_logs(es, INDEX, last_timestamp, size=1)
            if latest_logs:
                last_timestamp = latest_logs[-1]['_source']['@timestamp']

            # Esperar antes de leer los logs nuevamente
            time.sleep(READ_INTERVAL)

    except KeyboardInterrupt:
        print("Deteniendo la ejecución...")

    finally:
        # Cerrar la sesión de base de datos al final del proceso
        db.close()


if __name__ == "__main__":
    main()
