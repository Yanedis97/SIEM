from fastapi import FastAPI
from app.controllers import log_controller, alert_controller
from elasticsearch import Elasticsearch
from utils import normalize  # Para la normalización de logs
import rules.rules as rules
import threading
import time
import webbrowser


# Conexión a Elasticsearch
es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=('elastic', 'Y07U0Mmu7Z7+MpVfQJjf'),
    verify_certs=False  
)

# Crear instancia de FastAPI
app = FastAPI()

# Registrar los controladores
app.include_router(log_controller.router, prefix="/logs", tags=["Logs"])
app.include_router(alert_controller.router, prefix="/alerts", tags=["Alerts"])

# Índice de logs en Elasticsearch
INDEX = "logs-*"

# Intervalo para leer los logs (en segundos)
READ_INTERVAL = 30

# Último timestamp procesado (puede iniciarse como 'now-1d' o leerlo de la base de datos)
last_timestamp = "now-1d"

# Lista de dispositivos para reglas específicas
FILTERED_DEVICES = ["device1", "device2", "192.168.1.10"]

# Configuración de reglas con sus dispositivos específicos o None para aplicar a todos
RULES_CONFIG = {
    "brute_force": {
        "function": rules.check_brute_force,
        "devices": None,
        "log_size": 100
    },
    "privilege_changes": {
        "function": rules.check_privilege_changes,
        "devices": None,  # Se aplica a todos los dispositivos
        "log_size": 200
    },
    "anomalous_traffic": {
        "function": rules.check_anomalous_traffic,
        "devices": None,
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
        config["function"](logs, es)


def normalize_and_save_logs(es):
    """
    Inicia la normalización y el guardado de logs en Elasticsearch.
    """
    normalize.start_monitoring('C:\\logs', es)  # Pasa la instancia de Elasticsearch aquí


def start_log_monitoring():
    global last_timestamp
    normalize_and_save_logs(es)  # Iniciar normalización y guardado en un hilo separado

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

def start_fastapi_server():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

def open_user_interface():
    webbrowser.open("http://localhost:3000")

def main():
    # Iniciar la normalización y guardado de logs en un hilo separado
    log_thread = threading.Thread(target=start_log_monitoring, daemon=True)
    log_thread.start()

    # Aquí puedes agregar la lógica para abrir la interfaz de usuario.
    # Supongamos que se llama a 'open_user_interface()' cuando el usuario inicia sesión o abre el programa.
    open_user_interface()

    # Esperar a que el usuario decida iniciar el servidor FastAPI
    start_fastapi_server()  # Esto se ejecutará al hacer clic en el botón o ícono

if __name__ == "__main__":
    main()