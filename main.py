from fastapi import FastAPI
from app.controllers import log_controller, alert_controller, login_controller
from utils import normalize  # Para la normalización de logs
from utils import elasticsearch 
from rules import rules
import threading
import time
import webbrowser


es = elasticsearch.connect_elasticsearch()

# Crear instancia de FastAPI
app = FastAPI()

# Registrar los controladores
app.include_router(log_controller.router, prefix="/logs", tags=["Logs"])
app.include_router(alert_controller.router, prefix="/alerts", tags=["Alerts"])
app.include_router(login_controller.router, prefix="/", tags=["Login"])

# Índice de logs en Elasticsearch
INDEX = "logs"
if not es.indices.exists(index=INDEX):
    es.indices.create(index=INDEX)

# Intervalo para leer los logs (en segundos)
READ_INTERVAL = 5

# Último timestamp procesado (puede iniciarse como 'now-1d' o leerlo de la base de datos)
last_timestamp = "now-1d"

# Lista de dispositivos para reglas específicas
FILTERED_DEVICES = ["device1", "device2", "192.168.1.10"]

# Configuración de reglas con sus dispositivos específicos o None para aplicar a todos
# Configuración de reglas con sus dispositivos específicos o None para aplicar a todos
RULES_CONFIG = {
    "brute_force": {
        "function": rules.check_brute_force,
        "devices": None,
        "log_size": 100,
        "time_window": "now-2d"  # Últimos 2 días
    },
    "privilege_changes": {
        "function": rules.check_privilege_change,
        "devices": None,
        "log_size": 200,
        "time_window": "now-3h"  # Últimas 3 horas
    },
    "anomalous_traffic": {
        "function": rules.check_suspicious_traffic,
        "devices": None,
        "log_size": 50,
        "time_window": "now-1d"  # Últimas 24 horas
    },
    "system_errors": {
        "function": rules.check_system_errors,
        "devices": None,
        "log_size": 50,
        "time_window": "now-1d"  # Últimas 24 horas
    },
    "snort_alert": {
        "function": rules.check_snort_alert,
        "devices": None,
        "log_size": 50,
        "time_window": None  # Maneja su propio proceso de recuperación
    },
}


def fetch_logs(es, index, time_window, filtered_devices=None, size=100):
    """
    Obtiene los logs de Elasticsearch a partir de un tiempo dado y opcionalmente filtra por dispositivos.
    """
    query = {
        "size": size,
        "query": {
            "bool": {
                "must": []
            }
        },
        "sort": [
            {"timestamp": {"order": "asc"}}
        ]
    }

    # Si se proporciona un time_window, ajusta la consulta
    if time_window:
        query["query"]["bool"]["must"].append({
            "range": {
                "timestamp": {
                    "gte": time_window  # Usa 'gte' para obtener logs desde el tiempo especificado
                }
            }
        })

    if filtered_devices:
        query["query"]["bool"]["must"].append({
            "terms": {
                "device_id.keyword": filtered_devices  # Asegúrate que este campo coincide con tus logs
            }
        })

    response = es.search(index=index, body=query)
    logs = response['hits']['hits']
    return logs


def process_rule(rule_name, config, es):
    """
    Procesa una regla específica según la configuración definida.
    """
    print(f"Procesando regla: {rule_name}")

    logs = fetch_logs(
        es=es,
        index=INDEX,
        time_window=config["time_window"],  # Pasa el tiempo específico
        filtered_devices=config["devices"],
        size=config["log_size"]
    )
        
    # Llamar a la función de la regla con los logs obtenidos
    config["function"](logs, es)

def process_rules(es):
    """
    Procesa todas las reglas en hilos separados si es necesario.
    """
    threads = []
    print("empieza a llamar todas las funciones")
    for rule_name, config in RULES_CONFIG.items():
        thread = threading.Thread(target=process_rule, args=(rule_name, config, es))
        thread.start()
        threads.append(thread)

    # Esperar a que todas las reglas terminen de procesarse
    for thread in threads:
        thread.join()

def normalize_and_save_logs(es):
    """
    Inicia la normalización y el guardado de logs en Elasticsearch.
    """
    normalize.start_monitoring('C:\\logs', es)  # Pasa la instancia de Elasticsearch aquí


def start_process_rules():
    global last_timestamp  # Iniciar normalización y guardado en un hilo separado
    print("inicia monitoreo")
    try:
        while True:
            # Leer nuevos logs de Elasticsearch y procesar reglas
            try:
                process_rules(es)
            except Exception as e:
                print(f"Error al procesar reglas: {e}")

            # Actualizar el timestamp al último log procesado
            try:
                latest_logs = fetch_logs(es, INDEX, last_timestamp, size=1)
                if latest_logs:
                    last_timestamp = latest_logs[-1]['_source']['@timestamp']
            except Exception as e:
                print(f"Error al obtener logs: {e}")

            # Esperar antes de leer los logs nuevamente
            time.sleep(READ_INTERVAL)

    except KeyboardInterrupt:
        print("Deteniendo la ejecución...")

def start_fastapi_server():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

def open_user_interface():
    webbrowser.open("http://localhost:8000")

def main():
    # Iniciar normalización y guardado de logs
    normalize_and_save_logs(es)

    # Iniciar procesamiento de reglas de correlación
    log_thread = threading.Thread(target=start_process_rules, daemon=True)
    log_thread.start()

    open_user_interface()

    # Esperar a que el usuario decida iniciar el servidor FastAPI
    start_fastapi_server()  # Esto se ejecutará al hacer clic en el botón o ícono

if __name__ == "__main__":
    main()