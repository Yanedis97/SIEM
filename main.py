from threading import Thread
import webbrowser
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.controllers import log_controller, alert_controller, login_controller
from utils import normalize
from utils import elasticsearch 
from rules import rules
import uvicorn
import time
from datetime import datetime, timedelta

es = elasticsearch.connect_elasticsearch()

# Crear instancia de FastAPI
app = FastAPI()

# Configuración de políticas CORS para permitir cualquier origen
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5000", "localhost:3000",
                   "localhost:5173","http://127.0.0.1:5173",
                   "http://localhost:5173", "http://localhost:5173/",
                   "http://localhost:3000", "http://localhost:3000/"],
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=[
        "Access-Control-Allow-Headers",
        "Origin",
        "Accept",
        "X-Requested-With",
        "Content-Type",
        "Access-Control-Request-Method",
        "Access-Control-Request-Headers",
        "Access-Control-Allow-Origin",
    ],
)

# Registrar los controladores
app.include_router(log_controller.router, prefix="/logs", tags=["Logs"])
app.include_router(alert_controller.router, prefix="/alerts", tags=["Alerts"])
app.include_router(login_controller.router, prefix="/users", tags=["Users"])

# Índice de logs en Elasticsearch
INDEX = "logs"
if not es.indices.exists(index=INDEX):
    es.indices.create(index=INDEX)

# Intervalo para leer los logs (en segundos)
READ_INTERVAL = 50

# Último timestamp procesado (puede iniciarse como 'now-1d' o leerlo de la base de datos)
last_timestamp = "now-1d"

# Configuración de reglas específicas
RULES_CONFIG = {
    "brute_force": {
        "function": rules.check_brute_force,
        "devices": ["server_linux","windows_event","linux_log"],
        "log_size": 1000,
        "time_window": (datetime.now() - timedelta(minutes=10)).isoformat()
    },
    "privilege_changes": {
        "function": rules.check_privilege_change,
        "devices": ["server_linux","windows_event","linux_log"],
        "log_size": 1000,
        "time_window": (datetime.now() - timedelta(minutes=5)).isoformat()
    },
    "anomalous_traffic": {
        "function": rules.check_suspicious_traffic,
        "devices": ["firewall", "router", "switch", "server_linux"],
        "log_size": 1000,
        "time_window": (datetime.now() - timedelta(minutes=5)).isoformat()
    },
    "system_errors": {
        "function": rules.check_system_errors,
        "devices": ["os_server"], 
        "log_size": 1000,
        "time_window": None  # En tiempo real
    },
    "snort_alert": {
        "function": rules.check_snort_alert,
        "devices": ["snort"],
        "log_size": 1000,
        "time_window": (datetime.now() - timedelta(minutes=5)).isoformat()
    },
    "time_related_events": {
        "function": rules.check_time_related_events,
        "devices": ["any_device"],
        "log_size": 1000,
        "time_window": "now-5m"
    },
    "apt": {
        "function": rules.check_apt,
        "devices": ["critical_system", "network"],
        "log_size": 20,
        "time_window": "now-30m"
    },
    "recon_activity": {
        "function": rules.check_recon_activity,
        "devices": ["router", "switch"],
        "log_size": 5,
        "time_window": "now-3m"
    },
    "exploitation_attempts": {
        "function": rules.check_exploitation_attempts,
        "devices": ["server", "network_device"],
        "log_size": 3,
        "time_window": "now-5m"
    },
    "unauthorized_access": {
        "function": rules.check_unauthorized_access,
        "devices": ["auth_server"],
        "log_size": 5,
        "time_window": "now-3m"
    },
    "malware_activity_detection": {
        "function": rules.check_malware_activity,
        "devices": ["user_device", "file_server", "endpoint"],
        "log_size": 10,
        "time_window": "now-10m"
    },
    "user_behavior_anomaly": {
        "function": rules.check_user_behavior_anomaly,
        "devices": ["auth_server", "idm_server"],
        "log_size": 10,
        "time_window": "now-15m"
    },
    "data_exfiltration": {
        "function": rules.check_data_exfiltration,
        "devices": ["firewall", "file_server", "network_device"],
        "log_size": 1000, 
        "time_window": "now-10m"
    },
    "security_config_changes": {
        "function": rules.check_security_configuration_changes,
        "devices": ["firewall", "auth_server", "security_server"],  # Dispositivos relevantes
        "log_size": 10,  # Tamaño de log adecuado para cambios importantes
        "time_window": None  # En tiempo real
    },
    "suspicious_internal_connections": {
        "function": rules.check_suspicious_internal_connections,
        "devices": ["server", "network_device", "endpoint"],  # Dispositivos relevantes para conexiones internas
        "log_size": 100,  # Ajusta el tamaño según lo necesario
        "time_window": "now-5m"  # Ventana de 5 minutos
    }
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

    if time_window:
        query["query"]["bool"]["must"].append({
            "range": {
                "timestamp": {
                    "gte": time_window  # 'gte' para obtener logs desde el tiempo especificado
                }
            }
        })

    if filtered_devices:
        query["query"]["bool"]["must"].append({
            "terms": {
                "type.keyword": filtered_devices
            }
        })

    response = es.search(index=index, body=query)
    logs = response['hits']['hits']
    return logs


def process_rules(es):
    for rule_name, config in RULES_CONFIG.items():
        print(f"Procesando regla {rule_name}")
        
        try:
            logs = fetch_logs(
                es=es,
                index=INDEX,
                time_window=config["time_window"],
                filtered_devices=config["devices"],
                size=config["log_size"]
            )
            config["function"](logs)
        except Exception as e:
            print(f"Error al procesar logs para la regla {rule_name}: {e}")

def normalize_and_save_logs(es):
    """
    Inicia la normalización y el guardado de logs en Elasticsearch.
    """
    normalize.start_monitoring('C:\\logs', es)

def start_process_rules():
    global last_timestamp
    print("Inicia monitoreo")
    #try:
    while True:
        try:
            process_rules(es)
        except Exception as e:
            print(f"Error al procesar reglas: {e}")

        try:
            latest_logs = fetch_logs(es, INDEX, last_timestamp, size=1)
            if latest_logs:
                last_timestamp = latest_logs[-1]['_source']['timestamp']
        except Exception as e:
            print(f"Error al obtener logs: {e}")
        
        time.sleep(READ_INTERVAL)

    #except KeyboardInterrupt:
    #    print("Deteniendo la ejecución...")


def start_fastapi_server():
    """Inicia el servidor FastAPI bajo demanda."""
    try:
        uvicorn.run(app, host="0.0.0.0", port=8000)
    except KeyboardInterrupt:
        print("Interrupción manual detectada. Deteniendo el servidor...")
        return

def open_user_interface():
    """Función para abrir la interfaz cuando el usuario da clic en el ícono."""
    # Inicia el servidor FastAPI en un hilo separado
    start_fastapi_server()
    # Abre la interfaz de usuario en el navegador
    #webbrowser.open("http://localhost:8000")

def start_monitoring_task():
    log_thread = Thread(target=normalize_and_save_logs, args=(es,))
    log_thread.start()

    rules_thread = Thread(target=start_process_rules)
    rules_thread.start()

    #log_thread.join()
    #rules_thread.join()


def main():
    fastapi_thread = Thread(target=start_fastapi_server)
    fastapi_thread.start()

    start_monitoring_task()

    fastapi_thread.join()
if __name__ == "__main__":
    main()