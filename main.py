from fastapi import FastAPI
from app.controllers import log_controller, alert_controller, device_controller
from utils import normalize  # Normalización de logs
from elasticsearch import Elasticsearch
import time
from app.services import rule_service

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
app.include_router(device_controller.router, prefix="/devices", tags=["Devices"])

# Intervalo para leer los logs (en segundos)
READ_INTERVAL = 30

# Último timestamp procesado
last_timestamp = "now-1d"

@app.on_event("startup")
async def startup_event():
    """
    Función que se ejecuta al iniciar la aplicación.
    """
    normalize_and_save_logs(es)  # Iniciar la normalización en segundo plano si es necesario

@app.on_event("shutdown")
async def shutdown_event():
    """
    Función que se ejecuta cuando la aplicación se detiene.
    """
    print("Deteniendo la ejecución...")

def normalize_and_save_logs(es):
    """
    Inicia la normalización y el guardado de logs en Elasticsearch.
    """
    normalize.start_monitoring('C:\\logs', es)  # Pasa la instancia de Elasticsearch

def main():
    """
    Bucle principal para procesar reglas a intervalos regulares.
    """
    global last_timestamp
    try:
        while True:
            # Procesar las reglas con logs de Elasticsearch
            rule_service.process_rules(es, last_timestamp)

            # Obtener el último timestamp procesado
            latest_logs = rule_service.fetch_latest_log_timestamp(es, "logs-*", last_timestamp)
            if latest_logs:
                last_timestamp = latest_logs

            time.sleep(READ_INTERVAL)

    except KeyboardInterrupt:
        print("Ejecución interrumpida...")

if __name__ == "__main__":
    main()
