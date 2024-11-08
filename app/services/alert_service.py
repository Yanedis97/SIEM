from utils import elasticsearch

es = elasticsearch.connect_elasticsearch()

# Servicio para obtener todas las alertas guardadas con paginación
def get_all_alerts(page: int = 1, size: int = 10):
    try:
        # Usamos `from` y `size` para paginar los resultados
        start_from = (page - 1) * size
        result = es.search(index="alerts", size=size, from_=start_from, sort=[{"timestamp": {"order": "desc"}}])
        alerts = [hit['_source'] for hit in result['hits']['hits']]
        return alerts
    except Exception as e:
        raise e

# Servicio para obtener la alerta generada en tiempo real
def get_realtime_alert():
    try:
        # Filtramos por las alertas más recientes en tiempo real
        result = es.search(index="alerts", size=100, sort=[{"timestamp": {"order": "desc"}}])
        if result['hits']['hits']:
            alert = result['hits']['hits'][0]['_source']
            return alert
        else:
            return {"message": "No hay alertas en tiempo real"}
    except Exception as e:
        raise e
    
# Servicio para actualizar el estado de la alerta
def update_alert_status():
    try:
        # Filtramos por las alertas más recientes en tiempo real
        result = es.search(index="alerts", size=1, sort=[{"timestamp": {"order": "desc"}}])
        if result['hits']['hits']:
            alert = result['hits']['hits'][0]['_source']
            return alert
        else:
            return {"message": "No hay alertas en tiempo real"}
    except Exception as e:
        raise e