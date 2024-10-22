# services/alert_service.py
from elasticsearch import Elasticsearch

es = Elasticsearch([{'host': 'localhost', 'port': 9200}])

# Servicio para obtener todas las alertas guardadas
def get_all_alerts():
    try:
        result = es.search(index="alerts", size=1000)
        alerts = [hit['_source'] for hit in result['hits']['hits']]
        return alerts
    except Exception as e:
        raise e

# Servicio para obtener la alerta generada en tiempo real
def get_realtime_alert():
    try:
        # Filtramos por las alertas recientes en tiempo real
        result = es.search(index="alerts", size=1, sort="timestamp:desc")
        if result['hits']['hits']:
            alert = result['hits']['hits'][0]['_source']
            return alert
        else:
            return {"message": "No hay alertas en tiempo real"}
    except Exception as e:
        raise e
