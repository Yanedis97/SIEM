# services/log_service.py
from elasticsearch import Elasticsearch

es = Elasticsearch([{'host': 'localhost', 'port': 9200}])

# Servicio para obtener todos los logs
def get_all_logs():
    try:
        result = es.search(index="logs", size=1000)
        logs = [hit['_source'] for hit in result['hits']['hits']]
        return logs
    except Exception as e:
        raise e
