from utils import elasticsearch

es = elasticsearch.connect_elasticsearch()

def get_all_alerts(page: int = 1, size: int = 10):
    try:
        # Usamos `from` y `size` para paginar los resultados
        start_from = (page - 1) * size
        result = es.search(index="alerts", size=size, from_=start_from, sort=[{"timestamp": {"order": "desc"}}])
        alerts = [hit['_source'] for hit in result['hits']['hits']]
        return alerts
    except Exception as e:
        raise e

def get_active_alerts(page: int = 1, size: int = 10):
    try:
        start_from = (page - 1) * size
        result = es.search(
            index="alerts",
            body={
                "query": {
                    "match": {
                        "status": "active"
                    }
                }
            },
            size=size,
            from_=start_from,
            sort=[{"timestamp": {"order": "desc"}}]
        )
        active_alerts = [hit['_source'] for hit in result['hits']['hits']]
        return active_alerts
    except Exception as e:
        raise e
    
    
def update_alert_status(alert_id: str, status: str):
    try:
        result = es.update(
            index="alerts",
            id=alert_id,
            body={
                "doc": {
                    "status": status
                }
            }
        )
        if result['result'] == "updated":
            updated_alert = es.get(index="alerts", id=alert_id)
            return updated_alert['_source']
        else:
            return None
    except Exception as e:
        raise e