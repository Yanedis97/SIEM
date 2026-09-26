from fastapi import HTTPException
from utils import elasticsearch

es = elasticsearch.connect_elasticsearch()

# Servicio para obtener los logs con paginación
def get_all_logs(page: int = 1, size: int = 10):
    try:
        # Calcular el offset basado en el número de página y el tamaño de página
        offset = (page - 1) * size
        # Realizar la consulta a Elasticsearch con paginación
        result = es.search(index="logs", from_=offset, size=size, sort=[{"timestamp": {"order": "desc"}}])
        logs = [hit['_source'] for hit in result['hits']['hits']]
        return logs
    except Exception as e:
        raise e


def update_log(log_id, key_name):
    # Actualización del documento
    es.update(
        index="logs",
        id=log_id,
        body={
            "doc": {
                key_name: 1
            }
        }
    )


def get_logs_chart_data():
    """
    Servicio para obtener los datos necesarios para una gráfica de logs agrupados por fecha.
    """
    try:
        # Query de Elasticsearch con validación de rango de fechas
        result = es.search(
            index="logs",
            body={
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": "now-30d/d",  # Últimos 30 días
                            "lte": "now/d",
                            "format": "yyyy-MM-dd"
                        }
                    }
                },
                "size": 0,
                "aggs": {
                    "logs_by_date": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "day",
                            "format": "yyyy-MM-dd"
                        }
                    }
                }
            }
        )

        # Validación de datos en las agregaciones
        if "aggregations" not in result or "logs_by_date" not in result["aggregations"]:
            raise HTTPException(status_code=400, detail="Error en la agregación de Elasticsearch.")

        # Extraer datos de la agregación
        buckets = result["aggregations"]["logs_by_date"]["buckets"]
        logs_by_date  =  [{"date": bucket["key_as_string"], "count": bucket["doc_count"]} for bucket in buckets]

        # Query para contar el número total de logs
        total_logs_result = es.count(index="logs")
        total_logs = total_logs_result.get("count", 0)
        return {
            "logs_by_date": logs_by_date,
            "total_logs": total_logs
        }
    
    except Exception as e:
        # Rellenar el detalle del error en caso de excepción
        raise HTTPException(status_code=500, detail=f"Error al obtener datos de Elasticsearch: {str(e)}")