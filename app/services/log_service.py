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
        # Query de Elasticsearch con agregación por fecha
        result = es.search(
            index="logs",
            body={
                "size": 0,  # No necesitamos los documentos, solo las agregaciones
                "aggs": {
                    "logs_by_date": {
                        "date_histogram": {
                            "field": "timestamp",  # Asegúrate de que el campo 'timestamp' existe
                            "calendar_interval": "day",  # Agrupar por día
                            "format": "yyyy-MM-dd"  # Formato de salida para la fecha
                        }
                    }
                }
            }
        )

        # Verificar si la respuesta contiene la agregación esperada
        if "aggregations" not in result or "logs_by_date" not in result["aggregations"]:
            raise HTTPException(status_code=400, detail="Error en la agregación de Elasticsearch.")

        # Extraer datos de la agregación
        buckets = result["aggregations"]["logs_by_date"]["buckets"]
        return [{"date": bucket["key_as_string"], "count": bucket["doc_count"]} for bucket in buckets]
    
    except Exception as e:
        # Rellenar el detalle del error en caso de excepción
        raise HTTPException(status_code=500, detail=f"Error al obtener datos de Elasticsearch: {str(e)}")