from utils import elasticsearch

es = elasticsearch.connect_elasticsearch()

# Servicio para obtener los logs con paginación
def get_all_logs(page: int = 1, size: int = 10):
    try:
        # Calcular el offset basado en el número de página y el tamaño de página
        offset = (page - 1) * size
        # Realizar la consulta a Elasticsearch con paginación
        result = es.search(index="logs", from_=offset, size=size)
        logs = [hit['_source'] for hit in result['hits']['hits']]
        return logs
    except Exception as e:
        raise e
