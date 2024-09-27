from elasticsearch import Elasticsearch

# Conexión a Elasticsearch
es = Elasticsearch(["http://localhost:9200"])

# Búsqueda simple en el índice "logs"
response = es.search(
    index="logs",
    body={
        "query": {
            "match": {
                "message": "error"
            }
        }
    }
)

# Imprimir resultados
print(response)