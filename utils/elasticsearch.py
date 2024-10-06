from elasticsearch import Elasticsearch

def connect_elasticsearch():
    es = Elasticsearch([{'host': 'localhost', 'port': 9200}])
    if es.ping():
        print('Conexión exitosa a Elasticsearch')
    else:
        print('Conexión fallida')
    return es

def create_index(es, index_name):
    if not es.indices.exists(index=index_name):
        es.indices.create(index=index_name)
        print(f"Índice {index_name} creado.")
    else:
        print(f"Índice {index_name} ya existe.")
