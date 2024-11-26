from elasticsearch import Elasticsearch, AsyncElasticsearch

def connect_elasticsearch():
    es = Elasticsearch(
        "https://localhost:9200",
        basic_auth=('elastic', 'elastic'),
        verify_certs=False  
    )
    if es.ping():
        print('Conexión exitosa a Elasticsearch')
    else:
        print('Conexión fallida')
    return es

def connect_asyncelasticsearch():
    es = AsyncElasticsearch(
        "https://localhost:9200",
        basic_auth=('elastic', 'elastic'),
        verify_certs=False  
    )
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
