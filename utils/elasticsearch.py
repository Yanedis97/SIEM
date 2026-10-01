from elasticsearch import Elasticsearch, AsyncElasticsearch
import urllib3
import os

ES_HOST = os.getenv("ES_HOST", "https://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASSWORD = os.getenv("ES_PASSWORD", "elastic")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def connect_elasticsearch():
    es = Elasticsearch(
        ES_HOST,
        basic_auth=(ES_USER, ES_PASSWORD),
        verify_certs=False  
    )

def connect_asyncelasticsearch():
    es = AsyncElasticsearch(
        ES_HOST,
        basic_auth=(ES_USER, ES_PASSWORD),
        verify_certs=False  
    )

def create_index(es, index_name):
    if not es.indices.exists(index=index_name):
        es.indices.create(index=index_name)
        print(f"Índice {index_name} creado.")
    else:
        print(f"Índice {index_name} ya existe.")
