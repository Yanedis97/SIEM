from elasticsearch import Elasticsearch

class ElasticsearchConnector:
    def __init__(self, host='localhost', port=9200):
        self.es = Elasticsearch([{'host': host, 'port': port}])

    def get_logs(self, index="logs-*"):
        res = self.es.search(index=index, body={"query": {"match_all": {}}})
        return [hit["_source"] for hit in res['hits']['hits']]