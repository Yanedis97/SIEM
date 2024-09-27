from elasticsearch import Elasticsearch

def check_brute_force(es):
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.action": "login_failed"}},
                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                ]
            }
        },
        "aggs": {
            "failed_logins": {
                "terms": {
                    "field": "source.ip.keyword",
                    "min_doc_count": 5
                }
            }
        }
    }
    response = es.search(index="logs-*", body=query)
    for bucket in response['aggregations']['failed_logins']['buckets']:
        print(f"Alerta: Posible ataque de fuerza bruta desde {bucket['key']}")

es = Elasticsearch(["localhost:9200"])
check_brute_force(es)
