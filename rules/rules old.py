from elasticsearch import Elasticsearch
from datetime import datetime, timedelta

def check_brute_force(es, interval="1m"):
    current_time = datetime.utcnow()
    start_time = current_time - timedelta(minutes=1)
    
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.action": "login_failed"}},
                    {"range": {"@timestamp": {
                        "gte": start_time.isoformat(),
                        "lt": current_time.isoformat()
                        #"gte": "now-5m"
                    }}}
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


def check_privilege_changes(es):
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"match": {"event.action": "privilege_change"}},
                    {"range": {"@timestamp": {"gte": "now-1h"}}}
                ]
            }
        },
        "aggs": {
            "privilege_changes": {
                "terms": {
                    "field": "user.name.keyword",
                    "min_doc_count": 1
                }
            }
        }
    }
    response = es.search(index="logs-*", body=query)
    for bucket in response['aggregations']['privilege_changes']['buckets']:
        print(f"Alerta: Cambio de privilegios detectado para el usuario {bucket['key']}")


def check_anomalous_network_traffic(es):
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.category": "network"}},
                    {"range": {"@timestamp": {"gte": "now-10m"}}}
                ]
            }
        },
        "aggs": {
            "suspicious_ips": {
                "terms": {
                    "field": "source.ip.keyword",
                    "min_doc_count": 10  # Ajustar según comportamiento típico.
                }
            }
        }
    }
    response = es.search(index="logs-*", body=query)
    for bucket in response['aggregations']['suspicious_ips']['buckets']:
        print(f"Alerta: Tráfico sospechoso desde la IP {bucket['key']}")


def check_multiple_failed_logins(es):
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.action": "authentication_failed"}},
                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                ]
            }
        },
        "aggs": {
            "failed_logins": {
                "terms": {
                    "field": "user.name.keyword",
                    "min_doc_count": 5
                }
            }
        }
    }
    response = es.search(index="logs-*", body=query)
    for bucket in response['aggregations']['failed_logins']['buckets']:
        print(f"Alerta: Múltiples intentos fallidos para el usuario {bucket['key']}")


def check_critical_system_access(es):
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.category": "critical_system_access"}},
                    {"range": {"@timestamp": {"gte": "now-1h"}}}
                ]
            }
        },
        "aggs": {
            "accesses": {
                "terms": {
                    "field": "user.name.keyword",
                    "min_doc_count": 1
                }
            }
        }
    }
    response = es.search(index="logs-*", body=query)
    for bucket in response['aggregations']['accesses']['buckets']:
        print(f"Alerta: Acceso a sistema crítico por {bucket['key']}")



def detect_out_of_hours_access(es):
    query = {
        "size": 100,
        "query": {
            "bool": {
                "must": [
                    {"term": {"event.action": "login_success"}}
                ],
                "filter": {
                    "range": {
                        "@timestamp": {
                            "gte": "now-1h"  # Última hora
                        }
                    }
                }
            }
        }
    }
    response = es.search(index="logs-*", body=query)
    for hit in response['hits']['hits']:
        timestamp = hit['_source']['@timestamp']
        hour = datetime.datetime.fromisoformat(timestamp[:-1]).hour
        if hour < 9 or hour > 17:
            print(f"Alerta: Acceso fuera de horario detectado por {hit['_source']['user.name']} a las {timestamp}")



def detect_ddos(es):
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.category": "network"}},
                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                ]
            }
        },
        "aggs": {
            "ip_count": {
                "cardinality": {
                    "field": "source.ip.keyword"
                }
            },
            "target_services": {
                "terms": {
                    "field": "destination.port",
                    "min_doc_count": 100
                },
                "aggs": {
                    "unique_ips": {
                        "cardinality": {
                            "field": "source.ip.keyword"
                        }
                    }
                }
            }
        }
    }
    response = es.search(index="logs-*", body=query)
    for service in response['aggregations']['target_services']['buckets']:
        if service['unique_ips']['value'] > 100:  # Umbral de IPs únicas
            print(f"Alerta: Posible ataque DDoS al puerto {service['key']} con {service['unique_ips']['value']} IPs únicas.")
            


def detect_port_scan(es):
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.category": "network"}},
                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                ]
            }
        },
        "aggs": {
            "source_ips": {
                "terms": {
                    "field": "source.ip.keyword",
                    "size": 100
                },
                "aggs": {
                    "unique_ports": {
                        "cardinality": {
                            "field": "destination.port"
                        }
                    }
                }
            }
        }
    }
    response = es.search(index="logs-*", body=query)
    for bucket in response['aggregations']['source_ips']['buckets']:
        if bucket['unique_ports']['value'] > 10:  # Umbral de puertos únicos
            print(f"Alerta: Posible escaneo de puertos desde {bucket['key']} con {bucket['unique_ports']['value']} puertos diferentes.")



def detect_repeated_access(es):
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.action": "resource_access"}},
                    {"term": {"resource.access": "denied"}},
                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                ]
            }
        },
        "aggs": {
            "users": {
                "terms": {
                    "field": "user.name.keyword",
                    "size": 100
                },
                "aggs": {
                    "resource_attempts": {
                        "terms": {
                            "field": "resource.name.keyword",
                            "size": 10
                        }
                    }
                }
            }
        }
    }
    response = es.search(index="logs-*", body=query)
    for user in response['aggregations']['users']['buckets']:
        for resource in user['resource_attempts']['buckets']:
            print(f"Alerta: {user['key']} intentó acceder a {resource['key']} {resource['doc_count']} veces.")