import os
from elasticsearch import Elasticsearch

es = Elasticsearch([os.getenv("ELASTIC_NODE", "http://localhost:9200")])

def index_log(log):
    try:
        es.index(index="api_logs", body=log)
        print("Log indexed in Elasticsearch")
    except Exception as e:
        print("Error indexing log:", e)

