
"""
http://192.168.0.91/elasticsearch/_cat/indices?v
http://192.168.0.91/elasticsearch/
"""
from __future__ import print_function
import matplotlib.pyplot as plt
import elasticsearch as elasticsearch
import elasticsearch.helpers
from elasticsearch_dsl import Search
import numpy as np
import traceback
import json
import re
import igraph



"""
Scrolling: 
	query all:
		INDEX_NAME/_search/?scroll=5m   + qDict
		/twitter/tweet/_search?scroll=1m
	Then, WITHOUT index name in url:
		_search/scroll + {'scroll':'5m', 'scroll_id': 'aasdfh743...'}


Kibana console is up:
	http://192.168.0.91/app/kibana#/dev_tools/console?load_from=https:%2F%2Fwww.elastic.co%2Fguide%2Fen%2Felasticsearch%2Freference%2Fcurrent%2Fsnippets%2Fsearch-validate%2F3.json&_g=()
	http://192.168.0.91/app/kibana#/dev_tools/console?_g=()
	
curl -X POST "localhost:9200/_search/scroll" -H 'Content-Type: application/json' -d'
{
    "scroll" : "1m", 
    "scroll_id" : "DXF1ZXJ5QW5kRmV0Y2gBAAAAAAAAAD4WYm9laVYtZndUQlNsdDcwakFMNjU1QQ==" 
}
'

ipv4_dst_addr":"178.255.83.1

Working queries:
	By id:
	curl -H 'Content-Type:application/json' -XGET "http://192.168.0.91:80/elasticsearch/netflow-v5-2017.10.11/_search?&pretty&q=_id:AV8LhQqZyn_BE1UV4cVe"
	By src ip addr (requires scan/scroll, which isn't working yet):
	curl -H 'Content-Type:application/json' -XGET "http://192.168.0.91:80/elasticsearch/netflow-v5-2017.10.11/_search?&pretty&q=netflow.ipv4_src_addr:192.168.0.14"
	
	{'sort': [ '_doc']}
	
	Querying by doc id:
	http://192.168.0.91/elasticsearch/netflow-v5-2017.10.11/logs/AV8LhQqZyn_BE1UV4cVV
	
	#Works nicely, seems to represent a proper escaped windows curl test
	curl -X GET "http://192.168.0.91:80/elasticsearch/netflow-v5-2017.10.11/_search" -H 'Content-Type:application/json' -d"{\"query\": {\"match_all\":{}}}"
	curl -X GET "http://192.168.0.91:80/elasticsearch/netflow-v5-2017.10.11/_search" -H 'Content-Type:application/json' -d"{\"query\": {\"match_all\":{}}}"
	{\"query\":{
    "terms": {
      "_id": [ "1", "2" ] 
    }
  }
}
'
curl -X GET "http://192.168.0.91:80/elasticsearch/netflow-v5-2017.10.11/_search" -H "Content-type: application/json" -d '{\"query\":{\"terms\":{\"_id\":\"AV8LhQqZyn_BE1UV4cVe\"}}}'

	
	
"""


def lsIndices(es, indexRegex=None):
	"""
	Get a list of available indices. If @indexRegex is not none, indices will
	only be returned for which indexRegex.match(index) is not None.
	"""
	indices = es.indices.get_alias("*")
	if indexRegex is None:
		indices.sort()
	else:
		indices = [index for index in sorted(indices) if indexRegex.match(index) is not None]
	return indices

def aggregateQuery(es):
	"""
	An example of an aggregate query with sub-aggregation. The goal here is to group
	every flow by (ip-src,ip-dst), then to sub-aggregate flows based on protocol (or other attributes).
	This gives per-edge distributions per a particular field: protocol, data transfer, etc.
	
	For more info:
	
	curl -X GET "localhost:9200/_search" -H 'Content-Type: application/json' -d'{"query":{"match_all": {}}}'

	
	https://elasticsearch-dsl.readthedocs.io/en/5.4.0/search_dsl.html
	
	"""
	
	pass

	
def getAllDocs1(es, indices):

	hitCount = 0
	index = "netflow-v5-2017.10.11"
	#qDict = {'size': 1000000, 'query': {'match_all': {} }}
	qDict = {'size':1000, 'sort':['_doc']  }   # or just {'sort': [ '_doc']}
	qDict = {'size': 500, 'query': {'match_all':{}}}
	qDict = {'query': {'terms' : {'_id': 'AV8LhQqZyn_BE1UV4cVe'}}}
	
	s = Search(using=es,index=index)
	s.update_from_dict(qDict)
	total = s.count()
	s = s[0:total]
	results = s.execute()
	print("results.hits.total={}  s.count()={}  results.hits.hits={}".format(results.hits.total, s.count(), len(results.hits.hits)))
	#s = s[0:s.count()-1]
	#results = s.execute()
	print("Results: {}".format(len(results)))
	for result in s.scan():
		print(str(hitCount)+":  "+result.to_dict()["@timestamp"])
		hitCount+=1
	exit()
	
def getAllDocs3(es, indices):
	hitCount = 0
	index = "netflow-v5-2017.10.11"
	qDict = {'size': 10, 'query': {'match': {}}}
	qDict = {'query': {'terms' : {'_id': ['AV8LhQqZyn_BE1UV4cVe']}}}
	qDict = {'query': {'match': {'netflow.ipv4_src_addr':'192.168.0.14'}}}
	
	s = elasticsearch.helpers.scan(es,
				query=qDict,
				index=index,
				size=3,
				preserve_order=True,
				clear_scroll=False,
				scroll='5m'
			)

	try:
		for hit in s:
			hitCount += 1
			print(hit)
		print("SUCCESS hitCount: {}".format(hitCount))
	except:
		print("FAILED hitCount: {}".format(hitCount))
		traceback.print_exc()
	
	#print(str(s))
	#print(help(s))
	print("Total hits: {}".format(hitCount))
	exit()






	
def getAllDocs2(es):
	
	index = "netflow-v5-2017.10.11"
	qDict = {'size': 3, 'query': {'match_all':{}}}
	qDict = {'query': {'terms' : {'_id': ['AV8LhQqZyn_BE1UV4cVe']}}}
	qDict = {'query': {'match': {'netflow.ipv4_src_addr':'192.168.0.14'}}}
	
	page = es.search(
	  index = index,
	  #doc_type = 'yourType',
	  scroll = '2m',
	  search_type = 'query_then_fetch', #dfs_query_then_fetch
	  size = 5,
	  body = qDict)
	#print("INFO: "+str(es.info()))
	sid = page['_scroll_id']
	scroll_size = page['hits']['total']
	#print("Scroll id: {}".format(sid))
	# Start scrolling
	i = 0
	#help(es.scroll)
	while scroll_size > 0:
		print("Scrolling..."+sid)
		#page = es.scroll(scroll_id = sid, scroll = '1m')
		bodyDict = {'scroll_id': sid, 'scroll': '1m'}
		page = es.scroll(body = bodyDict, scroll = '1m')
		# Update the scroll ID
		sid = page['_scroll_id']
		print(sid)
		# Get the number of results that we returned in the last scroll
		scroll_size = len(page['hits']['hits'])
		print(str(i)+" scroll size: " + str(scroll_size))
		i += 1
	exit()
		
		
"""
Dump entire flow graph into igraph Graph object, where each node is a host.

client = Elasticsearch()

s = Search(using=client, index="my-index") \
    .filter("term", category="search") \
    .query("match", title="python")   \
    .exclude("match", description="beta")

s.aggs.bucket('per_tag', 'terms', field='tags') \
    .metric('max_lines', 'max', field='lines')

response = s.execute()

for hit in response:
    print(hit.meta.score, hit.title)

for tag in response.aggregations.per_tag.buckets:
    print(tag.key, tag.max_lines.value)
"""
def loadFlowGraph(es):
	netflowRegex = re.compile("netflow.*")
	indices = lsIndices(es, netflowRegex)
	print(str(indices))
	
	qDict = {'size': 1000000, 'query': {'match_all': {} }}
	#response = es.search(index="netflow*", body=qDict)
	#hitCount = 0
	#for hit in response.scan():
	#	hitCount+=1
	#print("Hits: {}".format(hitCount))
	#exit()
	
	s = elasticsearch.helpers.scan(es,
                query={"query": {"match": {}}},
                index="netflow*",
				size=100,
				preserve_order=True,
				clear_scroll=False,
				scroll=u'10M'
            )
	
	try:
		hitCount = 0
		for hit in s:
			hitCount +=1
			print(hit)
		print("hitCount: {}".format(hitCount))
	except:
		print("hitCount: {}".format(hitCount))
		traceback.print_exc()
	exit()
	search = Search(using=es, index="netflow*")
	#help(search)
	total = search.count()
	print("Count: {}".format(total))
	#exit()
	hitCount = 0
	for hit in search.scan():
		hitCount +=1
	print("HIts: {}".format(hitCount))
	
def connect(servAddr="192.168.0.91", servPort=80):
	es = None
	try:
		#es = elasticsearch.Elasticsearch( [{"host": servAddr, "port": servPort, "url_prefix": "elasticsearch"}] )
		es = elasticsearch.Elasticsearch(["http://192.168.0.91:80/elasticsearch"])
	except Exception:
		print("Connected successfully")
		print("Failed to connect")
		#es.info()
		traceback.print_exc()

	return es

	
def printIndices(es):
	#lists the raw indices by name
	indices = es.indices.get_alias("*")	
	for index in sorted(indices):
		print(index)

	#print only the unique indices by type, given their date-based naming convention
	indexTypes = set()
	for index in sorted(indices):
		indexTypes.add(index.split("-")[0])
	indexTypes = sorted(list(indexTypes))
	print("Filtered indices:")
	for index in indexTypes:
		print(index)

def aggregateIpGraph():
	esHeaders = {'Accept': 'text/plain, */*; q=0.01', \
				'Accept-Language': 'en-US,en;q=0.5', \
				'Accept-Encoding': 'gzip, deflate', \
				'kbn-version': '5.6.3', \
				'kbn-xsrf': 'reporting', \
				'DNT': '1'}

	#GET netflow-v5-2017.10.11/_search
	nfIndex = "netflow-v5-2017.10.11"
	
	qDict = {
		"size": 0,
		"aggs": {
		"dst_addr": {
			  "terms": {
				"field": "netflow.ipv4_dst_addr"
			  },
			  "aggs": {
				"src_addr": {
					"terms": {
						"field": "netflow.ipv4_src_addr"
					}
				}
			  }
			}
		}
	}
	
	es = elasticsearch.Elasticsearch(["http://192.168.0.91:80/elasticsearch"], headers=esHeaders)
	
	page = es.search(index=nfIndex, body=qDict)
	print("{}\n{}".format(type(page),str(json.dumps(page,indent=2))))
	#resultDict = json.loads(page)
	#print(page["aggregations"])
	print(str(qDict))
	exit()

		
def matchAll(es, index="*"):
	qDict = {'query': {'match_all': {} }}
	r = es.search(index=index, body=qDict)
	#print(str(type(r)))
	#print(str(r))
	jsonStr = json.dumps(r, indent=4, sort_keys=True)
	print(jsonstr)
	
	return jsonStr
	
def main():
	es = connect("192.168.0.91", 80)
	print(str(es))
	print("Info: "+str(es.info()))
	print("Indices: ")
	#printIndices(es)
	print(str(type(es.info())))
	
	regex = re.compile("netflow.*")
	indices = lsIndices(es,regex)
	#getAllDocs3(es, indices)
	
	aggregateIpGraph()
	
	"""
	getAllDocs2(es)
	exit()
	loadFlowGraph(es)
	exit()
	

	qDict = {'query': {'match_all': {} }}
	#qdict = {'aggs': {} }
	
	index = "*"
	index = "netflow-v9-2016.07.25"
	index = "packetbeat-2017.10.15"
	#index = "snort-2017.10.06"
	#index = "winlogbeat-2017.11.20"
	#index = "bro-2017.12.21"
	matchAll(es, index)
	r = es.search(index=index, body=qDict)	
	print(str(type(r)))
	print(str(r))
	print(json.dumps(r, indent=4, sort_keys=True))
	#"192.168.2.10","ipv4_src_addr": "192.168.2.50"
	"""

if __name__ == "__main__":
	main()