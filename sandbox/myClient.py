import sys
import requests
import json


"""
es = elasticsearch.Elasticsearch(["http://192.168.0.91:80/elasticsearch"])
qDict = {'query': {'match_all' : {}}}
index = "netflow-v5-2017.10.11"

#http://192.168.0.91/app/kibana#/dev_tools/console?_g=()

"""

def Test1():
	esHeaders = {'kbn-version':'5.6.3', 'content-type':'application/json', 'kbn-xsrf': 'reporting'}
	#esHeaders = {'content-type':'application/json'}
	qDict = {'query': {'match_all':{}}}

	r = requests.post("http://192.168.0.91:80/elasticsearch/netflow-v5-2017.10.11/_search?scroll=5m&size=2", data=json.dumps(qDict), headers=esHeaders)

	#print(str(r.text))
	jsonDict = r.json()
	print(r.json())
	print("Scroll id: "+jsonDict["_scroll_id"])
	scrollId = jsonDict["_scroll_id"]
	qDict = {'scroll':'5m', 'scroll_id':scrollId}

	while True:
		r = requests.post("http://192.168.0.91:80/elasticsearch/_search/scroll", data=json.dumps(qDict), headers=esHeaders)
		print(json.loads(r.text))

def Test2():
	esHeaders = {'kbn-version':'5.6.3', 'content-type':'application/json', 'kbn-xsrf': 'reporting'}
	#esHeaders = {'content-type':'application/json'}	
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
	r = requests.post("http://192.168.0.91:80/elasticsearch/netflow-v5-2017.10.11/_search", data=json.dumps(qDict), headers=esHeaders)

	jsonDict = r.json()
	print(r.json())


Test2()