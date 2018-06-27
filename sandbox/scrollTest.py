from __future__ import print_function
import elasticsearch as elasticsearch
import elasticsearch.helpers
from elasticsearch_dsl import Search
import traceback
import json

def getAllDocs2():

	esHeaders = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0', \
				'Accept': 'text/plain, */*; q=0.01', \
				'Accept-Language': 'en-US,en;q=0.5', \
				'Accept-Encoding': 'gzip, deflate', \
				'Referer': 'http://192.168.0.91/app/kibana', \
				'kbn-version': '5.6.3', \
				'kbn-xsrf': 'reporting', \
				'DNT': '1'}
	es = elasticsearch.Elasticsearch(["http://192.168.0.91:80/elasticsearch"])#, headers=esHeaders)
	qDict = {'query': {'match_all' : {}}}
	index = "netflow-v5-2017.10.11"
	#es.transport.connection_pool.connection.session.headers.update({'kbn-version': '5.6.3'})
	#res = es.search(index=index, doc_type='myType', body=doc,scroll='1m')
	res = es.search(index=index,  body=qDict, scroll='5m')
	scrollId = res['_scroll_id']
	print(scrollId)
	print(json.dumps(res, indent=4))
	qDict = {'scroll':'5m', 'scroll_id':scrollId}
	#res2 = es.scroll(scroll_id=scrollId, scroll='5m')
	while True:
		res2 = es.scroll(scroll_id = scrollId, body=qDict, scroll = '5m')
		#res2 = es.scroll(body=qDict)
		print(res2['_scroll_id'])
		print(json.dumps(res2, indent=4))
	

def aggregateQuery():
	es = elasticsearch.Elasticsearch(["http://192.168.0.91:80/elasticsearch"])#, headers=esHeaders)
	qDict = {'query': {'match_all' : {}}}
	index = "netflow-v5-2017.10.11"
	#es.transport.connection_pool.connection.session.headers.update({'kbn-version': '5.6.3'})
	#res = es.search(index=index, doc_type='myType', body=doc,scroll='1m')
	res = es.search(index=index,  body=qDict, scroll='5m')
	
	
	

def getAllDocs3():
	"""
	Testing the retrieval of all documents using _search/scroll via
	python client wrapper elasticsearch.helpers.scan().
	Elastic server version: 5.6.4, Lucene 6.6.1
	Python elasticsearch module version: VERSION = (5, 5, 2)
	"""
	
	es = elasticsearch.Elasticsearch(["http://192.168.0.91:80/elasticsearch"])
	hitCount = 0
	index = "netflow-v5-2017.10.11"
	qDict = {
				'query': {
					'match': {} 
					}
			}
	
	s = elasticsearch.helpers.scan(es,
				query=qDict,
				index=index,
				size=2,
				preserve_order=True,
				clear_scroll=True, #deletes the scroll on results-return or error
				#scroll='5m
			)

	try:
		for hit in s:
			hitCount += 1
			print(hit)
		print("SUCCESS hitCount: {}".format(hitCount))
	except:
		print("FAILED hitCount: {}".format(hitCount))
		traceback.print_exc()
	
	print("Total hits: {}".format(hitCount))

def main():
	
	try:
		getAllDocs2()
	except:
		traceback.print_exc()
		
	"""
	try:
		getAllDocs3()
	except:
		traceback.print_exc()
	"""
		
if __name__ == "__main__":
	main()
	