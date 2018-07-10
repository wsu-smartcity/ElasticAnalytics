import json
import requests


"""
Still not sure why, but the python elastic clients simply don't work, for scrolling,
aggs queries, and most other queries, so I had to write a simple raw Elastic-REST wrapper.
"""
class ElasticClient(object):
	def __init__(self, servAddr, headers=None):
		"""
			@servAddr: The full server address, including uri suffix of base elastic api, eg:  http://192.168.0.91:80/elasticsearch
			@headers: Any desired headers for every query/request. Its not clear when these are needed, such as 'kbn-xrsf'.
		"""
		self._servAddr = servAddr.rstrip("/")+"/" #verifies servAddr ends in /
		if headers is not None:
			self._headers = headers
		else:
			self._headers = {'kbn-version':'5.6.3', 'content-type':'application/json', 'kbn-xsrf': 'reporting'}

	def getIndexRecords(self):
		"""
		Used for catting a list of indices and some of their values (health, status, doc-counts, etc).
		
		Returns columns of a query to /_cat/indices?pretty, marshalled into json objects as:
			{u'status': u'open',
			 u'index': u'snort-2017.12.19',
			 u'uuid': u'tIhYDE7xSnKHsMg9ijLQ3w',
			 u'rep': u'0',
			 u'pri': u'1',
			 u'docs.deleted': u'0',
			 u'pri.store.size': u'38mb',
			 u'health': u'green',
			 u'store.size': u'38mb',
			 u'docs.count': u'10816'}
		"""
		r = requests.get(self._servAddr+"_cat/indices?format=json&pretty", headers = self._headers)
		return r.json()

	def listIndices(self, fullInfo=False, filterRegex=None):
		"""
		Get a list of available indices. If @indexRegex is not none, indices will
		only be returned for which indexRegex.match(index) is not None.
		
		@fullInfo: If true, return all columnar index info as returned by the /_cat/indices endpoint. If false,
		returns only the list of index names.
		@filterRegex: regex by which to filter the indices
		"""
		indices = [rec["index"] for rec in self.getIndexRecords()]
		
		if filterRegex is None:
			indices.sort()
		else:
			indices = sorted([index for index in indices if filterRegex.match(index) is not None])

		return indices
		
	def scroll(self, qDict, index, parser):
		"""
		Experimental for now; most queries shouldn't entail all the network traffic of iterating many/all records,
		or you're doing something wrong. In most cases, even analytics can be performed server-side, and the result
		returned.
		
		This could be a generator based function. See python 'yield' patterns.
		Alternatively, pass in an etl object to transform and analyze and store the results as they are received.
		
		@qDict: The initial query dict
		@index: Name of the index to query
		@etlObject: An object implementing a parse() method, presumably with an internal data structure for processing
		and storing the streaming results.
		
		Returns: Nothing, outputs are stored in @etlObject.
		"""
		#qDict = {'query': {'match_all':{}}}

		if "size" not in qDict:
			#default to 500 results per scroll
			addr = self._servAddr+index+"/_search?scroll=5m&size=500"
		else:
			addr = self._servAddr+index+"/_search?scroll=5m"
			
		r = requests.post(addr, data=json.dumps(qDict), headers=esHeaders)
		jsonDict = r.json()
		print(str(jsonDict))
		print("Scroll id: "+jsonDict["_scroll_id"])
		scrollId = jsonDict["_scroll_id"]
		qDict = {'scroll':'5m', 'scroll_id':scrollId}

		while True:
			r = requests.post(self._servAddr+"_search/scroll", data=json.dumps(qDict), headers=self._headers)
			print(json.loads(r.text))

	def aggregate(self, index, qDict):
		"""
		Returns the response of an aggs query in dict form.
		
		@qDict: A complete aggs query dict, such as this nested-aggs example:
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
		"""
		r = requests.post(self._servAddr+index+"/_search", data=json.dumps(qDict), headers=self._headers)
		return r.json()
