"""
A very simple creation pattern for building queries. Likely this could be a pure
static class with no state or internal data, but keep it as a traditional instanced-object instead.
This class is based entirely on the elasticsearch rest api, and just wraps the preparation of a few
recurring queries one is likely to use. So see the elastic rest api documentation for info. This
class just builds the query-dictionaries necessary for common queries.
"""

import json

class QueryBuilder(object):
	def __init__(self):
		pass
		
	def _buildAggBucketDict(self, bucketName, bucketType, docValueType, docValue, d=dict()):
		"""
		Utility for creating the bucket specification within an aggs query. Breaking this out
		here allows for it to be used more cleanly for recursively defined aggs queries, which
		can be arbitrarily nested.
		"""
		
		d[bucketName] = 	{
								bucketType: {
									docValueType: docValue,
									#docValueType: docValue,
									"size":40000
								}
							}
		return d
		
	def BuildAggregateQuery(self, bucketName, docValue, bucketType="terms", docValueType="field", size=0):
		"""
		Builds a simple elastic aggregate query. See https://www.elastic.co/guide/en/elasticsearch/reference/5.6/search-aggregations.html.
		
		@bucketName: Name for the buckets; the response will be accessible via this name.
		@docValue: The document field name, eg eg, "netflow.ipv4_src_addr".
		@bucketType: eg, 'terms' or a metric to compute such as 'avg'.
		@docValueType: eg, 'field;. I know of no other beside 'field'.
		@size: If non-zero, documents of this size chunk will be returned; if size=0, then no docs are passed, only buckets, which is what you want 99% of the time except maybe for verification.
		"""
		qDict = {
			"size": size,
			"aggs" : {}
		}
		qDict["aggs"] = self._buildAggBucketDict(bucketName, bucketType, docValueType, docValue, qDict)

		return qDict
	
	def TestBuildNestedAggsQuery(self):
		#bucketList = [("src_ip","netflow.ipv4_src_addr"), ("dst_ip","netflow.ipv4_dst_addr"), ("port","netflow.l4_dst_port"), ("pkt_size","netflow.in_bytes")]
		bucketList = [("src_ip","netflow.ipv4_src_addr"), ("dst_ip","netflow.ipv4_dst_addr"), ("port","netflow.l4_dst_port")]
		aggDict = self.BuildNestedAggsQuery(bucketList)
		print(str(aggDict.keys()))
		print(str(aggDict.values()))
		self._printDictRecursive(aggDict,"")
		print(json.dumps(aggDict,indent=2))
		aggDict1 = aggDict
		aggDict2 = self.BuildTripleAggregateQuery("src_ip","dst_ip","port", "netflow.ipv4_src_addr","netflow.ipv4_dst_addr","netflow.l4_dst_port")
		print(json.dumps(aggDict2, indent=2))
		print(str(aggDict1==aggDict2))
		
		
	def BuildNestedAggsQuery(self, bucketList, size=0, filterQuery={"match_all":{}}):
		"""
		For aggs queries deeper than three levels. Pass in @bucketList, a list of tuples of the form
		(bucketName, docValue, bucketType, docValueType). The 0th element of this list will
		be treated as the outermost bucket description, and the nth element as the innermost.
		For example to aggregate by src-ip, dst-ip, port, then packet size, one would pass
		[("src_ip","netflow.ipv4_src_addr), ("dst_ip","netflow.ipv4_dst_addr"), ("port","netflow.l4_dst_port"), ("pkt_size","netflow.in_bytes")]
		
		@bucketList: A list of bucket names, fielsds, types, as described above
		@size: How many docs to return; will nearly always be 0
		@filterQuery: The outermost query to execute before bucketing; elastic defaults to querying all docs, as does the default param here.
		"""

		nestedDict = {
			"size": size,
			"query":{
				"match_all": {}
			},
			"aggs" : None #overwritten below
		}
		
		aggDict = nestedDict
		for tup in bucketList:
			bucketName = tup[0]
			docValue = tup[1]
			#default/most-common values for these variables in an aggs query
			bucketType = "terms"
			docValueType = "field"
			#override bucketType and docValueType values if in @tup
			if len(tup) >= 3:
				bucketType = tup[2]
			if len(tup) >= 4:
				docValueType = tup[3]
			#build this next-inner bucket and insert into aggDict
			bucket = self._buildAggBucketDict(bucketName, bucketType, docValueType, docValue, {})
			#print("bucket: "+str(bucket))
			aggDict["aggs"] = bucket
			aggDict = bucket[bucketName]
		
		print("Agg query: "+str(json.dumps(nestedDict, indent=2)))
		
		return nestedDict

	def _printDictRecursive(self, d, prefix):
		for k in d.keys():
			if type(d[k]) != dict:
				print(prefix+str(k)+" : "+str(d[k]))
				
		for k in d.keys():
			if type(d[k]) == dict:
				print(prefix+"{")
				self._printDictRecursive(d[k],prefix+"  ")
				print(prefix+"}")
			
	def BuildAllDocQuery(self):
		return {'query': {'match_all':{}}}

	def BuildDoubleAggregateQuery(self, level1BucketName, \
										level2BucketName, \
										level1DocValue, \
										level2DocValue, \
										level1BucketType="terms", \
										level2BucketType="terms", \
										level1DocValueType="field", \
										level2DocValueType="field", \
										#level1Filter = None, \
										#level2Filter = None, \
										size=0):
		"""
		A fully-paramterized convenience wrapper around BuildNestedAggsQuery() for double-nested queries.
		Returns a double-nested aggregates query per the passed params.
		The simplest case of using a nested *aggs* query, similar to a double GROUP-BY query in sql.
		
		@level1BucketName: whatever name is desired; the response's buckets will be accessed via this name.
		@level1BucketType: eg, 'terms'. Note it is common to also pass a metric like 'avg', like in sql.
		@level1DocValueType:  eg, 'field'
		@level1DocValue:  eg, "netflow.ipv4_dst_addr"
		@level1Value: usually the attribute of a document, like "netflow.ipv4_src_addr" (where '.' is used like a path separator to drill deeper into an object)
		@level2 parameters: same as level 1, but for the inner buckets. However, note that its common to pass in a metric that elastic will recognize 
							for @level2BucketType, such as 'avg', to compute and return simply metrics on the inner buckets.
		@level1Filter: A filter dict, eg { "term": { "type": "t-shirt" } }, which would be used to filter bucketed docs to include only those of doc-type 't-shirt'.
		@size: Indicates how many of the documents to include along with the buckets; if 0, then only the buckets are returned, which is what you want 99% of the time.
		"""
		
		bucketList = [(level1BucketName, level1DocValue, level1BucketType, level1DocValueType), (level2BucketName, level2DocValue, level2BucketType, level2DocValueType)]
		qDict = self.BuildNestedAggsQuery(bucketList, size)
			
		return qDict

	def BuildTripleAggregateQuery(self, level1BucketName, \
										level2BucketName, \
										level3BucketName, \
										level1DocValue, \
										level2DocValue, \
										level3DocValue, \
										level1BucketType="terms", \
										level2BucketType="terms", \
										level3BucketType="terms", \
										level1DocValueType="field", \
										level2DocValueType="field", \
										level3DocValueType="field", \
										#level1Filter = None, \
										#level2Filter = None, \
										#level3Filter = None, \
										size=0):
		"""
		A fully-paramterized convenience wrapper around BuildNestedAggsQuery() for triple-nested queries.
		Returns a triply-nested aggregates query per the passed params.
		"""
		bucketList = [(level1BucketName, level1DocValue, level1BucketType, level1DocValueType), (level2BucketName, level2DocValue, level2BucketType, level2DocValueType), (level3BucketName, level3DocValue, level3BucketType, level3DocValueType)]
		qDict = self.BuildNestedAggsQuery(bucketList, size)
			
		return qDict
		
def main():
	builder = QueryBuilder()
	builder.TestBuildNestedAggsQuery()
		
if __name__ == "__main__":
	main()