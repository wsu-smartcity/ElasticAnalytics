"""
A very simple creation pattern for building queries. Likely this could be a pure
static class with no state or internal data, but keep it as a traditional instanced-object instead.
This class is based entirely on the elasticsearch rest api, and just wraps the preparation of a few
recurring queries one is likely to use. So see the elastic rest api documentation for info. This
class just builds the query-dictionaries necessary for common queries.

If more complicated logic is needed, eg aggregate queries and types get very complicated, you might
implement each aggregate query as an object in some inheritance structure of these query types, each
with a __str__() or __dict__() method to directly convert themselves to query dictionaries. This would
tidy up the query generation significantly, which below is somewhat wedded to 'terms' aggregate queries,
or at least very few aggregation query types. There are probably pretty good software patterns in the wild
for generating queries, in python or other languages that could be leveraged. Also consider modeling it
off the existing python-elastic clients out there.
"""

import json


class QueryBuilder(object):
	def __init__(self):
		pass
		
	def _buildAggBucketDict(self, bucketName, bucketType, docValueType, docValue, d=dict(), options=None):
		"""
		Utility for creating the bucket specification within an aggs query. Breaking this out
		here allows for it to be used more cleanly for recursively defined aggs queries, which
		can be arbitrarily nested.

		@bucketName: The name that will be assigned to the bucket returned by elastic
		@bucketType: The type of bucketing being performed. Currently on elastic 5.6, there are many: "terms", "date_histogram", etc. See the docs.
		@docValueType: Usually just "field"
		@docValue: The name of the field in the docs, which can be found in the index' mapping.
		@options: A dictionary containing key/value pairs where the key is likely the filtering clause (either "include" or "exclude")
					and the values are the corresponding match expressions (raw ip strings to include/exclude, for instance). The
					expression may also be a list of values, which elastic supports. E.g., {"exclude": ["192.168.0.4","127.0.0.1","192.168.0.7"]}
					Include/exclude expressions are all that is expected or supported of @options, but there are additional
					options in elastic 5.6 that may become useful. See docs.
		
		NOTE: Aggs 'term' query buckets are often inaccurate! See the docs about 'size': 
			https://www.elastic.co/guide/en/elasticsearch/reference/5.6/search-aggregations-bucket-terms-aggregation.html
			The size parameter must be set to some arbitrarily large size (max of 40,000), in order
			to satisfy a decent level of accuracy in the resulting aggregations. The accuracy is indicated
			in the aggs response, if needed, as fields:
				"doc_count_error_upper_bound": 0, 
				"sum_other_doc_count": 0,
			The problem is that aggs queries are multiplexed to each shard, each of which returns some top-k aggregate counts
			to the master node deploying the query, which then aggregates those aggregate into its own top-k counts. 
			But if k (e.g., @size) is not large enough, documents may be omitted from some shards. See the docs.
			Its a nuisance because one assumes the aggs queries would be precise and include all documents/aggregation-counts,
			but this surprisingly not the case. And very problematic, since 40,000 is the max value for size, which itself
			doesn't seem large enough for potentially huge result spaces for different kinds of queries.
		"""
		
		d[bucketName] = 	{
								bucketType: {
									docValueType: docValue,
									"size":40000 #see header, per @size
								}
							}
		
		if options is not None:
			for clause, expression in options.items():
				d[bucketName][bucketType][clause] = expression

		return d
		
	def BuildAggregateQuery(self, bucketName, docValue, bucketType="terms", docValueType="field", size=0, options=None):
		"""
		Builds a simple elastic aggregate query. See https://www.elastic.co/guide/en/elasticsearch/reference/5.6/search-aggregations.html.
		
		@bucketName: Name for the buckets; the response will be accessible via this name.
		@docValue: The document field name, eg eg, "netflow.ipv4_src_addr".
		@bucketType: eg, 'terms' or a metric to compute such as 'avg'.
		@docValueType: eg, 'field;. I know of no other beside 'field'.
		@size: If non-zero, documents of this size chunk will be returned; if size=0, then no docs are returned, only buckets, which is what you want 99% of the time except maybe for verification.
		@options: An optional dictionary of additional modifiers, e.g. {"include":"192.168.0.2"}
		"""
		qDict = {
			"size": size,
			"aggs" : {}
		}
		qDict["aggs"] = self._buildAggBucketDict(bucketName, bucketType, docValueType, docValue, qDict, options)

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
			opts = None
			#override bucketType and docValueType values if in @tup
			if len(tup) >= 3 and tup[2] is not None:
				bucketType = tup[2]
			if len(tup) >= 4 and tup[3] is not None:
				docValueType = tup[3]
			if len(tup) >= 5 and tup[4] is not None:
				opts = tup[4]
			#build this next-inner bucket and insert into aggDict
			bucket = self._buildAggBucketDict(bucketName, bucketType, docValueType, docValue, {}, opts)
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
										level1Filter = None, \
										level2Filter = None, \
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
		@level[1/2]Filter: A dict of key-value pairs representing include/exclude clauses in a terms-aggs query.
						Example usage: exclude two specific ip addresses using {"exclude":"192.168.0.4", "exclude":"192.168.0.5"}.
						Whatever is in these dicts will be inserted into the aggs query within the "terms" context of the query; see the docs for include/exclude syntax.
		@size: Indicates how many of the documents to include along with the buckets; if 0, then only the buckets are returned, which is what you want 99% of the time.
		"""
		if level1Filter is None:
			outerBucket = (level1BucketName, level1DocValue, level1BucketType, level1DocValueType)
		else:
			outerBucket = (level1BucketName, level1DocValue, level1BucketType, level1DocValueType, level1Filter)
		
		if level2Filter is None:
			innerBucket = (level2BucketName, level2DocValue, level2BucketType, level2DocValueType)
		else:
			innerBucket = (level2BucketName, level2DocValue, level2BucketType, level2DocValueType, level2Filter)

		bucketList = [outerBucket,innerBucket]
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
										level1Filter = None, \
										level2Filter = None, \
										level3Filter = None, \
										size=0):
		"""
		A fully-paramterized convenience wrapper around BuildNestedAggsQuery() for triple-nested queries.
		Returns a triply-nested aggregates query per the passed params.
		"""
		if level1Filter is None:
			bucket1 = (level1BucketName, level1DocValue, level1BucketType, level1DocValueType)
		else:
			bucket1 = (level1BucketName, level1DocValue, level1BucketType, level1DocValueType, level1Filter)
		
		if level2Filter is None:
			bucket2 = (level2BucketName, level2DocValue, level2BucketType, level2DocValueType)
		else:
			bucket2 = (level2BucketName, level2DocValue, level2BucketType, level2DocValueType, level2Filter)

		if level3Filter is None:
			bucket3 = (level3BucketName, level3DocValue, level3BucketType, level3DocValueType)
		else:
			bucket3 = (level3BucketName, level3DocValue, level3BucketType, level3DocValueType, level3Filter)

		bucketList = [bucket1, bucket2, bucket3]
		qDict = self.BuildNestedAggsQuery(bucketList, size)
			
		return qDict
		
def main():
	builder = QueryBuilder()
	builder.TestBuildNestedAggsQuery()
		
if __name__ == "__main__":
	main()
	