"""
A very simple creation pattern for building queries. Likely this could be a pure
static class with no state or internal data, but keep it as a traditional instanced-object instead.
This class is based entirely on the elasticsearch rest api, and just wraps the preparation of a few
recurring queries one is likely to use. So see the elastic rest api documentation for info. This
class just builds the query-dictionaries necessary for common queries.
"""

class QueryBuilder(object):
	def __init__(self):
		pass
		
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
			bucketName: {
				bucketType: { 
					docValueType: docValue,
				}
			}
		}

		return qDict
	
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
		qDict = {
			"size": size,
			"aggs": {
				level1BucketName: {
					level1BucketType: { 
						level1DocValueType: level1DocValue,
					},
					"aggs": {
						level2BucketName: {
							level2BucketType: { 
								level2DocValueType: level2DocValue,
							}
						}
					}
				}
			}
		}
			
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
		qDict = {
			"size": size,
			"aggs": {
				level1BucketName: {
					level1BucketType: { 
						level1DocValueType: level1DocValue,
					},
					"aggs": {
						level2BucketName: {
							level2BucketType: { 
								level2DocValueType: level2DocValue,
							},
							"aggs": {
								level3BucketName: {
									level3BucketType: { 
										level3DocValueType: level3DocValue,
									}
								}
							}
						}
					}
				}
			}
		}
			
		return qDict
		
		