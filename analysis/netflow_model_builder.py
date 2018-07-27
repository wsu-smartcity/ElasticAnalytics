"""
A builder class for building a netflow model (however we define it, based on results)
using an elastic-search client. This may end up being one of the primary interfaces
of the project for generating different views of the data: graphical, statistical,
et cetera.

TODO: Depending on the outcome of different statistical analyses, the outputs of this
class (statistical network models) could be factored out as their own dedicated object(s)
rather than raw python dicts and igraph Graphs. For now this class is a dirty prototype.

The primary purpose is to have a class that:
	1) can generate useful views/models and so forth, as we find them appropriate. For instance,
	it can build and return a graphical model of the a network based on netflows, along with
	different edge/vertex decorations.
	2) solely contains knowledge of the elastic client, potentially making this
	class more generic for other data sources by keeping them abstract. Builder patterns
	are specifically used to preserve this kind of separation.
"""

from elastic_client import ElasticClient
from elastic_query_builder import QueryBuilder
from netflow_model import NetFlowModel

import json
import igraph
import collections

class NetflowModelBuilder(object):
	def __init__(self, client):
		self._esClient = client
		self._queryBuilder = QueryBuilder()

	def _getAggResponseStats(self, aggResponse):
		"""		
		NOTE: Forget recursion for now, I'm assuming the outer bucket error counts reflects the summation of all inner ones,
		or will at least be greater than zero when any inner ones are greater than zero.
		
		Ideally, error counts should be all zeros, hence aggregating them and losing the information about their origin
		is unimportant.
		"""
		
		failureCount = aggResponse["_shards"]["failed"]
		docCountError = aggResponse["aggregations"][aggResponse["aggregations"].keys()[0]]["doc_count_error_upper_bound"]
		otherDocCount = aggResponse["aggregations"][aggResponse["aggregations"].keys()[0]]["sum_other_doc_count"]

		return failureCount, docCountError, otherDocCount

	def BuildIpTrafficModel(self, indexPattern="netflow*", ipVersion="all", ipBlacklist=[], ipWhitelist=[]):
		"""
		Using only netflow volume data, analyze the traffic patterns of the network, as a directed graph.
		
		@ipVersion: Selector for either ipv4 traffic, ipv6 traffic, or both aggregated together. Valid values
					are "ipv6", "ipv4", or "all".
		@ipBlacklist: A list of ip's to exclude from the network description
		@ipWhitelist: A whitelist of ip's to include; note that @ipBlacklist and @ipWhitelist are mutually exclusive; only one should be passed, if either. 
		
		Returns: An igraph Graph object with vertices representing hosts by ipv4/ipv6 address, and edges
		representing the existence of traffic between them. The edges are decorated with @weight, representing
		the number of netflows recorded between the hosts.
		"""
		index = indexPattern
		bucket1 = "src_addr"
		bucket2 = "dst_addr"
		
		options = dict()
		if ipBlacklist is not None and len(ipBlacklist) > 0:
			options["exclude"] = ipBlacklist
		if ipWhitelist is not None and len(ipWhitelist) > 0:
			options["include"] = ipWhitelist
		
		#aggregate ipv4 flows
		if ipVersion.lower() in ["ipv4","all"]:
			bucket1DocValue = "netflow.ipv4_src_addr"
			bucket2DocValue = "netflow.ipv4_dst_addr"
			options = options if len(options) > 0 else None
			qDict = self._queryBuilder.BuildDoubleAggregateQuery(
																	bucket1, 
																	bucket2, 
																	bucket1DocValue, 
																	bucket2DocValue, 
																	level1BucketType="terms",
																	level2BucketType="terms",
																	level1DocValueType="field",
																	level2DocValueType="field",
																	level1Filter=options,
																	level2Filter=options,
																	size=0)
			jsonBucket = self._esClient.aggregate(indexPattern, qDict)
			#print(json.dumps(jsonBucket))
			aggDict_Ipv4 = jsonBucket["aggregations"]
			failCount_Ipv4, docErrors_Ipv4, otherCount_Ipv4 = self._getAggResponseStats(jsonBucket)
		
		#aggregate ipv6 flows
		if ipVersion.lower() in ["ipv6", "all"]:
			bucket1DocValue = "netflow.ipv6_src_addr"
			bucket2DocValue = "netflow.ipv6_dst_addr"
			options = options if len(options) > 0 else None
			qDict = self._queryBuilder.BuildDoubleAggregateQuery(	bucket1,
																	bucket2,
																	bucket1DocValue,
																	bucket2DocValue,
																	level1BucketType="terms",
																	level2BucketType="terms",
																	level1DocValueType="field",
																	level2DocValueType="field",
																	level1Filter=options,
																	level2Filter=options,
																	size=0)
			jsonBucket = self._esClient.aggregate(indexPattern, qDict)
			aggDict_Ipv6 = jsonBucket["aggregations"]
			failCount_Ipv6, docErrors_Ipv6, otherCount_Ipv6 = self._getAggResponseStats(jsonBucket)
			
		#aggregate results per selected ip traffic type
		if ipVersion.lower() == "ipv4":		
			aggDict = aggDict_Ipv4
			failureCount, docErrorCount, otherCount = failCount_Ipv4, docErrors_Ipv4, otherCount_Ipv4
		elif ipVersion.lower() == "ipv6":
			aggDict = aggDict_Ipv6
			failureCount, docErrorCount, otherCount = failCount_Ipv6, docErrors_Ipv6, otherCount_Ipv6
		else:
			#aggregate the ipv4/6 dictionaries together
			aggDict = aggDict_Ipv4
			aggDict[bucket1]["buckets"] += aggDict_Ipv6[bucket1]["buckets"]
			#carry over the outer error statistics as well
			failureCount, docErrorCount, otherCount = failCount_Ipv4, docErrors_Ipv4, otherCount_Ipv4
			failureCount += failCount_Ipv6
			docErrorCount += docErrors_Ipv6
			otherCount += otherCount_Ipv6

		#at least report error counts to the console
		print("IpTrafficModel Aggs errors: failures={}  doc-count-error-bound={}  sum_other_doc_count={}".format(failureCount, docErrorCount, otherCount))

		return aggDict

	def PlotDirectedEdgeHistogram(self, g, edgeAttribute="weight", useLogP1Space=True):
		"""
		Given an igraph object @g with directed edges decorated with a "weight" scalar attribute,
		outputs histograms based on the edge relations for each src-dst pair. this is old code but embeds
		a useful analysis pattern of building a weighted, directed graph, then examining the distribution of
		weights for each set of neighbors.
		"""
		series = []
		for e in g.es:
			src = g.vs[e.source]["name"]
			dest = g.vs[e.target]["name"]
			if useLogP1Space:
				edgeValue = np.log(e[edgeAttribute])+1  #add one, simply for plotting
			else:
				edgeValue = e[edgeAttribute]
			pair = (src+"--"+dest, edgeValue)
			series.append(pair)
		
		print(str(series))
		df = pd.Series([pair[1] for pair in series], index=[pair[0] for pair in series])
		print(str(df))
		print("Plotting...")
		df.sort_values().plot(kind='bar',title="Log-Space Host-Host Flow Frequency")
		#hist.plot()
		plt.tight_layout()
		plt.show()
		plt.clf()
		
		#plot outgoing flow distributions, only for vertices with more than one outgoing edge
		for v in g.vs:
			edges = g.es.select(_source=v.index)
			if len(edges) > 1:
				print(str(len(edges)))
				neighborFrequencies = [(g.vs[e.target]["name"], e["weight"]) for e in edges]
				print("NEIGHBORS: "+str(neighborFrequencies))
				series = pd.Series([pair[1] for pair in neighborFrequencies], index=[pair[0] for pair in neighborFrequencies])
				series.sort_values().plot(kind='bar',title=v["name"]+" Neighbor Flow Frequency")
				plt.tight_layout()
				plt.show()
				plt.clf()
		
	def BuildIpTrafficGraphicalModel(self, ipTrafficModel, outerKey="src_addr", innerKey="dst_addr", labelVertices=True, labelEdges=True):
		"""
		Converts an ip-traffic model into an igraph Graph object. Graph objects can store attributes on edges, vertices, etc,
		so an entire graphical data structure can be built on top of them. Beware that some of that info may not survive its
		spotty serial/deserialization methods, so it might be preferable to implement a ToJson() method instead.

		Interesting interface to matrix land: adjacencyMatrix = g.get_adjacency(attribute="weight", default=0)
		
		@ipTrafficModel: A aggs-dict as returned by an aggregate-type query to the netflow indices.
		@outerKey: The outer key for the returned dict; just use "src_addr"
		@innerKey: The inner key for the returned dict; just use "dst_addr"
		@labelVertices/Edges: Just for visualization, whether or not to define @vertex_label and @edge_label at each vertex/edge.
		"""
		g = igraph.Graph(directed=True)
		es = [] #store as: (src,dst,edge_weight) threeples
		
		for outerBucket in ipTrafficModel[outerKey]["buckets"]:
			srcKey = outerBucket["key"]
			for innerBucket in outerBucket[innerKey]["buckets"]:
				dstKey = innerBucket["key"]
				count  = innerBucket["doc_count"]
				es.append((srcKey,dstKey,count))

		#build the vertex set
		vs = [edge[0] for edge in es]
		vs += [edge[1] for edge in es]
		vs = list(set(vs)) #uniquify the vertices
		g.add_vertices(vs)
		if labelVertices:
			for v in g.vs:
				v["vertex_label"] = v["name"]

		#add the edges
		for edge in es:
			g.add_edge(edge[0], edge[1], weight=edge[2])
		
		if labelEdges:
			g.es["label"] = [str(weight) for weight in g.es["weight"]]
		
		return g

	def BuildProtocolModel(self, indexPattern="netflow*", ipVersion="all", protocolBucket="port", ipBlacklist=[], ipWhitelist=[]):
		"""
		Builds a dou bly-nested model of traffic via the following: src_ip -> dst_ip -> port/protocol.
		Or rather simply, gets the distribution of traffic per each src-dst ip edge in the network per
		either the port number of the netflow of the protocol number. Port number is indicative of 
		transport layer activity/protocol (http, ftp, etc), whereas the protocol number is at the ip/network
		layer and usually only represents ip, icmp, or similar network-layer protocols.
		
		Returns: The representation is returned as a nested dict: d[src_ip][dst_ip] -> {histogram of "port"/"protocol" : volume pairs}
		
		@protocolBucket: A str which must be either "port" or "protocol", designating the grouping parameter of this method: by port or by network-layer protocol.
		@ipVersion: Indicates which layer-3 traffic to include: ipv4, ipv6, or both. Valid values are "ipv4", "ipv6", or "all"; "all" is preferred, I just
					wanted to make sure the code was factored to support this selector.
		"""
		bucket1 = "src_addr"
		bucket2 = "dst_addr"
		bucket3 = "protocol"		
		options = dict()
		if ipBlacklist is not None and len(ipBlacklist) > 0:
			options["exclude"] = ipBlacklist
		if ipWhitelist is not None and len(ipWhitelist) > 0:
			options["include"] = ipWhitelist
		options = options if len(options) > 0 else None
		
		#see header. @port must be "port" or "protocol".
		if protocolBucket.lower() == "port":
			bucket3Key = "netflow.l4_dst_port"
		else:
			bucket3Key = "protocol"

		#aggregate host-host ipv4 traffic by port/protocol
		if ipVersion.lower() in ["ipv4","all"]:
			qDict = self._queryBuilder.BuildTripleAggregateQuery(	bucket1,
																	bucket2,
																	bucket3,
																	"netflow.ipv4_src_addr",
																	"netflow.ipv4_dst_addr",
																	"netflow.l4_dst_port",
																	level1BucketType="terms",
																	level2BucketType="terms",
																	level3BucketType="terms",
																	level1DocValueType="field",
																	level2DocValueType="field",
																	level3DocValueType="field",
																	level1Filter=options, #filter ips by src-addr
																	level2Filter=options, #filter ips by dest-addr
																	level3Filter=None,
																	size=0)
			jsonBucket = self._esClient.aggregate(indexPattern, qDict)
			aggDict_Ipv4 = jsonBucket["aggregations"]
			failCount_Ipv4, docErrors_Ipv4, otherCount_Ipv4 = self._getAggResponseStats(jsonBucket)
			#print(str(aggDict_Ipv4))
			#print(json.dumps(aggDict_Ipv4, indent=1))

		#aggregate host-host ipv6 traffic by port/protocol
		if ipVersion.lower() in ["ipv6", "all"]:
			qDict = self._queryBuilder.BuildTripleAggregateQuery(	bucket1,
																	bucket2,
																	bucket3,
																	"netflow.ipv6_src_addr",
																	"netflow.ipv6_dst_addr",
																	"netflow.l4_dst_port",
																	level1BucketType="terms",
																	level2BucketType="terms",
																	level3BucketType="terms",
																	level1DocValueType="field",
																	level2DocValueType="field",
																	level3DocValueType="field",
																	level1Filter=options, #filter ips by src-addr
																	level2Filter=options, #filter ips by dest-addr
																	level3Filter=None,
																	size=0)
			jsonBucket = self._esClient.aggregate(indexPattern, qDict)
			aggDict_Ipv6 = jsonBucket["aggregations"]
			failCount_Ipv6, docErrors_Ipv6, otherCount_Ipv6 = self._getAggResponseStats(jsonBucket)

		#aggregate results per selected ip traffic type
		if ipVersion.lower() == "ipv4":		
			aggDict = aggDict_Ipv4
			failureCount, docErrorCount, otherCount = failCount_Ipv4, docErrors_Ipv4, otherCount_Ipv4
		elif ipVersion.lower() == "ipv6":
			aggDict = aggDict_Ipv6
			failureCount, docErrorCount, otherCount = failCount_Ipv6, docErrors_Ipv6, otherCount_Ipv6
		else:
			#aggregate the ipv4/6 dictionaries together
			aggDict = aggDict_Ipv4
			aggDict[bucket1]["buckets"] += aggDict_Ipv6[bucket1]["buckets"]
			#carry over the outer error statistics as well
			failureCount, docErrorCount, otherCount = failCount_Ipv4, docErrors_Ipv4, otherCount_Ipv4
			failureCount += failCount_Ipv6
			docErrorCount += docErrors_Ipv6
			otherCount += otherCount_Ipv6

		print("BuildProtocolModel({}) Aggs errors: failures={}  doc-count-error-bound={}  sum_other_doc_count={}".format(protocolBucket, failureCount, docErrorCount, otherCount))
			
		#convert the response to something easier to work with, and keys as [src][dst] -> protocol-histogram
		d = dict()
		for outerBucket in aggDict[bucket1]["buckets"]:
			src_addr = outerBucket["key"]
			src_dict = d.setdefault(src_addr, dict())
			for innerBucket in outerBucket[bucket2]["buckets"]:
				dest_addr = innerBucket["key"]
				dest_dict = src_dict.setdefault(dest_addr, dict())
				#convert these innermost buckets to a histogram from the elastic-aggs query json representation
				hist = { pair["key"]:pair["doc_count"] for pair in innerBucket[bucket3]["buckets"] }
				dest_dict[bucket3] = hist

		return d

	def BuildFlowSizeModel(self, indexPattern="netflow*", ipVersion="all", protocolBucket="port", sizeAttrib="netflow.in_bytes", ipBlacklist=[], ipWhitelist=[]):
		"""
		Builds a triply-nested model of packet size (either in bytes or #packets in flow) determined
		or even src-ip -> dst-ip -> protocol -> port, but I'm keeping it simple for now.
		by src-ip -> dst-ip -> port -> packet_size. This could estimate by src-ip -> dst-ip -> protocol instead,
		
		NOTE: The returned histograms are over flow-sizes with their associated counts, which are really discretized versions
		of continuous distributions, and not multiclass distributions. Hence if a particular src-dst-port entry has (2345:4)
		(4 flows of size 2345), this should not be interpreted as 4 occurrences of "class" 2345 like in other distributions.
		So don't forget to multiply 4*2345 when cnoverting the histogram to its means/variances; don't treat the entries like
		events, e.g. '4 events of class 2345'.
		
		@sizeAttrib: The document size attribute/field in the netflow. Valid values are "in_bytes" (model flows
					by bytes) or "in_pkts" (model number of packets in flows).
		@protocolBucket: The document attribute by which to aggregate packets, either by network layer protocol
						(netflow.protocol), or by layer-4 port (netflow.l4_dst_port). Valid values are "port" or
						"protocol".
		@ipBlacklist: List of ips to exclude
		@ipWhitelisT: List of ips to include
		
		Returns: A triply-nested dict of dicts, as d[src_ip][dst_ip][port][]
		"""
		index   = "netflow*"
		bucket1 = "src_addr"
		bucket2 = "dst_addr"
		bucket3 = protocolBucket
		bucket4 = sizeAttrib

		docValue1_Ipv4 = "netflow.ipv4_src_addr"
		docValue2_Ipv4 = "netflow.ipv4_dst_addr"
		docValue1_Ipv6 = "netflow.ipv6_src_addr"
		docValue2_Ipv6 = "netflow.ipv6_dst_addr"
		docValue4 = sizeAttrib

		ipOptions = dict()
		if ipBlacklist is not None and len(ipBlacklist) > 0:
			ipOptions["exclude"] = ipBlacklist
		if ipWhitelist is not None and len(ipWhitelist) > 0:
			ipOptions["include"] = ipWhitelist
		ipOptions = ipOptions if len(ipOptions) > 0 else None
		
		#see header. @protocolBucket must be "port" or "protocol".
		if protocolBucket == "port":
			docValue3 = "netflow.l4_dst_port"
		elif protocolBucket == "protocol":
			docValue3 = "protocol"
		
		#aggregate ipv4 traffic
		if ipVersion.lower() in ["ipv4","all"]:
			bucketList = [(bucket1, docValue1_Ipv4, "terms", "field", ipOptions), (bucket2, docValue2_Ipv4, "terms", "field", ipOptions), (bucket3, docValue3), (bucket4, docValue4)]
			qDict = self._queryBuilder.BuildNestedAggsQuery(bucketList, size=0)
			jsonBucket = self._esClient.aggregate(indexPattern, qDict)
			aggDict_Ipv4 = jsonBucket["aggregations"]
			#print(json.dumps(jsonBucket, indent=2))
			failCount_Ipv4, docErrors_Ipv4, otherCount_Ipv4 = self._getAggResponseStats(jsonBucket)

		#aggregate ipv6 traffic
		if ipVersion.lower() in ["ipv6","all"]:
			bucketList = [(bucket1, docValue1_Ipv6, "terms", "field", ipOptions), (bucket2, docValue2_Ipv6, "terms", "field", ipOptions), (bucket3, docValue3), (bucket4, docValue4)]
			qDict = self._queryBuilder.BuildNestedAggsQuery(bucketList, size=0)
			jsonBucket = self._esClient.aggregate(indexPattern, qDict)
			aggDict_Ipv6 = jsonBucket["aggregations"]
			failCount_Ipv6, docErrors_Ipv6, otherCount_Ipv6 = self._getAggResponseStats(jsonBucket)

		#aggregate results per selected ip traffic type
		if ipVersion.lower() == "ipv4":
			aggDict = aggDict_Ipv4
			failureCount, docErrorCount, otherCount = failCount_Ipv4, docErrors_Ipv4, otherCount_Ipv4
		elif ipVersion.lower() == "ipv6":
			aggDict = aggDict_Ipv6
			failureCount, docErrorCount, otherCount = failCount_Ipv6, docErrors_Ipv6, otherCount_Ipv6
		else:
			#aggregate the ipv4/6 dictionaries together
			aggDict = aggDict_Ipv4
			aggDict[bucket1]["buckets"] += aggDict_Ipv6[bucket1]["buckets"]
			#carry over the outer error statistics as well
			failureCount, docErrorCount, otherCount = failCount_Ipv4, docErrors_Ipv4, otherCount_Ipv4
			failureCount += failCount_Ipv6
			docErrorCount += docErrors_Ipv6
			otherCount += otherCount_Ipv6

		#report failures/successes; its critical to at least know these values off-hand, to verify queries are accurate
		print("BuildFlowSizeModel Aggs errors: failures={}  doc-count-error-bound={}  sum_other_doc_count={}".format(failureCount, docErrorCount, otherCount))

		#convert the response to something easier to work with, and keys as [src][dst][protocol/port] -> size-histogram
		d = dict()
		for srcBucket in aggDict[bucket1]["buckets"]:
			src_addr = srcBucket["key"]
			src_dict = d.setdefault(src_addr, dict())
			for destBucket in srcBucket[bucket2]["buckets"]:
				dest_addr = destBucket["key"]
				dest_dict = src_dict.setdefault(dest_addr, dict())
				for protoBucket in destBucket[bucket3]["buckets"]:
					protocol = protoBucket["key"] #either a protocol or port #
					protocol_dict = dest_dict.setdefault(protocol, dict())
					#convert these innermost buckets to a histogram from the elastic-aggs query json representation
					hist = { pair["key"]:pair["doc_count"] for pair in protoBucket[bucket4]["buckets"] } #maps integer byte-counts to their frequency; yes, it is dopey.
					protocol_dict[bucket4] = hist

		return d

	def BuildNetFlowModel(self, indexPattern="netflow*", ipVersion="all", ipBlacklist=None, ipWhitelist=None):
		"""
		Builds a very specific kind of flow model, represented as a graph with edges and
		vertices containing further information.
		
		@ipVersion: str 'ipv4' 'ipv6' or 'all', indicating which type of traffic to include in the model
		@ipBlacklist: A list of ips to exclude from the model; these may contain wildcards, per the
					'include'/'exclude' filter param style of elastic 5.6 aggs queries.
		@ipWhitelist: A list of ips to exclusively include.
		
		Of course, @ipBlacklist/@ipWhitelist should be treated as mutually exclusive.
		"""
		
		#friendly reminder about ip black/whitelists
		if ipBlacklist is not None or ipWhitelist is not None:
			print("REMINDER: When passing @ipBlacklist or @ipWhitelist, prefer a raw list of fully specified host ips.")
			print("          CIDR prefixes are supported but untested; also, ip fields don't support reguler expressions.")
			print("          See elastic docs on include/exclude params of terms queries for specific info.")
		
		#query the netflow indices for all traffic between hosts
		ipModel = self.BuildIpTrafficModel(indexPattern, ipVersion=ipVersion, ipBlacklist=ipBlacklist, ipWhitelist=ipWhitelist)
		g = self.BuildIpTrafficGraphicalModel(ipModel)
		flowModel = NetFlowModel(g)
		flowModel.PlotIpTrafficModel()
		
		#aggregate host-to-host traffic by ip protocol (icmp traffic, though infrequent, is not always safe: ping+traceroute are used for recon, and other methods use icmp for key transmission
		protocolModel = self.BuildProtocolModel(indexPattern, ipVersion=ipVersion, protocolBucket="protocol", ipBlacklist=ipBlacklist, ipWhitelist=ipWhitelist)
		#print(str(protocolModel))
		if not flowModel.MergeEdgeModel(protocolModel, "protocol"):
			print("ERROR could not merge protocol model into flow model")

		#aggregate host-to-host traffic by layer-4 dest port. Some, but not all, dest-port usage is indicative of the application layer protocol (ftp, http, etc).
		portModel = self.BuildProtocolModel(indexPattern, ipVersion=ipVersion, protocolBucket="port", ipBlacklist=ipBlacklist, ipWhitelist=ipWhitelist)
		if not flowModel.MergeEdgeModel(portModel, "port"):
			print("ERROR could not merge port model into flow model")
		
		#aggregate host-to-host port traffic by packet size
		pktSizeModel = self.BuildFlowSizeModel(indexPattern, ipVersion=ipVersion, protocolBucket="port", sizeAttrib="netflow.in_bytes", ipBlacklist=ipBlacklist, ipWhitelist=ipWhitelist)
		if not flowModel.MergeEdgeModel(pktSizeModel, "in_bytes"):
			print("ERROR could not merge port model into flow model")

		"""
		#FUTURE
		#aggregate host-to-host port traffic by time-stamp
		#pktSizeModel = self.BuildFlowTimestampModel()

		print("Num ip addrs: {}".format(len(g.vs)))
		print("Target in addrs: {}".format("207.241.22" in str(protocolModel)))
		addrs = set()
		for src in protocolModel.keys():
			addrs.add(src)
			for dst in protocolModel[src].keys():
				addrs.add(src)
				
		with open("addrs.txt","w+") as ofile:
			for addr in addrs:
				ofile.write(addr+"\n")

		for addr in sorted(list(addrs)):
			if "31.13." in addr:
				print("Hit: {}".format(addr))
			print(addr)
			
		print("Target in addrs: {}".format("31.13.76" in str(protocolModel)))
		"""
		
		return flowModel

def main():
	servAddr = "http://192.168.0.91:80/elasticsearch"
	client = ElasticClient(servAddr)
	builder	= NetflowModelBuilder(client)
	ipVersion = "ipv4"
	
	"""
	Note that blacklist/whitelist are passed along to "include"/"exclude" aggs clauses, which process
	single strings params as regexes, and arrays (lists) as exact matches. So passing a list of ips will
	exact match on those ips; passing a single string will be treated as a regex ("regexp queries" in elastic speak).
	Passing a single-item list will be converted to a regex. Also, avoid ambiguous include/exclude logic, since usually
	such combinations of the two can be achieved with only one of include/exclude and a decent regex. Passing both
	should be avoided because of its ambiguous meaning, but technically because it isn't clear in which order each
	should be applied (excluding a set of regexes, then including itm etc). Try to stick with one. Elastic also
	returns errors when passing a single item include list and an exclude regex, so elastic's implementation is sketchy.
	
	Regexes work for ip fields in include/exclude clauses, but its ill-advised. Some of our indices complain about the datatype.
	Elasticsearch docs specify using only arrays of values in the include/exclude clause of aggs queries, not regexes,
	so stick with that. The ip fields do support CIDR prefix lengths, though, for range based queries.
	"""
	#blacklist = ["192.168.0.14", "192.168.19.1", "192.168.0.13", "192.168.0.12", "192.168.56.1", "192.168.99.1"]
	#whitelist = None
	#blacklist = ["192.168.0.14","192.168.10.2"]
	#blacklist = "192.168.0.14"
	blacklist = None
	whitelist = ["192.168.2.0/24"]
	
	whitelist = ["192.168.2.10",
				"192.168.2.101",
				"192.168.2.102",
				"192.168.2.103",
				"192.168.2.104",
				"192.168.2.105",
				"192.168.2.106",
				"192.168.2.107",
				"192.168.2.108",
				"192.168.0.11",
				"255.255.255.255",
				"127.0.0.1",
				"128.0.0.0",
				"0.0.0.0",
				"192.255.255.0"]
	
	#whitelist = "192\.168\.(2|0|1)\..*"
	#whitelist = "192\.168\.2\..*"
	#whitelist = None
	indexPattern = "netflow*"
	indexPattern = "netflow-v9-2017*"
	#uses '-' to exclude specific indices or index-patterns
	indexPattern = "netflow-v9-2017*,-netflow-v9-2017.04*" #april indices have failed repeatedly, due to what appears to be differently-index data; may require re-indexing
	model = builder.BuildNetFlowModel(indexPattern, ipVersion=ipVersion, ipBlacklist=blacklist, ipWhitelist=whitelist)
	model.Save("pickled_model.pickle")
	
if __name__ == "__main__":
	main()
