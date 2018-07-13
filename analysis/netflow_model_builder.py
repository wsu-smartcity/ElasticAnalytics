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
	
	"""
	For now, just some data exploration of the netflow* index data to check out the statistical properties and prior
	distribution of the data by various aggregations (ip addresses, ports, protocols, etc).
	"""

	def PlotIpTrafficModel(self, g, labelVertices=True, labelEdges=True):
		"""
		@g: An igraph.Graph object
		"""
		visual_style = {}
		visual_style["vertex_size"] = 15
		visual_style["vertex_color"] = "green"
		if labelVertices:
			try:
				visual_style["vertex_label"] = g.vs["name"]
			except:
				pass
		if labelEdges:
			try:
				visual_style["edge_label"] = g.es["label"]
			except:
				pass
		visual_style["vertex_label_size"] = 12
		visual_style["layout"] = g.layout("kk")
		visual_style["bbox"] = (800, 800)
		visual_style["margin"] = 50
		graphPlot = igraph.plot(g, **visual_style)

		return graphPlot

	def BuildIpTrafficModel(self, ipVersion="all"):
		"""
		Using only netflow volume data, analyze the traffic patterns of the network, as a directed graph.
		
		@ipVersion: Selector for either ipv4 traffic, ipv6 traffic, or both aggregated together. Valid values
					are "ipv6", "ipv4", or "all".
		
		Returns: An igraph Graph object with vertices representing hosts by ipv4/ipv6 address, and edges
		representing the existence of traffic between them. The edges are decorated with @weight, representing
		the number of netflows recorded between the hosts.
		"""
		index = "netflow*"
		bucket1 = "src_addr"
		bucket2 = "dst_addr"
		
		#aggregate ipv4 flows
		if ipVersion.lower() in ["ipv4","all"]:
			bucket1DocValue = "netflow.ipv4_src_addr"
			bucket2DocValue = "netflow.ipv4_dst_addr"
			qDict = self._queryBuilder.BuildDoubleAggregateQuery(bucket1, bucket2, bucket1DocValue, bucket2DocValue, level1BucketType="terms", level2BucketType="terms", level1DocValueType="field", level2DocValueType="field",  size=0)
			jsonBucket = self._esClient.aggregate(index, qDict)
			aggDict_Ipv4 = jsonBucket["aggregations"]
		#aggregate ipv6 flows
		if ipVersion.lower() in ["ipv6", "all"]:
			bucket1DocValue = "netflow.ipv6_src_addr"
			bucket2DocValue = "netflow.ipv6_dst_addr"
			qDict = self._queryBuilder.BuildDoubleAggregateQuery(bucket1, bucket2, bucket1DocValue, bucket2DocValue, level1BucketType="terms", level2BucketType="terms", level1DocValueType="field", level2DocValueType="field",  size=0)
			jsonBucket = self._esClient.aggregate(index, qDict)
			aggDict_Ipv6 = jsonBucket["aggregations"]

		if ipVersion.lower() == "ipv4":
			aggDict = aggDict_Ipv4
		elif ipVersion.lower() == "ipv6":
			aggDict = aggDict_Ipv6
		else:
			#aggregate the ipv4/6 dictionaries together
			aggDict = aggDict_Ipv4
			aggDict[bucket1]["buckets"] += aggDict_Ipv6[bucket1]["buckets"]
		
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
		
	def BuildIpTrafficGraphicalModel(self, ipTrafficModel, outerKey="src_addr", innerKey="dst_addr", labelVertices=True, labelEdges=False):
		"""
		Converts an ip-traffic model into an igraph Graph object. Graph objects can store attributes on edges, vertices, etc,
		so an entire graphical data structure can be built on top of them. Beware that some of that info may not survive its
		spotty serial/deserialization methods, so it might be preferable to implement a ToJson() method instead.
		
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
				count = innerBucket["doc_count"]
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
		
		"""
		labelVertices=True
		labelEdges=False
		#aggDict = {u'src_addr': {u'buckets': [{u'dst_addr': {u'buckets': [{u'key': u'192.168.1.160', u'doc_count': 1061347}, {u'key': u'192.168.1.11', u'doc_count': 14857}, {u'key': u'192.168.0.12', u'doc_count': 14852}, {u'key': u'192.168.1.102', u'doc_count': 13044}, {u'key': u'239.255.255.250', u'doc_count': 7607}, {u'key': u'192.168.0.11', u'doc_count': 7382}, {u'key': u'192.168.0.91', u'doc_count': 5283}, {u'key': u'192.168.3.216', u'doc_count': 1730}, {u'key': u'192.168.0.1', u'doc_count': 625}, {u'key': u'192.168.1.118', u'doc_count': 257}], u'sum_other_doc_count': 544, u'doc_count_error_upper_bound': 1}, u'key': u'192.168.2.10', u'doc_count': 1127528}, {u'dst_addr': {u'buckets': [{u'key': u'192.168.2.10', u'doc_count': 1061347}, {u'key': u'239.255.255.250', u'doc_count': 14710}, {u'key': u'192.168.0.14', u'doc_count': 605}, {u'key': u'255.255.255.255', u'doc_count': 315}, {u'key': u'224.0.0.1', u'doc_count': 312}, {u'key': u'224.0.0.252', u'doc_count': 264}, {u'key': u'224.0.0.251', u'doc_count': 9}, {u'key': u'224.0.1.129', u'doc_count': 2}, {u'key': u'239.192.152.143', u'doc_count': 2}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.1.160', u'doc_count': 1077566}, {u'dst_addr': {u'buckets': [{u'key': u'192.168.0.1', u'doc_count': 104641}, {u'key': u'239.255.255.250', u'doc_count': 81122}, {u'key': u'224.0.0.252', u'doc_count': 24754}, {u'key': u'172.217.3.163', u'doc_count': 20530}, {u'key': u'172.217.3.174', u'doc_count': 19105}, {u'key': u'134.121.120.167', u'doc_count': 16311}, {u'key': u'192.168.3.255', u'doc_count': 8152}, {u'key': u'64.4.54.254', u'doc_count': 7700}, {u'key': u'64.71.168.217', u'doc_count': 7127}, {u'key': u'192.168.1.114', u'doc_count': 6920}], u'sum_other_doc_count': 187585, u'doc_count_error_upper_bound': 1754}, u'key': u'192.168.0.14', u'doc_count': 483947}, {u'dst_addr': {u'buckets': [{u'key': u'192.168.0.14', u'doc_count': 120591}, {u'key': u'255.255.255.255', u'doc_count': 2397}, {u'key': u'239.255.255.250', u'doc_count': 508}, {u'key': u'192.168.2.10', u'doc_count': 247}, {u'key': u'192.168.3.224', u'doc_count': 79}, {u'key': u'224.0.0.1', u'doc_count': 63}, {u'key': u'224.0.0.252', u'doc_count': 14}, {u'key': u'192.168.0.109', u'doc_count': 10}, {u'key': u'192.168.0.111', u'doc_count': 4}, {u'key': u'192.168.0.16', u'doc_count': 4}], u'sum_other_doc_count': 7, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.0.1', u'doc_count': 123924}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 87186}, {u'key': u'192.168.2.10', u'doc_count': 21272}, {u'key': u'192.168.3.255', u'doc_count': 8093}, {u'key': u'255.255.255.255', u'doc_count': 2206}, {u'key': u'192.168.0.14', u'doc_count': 78}, {u'key': u'224.0.0.252', u'doc_count': 2}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.0.12', u'doc_count': 118837}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 69383}, {u'key': u'192.168.3.255', u'doc_count': 11231}, {u'key': u'192.168.0.14', u'doc_count': 200}, {u'key': u'192.168.2.10', u'doc_count': 64}, {u'key': u'224.0.0.252', u'doc_count': 35}, {u'key': u'255.255.255.255', u'doc_count': 4}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.0.13', u'doc_count': 80917}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 37482}, {u'key': u'192.168.2.10', u'doc_count': 18645}, {u'key': u'192.168.15.255', u'doc_count': 7153}, {u'key': u'192.168.3.255', u'doc_count': 6852}, {u'key': u'255.255.255.255', u'doc_count': 3385}, {u'key': u'192.168.0.14', u'doc_count': 107}, {u'key': u'224.0.0.251', u'doc_count': 28}, {u'key': u'224.0.0.252', u'doc_count': 10}, {u'key': u'192.168.1.111', u'doc_count': 5}, {u'key': u'224.0.1.129', u'doc_count': 1}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.1.102', u'doc_count': 73668}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 32847}, {u'key': u'192.168.2.10', u'doc_count': 21241}, {u'key': u'192.168.3.255', u'doc_count': 12561}, {u'key': u'255.255.255.255', u'doc_count': 3511}, {u'key': u'192.168.0.14', u'doc_count': 355}, {u'key': u'192.168.2.101', u'doc_count': 9}, {u'key': u'192.168.2.102', u'doc_count': 9}, {u'key': u'192.168.2.103', u'doc_count': 9}, {u'key': u'192.168.2.107', u'doc_count': 8}, {u'key': u'192.168.2.108', u'doc_count': 8}], u'sum_other_doc_count': 35, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.1.11', u'doc_count': 70593}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 48167}, {u'key': u'192.168.1.255', u'doc_count': 7814}, {u'key': u'255.255.255.255', u'doc_count': 2350}, {u'key': u'224.0.0.252', u'doc_count': 80}, {u'key': u'192.168.3.255', u'doc_count': 3}, {u'key': u'224.0.0.251', u'doc_count': 3}, {u'key': u'192.168.0.14', u'doc_count': 1}, {u'key': u'192.168.1.101', u'doc_count': 1}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.1.14', u'doc_count': 58419}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 31456}, {u'key': u'255.255.255.255', u'doc_count': 8959}, {u'key': u'192.168.3.255', u'doc_count': 7454}, {u'key': u'192.168.2.10', u'doc_count': 7387}, {u'key': u'192.168.0.14', u'doc_count': 187}, {u'key': u'224.0.0.252', u'doc_count': 4}, {u'key': u'192.168.0.16', u'doc_count': 3}, {u'key': u'192.168.2.101', u'doc_count': 1}, {u'key': u'192.168.2.102', u'doc_count': 1}, {u'key': u'192.168.2.103', u'doc_count': 1}], u'sum_other_doc_count': 6, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.0.11', u'doc_count': 55459}], u'sum_other_doc_count': 410259, u'doc_count_error_upper_bound': 4257}}
		g = self._ipModelToNetworkGraph(aggDict, bucket1, bucket2, labelVertices, labelEdges)
		g.write_graphml("./ip_traffic.graphml")
		graphPlot = PlotIpTrafficModel(g, labelVertices, labelEdges)
		graphPlot.save("ipTraffic.png")
		adjacencyMatrix = g.get_adjacency(attribute="weight", default=0)
		print(str(type(adjacencyMatrix))+"\n"+str(adjacencyMatrix))
		
		self.PlotDirectedEdgeHistogram(g, "weight")
		
		return g
		"""

	def BuildProtocolModel(self, ipVersion="all", protocolBucket="port"):
		"""
		Builds a triply-nested model of traffic via the following: src_ip -> dst_ip -> port/protocol.
		Or rather simply, gets the distribution of traffic per each src-dst ip edge in the network per
		either the port number of the netflow of the protocol number. Port number is indicative of 
		transport layer activity/protocol (http, ftp, etc), whereas the protocol number is at the ip/network
		layer and usually only represents ip, icmp, or similar network-layer protocols.
		
		Returns: The representation is returned as a nested dict: d[src_ip][dst_ip] -> {histogram of "port"/"protocol" : volume pairs}
		
		@protocolBucket: A str which must be either "port" or "protocol", designating the grouping parameter of this method: by port or by network-layer protocol.
		@ipVersion: Indicates which layer-3 traffic to include: ipv4, ipv6, or both. Valid values are "ipv4", "ipv6", or "all"; "all" is preferred, I just
					wanted to make sure the code was factored to support this selector.
		"""
		index = "netflow*"
		bucket1 = "src_addr"
		bucket2 = "dst_addr"
		bucket3 = "protocol"

		#see header. @port must be "port" or "protocol".
		if protocolBucket.lower() == "port":
			bucket3Key = "netflow.l4_dst_port"
		else:
			bucket3Key = "protocol"

		#aggregate host-host ipv4 traffic by port/protocol
		if ipVersion.lower() in ["ipv4","all"]:
			qDict = self._queryBuilder.BuildTripleAggregateQuery(bucket1, bucket2, bucket3, "netflow.ipv4_src_addr", "netflow.ipv4_dst_addr", "netflow.l4_dst_port", level1BucketType="terms", level2BucketType="terms", level3BucketType="terms", level1DocValueType="field", level2DocValueType="field", level3DocValueType="field", size=0)
			jsonBucket = self._esClient.aggregate(index, qDict)
			aggDict_Ipv4 = jsonBucket["aggregations"]
			#print(str(aggDict_Ipv4))
			print(json.dumps(aggDict_Ipv4, indent=1))

		#aggregate host-host ipv6 traffic by port/protocol
		if ipVersion.lower() in ["ipv6", "all"]:
			qDict = self._queryBuilder.BuildTripleAggregateQuery(bucket1, bucket2, bucket3, "netflow.ipv6_src_addr", "netflow.ipv6_dst_addr", "netflow.l4_dst_port", level1BucketType="terms", level2BucketType="terms", level3BucketType="terms", level1DocValueType="field", level2DocValueType="field", level3DocValueType="field", size=0)
			jsonBucket = self._esClient.aggregate(index, qDict)
			aggDict_Ipv6 = jsonBucket["aggregations"]

		#combine the two traffic aggregations: ipv4 and ipv6
		if ipVersion.lower() == "all":
			aggDict = aggDict_Ipv4
			aggDict[bucket1]["buckets"] += aggDict_Ipv6[bucket1]["buckets"]
		elif ipVersion.lower() == "ipv4":
			aggDict = aggDict_Ipv4
		elif ipVersion.lower() == "ipv6":
			aggDict = aggDict_Ipv6

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

		#print("DDD: "+json.dumps(d, indent=2))
				
		return d
		
	def _esAggDictToPyDict(self, aggDict, bucketKeyList):
		"""
		The elastic-search aggs query response is a dictionary with a bunch of metadata we don't currently need.
		This converts it into a regular python dictionary, removing the stuff we don't need.
		"""
		d = dict()
		
		for key in bucketKeyList:
			pass
		return d

	def BuildFlowSizeModel(self, ipVersion="all", protocolBucket="port", sizeAttrib="in_bytes"):
		"""
		Builds a triply-nested model of packet size (either in bytes or #packets in flow) determined
		or even src-ip -> dst-ip -> protocol -> port, but I'm keeping it simple for now.
		by src-ip -> dst-ip -> port -> packet_size. This could estimate by src-ip -> dst-ip -> protocol instead,
		
		@sizeAttrib: The document size attribute/field in the netflow. Valid values are "in_bytes" (model flows
					by bytes) or "in_pkts" (model number of packets in flows).
		@protocolBucket: The document attribute by which to aggregate packets, either by network layer protocol
						(netflow.protocol), or by layer-4 port (netflow.l4_dst_port). Valid values are "port" or
						"protocol".
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
		
		#see header. @protocolBucket must be "port" or "protocol".
		if protocolBucket == "port":
			docValue3 = "netflow.l4_dst_port"
		elif protocolBucket == "protocol":
			docValue3 = "protocol"
		
		#aggregate ipv4 traffic
		if ipVersion.lower() in ["ipv4","all"]:
			bucketList = [(bucket1, docValue1_Ipv4), (bucket2, docValue2_Ipv4), (bucket3, docValue3), (bucket4, docValue4)]
			qDict = self._queryBuilder.BuildDeepAggsQuery(bucketList, size=0)
			jsonBucket = self._esClient.aggregate(index, qDict)
			aggDict_Ipv4 = jsonBucket["aggregations"]

		#aggregate ipv6 traffic
		if ipVersion.lower() in ["ipv6","all"]:
			bucketList = [(bucket1, docValue1_Ipv6), (bucket2, docValue2_Ipv6), (bucket3, docValue3), (bucket4, docValue4)]
			qDict = self._queryBuilder.BuildDeepAggsQuery(bucketList, size=0)
			jsonBucket = self._esClient.aggregate(index, qDict)
			aggDict_Ipv6 = jsonBucket["aggregations"]

		#combine the two traffic aggregations: ipv4 and ipv6
		if ipVersion.lower() == "all":
			aggDict = aggDict_Ipv4
			aggDict[bucket1]["buckets"] += aggDict_Ipv6[bucket1]["buckets"]
		elif ipVersion.lower() == "ipv4":
			aggDict = aggDict_Ipv4
		elif ipVersion.lower() == "ipv6":
			aggDict = aggDict_Ipv6
			
		return aggDict

	def BuildNetFlowModel(self):
		"""
		Builds a very specific kind of flow model, represented as a graph with edges and
		vertices containing further information.
		"""
		
		#query the netflow indices for all traffic between hosts
		ipModel = self.BuildIpTrafficModel(ipVersion="all")
		g = self.BuildIpTrafficGraphicalModel(ipModel)
		flowModel = NetFlowModel(g)
		#self.PlotIpTrafficModel(g)
		
		
		#aggregate host-to-host traffic by ip protocol (icmp traffic, though infrequent, is not always safe: ping+traceroute are used for recon, and other methods use icmp for key transmission
		protocolModel = self.BuildProtocolModel(ipVersion="all", protocolBucket="protocol")
		print(str(protocolModel))
		if not flowModel.MergeEdgeModel(protocolModel, "protocol"):
			print("ERROR could not merge protocol model into flow model")
			print(str(protocolModel))
		"""
		#aggregate host-to-host traffic by layer-4 dest port. Some, but not all, dest-port usage is indicative of the application layer protocol (ftp, http, etc).
		portModel = self.BuildProtocolModel(ipVersion="all", protocolBucket="port")
		if not flowModel.MergeEdgeModel(portModel, "port"):
			print("ERROR could not merge port model into flow model")
		
		#aggregate host-to-host port traffic by packet size
		pktSizeModel = self.BuildFlowSizeModel(ipVersion="all", protocolBucket="port", sizeAttrib="in_bytes")
		if not flowModel.MergeEdgeModel(pktSizeModel, "pkt_size"):
			print("ERROR could not merge port model into flow model")
		
		#FUTURE
		#aggregate host-to-host port traffic by time-stamp
		#pktSizeModel = self.BuildFlowTimestampModel()
		"""
		print("Num ip addrs: {}".format(len(g.vs)))
		print("Target in addrs: {}".format("207.241.22" in str(protocolModel)))
		addrs = set()
		for src in protocolModel.keys():
			addrs.add(src)
			for dst in protocolModel.keys():
				addrs.add(src)
				
		with open("addrs.txt","w+") as ofile:
			for addr in addrs:
				ofile.write(addr+"\n")
				
		for addr in addrs:
			if "31.13." in addr:
				print("Hit: {}".format(addr))
		
		print("Target in addrs: {}".format("31.13.76" in str(protocolModel)))
		
		
		return 1
		
def main():
	servAddr = "http://192.168.0.91:80/elasticsearch"
	client = ElasticClient(servAddr)
	builder = NetflowModelBuilder(client)
	model = builder.BuildNetFlowModel()
		
if __name__ == "__main__":
	main()
		