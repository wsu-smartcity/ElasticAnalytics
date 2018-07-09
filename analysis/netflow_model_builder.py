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

import json
import igraph

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
				print("No vertex labels found, skipping")
		if labelEdges:
			try:
				visual_style["edge_label"] = g.es["label"]
			except:
				print("No edge labels found, skipping")
		visual_style["vertex_label_size"] = 12
		visual_style["layout"] = g.layout("kk")
		visual_style["bbox"] = (800, 800)
		visual_style["margin"] = 50
		graphPlot = igraph.plot(g, **visual_style)

		return graphPlot

	def BuildIpTrafficModel(self):
		"""
		Using only netflow volume data, analyze the traffic patterns of the network, as a directed graph.
		
		Returns: An igraph Graph object with vertices representing hosts by ipv4/ipv6 address, and edges
		representing the existence of traffic between them. The edges are decorated with @weight, representing
		the number of netflows recorded between the hosts.
		"""
		index = "netflow*"
		bucket1 = "src_addr"
		bucket2 = "dst_addr"
		
		#aggregate ipv4 flows
		bucket1DocValue = "netflow.ipv4_src_addr"
		bucket2DocValue = "netflow.ipv4_dst_addr"
		qDict = self._queryBuilder.BuildDoubleAggregateQuery(bucket1, bucket2, bucket1DocValue, bucket2DocValue, level1BucketType="terms", level2BucketType="terms", level1DocValueType="field", level2DocValueType="field",  size=0)
		jsonBucket = self._esClient.aggregate(index, qDict)
		aggDict_Ipv4 = jsonBucket["aggregations"]
		#aggregate ipv6 flows
		bucket1DocValue = "netflow.ipv6_src_addr"
		bucket2DocValue = "netflow.ipv6_dst_addr"
		qDict = self._queryBuilder.BuildDoubleAggregateQuery(bucket1, bucket2, bucket1DocValue, bucket2DocValue, level1BucketType="terms", level2BucketType="terms", level1DocValueType="field", level2DocValueType="field",  size=0)
		jsonBucket = self._esClient.aggregate(index, qDict)
		aggDict_Ipv6 = jsonBucket["aggregations"]
		#aggregate the ipv4/6 dictionaries together
		aggDict = aggDict_Ipv4
		aggDict[bucket1]["buckets"] += aggDict_Ipv6[bucket1]["buckets"]
		
		labelVertices=True
		labelEdges=False
		#aggDict = {u'src_addr': {u'buckets': [{u'dst_addr': {u'buckets': [{u'key': u'192.168.1.160', u'doc_count': 1061347}, {u'key': u'192.168.1.11', u'doc_count': 14857}, {u'key': u'192.168.0.12', u'doc_count': 14852}, {u'key': u'192.168.1.102', u'doc_count': 13044}, {u'key': u'239.255.255.250', u'doc_count': 7607}, {u'key': u'192.168.0.11', u'doc_count': 7382}, {u'key': u'192.168.0.91', u'doc_count': 5283}, {u'key': u'192.168.3.216', u'doc_count': 1730}, {u'key': u'192.168.0.1', u'doc_count': 625}, {u'key': u'192.168.1.118', u'doc_count': 257}], u'sum_other_doc_count': 544, u'doc_count_error_upper_bound': 1}, u'key': u'192.168.2.10', u'doc_count': 1127528}, {u'dst_addr': {u'buckets': [{u'key': u'192.168.2.10', u'doc_count': 1061347}, {u'key': u'239.255.255.250', u'doc_count': 14710}, {u'key': u'192.168.0.14', u'doc_count': 605}, {u'key': u'255.255.255.255', u'doc_count': 315}, {u'key': u'224.0.0.1', u'doc_count': 312}, {u'key': u'224.0.0.252', u'doc_count': 264}, {u'key': u'224.0.0.251', u'doc_count': 9}, {u'key': u'224.0.1.129', u'doc_count': 2}, {u'key': u'239.192.152.143', u'doc_count': 2}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.1.160', u'doc_count': 1077566}, {u'dst_addr': {u'buckets': [{u'key': u'192.168.0.1', u'doc_count': 104641}, {u'key': u'239.255.255.250', u'doc_count': 81122}, {u'key': u'224.0.0.252', u'doc_count': 24754}, {u'key': u'172.217.3.163', u'doc_count': 20530}, {u'key': u'172.217.3.174', u'doc_count': 19105}, {u'key': u'134.121.120.167', u'doc_count': 16311}, {u'key': u'192.168.3.255', u'doc_count': 8152}, {u'key': u'64.4.54.254', u'doc_count': 7700}, {u'key': u'64.71.168.217', u'doc_count': 7127}, {u'key': u'192.168.1.114', u'doc_count': 6920}], u'sum_other_doc_count': 187585, u'doc_count_error_upper_bound': 1754}, u'key': u'192.168.0.14', u'doc_count': 483947}, {u'dst_addr': {u'buckets': [{u'key': u'192.168.0.14', u'doc_count': 120591}, {u'key': u'255.255.255.255', u'doc_count': 2397}, {u'key': u'239.255.255.250', u'doc_count': 508}, {u'key': u'192.168.2.10', u'doc_count': 247}, {u'key': u'192.168.3.224', u'doc_count': 79}, {u'key': u'224.0.0.1', u'doc_count': 63}, {u'key': u'224.0.0.252', u'doc_count': 14}, {u'key': u'192.168.0.109', u'doc_count': 10}, {u'key': u'192.168.0.111', u'doc_count': 4}, {u'key': u'192.168.0.16', u'doc_count': 4}], u'sum_other_doc_count': 7, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.0.1', u'doc_count': 123924}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 87186}, {u'key': u'192.168.2.10', u'doc_count': 21272}, {u'key': u'192.168.3.255', u'doc_count': 8093}, {u'key': u'255.255.255.255', u'doc_count': 2206}, {u'key': u'192.168.0.14', u'doc_count': 78}, {u'key': u'224.0.0.252', u'doc_count': 2}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.0.12', u'doc_count': 118837}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 69383}, {u'key': u'192.168.3.255', u'doc_count': 11231}, {u'key': u'192.168.0.14', u'doc_count': 200}, {u'key': u'192.168.2.10', u'doc_count': 64}, {u'key': u'224.0.0.252', u'doc_count': 35}, {u'key': u'255.255.255.255', u'doc_count': 4}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.0.13', u'doc_count': 80917}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 37482}, {u'key': u'192.168.2.10', u'doc_count': 18645}, {u'key': u'192.168.15.255', u'doc_count': 7153}, {u'key': u'192.168.3.255', u'doc_count': 6852}, {u'key': u'255.255.255.255', u'doc_count': 3385}, {u'key': u'192.168.0.14', u'doc_count': 107}, {u'key': u'224.0.0.251', u'doc_count': 28}, {u'key': u'224.0.0.252', u'doc_count': 10}, {u'key': u'192.168.1.111', u'doc_count': 5}, {u'key': u'224.0.1.129', u'doc_count': 1}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.1.102', u'doc_count': 73668}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 32847}, {u'key': u'192.168.2.10', u'doc_count': 21241}, {u'key': u'192.168.3.255', u'doc_count': 12561}, {u'key': u'255.255.255.255', u'doc_count': 3511}, {u'key': u'192.168.0.14', u'doc_count': 355}, {u'key': u'192.168.2.101', u'doc_count': 9}, {u'key': u'192.168.2.102', u'doc_count': 9}, {u'key': u'192.168.2.103', u'doc_count': 9}, {u'key': u'192.168.2.107', u'doc_count': 8}, {u'key': u'192.168.2.108', u'doc_count': 8}], u'sum_other_doc_count': 35, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.1.11', u'doc_count': 70593}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 48167}, {u'key': u'192.168.1.255', u'doc_count': 7814}, {u'key': u'255.255.255.255', u'doc_count': 2350}, {u'key': u'224.0.0.252', u'doc_count': 80}, {u'key': u'192.168.3.255', u'doc_count': 3}, {u'key': u'224.0.0.251', u'doc_count': 3}, {u'key': u'192.168.0.14', u'doc_count': 1}, {u'key': u'192.168.1.101', u'doc_count': 1}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.1.14', u'doc_count': 58419}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 31456}, {u'key': u'255.255.255.255', u'doc_count': 8959}, {u'key': u'192.168.3.255', u'doc_count': 7454}, {u'key': u'192.168.2.10', u'doc_count': 7387}, {u'key': u'192.168.0.14', u'doc_count': 187}, {u'key': u'224.0.0.252', u'doc_count': 4}, {u'key': u'192.168.0.16', u'doc_count': 3}, {u'key': u'192.168.2.101', u'doc_count': 1}, {u'key': u'192.168.2.102', u'doc_count': 1}, {u'key': u'192.168.2.103', u'doc_count': 1}], u'sum_other_doc_count': 6, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.0.11', u'doc_count': 55459}], u'sum_other_doc_count': 410259, u'doc_count_error_upper_bound': 4257}}
		g = self._ipAggregateToNetworkGraph(aggDict, bucket1, bucket2, labelVertices, labelEdges)
		g.write_graphml("./ip_traffic.graphml")
		graphPlot = PlotIpTrafficModel(g, labelVertices, labelEdges)
		graphPlot.save("ipTraffic.png")
		adjacencyMatrix = g.get_adjacency(attribute="weight", default=0)
		print(str(type(adjacencyMatrix))+"\n"+str(adjacencyMatrix))
		
		PlotDirectedEdgeHistogram(g, "weight")

		return g

	def BuildProtocolModel(self, bucket="port", ipVersion="all"):
		"""
		Builds a triply-nested model of traffic via the following: src_ip -> dst_ip -> port/protocol.
		Or rather simply, gets the distribution of traffic per each src-dst ip edge in the network per
		either the port number of the netflow of the protocol number. Port number is indicative of 
		transport layer activity/protocol (http, ftp, etc), whereas the protocol number is at the ip/network
		layer and usually only represents ip, icmp, or similar network-layer protocols.
		
		Returns: The representation is returned as a nested dict: d[src_ip][dst_ip] -> {histogram of "port"/"protocol" : volume pairs}
		
		@bucket: A str which must be either "port" or "protocol", designating the grouping parameter of this method: by port or by network-layer protocol.
		@ipVersion: Indicates which layer-3 traffic to include: ipv4, ipv6, or both. Valid values are "ipv4", "ipv6", or "all"; "all" is preferred, I just
					wanted to make sure the code was factored to support this selector.
		"""
		index = "netflow*"
		bucket1 = "src_addr"
		bucket2 = "dst_addr"
		bucket3 = "protocol"

		#see header. @port must be "port" or "protocol".
		if bucket == "port":
			bucket3Key = "netflow.l4_dst_port"	# "protocol" or "port"
		else:
			bucket3Key = "protocol"				# "protocol" or "port"

		#aggregate host-host ipv4 traffic by port/protocol
		if ipVersion.lower() in ["ipv4","all"]:
			qDict = QueryBuilder().BuildTripleAggregateQuery(bucket1, bucket2, bucket3, "netflow.ipv4_src_addr", "netflow.ipv4_dst_addr", "netflow.l4_dst_port", level1BucketType="terms", level2BucketType="terms", level3BucketType="terms", level1DocValueType="field", level2DocValueType="field", level3DocValueType="field", size=0)
			jsonBucket = client.aggregate(index, qDict)
			aggDict_Ipv4 = jsonBucket["aggregations"]
			print(str(aggDict))

		#aggregate host-host ipv6 traffic by port/protocol
		if ipVersion.lower() in ["ipv6", "all"]:
			qDict = QueryBuilder().BuildTripleAggregateQuery(bucket1, bucket2, bucket3, "netflow.ipv6_src_addr", "netflow.ipv6_dst_addr", "netflow.l4_dst_port", level1BucketType="terms", level2BucketType="terms", level3BucketType="terms", level1DocValueType="field", level2DocValueType="field", level3DocValueType="field", size=0)
			jsonBucket = client.aggregate(index, qDict)
			aggDict_Ipv6 = jsonBucket["aggregations"]

		#combine the two traffic aggregations: ipv4 and ipv6
		if ipVersion.lower() == "all":
			aggDict = aggDict_Ipv4
			aggDict[bucket1]["buckets"] += aggDict_Ipv6[bucket1]["buckets"]

		return aggDict
	
	def BuildFlowModel(self):
		"""
		Builds a very specific kind of flow model, represented as a graph with edges and
		vertices containing further information.
		"""
		
		#query the netflow indices for all traffic between hosts
		ipModel = self.BuildIpTrafficModel()
		
		#aggregate host-to-host traffic by ip protocol (icmp traffic, though infrequent, is not always safe: ping+traceroute are used for recon, and other methods use icmp for key transmission
		protocolModel = self.BuildProtocolModel(bucket="protocol", ipVersion="all")
		
		#aggregate host-to-host traffic by layer-4 dest port. Some, but not all, dest-port usage is indicative of the application layer protocol (ftp, http, etc).
		portModel = self.BuildProtocolModel(bucket="protocol", ipVersion="all")
		
		#aggregate host-to-host port traffic by packet size
		pktSizeModel = self.BuildPacketSizeModel()
		
		#FUTURE
		#aggregate host-to-host protocol traffic by packet size
		
		#aggregate host-to-host traffic by timestamp (any comrades running on the julian calendar?)
		
		#aggregate host-to-host port traffic by timestamp
		
		
		return model
		