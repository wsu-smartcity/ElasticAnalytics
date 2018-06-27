from elastic_client  import Client
from elastic_query_builder import QueryBuilder

import igraph
import matplotlib.pyplot as plt
import numpy as np
import re
import pandas as pd

#for protocol analysis
import socket

"""
For now, just some data exploration of the netflow* index data to check out the statistical properties and prior
distribution of the data by various aggregations (ip addresses, ports, protocols, etc).
"""

def PlotNetworkGraph(g, labelVertices=True, labelEdges=True):
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

def AggToNetworkGraph(aggDict, outerKey="src_addr", innerKey="dst_addr", labelVertices=False, labelEdges=False):
	"""
	@aggDict: The @aggregates dict of an ip-oriented aggregation query.
	"""
	g = igraph.Graph(directed=True)
	es = [] #store as: (src,dst,edge_weight) threeples
	
	for outerBucket in aggDict[outerKey]["buckets"]:
		srcKey = outerBucket["key"]
		for innerBucket in outerBucket[innerKey]["buckets"]:
			dstKey = innerBucket["key"]
			count = innerBucket["doc_count"]
			es.append((srcKey,dstKey,count))

	vs = [edge[0] for edge in es]
	vs += [edge[1] for edge in es]
	vs = list(set(vs))
	
	g.add_vertices(vs)
	if labelVertices:
		for v in g.vs:
			v["vertex_label"] = v["name"]

	for edge in es:
		g.add_edge(edge[0], edge[1], weight=edge[2])
	
	if labelEdges:
		g.es["label"] = [str(weight) for weight in g.es["weight"]]
	
	return g

def PlotDirectedEdgeHistogram(g, edgeAttribute, useLogP1Space=True):
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

def IpTrafficAnalysis(client, ipv4=True):
	"""
	Using only netflow data, analyze the traffic patterns and packet distribution of the network as a directed graph.
	"""
	index = "netflow*"
	bucket1 = "src_addr"
	bucket2 = "dst_addr"
	
	if ipv4:
		bucket1DocValue = "netflow.ipv4_src_addr"
		bucket2DocValue = "netflow.ipv4_dst_addr"
	else:
		bucket1DocValue = "netflow.ipv6_src_addr"
		bucket2DocValue = "netflow.ipv6_dst_addr"
	
	qDict = QueryBuilder().BuildDoubleAggregateQuery(bucket1, bucket2, bucket1DocValue, bucket2DocValue, level1BucketType="terms", level2BucketType="terms", level1DocValueType="field", level2DocValueType="field",  size=0)
	jsonBucket = client.aggregate(index, qDict)
	aggDict = jsonBucket["aggregations"]
	print(str(aggDict))
	
	labelVertices=True
	labelEdges=False
	#aggDict = {u'src_addr': {u'buckets': [{u'dst_addr': {u'buckets': [{u'key': u'192.168.1.160', u'doc_count': 1061347}, {u'key': u'192.168.1.11', u'doc_count': 14857}, {u'key': u'192.168.0.12', u'doc_count': 14852}, {u'key': u'192.168.1.102', u'doc_count': 13044}, {u'key': u'239.255.255.250', u'doc_count': 7607}, {u'key': u'192.168.0.11', u'doc_count': 7382}, {u'key': u'192.168.0.91', u'doc_count': 5283}, {u'key': u'192.168.3.216', u'doc_count': 1730}, {u'key': u'192.168.0.1', u'doc_count': 625}, {u'key': u'192.168.1.118', u'doc_count': 257}], u'sum_other_doc_count': 544, u'doc_count_error_upper_bound': 1}, u'key': u'192.168.2.10', u'doc_count': 1127528}, {u'dst_addr': {u'buckets': [{u'key': u'192.168.2.10', u'doc_count': 1061347}, {u'key': u'239.255.255.250', u'doc_count': 14710}, {u'key': u'192.168.0.14', u'doc_count': 605}, {u'key': u'255.255.255.255', u'doc_count': 315}, {u'key': u'224.0.0.1', u'doc_count': 312}, {u'key': u'224.0.0.252', u'doc_count': 264}, {u'key': u'224.0.0.251', u'doc_count': 9}, {u'key': u'224.0.1.129', u'doc_count': 2}, {u'key': u'239.192.152.143', u'doc_count': 2}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.1.160', u'doc_count': 1077566}, {u'dst_addr': {u'buckets': [{u'key': u'192.168.0.1', u'doc_count': 104641}, {u'key': u'239.255.255.250', u'doc_count': 81122}, {u'key': u'224.0.0.252', u'doc_count': 24754}, {u'key': u'172.217.3.163', u'doc_count': 20530}, {u'key': u'172.217.3.174', u'doc_count': 19105}, {u'key': u'134.121.120.167', u'doc_count': 16311}, {u'key': u'192.168.3.255', u'doc_count': 8152}, {u'key': u'64.4.54.254', u'doc_count': 7700}, {u'key': u'64.71.168.217', u'doc_count': 7127}, {u'key': u'192.168.1.114', u'doc_count': 6920}], u'sum_other_doc_count': 187585, u'doc_count_error_upper_bound': 1754}, u'key': u'192.168.0.14', u'doc_count': 483947}, {u'dst_addr': {u'buckets': [{u'key': u'192.168.0.14', u'doc_count': 120591}, {u'key': u'255.255.255.255', u'doc_count': 2397}, {u'key': u'239.255.255.250', u'doc_count': 508}, {u'key': u'192.168.2.10', u'doc_count': 247}, {u'key': u'192.168.3.224', u'doc_count': 79}, {u'key': u'224.0.0.1', u'doc_count': 63}, {u'key': u'224.0.0.252', u'doc_count': 14}, {u'key': u'192.168.0.109', u'doc_count': 10}, {u'key': u'192.168.0.111', u'doc_count': 4}, {u'key': u'192.168.0.16', u'doc_count': 4}], u'sum_other_doc_count': 7, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.0.1', u'doc_count': 123924}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 87186}, {u'key': u'192.168.2.10', u'doc_count': 21272}, {u'key': u'192.168.3.255', u'doc_count': 8093}, {u'key': u'255.255.255.255', u'doc_count': 2206}, {u'key': u'192.168.0.14', u'doc_count': 78}, {u'key': u'224.0.0.252', u'doc_count': 2}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.0.12', u'doc_count': 118837}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 69383}, {u'key': u'192.168.3.255', u'doc_count': 11231}, {u'key': u'192.168.0.14', u'doc_count': 200}, {u'key': u'192.168.2.10', u'doc_count': 64}, {u'key': u'224.0.0.252', u'doc_count': 35}, {u'key': u'255.255.255.255', u'doc_count': 4}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.0.13', u'doc_count': 80917}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 37482}, {u'key': u'192.168.2.10', u'doc_count': 18645}, {u'key': u'192.168.15.255', u'doc_count': 7153}, {u'key': u'192.168.3.255', u'doc_count': 6852}, {u'key': u'255.255.255.255', u'doc_count': 3385}, {u'key': u'192.168.0.14', u'doc_count': 107}, {u'key': u'224.0.0.251', u'doc_count': 28}, {u'key': u'224.0.0.252', u'doc_count': 10}, {u'key': u'192.168.1.111', u'doc_count': 5}, {u'key': u'224.0.1.129', u'doc_count': 1}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.1.102', u'doc_count': 73668}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 32847}, {u'key': u'192.168.2.10', u'doc_count': 21241}, {u'key': u'192.168.3.255', u'doc_count': 12561}, {u'key': u'255.255.255.255', u'doc_count': 3511}, {u'key': u'192.168.0.14', u'doc_count': 355}, {u'key': u'192.168.2.101', u'doc_count': 9}, {u'key': u'192.168.2.102', u'doc_count': 9}, {u'key': u'192.168.2.103', u'doc_count': 9}, {u'key': u'192.168.2.107', u'doc_count': 8}, {u'key': u'192.168.2.108', u'doc_count': 8}], u'sum_other_doc_count': 35, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.1.11', u'doc_count': 70593}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 48167}, {u'key': u'192.168.1.255', u'doc_count': 7814}, {u'key': u'255.255.255.255', u'doc_count': 2350}, {u'key': u'224.0.0.252', u'doc_count': 80}, {u'key': u'192.168.3.255', u'doc_count': 3}, {u'key': u'224.0.0.251', u'doc_count': 3}, {u'key': u'192.168.0.14', u'doc_count': 1}, {u'key': u'192.168.1.101', u'doc_count': 1}], u'sum_other_doc_count': 0, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.1.14', u'doc_count': 58419}, {u'dst_addr': {u'buckets': [{u'key': u'239.255.255.250', u'doc_count': 31456}, {u'key': u'255.255.255.255', u'doc_count': 8959}, {u'key': u'192.168.3.255', u'doc_count': 7454}, {u'key': u'192.168.2.10', u'doc_count': 7387}, {u'key': u'192.168.0.14', u'doc_count': 187}, {u'key': u'224.0.0.252', u'doc_count': 4}, {u'key': u'192.168.0.16', u'doc_count': 3}, {u'key': u'192.168.2.101', u'doc_count': 1}, {u'key': u'192.168.2.102', u'doc_count': 1}, {u'key': u'192.168.2.103', u'doc_count': 1}], u'sum_other_doc_count': 6, u'doc_count_error_upper_bound': 0}, u'key': u'192.168.0.11', u'doc_count': 55459}], u'sum_other_doc_count': 410259, u'doc_count_error_upper_bound': 4257}}
	g = AggToNetworkGraph(aggDict, bucket1, bucket2, labelVertices, labelEdges)
	g.write_graphml("./ip_traffic.graphml")
	graphPlot = PlotNetworkGraph(g, labelVertices, labelEdges)
	graphPlot.save("ipTraffic.png")
	adjacencyMatrix = g.get_adjacency(attribute="weight", default=0)
	print(str(type(adjacencyMatrix))+"\n"+str(adjacencyMatrix))
	
	PlotDirectedEdgeHistogram(g, "weight")


#utility for aggregating the result of a triple-nested aggregate query over ip/ip/protocol only protocol numbers.
#Return histogram-like dict of key-value pairs (protocol->count).
def AggregateProtocols(aggDict, srcKey="src_addr", dstKey="dst_addr", protocolKey="protocol"):
	protocolHist = dict()

	for srcBucket in aggDict[srcKey]["buckets"]:
		#src = srcBucket["key"]
		for dstBucket in srcBucket[dstKey]["buckets"]:
			#dst = dstBucket["key"]
			for protocolBucket in dstBucket[protocolKey]["buckets"]:
				protocol = protocolBucket["key"]
				count = protocolBucket["doc_count"]
				if protocol in protocolHist:
					protocolHist[protocol] += count
				else:
					protocolHist[protocol] = count
					
	return protocolHist
	
def ProtocolAnalysis(client):
	bucket1 = "src_addr"
	bucket2 = "dst_addr"
	bucket3 = "port"
	
	#you can analyze protocols by @protocol field of netflows, or by dst-port
	bucket3Key = "protocol"
	#bucket3Key = "netflow.l4_dst_port"
	
	qDict = QueryBuilder().BuildTripleAggregateQuery(bucket1, bucket2, bucket3, "netflow.ipv4_src_addr", "netflow.ipv4_dst_addr", "netflow.l4_dst_port", level1BucketType="terms", level2BucketType="terms", level3BucketType="terms", level1DocValueType="field", level2DocValueType="field", level3DocValueType="field", size=0)
	index = "netflow*"
	jsonBucket = client.aggregate(index, qDict)
	aggDict = jsonBucket["aggregations"]
	print(str(aggDict))
	
	#aggregate all buckets together per protocol only
	protocolHistogram = AggregateProtocols(aggDict, bucket1, bucket2, bucket3)
	protocolHistogram = sorted(list(protocolHistogram.items()), key= lambda t: t[1])
	labels = []
	for pair in protocolHistogram:
		label = str(pair[0])
		try:
			proto = socket.getservbyport(pair[0])
			label = proto+":"+label
		except:
			pass
		labels.append(label)
	print(protocolHistogram)
	
	#plot the histogram
	df = pd.Series([pair[1] for pair in protocolHistogram], index=labels)
	print(str(df))
	print("Plotting...")
	df.sort_values().plot(kind='bar',title="Log-Space Host-Host Flow Frequency")
	#hist.plot()
	plt.tight_layout()
	plt.show()
	
	plt.clf()
	
def main():
	servAddr = "http://192.168.0.91:80/elasticsearch"
	client = Client(servAddr)
	print(str(client.listIndices()))
	IpTrafficAnalysis(client)
	#ProtocolAnalysis(client)
	
if __name__ == "__main__":
	main()