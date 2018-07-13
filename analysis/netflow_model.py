"""
A concrete representation of a network based on netflow data.
This could bea hierarchy of different views of netflow data
suitable for different analyses, but keeping it concrete and simple
for now, as a static graph with edges decorated with frequency data.

This class is a little overboard until statistical analysis shows what kinds of views/queries
on network data are most effective. But it would be good practice for such a class to exist,
one self-describing such network models and encapsulating complex queries.

NOTES: For validity/verfication purposes this class would require stringent error checking. The reason is that merging in multiple
dataviews into a single graph is highly error prone for a bunch of reasons. Say that using an aggs query to some netflow elastic
indices you bucket the number of documents 'k' (flows) between each pair of hosts based on ip address. Then you later
drill deeper into the distribution of port/protocols for each of these edges, deriving a histogram over port/protocols
for each edges, using another aggs query. I've observed that these histograms have exhibited the following problems:
	1) The sum of a histogram's values should equal the 'k' mentioned previously, but don'tad
	2) The edge-histogram based aggs query returns histograms over edges that were not in the original
	query by which the host-graph was constructed! In detail, say you use a double-aggs query to build a weighted
	network graph, where edge weights are the number of flows 'k' between hosts. Then you use a triple-aggs query to 
	derive histograms of the traffic type (or other attributes) of the 'k' flows between hosts. The triple-aggs query
	may return histograms for edges that were not included 
	
The sources of these data integrity errors are elastic, query design, and code errors. But they need to be mitigated
by performing numerical checks and structural checks. For instance, by at least verifying that for edge-based histograms,
that the sum of the histogram's values is equal to 'k' from another query. Graphs and graph data always gets nasty in this way,
and the numerical mistakes can completely upset proper probability distributions.


"""

import igraph

class NetFlowModel(object):
	def __init__(self, ipTrafficModel):
		"""
		Initializes the NetworkModel with a fully populated igraph.Graph object @ipTrafficModel.
		Its a tad ugly to pass in the model to this object instead of implementing self-initialization
		in some form, but its nice to delegate to the NetflowModelBuilder class, simply because it exists
		and it encapsulates construction logic for these data representations.
		"""
		self._graph = ipTrafficModel
		self._edgeModels = [] # a list of the edge-based models (hisograms, weights, etc) added to the model
		
	def _getGraphVertexNames(self):
		return [v["name"] for v in self._graph.vs]
	
	def Print(self):
		print("Vertices:")
		for v in self._graph.vs:
			print("  "+v["name"])
		
		print("\nEdges: ")
		for edge in self._graph.es:
			src  = self._graph.vs[edge.source]["name"]
			dest = self._graph.vs[edge.target]["name"]
			print("  ({}->{})".format(src,dst))
			
		print("Edge models: {}".format(self._edgeModels))
	
	def _isValidEdgeModel(self, edgeModel, modelName):
		"""
		Given an edgeModel we want to merge into the graph, we need to verify that:
			1) every key in edgeModels inner/outer dict keys is in the network graph
			2) every pair of (outer,inner) keys in @edgeModel has a corresponding edge in the graph
			3) the edge model name doesn't already exist in the edges
		"""
		isValid = True
		modelKeys = set(src for src in edgeModel.keys())
		modelKeys = modelKeys.union(set(dst for src in edgeModel.keys() for dst in edgeModel[src].keys()))
		vertexNames = self._getGraphVertexNames()
		
		missingNames = [name for name in modelKeys if name not in vertexNames]
		if any(missingNames):
			print("ERROR edgeModel key {} not in network graph vertices: {}".format(missingNames, vertexNames))
			isValid = False
				
		for src in edgeModel.keys():
			for dst in edgeModel[src].keys():
				try: 
					edge = self._getEdge(src, dst)
				except:
					print("ERROR no edge ({},{}) in graph".format(src,dst))
					isValid = False
					
		if any(modelName in edge.attribute_names() for edge in self._graph.es):
			print("ERROR edge model name {} already exists".format(modelName))
			isValid = False

		return isValid

	def MergeEdgeModel(self, edgeModel, modelName):
		"""
		Stores models on the edges of the current network graph, using igraph's ability
		to store attributes in edges, vertices, and the graph itself. This exemplifies
		using the igraph Graph object as a complex data structure. Note that this function
		potentially operates on the entire graph.
		
		Given a doubly-nested dict @edgeModel with keys [src_ip][dest_ip] and some values,
		stores each value in the associated ip-based graph edges using @modelName as a key.
		For instance, @edgeModel could contain histograms of port activity between hosts;
		then for each ip-src/ip-dst pair in @edgeModel there would be some histogram of port
		traffic (port#,frequency) which would be stored on the edge between these hosts under
		the name @modelName. The stored values can be arbitrary data structures known to the
		user: integers, floats, or complex objects like lists, histograms, etc.
		
		@edgeModel: A nested dict of dicts, whose outer keys are src-ip's and inner keys are
					dst-ip's, like: [src-ip][dst-ip] -> value.
		@modelName: The name under which to store the model(s) as an edge attribute of each
		igraph edge.
		"""
		succeeded = True
		
		#verify every outer/inner key in @edgeModel matches a vertex in the traffic graph, and has an edge
		if not self._isValidEdgeModel(edgeModel, modelName):
			print("WARNING attempting to add invalid edge model {}, safety not guaranteed...".format(modelName))
		
		for src in edgeModel.keys():
			for dst in edgeModel[src].keys():
				model = edgeModel[src][dst]
				if not self._addEdgeAttribute(src, dst, modelName, model):
					print("Adding edge attribute {} failed in MergeEdgeModel() for ({},{})".format(modelName, src, dst))
					succeeded = False
					self._edgeModels.append(modelName)
					
		return succeeded
		
	def _getEdge(self, src, dst):
		"""
		This function will throw if either or src/dst are not in graph vertices, or likewise no edge between them.
		Caller should catch any exceptions.
		
		@src: Name of source vertex
		@dst: Name of dest vertex
		"""
		src = self._graph.vs.find(name=srcIp)
		dst = self._graph.vs.find(name=dstIp)
		edge = self._graph.es.find(_source=src.index, _target=dst.index)
		
		return edge
		
	def _addEdgeAttribute(self, srcIp, dstIp, key, value):
		succeeded = False
		try:
			edge = self._getEdge()
			if key not in edge.attribute_names():
				edge[key] = model
				succeeded = True
			else:
				print("ERROR attempted to add key >{}< to edge ({}, {}), but already exists in edge attributes: {}".format(key, src["name"], dst["name"], edge.attribute_names()))
		except:
			print("ERROR srcIp or dstIp vertices or edge not found")
		return succeeded
		
	def GetConditionalDistribution(self):
		#under construction
		pass
	
	def Save(self, fpath):
		self._graph.write_pickle(fpath)

	def Read(self, fpath):
		self._graph = igraph.Graph.Read_Pickle(fpath)
		
		
		