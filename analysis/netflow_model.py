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
import traceback
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
		return sorted([v["name"] for v in self._graph.vs])
	
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
		#build the set of keys in @edgeModel
		modelKeys = set()
		for src in edgeModel.keys():
			modelKeys.add(src)
			for dst in edgeModel.keys():
				modelKeys.add(dst)
		#get the keys of the current graph
		vertexNames = self._getGraphVertexNames()
		
		missingNames = sorted([name for name in modelKeys if name not in vertexNames])
		if any(missingNames):
			print("ERROR edgeModel keys {}\n ...not in network graph vertices: {}".format(missingNames, vertexNames))
			isValid = False

		for src in edgeModel.keys():
			for dst in edgeModel[src].keys():
				try:
					edge = self._getEdge(src, dst)
				except:
					print("ERROR no edge ({},{}) in graph".format(src,dst))
					traceback.print_exc()
					isValid = False

		if modelName in self._graph.es.attribute_names():
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
				else:
					self._edgeModels.append(modelName)
					
		return succeeded

	def _getHostVertexIndex(self, vname):
		#Given a hostname (vertex name) return its vertex index in the igraph object, or throw if not found.
		vId = -1
		vIds = [v for v in self._graph.vs if v["name"] == vname]
		if len(vIds) == 0:
			#vertex not found, so raise exception
			raise Exception('ERROR vertex {} not found'.format(vname))
		elif len(vIds) > 1:
			#more than one vertex found under @vname, which violates our model since vertices should be unique
			raise Exception('ERROR multiple ({}) vertices like {} found'.format(len(vIds), vname))
		else:
			#normal path, exactly one vertex found
			vId = vIds[0]
			
		return vId
		
	def _getVertex(self, vId):
		return self._graph.vs[vId]
		
	def _getVertexByName(self, fname):
		return self._getVertex(self._getHostVertexIndex(vname))

	def _isValidProbabilityQuery(self, query):
		vnames = [v["name"] for v in self._graph.vs]
		isValid = True
		
		#verify src is in model, if passed
		if "src" in query.keys() and query["src"] not in vnames:
			print("ERROR @src passed in query, but name not in model: {}".format(query["src"]))
			isValid = False
		#verify dst is in model, if passed
		if "dst" in query.keys() and query["dst"] not in vnames:
			print("ERROR @dst passed in query, but name not in model: {}".format(query["dst"]))
			isValid = False
		#verify an edge exists between src and dst if both passed
		if "dst" in query.keys() and "src" in query.keys():
			srcId = self._getHostVertexIndex(query["src"])
			dstId = self._getHostVertexIndex(query["dst"])
			edges = self._graph.es.select(_source=srcId, _target=dstId)
			if len(edges) == 0:
				print("ERROR no edge found between hosts {} and {}".format(query["src"], query["dst"]))
				isValid = False
		
		if "protocol" in query.keys() and "protocol" not in self._edgeModels:
			print("ERROR @protocol not in stored edge models of netflow model")
			isValid = False
		if "port" in query.keys() and "port" not in self._edgeModels:
			print("ERROR @port not in stored edge models of netflow model")
			isValid = False

		return isValid
		
	def ProbabilisticQuery(self, query):
		"""
		qString cases:
			1) All fixed variables:
				(src : 192.168.0.3) (dst : 192.168.0.4) (protocol : 6) (port: 22)
				In english: 'Get conditional probability of tcp flow over port 22 between 192.168.0.3 and 192.168.0.4'
			
			2) One host:
			
				a. Conditional distribution for outbound flows from host 192.168.0.3:
				(src : 192.168.0.3) (protocol : 6) (port: 22)
				
				b. Conditional distribution for inbound flow to host 192.168.0.4:
				(dst : 192.168.0.4) (protocol : 6) (port: 22)
				
			3)	All hosts:
				a. Evaluate probability of tcp-ssh traffic summed over all hosts
				(protocol : 6) (port: 22)
	
			(src : 192.168.0.3) (dst : 192.168.0.4) (protocol : 6) (port: 22) (in_bytes : 350)
	
	
		The query occurs in steps:
			1) Get edges for passed hosts, if any, and aggregate these edges together
			2) Conditon on passed variables: protocol, then port, then minute characteristics (flow count/bytes, duration, etc)
		"""
		prob = 0.0
		
		#basic query validation
		if not self._isValidquery(query):
			raise Exception("Invalid query; see previous output")
		
		if "src" in query.keys():
			srcIndex = self._getHostVertexIndex(query["src"])
		if "dst" in query.keys():
			dstIndex = self._getHostVertexIndex(query["dst"])
		
		if "src" in query.keys() and "dst" in query.keys():
			edges = self._graph.es.select(_source=srcIndex, _target=dstIndex)
		elif "src" in query.keys():
			edges = self._graph.es.select(_source=srcIndex)
		elif "dst" in query.keys():
			edges = self._graph.es.select(_target=dstIndex)
		else:
			#get all edges, entire network
			edges = self._graph.es
			
		#Drill into the histograms on all selected edges...
		#for now, treat @protocol and @port as separate variables, though port has a logical dependence on network layer protocol (tcp, udp, etc)
		if "protocol" in query.keys():
			hists = [edge["protocol"] for edge in edges]
			hist = self._mergeHistograms(hists)
		elif "port" in query.keys():
			hists = [edge["port"] for edge in edges]
			hist = self._mergeHistograms(hists)
		 
		 
		 
		 
	def _aggregateHistograms(self, hists):
		"""
		A common taks for statistical analyses will be merging multiple histograms together,
		where each histogram is a dictionary of type @key->scalar-frequency. Overlapping
		keys thus have their frequencies added together.
		"""
		keys = [key for hist in hists for key in hist.keys()]
		mergedHist = dict([(key:0) for key in keys])

		for hist in hists:
			for key, value in hist.items():
				mergedHist[key] += value

		return mergedHist
			
	def QueryInterhostPortProbability(self, ports):
		if "port" not in self._edgeModels:
			print("ERROR 'port' not in edgeModels, cannot query port distributions")
			return -1.0

		pPorts = 0.0
		minProb = 1000
		maxProb = -1.0
		for h1 in self._graph.vs:
			for edge in self._graph.es.select(_source=h1.index):
				#aggregate the ports for this edge
				edgeModel = edge["port"]
				z = sum([portModel.values()])
				portFlows = sum([edgeModel["port"] for port in ports if port in edgeModel])
				pPorts = portFlows / z
				#update min and max
				minProb = min(pPorts, minProb)
				maxProb = max(pPorts, maxProb)
					
		return pPorts, minProb, maxProb

	def PlotIpTrafficModel(self, labelVertices=True, labelEdges=True, nightScheme=True):
		"""
		Plots and shows the ip-graph of hosts in @g. The graph is only plotted if it has less than some modest
		and plottable number of vertices, as many graphs are too huge to fit in memory. If needed, a solution
		is to generate a view of the graph, such as only plotting vertices under some criterion, then plotting
		this view of the graph.
		
		Returns: The plot, or None if a failure occurred.
		"""
		graphPlot = None
		visual_style = {}
		if nightScheme:
			#see igraph.drawing.colors.known_colors list for all color options
			visual_style["background"] = "grey8"
			visual_style["vertex_label_color"] = "grey90"
			visual_style["edge_label_color"] = "grey90"
			visual_style["edge_color"] = "grey60"
			visual_style["vertex_color"] = "green3"
		else:
			visual_style["vertex_color"] = "green"
		
		if len(self._graph.vs) < 200:
			try:
				if labelVertices:
					try:
						visual_style["vertex_label"] = self._graph.vs["name"]
					except:
						pass
				if labelEdges:
					try:
						visual_style["edge_label"] = self._graph.es["label"]
					except:
						pass
				visual_style["vertex_label_size"] = 12
				visual_style["layout"] = self._graph.layout("kk")
				visual_style["bbox"] = (1100, 1100)
				visual_style["margin"] = 50
				graphPlot = igraph.plot(self._graph, **visual_style)
			except:
				traceback.print_exc()
		else:
			print("Graph too large to plot ({} > 200 vertices), skipping plotting...".format(len(self._graph.vs)))
				
		return graphPlot
		
	def _getEdge(self, srcIp, dstIp):
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
		
	def _addEdgeAttribute(self, srcIp, dstIp, attrib, value):
		"""
		 Three cases are handled below:
			1) @attrib not in edge.attribute_names(), so just add it: 'edge[attrib] = value'
			2) @attrib is in edge.attribute_names() and edge[attrib] is None, so handle just like in (1): 'edge[attrib] = value'
				This case occurs because in igraph adding an attribute to one edge broadcasts that name
				to all edges and initializes their value to None.
			3) @attrib is in edge.attribute_names() and is not None. This is the only error case, meaning the
				attribute was already set, and we are attempting to overwrite it.
		"""
		succeeded = False
		
		try:
			edge = self._getEdge(srcIp, dstIp)
			if attrib not in edge.attribute_names() or edge[attrib] is None:
				edge[attrib] = value
				succeeded = True
			else:
				#@attrib is in edge attributes, and is not None
				print("ERROR attempted to add attrib >{}< to edge ({}, {}), but attribute already initialized: {}".format(attrib, srcIp, dstIp, edge[attrib]))
		except:
			print("ERROR srcIp or dstIp vertices or edge not found")
			traceback.print_exc()
		
		return succeeded
		
	def GetConditionalDistribution(self):
		#under construction
		pass
	
	def Save(self, fpath):
		if ".pickle" not in fpath:
			savePath = fpath+".pickle"
		else:
			savePath = fpath
		self._graph.write_pickle(savePath)

	def Read(self, fpath):
		self._graph = igraph.Graph.Read_Pickle(fpath)
		
		
		