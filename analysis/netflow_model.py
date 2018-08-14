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
import numpy as np

class NetFlowModel(object):
	def __init__(self, ipTrafficModel=None):
		"""
		Initializes the NetworkModel with a fully populated igraph.Graph object @ipTrafficModel.
		Its a tad ugly to pass in the model to this object instead of implementing self-initialization
		in some form, but its nice to delegate to the NetflowModelBuilder class, simply because it exists
		and it encapsulates construction logic for these data representations.
		"""
		if ipTrafficModel is not None:
			self._graph = ipTrafficModel
			self._graph["edgeModels"] = [] # a list of the edge-based model names (histograms, weights, etc) added to the model
		else:
			pass
		
	def _getGraphVertexNames(self):
		return sorted([v["name"] for v in self._graph.vs])

	def GetEdgeDistributionMatrix(self, distName):
		"""
		This is not for edge-distributions per se, but rather for the distributions stored in the edges, such 
		as the port-number distribution storing a map of port number keys to frequency values (number of netflows for that port#).
		This is a high level wrapper for converting such a categorical edge distribution to a matrix; this matrix is
		defined in the header for GetCategoricalDistributionsAsNumpyMatrix(), but consists of all the distributions
		stacked on top one another. So each row in the matrix is one distribution, and thus the matrix has a number 
		of rows equal to the number of distributions. The columns reflect the number of categories over all distributions.
		"""
		if distName not in self._graph["edgeModels"]:
			print("ERROR, {} not in edge models".format(distName))
			return None, None

		dists = self.GetEdgeDistributions(distName).values()
		matrix, colIndex = self.GetCategoricalDistributionsAsNumpyMatrix(dists)
		
		return matrix, colIndex
			
	def InitializeMitreTacticModel(self, featureModel):
		"""
		Given an @featureModel, an AttackFeatureModel object storing MITRE ATT&CK features, this
		assigns a tactic probability to every node (host) in the network. The only tactics covered so
		far are execution, privilege escalation, lateral movement, and discovery. Each tactic is assigned
		a probability based on the conditional probability of observing any of that tactic's features at
		that particular host. "Any of" implies the probability of each feature (which are independent) can
		be just added together, hence the probability of a tactic is just the sum of individual techniques.
		We could come up with more advanced definitions, but this is sufficient for descriptive stats for now,
		in terms of rudimentary queries, "given this tactic, what is its probability in the network?"
		
		TODO: This is an area with a lot of code smell; not sure which objects should run probability calculation
		logic and so forth, especially if techniques are ever analyzed on the basis of custom elastic queries. An 
		example would be the nmap techniques or os-fingerprinting within the discovery tactic; detecting these
		techniques might involve implementing custom elastic queries to detect port activity characteristic of
		mapping. But querying elastic means the netflow model now requires knowledge of the elastic instance... which
		breaks a lot of encapsulation.
		"""
		
		modelName = "ATT&CK_Model"
		#Initialize a model at each vertex; each host/vertex stores an 'ATT&CK_Model' table, which in turn
		#maps each tactic name (e.g. 'lateral_movement') to its probability.
		for v in self._graph.vs:
			v[modelName] = dict()
		
		lm = "lateral_movement"
		exe = "execution"
		disc = "discovery"
		pe = "privilege_escalation"
		
		#assign lateral movement tactic probability to all nodes
		for v in self._graph.vs:
			attackTable = v[modelName]
			attackTable["lateral_movement"] = self._simpleTacticProb(v, featureModel, "lateral_movement")
			attackTable["execution"] = self._simpleTacticProb(v, featureModel, "execution")
			attackTable["discovery"] = self._simpleTacticProb(v, featureModel, "discovery")
			attackTable["privilege_escalation"] = self._simpleTacticProb(v, featureModel, "privilege_escalation")


	def _simpleTacticProb(self, featureModel, tactic):
		#@tactic: One of "lateral_movement", "discovery", "execution", or "privilege_escalation".
		prob = 0.0
		for technique in featureModel.AttackTable[tactic]:
			#get the technique probability by summing over all its recognized ports
			portProb = sum([ port  for port in technique.Ports ])
			#get the technique probability summed over event-ids
			eventProb = sum([eventId for eventId in technique.WinlogEvents])
			#bro-events, not implemented
			#broProb = sum([eventId for eventId in technique.broEvents])
			#es-query; not yet implemented
			#esProb = sum([eventId for eventId in technique.])

	def GetCategoricalDistributionsAsNumpyMatrix(self, dists, dtype=np.float32):
		"""
		Accepts @dists, a set of n k-dimensional categorical distributions, and converts each distribution to a numpy 
		vector. Thus the returned matrix is size n x k, where 'n' is the number of distributions, and k is the
		number of categories over all distributions.
		
		@dists: An iterable of dictionaries describing categorical data, as key=category -> val=frequency.
		
		Returns: An (n x k) matrix as described, along with @columnIndex, a dict mapping indices distribution keys
		(class names) to their columnar indices in the matric.
		"""
		colIndex = dict()
		keyCt = 0
		
		#build the columnIndex
		for dist in dists:
			for key in dist.keys():
				#builds the mapping from distribution keys to column indices in the output matrix
				if key not in colIndex.keys():
					colIndex[key] = keyCt
					keyCt += 1

		#build the actual matrix
		matrix = np.zeros(shape=(len(dists),keyCt), dtype=dtype)
		for row, dist in enumerate(dists):
			for key, val in dist.items():
				col = colIndex[key]
				#print("{}".format(val))
				matrix[row,col] = val

		return matrix, colIndex
	
	def GetEdgeDistributions(self, distName):
		"""
		Returns all of the port# distributions for each direct edge (host1 -> host2),
		provided they have been built and stored in the model. To retain host-host information,
		the histograms are returned as a dict (host1,host2) -> port histogram. Returns None
		if no port models stored under @distName.
		
		@distName: The name of the distribution to fetch, e.g. "port"
		"""
		if distName in self._graph.es.attribute_names():
			hists = {}
			for edge in self._graph.es:
				src  = self._graph.vs[edge.source]["name"]
				dest = self._graph.vs[edge.target]["name"]
				key = (src,dest)
				value = edge[distName][distName] #these models necessarily exist, since every netflow has a port number, and every edge indicates at least one flow
				hists[key] = value
		else:
			hists = None

		return hists
	
	def Print(self):
		print("Vertices:")
		for v in self._graph.vs:
			print("  "+v["name"])
		
		print("\nEdges: ")
		for edge in self._graph.es:
			src  = self._graph.vs[edge.source]["name"]
			dest = self._graph.vs[edge.target]["name"]
			print("  ({}->{})".format(src,dst))
			
		print("Edge models: {}".format(self._graph["edgeModels"]))
	
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

	def _isValidVertexModel(self, vertexModel, modelName):
		"""
		Verifies:
			1) all vertex-name keys in @vertexModel are vertices in the graph
			2) @modelName is not already in the self._graph.vs vertex models
		"""
		isValid = True
		
		#get the keys of the current graph
		vertexNames = self._getGraphVertexNames()
		
		missingNames = sorted([name for name in vertexModel.keys() if name not in vertexNames])
		if any(missingNames):
			print("ERROR edgeModel keys {}\n ...not in network graph vertices: {}".format(missingNames, vertexNames))
			isValid = False
		
		if modelName in self._graph.vs.attribute_names():
			print("ERROR vertex model name {} already exists".format(modelName))
			isValid = False
	
		return isValid
			
	def MergeVertexModel(self, vertexModel, modelName):
		"""
		Method for storing vertex distributions/models on each vertex under @modelName.
		Here @vertexModel is a dictionary of form: vertexName -> model. So it is a dictionary of
		vertex name keys, each of which contains a single model of some arbitrary form.
		For each vertex in @vertexModel.keys(), the model is stored under @modelName.
		
		@vertexModel: A dictionary mapping vertex names to models, e.g., vertex names to event-id
					  histograms from winlog data.
		@modelName: The name under which to store the models for all vertices.
		"""
		succeeded = False

		if not self._isValidVertexModel(vertexModel, modelName):
			print("ERROR attempted to add invalid vertex model")
		else:
			#add model to each individual vertex in @vertexModel
			for vname in vertexModel.keys():
				vertex = self._getVertexByName(vname)
				vertex[modelName] = vertexModel
			succeeded = True
			
		return succeeded
		
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
					self._graph["edgeModels"].append(modelName)
					
		return succeeded

	def _getHostVertexIndex(self, vname):
		#Given a hostname (vertex name) return its vertex index in the igraph object, or throw if not found.
		vId = -1
		vIds = [v.index for v in self._graph.vs if v["name"] == vname]
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
		#Gets a vertex by id @vId, assuming its id is known
		return self._graph.vs[vId]
		
	def _getVertexByName(self, vname):
		#Returns igraph Vertex object corresponding to @vname
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
		
		#make sure selected models are actually in the edge models
		if "protocol" in query.keys() and "protocol" not in self._graph["edgeModels"]:
			print("ERROR @protocol not in stored edge models of netflow model")
			isValid = False
		if "port" in query.keys() and "port" not in self._graph["edgeModels"]:
			print("ERROR @port not in stored edge models of netflow model")
			isValid = False
		if "in_bytes" in query.keys() and "in_bytes" not in self._graph["edgeModels"]:
			print("ERROR @in_bytes not in stored edge models of netflow model")
			isValid = False
			
		return isValid
		
	def GetVertexFlowProbability(self, vertexName, mode="IN"):
		"""
		Simple to expose, since this info was stored during model construction. Returns the
		overall unconditional probability of a vertex in the graph, defined as #(v,n) / sum(g,v,n),
		where #(v,n) represents the number of flows corresponding to @mode.
		@mode: One of "IN" "OUT" or "ALL", determining whether vertex' probability is determined by incoming,
				outgoing, or all flows in an out.
				
		NOTE: WHEN USING THIS FUNCTION, THINK ABOUT AND ACCOUNT FOR REFLEXIVE EDGES. Not sure how many
		hosts might have them, but they are an easily overlooked problem case, since a relfexive edge
		is both incident and outgoing, and could screw up probability calculations, for instance.
		"""
		
		if mode not in {"IN","OUT","ALL"}:
			raise Exception("ERROR incorrect mode passed to GetVertexFlowProbability(). Must be one of 'IN', 'OUT', or 'ALL'.")
		if vertexName not in [v["name"] for v in self._graph.vs]:
			raise Exception("ERROR no such node found in graph: {}".format(vertexName))
			
		#get the selected vertex and its id
		vertex = self._getVertexByName(vertexName)
		vId = vertex.index
			
		#get the flows for the selected node, and the normalization constant for the entire graph under @mode
		if mode == "IN":
			#get only the incident flow counts
			vFlows = [e["weight"] for e in self._graph.es.select(_target=vId)]
			z = [e["weight"] for v in self._graph.vs for e in self._graph.es.select(_target=v.index)]
		elif mode == "OUT":
			#get only the outgoing flow counts
			vFlows = [e["weight"] for e in self._graph.es.select(_source=vId)]
			z = [e["weight"] for v in self._graph.vs for e in self._graph.es.select(_source=v.index)]
		elif mode == "ALL":
			#get all flows for which the vertex is target or source
			vFlows = [e["weight"] for e in self._graph.es.select(_source=vId)]
			vFlows = [e["weight"] for e in self._graph.es.select(_target=vId)]
			z = [e["weight"] for v in self._graph.vs for e in self._graph.es.select(_source=v.index)]
			z += [e["weight"] for v in self._graph.vs for e in self._graph.es.select(_target=v.index)]
	
		return float(sum(vflows)) / float(sum(z))
		
	def ProbabilisticQuery(self, query):
		"""
		NOTE: This currently only supports queries to src/dst and only one of port or protocol. The
		latter must be included.
		
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
			(src : 192.168.0.3) (dst : 192.168.0.4) (protocol : 6) (port: 22) (in_bytes : 350)
	
		The query occurs in steps:
			1) Get edges for passed hosts, if any, and aggregate these edges together
			2) Conditon on passed variables: protocol, then port, then minute characteristics (flow count/bytes, duration, etc)
			
		Note that this query currently only covers a very, very small subset of variables in the/a full Bayesian
		conditional probability distribution over the random events (src,dst,protocol,port,flow_characteristics),
		if any of these variables are allowed to be omitted or "port:*". But the use-case of only allowing
		src/dest to be unbound should be sufficient for our probability models; otherwise full
		queries over the random variables would require a big bayesian query pipeline to be written.
		
		Precondition: A query is valid iff its src/dst hosts are in the model, and likewise any models like "port" "protocol" or "in_bytes".
		the query may specify only one or neither of src/dst, but must specify port, protocol, or in_bytes if they are passed. This is 
		so only straightforward queries can be calculated, which is all we really need, except maybe allowing src/dst to be aggregated.
		"""
		prob = 0.0
		
		#basic query validation
		if not self._isValidProbabilityQuery(query):
			raise Exception("Invalid query; see previous output")
		
		#get the src/dst host vertices before querying them
		if "src" in query.keys():
			srcIndex = self._getHostVertexIndex(query["src"])
		if "dst" in query.keys():
			dstIndex = self._getHostVertexIndex(query["dst"])
		
		#get the edges selected based on src and dst host
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
		#if "in_bytes" in query.keys():  #IGNORE FLOW CHARACTERISTIC MODELS, THEY ARE NOT SUPPORTED YET
		if "protocol" in query.keys():
			hists = [edge["protocol"] for edge in edges]
			hist = self._aggregateHistograms(hists)
			count = hist.get( default=0.0)
			z = float(sum(hist.values()))
		elif "port" in query.keys():
			hists = [edge["port"] for edge in edges]
			hist = self._aggregateHistograms(hists)
			count = hist.get( default=0.0)
			z = float(sum(hist.values()))
		
		return count / z

	def _aggregateHistograms(self, hists):
		"""
		A common taks for statistical analyses will be merging multiple histograms together,
		where each histogram is a dictionary of type @key->scalar-frequency. Overlapping
		keys thus have their frequencies added together.
		"""
		keys = [key for hist in hists for key in hist.keys()]
		mergedHist = dict([(key,0) for key in keys])

		for hist in hists:
			for key, value in hist.items():
				mergedHist[key] += value

		return mergedHist
			
	def GetNetworkPortModel(self, ports):
		"""
		Returns a port histogram across the entire network, of type port# -> frequency.
		One can then easily query 
		"""
		if "port" not in self._graph["edgeModels"]:
			print("ERROR 'port' not in edgeModels, cannot query port distributions")
			return -1.0
			
		print("REMINDER: port model returned by GetNetworkPortModel() not yet conditioned on network layer protocol (udp, tcp, etc)")

		portModel = dict()
		for edge in self._graph.es:
			#aggregate the ports for this edge
			edgeModel = edge["port"]
			#print("PORT MODEL: {}".format(edgeModel))
			#print("PROTOCOL MODEL: {}".format(edge["protocol"]))
			for port, frequency in edgeModel["port"].items():
				if port in portModel:
					portModel[port] += frequency
				else:
					portModel[port] = frequency

		return portModel

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
		self._graph.write_pickle(fpath)

	
	def Read(self, fpath):
		self._graph = igraph.Graph.Read_Pickle(fpath)
