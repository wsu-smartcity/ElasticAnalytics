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
		
		self._mitreModelName = "ATT&CK_Model"
		
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
			
	def HasEventModel(self):
		#Returns whether or not the winlog event-id distribution has been stored; good to check before
		#deriving analytics, which will be incomplete if not winlog data has been stored in the model.
		return "event_id" in self._graph.vs.attribute_names()
		
	def HasPortModel(self):
		return "port" in self._graph.es.attribute_names()
	def HasProtocolModel(self):
		return "protocol" in self._graph.es.attribute_names()
	def HasMitreAttackModel(self):
		return self._mitreModelName in self._graph.vs.attribute_names()
			
	def InitializeMitreHostTacticModel(self, featureModel):
		"""
		Given an @featureModel, an AttackFeatureModel object storing MITRE ATT&CK features, this
		assigns a tactic probability to every node (host) in the network. The only tactics covered so
		far are execution, privilege escalation, lateral movement, and discovery. Each tactic is assigned
		a probability based on the conditional probability of observing any of its techniques' features at
		that particular host. "Any of" implies the probability of each feature (which are independent) can
		be just added together, hence the probability of a tactic can be defined as the sum of individual techniques.
		We could come up with more advanced definitions, but this is sufficient for descriptive stats for now,
		in terms of rudimentary queries, like "given this tactic, what is the sum probability of all of its features in
		normal network data?"
		
		TODO: This is an area with a lot of code smell; not sure which objects should run probability calculation
		logic and so forth, especially if techniques are ever analyzed on the basis of custom elastic queries. An
		example would be the nmap techniques or os-fingerprinting within the discovery tactic; detecting these
		techniques might involve implementing custom elastic queries to detect port activity characteristic of
		mapping. But querying elastic means the netflow model now requires knowledge of the elastic instance... which
		breaks a lot of encapsulation.
		
		Notes: there are multiple parameters possible in this analysis in terms of how we view/define various
		probability distributions. For example, @edgeView defines whether or not to score relational flow-based
		distributions at each node by one of {"in","out","undirected"}, which indicates scoring incident edges, out-going edges,
		or undirected (include both in- and out-going edges). This choice is thus a 'parameter' of the analysis,
		since it determines different probability values, and also it embeds an interpretation of how to view/score
		malicious activity.
		"""
		modelName = self._mitreModelName
		#@edgeView may be one of {"in","out","undirected"}, indicating which edges to evaluate relational/edge-based probability distributions.
		edgeView = "undirected"
		#Initialize a model at each vertex; each host/vertex stores an 'ATT&CK_Model' table, which in turn
		#maps each tactic name (e.g. 'lateral_movement') to its probability.
		for v in self._graph.vs:
			v[modelName] = dict()

		lm = "lateral_movement"
		exe = "execution"
		disc = "discovery"
		pe = "privilege_escalation"

		#A few check to make sure the model has been initialized with data estimates for all of the features for attack detection (port usage, winlog event id's, etc)
		if not self.HasEventModel():
			print("WARNING initializing MITRE host tactic model without an initialized winlog host-event model; estimates of event-ids will be incomplete.")
		if not self.HasPortModel():
			print("WARNING initializing MITRE host tactic model without an initialized port edge-model; estimates of port-based events will be incomplete.")

		#assign lateral movement tactic probability to all nodes
		for v in self._graph.vs:
			attackTable = v[modelName]
			#Lateral movement can be characterized as both a host-level and relational/edge-based. The former
			#gives a single value per-host; the latter gives multiple values for a host, one for each of its peers (a transition model).
			#I build and store both, since both may be useful.
			attackTable["lateral_movement_relational"] = self._relationalTacticProb(v, featureModel, "lateral_movement")
			attackTable["lateral_movement"] = self._simpleTacticProb(v, featureModel, "lateral_movement", edgeView)
			attackTable["execution"] = self._simpleTacticProb(v, featureModel, "execution", edgeView)
			attackTable["discovery"] = self._simpleTacticProb(v, featureModel, "discovery", edgeView)
			attackTable["privilege_escalation"] = self._simpleTacticProb(v, featureModel, "privilege_escalation", edgeView)
		
	def PrintAttackModels(self):
		"""
		Print ATT&CK table data at each node, in which we stored tactic probabilities at each node.
		"""
		if not self.HasMitreAttackModel():
			print("ERROR not ATT&CK model initialized in model")
			return
			
		for v in self._graph.vs:
			model = v[self._mitreModelName]
			print("{} model: {}".format(v["name"], model))

	def _getVertexEventProb(self, vertex, eventIds):
		#@vertex: An igraph vertex object representing a host in the graph
		#@eventIds: A list or iterable of integer winlog event ids. The sum probability of all these will be returned.
		if not self.HasEventModel():
			print("ERROR called _getVertexEventProb without an initialized event-id model")
			return 0.0
		
		eventModel = vertex["event_id"]
		#print("{}".format(eventModel))
		#vertex' event_id model is None if it has no data, as for many ied's, such as the relays. Event ids typically pertain only to scada, fw, hmi, and similar devices.
		if eventModel is None:
			print("warning: {} not in eventModel".format(vertex["name"]))
			return 0.0
			
		#gotta drill in a little more to get the actual event distribution
		eventModel = eventModel[vertex["name"]]["event_id"]
		prob = 0.0
		z = float(sum([val for val in eventModel.values()]))
		for event in eventIds:
			if event in eventModel.keys():
				prob += eventModel[event]
			else:
				print("WARN no event {} for host {}".format(event, vertex["name"]))
		prob /= z
		
		return prob

	def _getVertexPortEventProb(self, vertex, ports, arcType="in", aggProbs=True):
		"""
		@vertex: An igraph vertex object from the netflow model
		@ports: A list of ports whose sum probability will be calculated; this treats port#'s in flows as independent events.
		@arcType: One of "in", "out", or "undirected". These are defined as follows:
			if "out", then only port events from this host to other hosts (including itself) will be evaluated
			if "in", then only inbound traffic to this node will be evaluated 
			if "undirected", then all in/out traffic will be evaluated.
			These options can lead to completely different estimates and views of vulnerability,
			depending on the desired view: outlinks, inlinks, or undirected models. "In" reflects
			the view of this vertex being attacked, whereas "out" views a node as being compromised
			and attempting to compromise others.
			
		@aggProb: Whether or not to aggregate the probability of each port over multiple edge-distributions.
		If true, then the edge distributions are aggregated together before calculating the probability of a port.
		If false, then a port's probability is the sum of individual probabilities from each edge.
		Example: Say you have these two edge distributions for port 80 and 22: [{80:5000, 22:1}, {80:5000, 22:5000}]
			If aggProbs=true, then p(port=22) = (5000+1) / 15001
			if aggProbs=false, then p(port=22) = 1 / 5001 + 5000 / 10000
		"""
		arcType = arcType.lower()
		if arcType not in {"in", "out", "undirected"}:
			print("ERROR arcType {} invalid in _getVertexPortEventProb()".format(arcType))
			return 0.0

		#aggregate the edges over which to evaluate port activity
		if arcType == "out":
			edges = [edge for edge in self._graph.es.select(_source=vertex.index)]
		elif arcType == "in":
			edges = [edge for edge in self._graph.es.select(_target=vertex.index)]
		elif arcType == "undirected":
			edges =  [edge for edge in self._graph.es.select(_source=vertex.index)]
			edges += [edge for edge in self._graph.es.select(_target=vertex.index)]

		pPorts = 0.0
		z = 0.0
		if aggProbs:
			for edge in edges:
				portModel = edge["port"]["port"]
				z += float(sum([val for val in portModel.values()]))
				pPorts += float(sum([portModel[port] for port in ports if port in portModel]))
			if z > 0:
				pPorts = pPorts / z
			else:
				print("prob/Z {} {}".format(pPorts, z))
		else:
			for edge in edges:
				portModel = edge["port"]["port"]
				z = float(sum([val for val in portModel.values()]))
				pPort_this_edge = float(sum([portModel[port] for port in ports if port in portModel]))
				if z > 0:
					pPorts += (pPort_this_edge / z)
				else:
					print("prob/Z {} {}".format(pPorts, z))

		return pPorts
		
	def _relationalTacticProb(self, vertex, featureModel, tactic):
		"""
		In contrast to _simpleTacticProb, this returns not a scalar value but a list of tactic probabilities
		each with an associated peer/host. Whereas _simpleTacticProb evaluates local host behavior, _relationalTacticProb
		returns probabilities that depend on each neighbor of some host, and returns the probability of the tactic for each
		such host as a list: [(hostname, tactic-prob), (hostname, tactic-prob), ...]. This is akin to a transition model
		for the current host and tactic.
		
		NOTE: This function was modeled only after lateral-movement tactics, and would need to be evaluated for others
		as to how they should be implemented. For example, should winlog event-ids for relational tactic features be
		evaluated at the source host or dest? It really depends on the tactic itself. For now, I'm only including 
		outgoing port-based features, since these are the only relational data we have.
		
		NOTE: Many hosts will have no relational tactic probs, such as if they are slave devices and only/mostly receive messages.
		Also, I omitted arcType (edge direction) from this function, since this method tends to imply a directed model. But you
		could hack undirected edge distributions simply by calling this function for some subset of neighbors in the graph and
		unioning the result.
		
		@vertex: An igraph vertex object in the graph
		@featureModel: An AttackFeatureModel object
		@tactic: One of "lateral_movement", "discovery", "execution", or "privilege_escalation".
		"""
		ports = []
		eventIds = []
		#first union all of the unique features to analyze, since there is significant overlap
		for technique in featureModel.AttackTable[tactic]:
			ports += technique.Ports
			#eventIds += technique.WinlogEvents
		#uniquify the events and ports, since there will often be repeats over all of the techniques for a given tactic
		ports = list(set(ports))
		#eventIds = list(set(eventIds))
		
		print("PORTS: "+str(ports))
		
		#calculate the probability of the given features for all neighboring hosts in the netflow model
		neighborProbs = []
		for edge in self._graph.es.select(_source=vertex.index):
			#get the probability of these port events per each destination host
			host = self._graph.vs[edge.target]["name"]
			portModel = edge["port"]["port"]
			z = float(sum([val for val in portModel.values()]))
			pPorts = float(sum([portModel[port] for port in ports if port in portModel.keys()]))
			print("P PORTS: "+str(pPorts))
			if z > 0:
				pPorts = pPorts / z
				neighborProbs.append( (host, pPorts) )
			else:
				print("WARNING z<=0 in _relationalTacticProb. prob/Z {} {}".format(pPorts, z))
		
		return neighborProbs
		
	def _simpleTacticProb(self, vertex, featureModel, tactic, arcType="undirected"):
		"""
		@vertex: An igraph vertex object in the graph
		@featureModel: An AttackFeatureModel object
		@tactic: One of "lateral_movement", "discovery", "execution", or "privilege_escalation".
		@arcType: Whether or not to evaluate flow-based (relational) probabilities on the basis of outgoing
				  host edges, incident edges, or undirected (both incident and outgoing edges).
		"""
		ports = []
		eventIds = []
		#first union all of the unique features to analyze, since there is significant overlap
		for technique in featureModel.AttackTable[tactic]:
			ports += technique.Ports
			eventIds += technique.WinlogEvents
		#uniquify the events and ports, since there will often be repeats over all of the techniques for a given tactic
		ports = list(set(ports))
		eventIds = list(set(eventIds))
		
		#with unique set of ports and event-ids, calculate the attack probability as the sum of all these events
		eventProb = self._getVertexEventProb(vertex, eventIds)
		portProb = self._getVertexPortEventProb(vertex, ports, arcType, aggProbs=True)
		totalProb = eventProb + portProb
		
		return totalProb

	def GetSystemMitreAttackDistribution(self, tacticIndex=None):
		"""
		Given that we have constructed the MITRE-based attack feature distributions within the netflow-model,
		we have a complete description of the probability of different ATT&CK tactic features at each host.
		This method compiles and returns these distributions in a single matrix. The matrix is square n x n, but
		has an additional axis for four different tactics: {privilege escalation, execution, lateral movement,
		and discovery}. Thus the matrix is n x n x #tactics = n x n x 4, where n = #hosts. Of course by summing
		along the tactic axis, one gets a simplified n x n matrix describing the distribution over the union of
		all/any tactics.
		
		Also recall that the empirical cyber distribution describes the probability of tactic features, and is thus
		limited in scope to what features are defined in attack_features.py.
		
		@tacticIndex: If passed, this preserves the mapping of tactic names to indices along the third axis of @D_system
						such as to keep it aligned with another matrix. Otherwise this matrix is just created here.
		
		Returns: @D_system, an n x n x 4 matrix, as described
				@hostIndex: Per usual, maps host names to row/col indices in @D_system
				@tacticIndex: Maps tactics to 
		"""
		
		#create a matrix of the host in the netflow model
		nHosts = len(self._graph.vs)
		#build a mapping from hostnames to matrix indices
		hostIndex = dict((v["name"],i) for i, v in enumerate(self._graph.vs))
		if tacticIndex is None:
			#the mapping from implemented tactics to matrix indices along the matrix' third axis
			tacticIndex = {"discovery" : 0, "lateral-movement" : 1 , "privilege-escalation" : 2, "execution" : 3}
		#build the system matrix
		nTactics = len(tacticIndex.keys())
		D_system = np.zeros(shape=(nHosts, nHosts, nTactics), dtype=np.float)
		#populate the matrix
		for v in self._graph.vs:
			#get the vertex' attack probability table
			attackTable = v[self._mitreModelName]
			print("ATTACK TABLE: "+str(attackTable))
			#get this host's row/col index in the matrix
			v_i = hostIndex[v["name"]]
			#fill diagonal elements with on-host attack event feature probabilities: discovery, execution, privilege escalation
			#get exe prob
			exeProb = attackTable["execution"]
			exe_k = tacticIndex["execution"]
			D_system[v_i, v_i, exe_k] = exeProb
			#get discovery prob
			discProb = attackTable["discovery"]
			disc_k = tacticIndex["discovery"]
			D_system[v_i, v_i, disc_k] = discProb
			#privilege escalation
			peProb = attackTable["privilege_escalation"]
			pe_k = tacticIndex["privilege-escalation"]
			D_system[v_i, v_i, pe_k] = peProb
			#now set the off-diagonal elements with individual lateral-movement feature probabilities
			lm_k = tacticIndex["lateral-movement"]
			for neighbor, lmProb in attackTable["lateral_movement_relational"]:
				neighbor_i = hostIndex[neighbor]
				D_system[v_i, neighbor_i, lm_k] = lmProb
				
		return D_system, hostIndex, tacticIndex
				
		
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
				graphPlot.save("network.png")
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
