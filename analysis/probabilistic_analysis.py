from __future__ import print_function

import sys

from random_walk import *
from model_builder import ModelBuilder
from elastic_client import ElasticClient
from attack_features import *

class ModelAnalyzer(object):
	def __init__(self, netflowModel, winlogModel):
		self._netflowModel = netflowModel
		self._winlogModel = winlogModel
		#self._attackFeatureModel = attack_features.AttackFeaturemodel()
		self._hasMitreTacticModel = False
		
	def _lateralMovementAnalysis_Old(self):
		"""
		Sandbox code for modeling and exploring the detection of lateral movement instances.
		Lateral movement is a class of MITRE ATT&CK, where each instance has a specific set of attributes.
		For example, a specific instance is PassTheHash, whose attributes include use of ports 445 or 139, 
		AND a Bro SMB-MONITOR event AND winlog events id's 528,552, OR 4648. Note the query-like nature
		of the attack's attributes. It is in no way clear how to combine netflow, winlog, and bro data as
		described, its just an abstract example.
		"""
		
		#Implements DistributedComponentObjectModel
		portEvents = [80,443,8443,8082]
		#broEvents = ["SMB_MONITOR"]
		winlogEventIds = [528,552,4648]
		#Query the netflow model for netflow events
		portModel = self._netflowModel.GetNetworkPortModel(portEvents)
		z = float(sum(portModel.values()))
		portProbs = []
		for port in portEvents:
			if port in portModel:
				pPort = portModel[port] / z
			else:
				pPort = 0.0
			portProbs.append(pPort)
		
		print("Port probabilities: {}".format(portProbs))
		
		pEvents = self._getEventUnionProbability(winlogEventIds)
		print("Unconditional probability of event ids: {}".format(pEvents))
		print("Event probabilities: {}".format(self._getEventProbabilities(winlogEventIds).items()))
		
	def _getEventProbabilities(self, eventIds):
		return dict([(eventId, self._getEventProbability(eventId)) for eventId in eventIds])
		
	def _getEventProbability(self, eventId, host="any"):
		"""
		@host: Either "any" or pass the specific hostname of interest
		"""
		pEvent = 0.0
		if host == "any":
			for host in self._winlogModel:
				hist = self._winlogModel[host]["event_id"]
				z = float(sum(hist.values()))
				if eventId in hist:
					pEvent += (float(hist[eventId]) / z)
		else:
			hist = self._winlogModel[host]["event_id"]
			z = float(sum(hist.values()))
			if eventId in hist:
				pEvent += (float(hist[eventId]) / z)
		
		return pEvent

	def _getEventUnionProbability(self, eventIds):
		"""
		The winlog event-id model is a set of per-host multinomial distributions over event-ids:
			host -> event-id -> frequency
			
		Given a list of event ids, this aggregate the probability of any of those events in the model.
		"""
		return float(sum(self._getEventProbabilities(eventIds).values()))
		
	def Analyze(self):
		"""
		Driver for sandbox code for analyzing the graphical model in whatever
		ways end up being useful or apparently successful.
		"""
		
		self._lateralMovementAnalysis_Old()
		
	def AssignMitreTacticProbabilities(self):
		"""
		For each node/host in the network, assign a model of the combined probability of
		each ATT&CK tactic given our dataset, but only including execution, privilege escalation, lateral movement,
		and discovery. Host level events (winlog ids) are not relational an thus stored under a single
		table, whereas inter-host events (port flows) are relational and are broken out by dest host.
		
		But each host can just have a simple table that incorporates all of this information into a single metric.
		
			Host ATT&CK tactic table:
				lateral_movement		--> sum probability over all l.m. techniques
				execution 				--> sum probability over all exe techniques
				discovery				--> sum probability over all discovery techniques
				privilege_escalation	--> sum probability over all p.e. techniques
		"""
		
		featureModel = AttackFeatureModel()
		self._netflowModel.InitializeMitreHostTacticModel(featureModel)
		self._hasMitreTacticModel = True #This flag is just so I don't screw up the order of model construciton and analyses
		
	def _errorCheckKeys(self, hostMap, attackHostIndex, whitelist):
		success = True
		#Single purpose error check, placed here to de-clutter error checking in AnalyzeStationaryAttackDistribution.
		#This verifies that all whitelisted hostMap keys are in attackHostIndex, and vice versa.
		missingKeys = set(hostMap).intersection(set(whitelist)).difference( set(attackHostIndex.keys()))
		if any(missingKeys): #check for keys in hostMap missing from attackHostIndex
			print("ERROR keys in hostMap missing from attackHostIndex: {}".format(missingKeys))
			print("hostMap: {}".format(hostMap))
			print("Whitelist: {}".format(whitelist))
			print("attackHostIndex: {}".format(attackHostIndex))
			success = False
		#the opposite case: check for keys in attackHostIndex missing from hostMap
		missingKeys = set(attackHostIndex.keys()).difference( set(hostMap.keys()))
		if any(missingKeys):
			print("ERROR keys in attackHostIndex missing from hostMap: {}".format(missingKeys))
			print("hostMap: {}".format(hostMap))
			print("Whitelist: {}".format(whitelist))
			print("attackHostIndex: {}".format(attackHostIndex))
			success = False
		return success
			
	def AnalyzeStationaryAttackDistribution(self):
		"""
		Implements the algorithm for estimating the steady state distribution of attacks per hosts on the network.
		"""
		if not self._hasMitreTacticModel:
			print("ERROR mitre tactic models not yet initialized, stationary analysis aborted")
			return
		
		np.set_printoptions(precision=4, suppress=True)
		
		#The random walk script manually defines hosts by name; to relate these with the network model we need a map.
		#The nulls are in progress and will just be omitted from out mathematical models; we just need to formalize the who's-who in our data.
		hostMap = {
				"scada"  : "192.168.0.11",
				"hmi"    : "NULL",
				"sw1"    : "NULL",
				"fw1"    : "NULL",
				"fw2"    : "NULL",
				"sw2"    : "NULL",
				"gw"     : "192.168.2.10",
				"eng"    : "NULL",
				"relay1" : "192.168.2.101",
				"relay2" : "192.168.2.102",
				"relay3" : "192.168.2.103",
				"relay4" : "192.168.2.104",
				"relay5" : "192.168.2.105",
				"relay6" : "192.168.2.106",
				"relay7" : "192.168.2.107",
				"relay8" : "192.168.2.108"
			}
		
		"""
		First, generate a ton of walks on the host graph, under the distribution dictated in random_walk.py.
		These can be used to construct a frequency matrix of transitions between tactics; the rows/cols of this 
		matrix are the hosts on the network. The diagonal elements represent host-level events, whereas the off-diagonal
		are tactics representing a transition from one host to another. Here, the matrix is simply built
		and returned from some previously stored walks; this separates the walk process and the matrix-construction.
		"""
		generator = RandomWalkGenerator(show=False)
		#Get a whitelist of systems of interest to include in walk matrix
		whitelist = [key for key in hostMap.keys() if hostMap[key] != "NULL"] #only analyze hosts we can bind to an address in the data
		print("Whitelist: "+str(whitelist))
		#remember @D_attack is an (n x n x #tactics) matrix, so a stack of n x n matrices, each of which is for some tactic
		D_attack, attackHostIndex, tacticIndex = generator.BuildRandomWalkMatrix(whitelist)
		self.PrintHostTacticMatrix(D_attack, attackHostIndex)
		
		#Error check the @hostMap host keys and those stored in @attackHostIndex, the host-index returned by BuildRandomWalkMatrix().
		#This is a critical check to alert, since the walk matrix is built from previously-generated walks/hosts; if those become out of date, we want to know about it.
		print("Error checking matrix keys...",end="")
		check = "PASS" if self._errorCheckKeys(hostMap, attackHostIndex, whitelist) else "FAIL"
		print(check)

		#The next few steps are all matrix alignment, since their row/cols are index by different hostnames, and may differ in size
		D_system, systemHostIndex, systemTacticIndex = self._netflowModel.GetSystemMitreAttackDistribution(tacticIndex)
		print("System attack matrix: ")
		self.PrintHostTacticMatrix(D_system, systemHostIndex)
		print("System tactic index: "+str(sorted(systemTacticIndex.items(), key= lambda t:t[1])))
		#filter the system model to only include the systems listed above in @hostMap; this must be done to 'align' the two models
		systemWhitelist = [hostMap[host] for host in whitelist]
		D_system, systemHostIndex = self._filterMatrix(D_system, systemHostIndex, systemWhitelist)

		#Alias the walk-based host keys by their physical addresses in @hostMap, to begin aligning the two matrices.
		attackHostIndex = self._aliasMatrixIndex(attackHostIndex, hostMap) #As a result of this, both matrix indices have the same keys, but different value mappings.
		
		#Re-order the attack matrix, which is organized by hostnames ("gw", "scada", etc), to be the same as D_system,
		#which is organized by the vertex names (ip addresses) in the netflow model.
		D_attack, attackHostIndex = self._reorderMatrix(D_attack, attackHostIndex, systemHostIndex)
		#From here, the two matrices @D_attack and @D_system are aligned, s.t. their rowIndices are equal.
		
		print("System attack matrix: ")
		self.PrintHostTacticMatrix(D_system, systemHostIndex)
		print("Re-ordered tactic walk matrix: ")
		self.PrintHostTacticMatrix(D_attack, attackHostIndex)
		
		#element-wise multiply the two matrices, aka hadamard product. Be careful with numpy: np.matrix '*' operator is inner-product; ndarray '*' operator means hadamard/elementwise
		D_transition = D_attack * D_system
		print("Stochasticize: "+str(D_transition))
		D_transition = self._stochasticizeTacticMatrix(D_transition, aggregateThirdAxis=True)
		
		print("TODO: fill hostMap, and also makes sure the graph topology in random_walk matches the netflow model (can these manual connections be factored out?)")
		
		for i in range(20):
			print("Model power {}: {}".format(i,str(D_transition)))
			D_transition = np.dot(D_transition, D_transition)
		
	def PrintHostTacticMatrix(self, matrix, hostIndex):
		print("MATRIX {} x {} x {}".format(matrix.shape[0], matrix.shape[1], matrix.shape[2]))
		print("HOSTS: {}".format(sorted(hostIndex.items(), key = lambda t: t[1])))
		
		for i in range(4):
			print("TACTIC {}:\n{}".format(i, str(matrix[:,:,i])))
		
	def _aliasMatrixIndex(self, originalIndex, keyAliasMap):
		"""
		Given a matrix row/col index mapping names to corresponding integer row/col values,
		and a map converting its keys to alias strings, just replaces those keys with the
		alias strings.
		
		@originalIndex: A map of string keys to matrix row/col integers
		@keyAliasMap: A map from key strings to alias strings. Every key in @originalIndex
		will be replaced by the values in this map.
		"""
		newIndex = dict()
		for key, val in originalIndex.items():
			newIndex[ keyAliasMap[key] ] = val
		return newIndex
		
	def _filterMatrix(self, M, hostIndex, hostWhitelist):	
		"""
		NOTE: This is a duplicate of random_walk.py's _filterWalkMatrix.
		
		From @M, return a matrix consisting only of the subset of rows/cols included in @hostWhitelist.
		
		@M: An n x n x k matrix, where k > 1.
		@hostIndex: A map of host names to their corresponding row/col indices in @MITRE
		@hostWhitelist: A list of hosts; only these will be included in the returned items

		Returns: @M_filtered, a matrix consisting only of the host rows/cols included in hostWhitelist,
				@hostIndex_filtered: The same as @hostIndex, but with only the hosts in @hostWhitelist
		"""
		
		if len(M.shape) < 3:
			print("ERROR _filterMatrix called for matrix with fewer than three axes")
			return M, hostIndex
		
		n = len(hostWhitelist)
		numTactics = M.shape[2]
		M_filtered = np.zeros(shape=(n,n,numTactics))
		#build the filtered hostIndex
		filteredIndex = dict((host, i) for i, host in enumerate(hostWhitelist))
		
		for host in hostWhitelist:
			h_i = hostIndex[host]
			h_f_i = filteredIndex[host]
			for neighbor in hostWhitelist:
				n_i = hostIndex[neighbor]
				n_f_i = filteredIndex[neighbor]
				M_filtered[h_f_i, n_f_i, :] = M[h_i, n_i, :]
		
		return M_filtered, filteredIndex

	def _reorderMatrix(self, M, currentIndex, targetIndex):
		"""
		Frequently we are building matrices whose rows/cols represent certain hosts,
		but the mapping from host-names to row/col indices in any given matrix is artbirary
		depending on the information available. The lack of order makes matrix operations meaningless
		due to lack of alignment. This function take a matrix @M and its current mapping @currentIndex from
		strings to row/col indices and re-orders it to the same order as @targetIndex. Only rows/cols
		are re-ordered; any third axis info order is preserved.
		
		@M: Some n x n x k matrix; could also be n x n. Two or three axes matrices are supported. @M must be square
			in the sense that it is a symmetric matrix along any slice of its third axis.
		@currentIndex: Current mapping from string values to row/col integer indices of @MITRE
		@targetIndex: The target mapping. Note that @currentIndex and @targetIndex must have all the same
			keys, and the same values, but a different mapping from keys to values.
		"""
		M_new = np.zeros(shape=M.shape)
		isThreeAxis = len(M.shape) == 3
		
		for name, index in currentIndex.items():
			newIndex = targetIndex[name]
			if isThreeAxis:
				for peer, peerIndex in currentIndex.items():
					newPeerIndex = targetIndex[peer]
					M_new[newIndex, newPeerIndex, :] = M[index, peerIndex, :]
			else:
				M_new[newIndex, newIndex] = M[index,index]
				
		return M_new, targetIndex

	"""
	def _getSystemMitreAttackDistribution(self):
		
		Given that we have constructed the MITRE-based attack feature distributions within the netflow-model,
		we have a complete description of the probability of different ATT&CK tactic features at each host.
		This method compiles and returns these distributions in a single matrix. The matrix is square n x n, but
		has an additional axis for four different tactics: {privilege escalation, execution, lateral movement,
		and discovery}. Thus the matrix is n x n x #tactics = n x n x 4, where n = #hosts. Of course by summing
		along the tactic axis, one gets a simplified n x n matrix describing the distribution over the union of
		all/any tactics.
		
		Also recall that the empirical cyber distribution describes the probability of tactic features, and is thus
		limited in scope to what features are defined in attack_features.py.
		
		pass
	"""
				
	def _stochasticizeTacticMatrix(self, matrix, aggregateThirdAxis=True):
		"""
		*This is only for 3-axis matrices currently: axes 1/2 are hosts, 3rd axis are tactics.
		@matrix: An n x n x #tactics matrix
		
		Utility for converting any real-valued, positive, square matrix to a stochastic matrix suitable as a transition model,
		which permits it to be analyzed using markovian approaches and other good stuff.
		
		A positive matrix can be converted into a stochastic matrix by simply dividing each row by its sum; in graphical
		terms, this is equivalent to converting outgoing flow at each node (a row in a matrix) to a probability distribution
		by just dividing the outgoing rates by the sum over all outgoing edges.
		
		Returns: A copy of @matrix stochasticized
		"""
		
		if matrix.shape[0] != matrix.shape[1]:
			print("ERROR matrix not square in _stochasticizeTacticMatrix")
			raise Exception("Non-square matrix passed to _stochasticizeTacticMatrix")

		hasNegativeEntries = len(matrix[matrix < 0]) > 0
		if hasNegativeEntries:
			print("ERROR matrix not positive in _stochasticizeTacticMatrix")
			raise Exception("Non-positive matrix passed to _stochasticizeTacticMatrix")
		
		if aggregateThirdAxis and len(matrix.shape) < 3:
			print("ERROR passed aggregateThirdAxis=True to _stochasticizeTacticMatrix, but matrix of shape "+str(matrix.shape))
			raise Exception("Passed aggregateThirdAxis=True to _stochasticizeTacticMatrix, but matrix of shape "+str(matrix.shape))
		
		if not aggregateThirdAxis:
			print("ERROR aggregateThirdAxis=False, but not implemented yet")
			raise Exception("aggregateThirdAxis=False not implemented")
		else:
			#just sum the matrix over its third axis, and then pass to the 2d stochasticize function
			#model = np.sum(matrix, axis=2)
			model = matrix[:,:,1]
			model = self._stochasticizeTwoDimMatrix(model)
			"""
			model = np.zeros(shape=(matrix.shape[0],matrix.shape[1]), dtype=np.float)
			for row in range(matrix.shape[0]):
				#aggregate the row along the third/tactic axis
				aggRow = np.sum(matrix[row,:,:], axis=1) #gets the 2d row of 3d data, aggregated over all tactics (the third axis)
				rowSum = np.sum(aggRow)
				if rowSum <= 0:
					print("WARNING rowSum="+str(rowSum))
					model[row,:] = 0.0
				else:
					model[row,:] = aggRow / rowSum
			"""

		return model
		
	def _stochasticizeTwoDimMatrix(self, matrix, uniformizeZeroRows=True, allowAbsorption=False):
		"""
		Given any n x n positive matrix, stochasticizes the entries by normalizing each row by its sum.
		
		@uniformizeZeroRows: If true, then rows of all zeroes will be set to uniform probabilities: row = 1 / len(row), where row is a vector
		@allowAbsorption: An absorbing state transitions to itself with probability 1.0, hence its diagonal value will be 1.0.
						This is problematic when calculating the stationary distribution, because the probability of such states tends to 1.0,
						since all paths leading to it end there. If @allowAbsorption is false, then the row is set to the uniform probability
						of transitioning to all other states, basically restarting the stochastic process from a random state.
		"""
		if matrix.shape[0] != matrix.shape[1]:
			print("ERROR matrix not square in _stochasticizeTacticMatrix")
			raise Exception("Non-square matrix passed to _stochasticizeTacticMatrix")

		hasNegativeEntries = len(matrix[matrix < 0]) > 0
		if hasNegativeEntries:
			print("ERROR matrix not positive in _stochasticizeTwoDimMatrix")
			raise Exception("Non-positive matrix passed to _stochasticizeTwoDimMatrix")
			
		model = np.zeros(shape=matrix.shape, dtype=np.float)
		for i in range(matrix.shape[0]):
			row = matrix[i,:]
			rowSum = np.sum(row)
			if rowSum <= 0:
				print("WARNING rowSum="+str(rowSum))
				if uniformizeZeroRows:
					model[i,:] = 1.0 / float(matrix.shape[1])
				else:
					model[i,:] = 0.0
			else:
				model[i,:] = row / rowSum
				
			if not allowAbsorption and model[i,i] == 1.0:
				model[i,:] = 1.0 / float(matrix.shape[1])
		
		return model
		
def main():
	#Build the client
	servAddr = "http://192.168.0.91:80/elasticsearch"
	client = ElasticClient(servAddr)
	#Build the netflow model
	builder	= ModelBuilder(client)
	ipVersion = "ipv4"
	blacklist = None
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
	
	hostnameConversionTable = {
								"HP-B53-01": "192.168.0.11",	#scada 
								"COM600-PC": "192.168.2.10"		#abb substation mgt unit; aka 'rtu'
							}
	
	indexPattern = "netflow*"
	indexPattern = "netflow-v9-2017*"
	#uses '-' to exclude specific indices or index-patterns
	indexPattern = "netflow-v9-2017*,-netflow-v9-2017.04*" #april indices have failed repeatedly, due to what appears to be differently-index data; may require re-indexing
	netflowModel = builder.BuildNetFlowModel(indexPattern, ipVersion=ipVersion, ipBlacklist=blacklist, ipWhitelist=whitelist)
	winlogModel = builder.BuildWinlogEventIdModel("winlogbeat*")
	#just resolves the keys of the winlogmodel (hostnames) to their ip addresses
	convertedModel = dict([(hostnameConversionTable[host], model) for host, model in winlogModel.items()])
	netflowModel.MergeVertexModel(convertedModel, "event_id") #store the event model in the nodes; this is redundant, but fine for now
	#Build the analyzer
	analyzer = ModelAnalyzer(netflowModel, winlogModel)
	#analyzer.Analyze()
	analyzer.AssignMitreTacticProbabilities()
	netflowModel.Save("netflowModel.pickle")
	netflowModel.PrintAttackModels()
	analyzer.AnalyzeStationaryAttackDistribution()
	
	
		
if __name__ == "__main__":
	main()