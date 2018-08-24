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
		
	def BuildMarkovianTacticMatrix(self, transitionMatrix):
		"""
		Given @transitionMatrix, a matrix describing tactical transitions between and within hosts, as defined by random_walk.
		This matrix defines the distribution of tactical transitions, independent of the distribution of normal activity on the network.
		The network model, @self._netflowModel, contains the distribution of normal data.
		The hadamard product of these matrices gives an expectation of tactics which combines the two distributions.
		By normalizing this matrix (to a doubly-stochastic matrix), we get a markov transition model by which to calculate
		stationary distributions over tactics and hosts.
		"""
		pass
		
	def AnalyzeStationaryAttackDistribution(self):
		"""
		Implements the algorithm for estimating the steady state distribution of attacks per hosts on the network.
		"""
		if not self._hasMitreTacticModel:
			print("ERROR mitre tactic models not yet initialized, stationary analysis aborted")
			return
		
		#The random walk script manually defines hosts by name; to relate these with the network model we need a map.
		#The nulls are in progress and will just be omitted from out mathematical models; we just need to formalize the who's-who in our data.
		hostMap = {
				"scada"  : "192.168.0.11",
				"hmi"    : "NULL",
				"sw1"    : "NULL",
				"fw1"    : "NULL",
				"fw2"    : "NULL",
				"sw2"    : "NULL",
				"gw"     : "192.168.0.10",
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
		#remember @D_attack is an (n x n x #tactics) matrix, so a stack of n x n matrices, each of which is for some tactic
		D_attack, hostIndex, tacticIndex = generator.BuildRandomWalkMatrix(hostMap.keys())
		print(str(hostIndex))
		print(str(tacticIndex))
		print(str(D_attack))
		print(str(D_attack.shape))
		
		"""
		Now derive a matrix combining the attack frequency distribution @D_attack, with the empirical system data, @D_system, stored in the netflow model.
		Loosely speaking, this represents a metric of observability, although the language needs to be tightened up.
		"""
		D_system, hostIndex, tacticIndex = self._netflowModel.GetSystemMitreAttackDistribution(hostIndex, tacticIndex)
		
		matrix = self._stochasticizeMatrix(matrix)
		print("TODO: fill hostMap, and also makes sure the graph topology in random_walk matches the netflow model (can these manual connections be factored out?)")
		
	def _getSystemMitreAttackDistribution(self):
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
		"""
		
		
		
		
		
		
	def _stochasticizeMatrix(self, matrix):
		"""
		Utility for converting any real-valued, positive, square matrix to a stochastic matrix suitable as a transition model,
		which permits it to be analyzed using markovian approaches and other good stuff.
		
		A positive matrix can be converted into a stochastic matrix by simply dividing each row by its sum; in graphical
		terms, this is equivalent to converting outgoing flow at each node (a row in a matrix) to a probability distribution
		by just dividing the outgoing rates by the sum over all outgoing edges.
		
		Returns: A copy of @matrix stochasticized
		"""
		
		if matrix.shape[0] != matrix.shape[1]:
			print("ERROR matrix not square in _stochasticizeMatrix")
			raise Exception("Non-square matrix passed to _stochasticizeMatrix")
		hasNegativeEntries = len(matrix[matrix < 0])
		if not isPositiveMatrix:
			print("ERROR matrix not positive in _stochasticizeMatrix")
			raise Exception("Non-positive matrix passed to _stochasticizeMatrix")
		
		model = np.zeros(shape=(matrix.shape[0],matrix.shape[1]))
		
		for row in range(matrix.shape[0]):
			rowSum = np.sum(matrix[row,:])
			model[row,:] = matrix[row,:] / rowSum

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