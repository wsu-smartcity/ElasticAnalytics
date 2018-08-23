import sys

from model_builder import ModelBuilder
from elastic_client import ElasticClient
from attack_features import *

class ModelAnalyzer(object):
	def __init__(self, netflowModel, winlogModel):
		self._netflowModel = netflowModel
		self._winlogModel = winlogModel
		#self._attackFeatureModel = attack_features.AttackFeaturemodel()
		
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
		
		
	def AnalyzeStationaryAttackDistribution(self):
		
		
		
		
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
		
if __name__ == "__main__":
	main()