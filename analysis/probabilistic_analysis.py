import sys
from netflow_model_builder import NetflowModelBuilder


class ModelAnalyzer(object):
	def __init__(self, netflowModel):
		self._netflowModel = netflowModel
		self._winlogModel = winlogModel
		
	def _lateralMovementAnalysis(self):
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
		#winlogEventIds = [528,552,4648]
		#Query the netflow model for netflow events
		self._netflowModel.GetConditionalInterhostPortModel(portEvents)
		
		
	def Analyze(self):
		"""
		Driver for sandbox code for analyzing the graphical model in whatever
		ways end up being useful or apparently successful.
		"""
		
		self._lateralMovementAnalysis()
		
		
		
		
def main():
	#Build the client
	servAddr = "http://192.168.0.91:80/elasticsearch"
	client = ElasticClient(servAddr)
	#Build the netflow model
	builder	= NetflowModelBuilder(client)
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
	
	indexPattern = "netflow*"
	indexPattern = "netflow-v9-2017*"
	#uses '-' to exclude specific indices or index-patterns
	indexPattern = "netflow-v9-2017*,-netflow-v9-2017.04*" #april indices have failed repeatedly, due to what appears to be differently-index data; may require re-indexing
	model = builder.BuildNetFlowModel(indexPattern, ipVersion=ipVersion, ipBlacklist=blacklist, ipWhitelist=whitelist)
	#Build the analyzer
	analyzer = ModelAnalyzer(model)
	analyzer.Analyze()
		
		
if __name__ == "__main__":
	main()