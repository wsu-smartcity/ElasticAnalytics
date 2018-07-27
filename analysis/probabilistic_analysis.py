import sys
from netflow_model_builder import NetflowModelBuilder


class ModelAnalyzer(object):
	def __init__(self, netflowModel):
		self._netflowModel = netflowModel
		self._winlogmodel = winlogModel
		
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
	

		
if __name__ == "__main__":
	main()