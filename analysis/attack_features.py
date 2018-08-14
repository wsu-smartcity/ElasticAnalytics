"""
A single manually-defined database of technique attack features, per ATT&CK tactic.
Hence the dependence is tactic -> technique -> features.

Rather than being manually compiled and stored, the features could be shared/automated
in some way using stix-like behavioral analytics or unfetter.
"""

#TODO: Seems like an indicator of poor code factoring to bring query_builder into here to construct detection-feature queries; and only currently used for network-scan-detection query
from elastic_query_builder import QueryBuilder

class Technique(object):
	def __init__(self, portList=[], broEvents=[], winlogEvents=[], esQuery=None):
		"""
		Every Technique has an associated set of features, which can be defined probabilistically
		or in binary fashion, meaning anything detected under some criterion is malicious (e.g. signature detection).
		@esQuery: An elasticsearch query returning results only if its conditions are satisfied. One can craft
					a query to detect very specific behavior, such as network scans.
		"""

		self.Ports = portList
		self.BroEvents = broEvents
		self.WinlogEvents = winlogEvents
		self.ElasticQuery = esQuery

class AttackFeatureModel(object):

	"""
	Each technique consists of a bunch of manually defined features
	
	Many of these are still poorly defined:
		*many techniques contain null values
		*a few of the defined ones have question marks, not sure they are complete/good features to estimate
	"""
	
	#LATERAL MOVEMENT
	Apple_Script = Technique(portList=[22], broEvents=[], winlogEvents=[])
	App_Deployment_Software = Technique(portList=[80,443,8443,8082], broEvents=[], winlogEvents=[])
	Distributed_Component_Object_Model = Technique(portList=[135,138,139,445], broEvents=[], winlogEvents=[528,552,4648])
	Logon_Scripts = Technique(portList=[445,139], broEvents=[], winlogEvents=[528,552])
	Pass_The_Hash = Technique(portList=[445,139], broEvents=[], winlogEvents=[4624])
	Pass_The_Ticket = Technique(portList=[464,389], broEvents=[], winlogEvents=[])
	Remote_Desktop_Protocol = Technique(portList=[3389], broEvents=[], winlogEvents=[1149])
	Remote_File_Copy = Technique(portList=[20,21,22,445,3389], broEvents=[], winlogEvents=[1149])
	SSH_Hijacking= Technique(portList=[22], broEvents=[], winlogEvents=[])
	Shared_Webroot = Technique(portList=[80,443], broEvents=[], winlogEvents=[])
	Taint_Shared_Content = Technique(portList=[135,138,139,445], broEvents=[], winlogEvents=[])
	Third_Party_Software = Technique(portList=[80,443,1433,5900], broEvents=[], winlogEvents=[])
	Windows_Admin_Shares = Technique(portList=[443,139], broEvents=[], winlogEvents=[528,552,4648])
	Windows_Remote_Management = Technique(portList=[445,139], broEvents=[], winlogEvents=[528,552,4648])
	#DISCOVERY (many discovery events are still null
	Network_Service_Scanning = Technique(esQuery=QueryBuilder.BuildNetworkScanDetectionQuery())
	Network_Share_Discovery = Technique(portList=[445,139], broEvents=[], winlogEvents=[])
	Query_Registry = Technique(winlogEvents=[4656])
	Security_Software_discovery = Technique(winlogEvents=[4656])
	#EXECUTION (all execution events are null)
	#PRIVILEGE ESCALATION (all of these are intra-host)
	Accessibility_Features = Technique(portList=[4657])
	App_Cert_Dll = Technique(winlogEvents=[4657])
	App_Init_Dll = Technique(winlogEvents=[4657])
	Application_Shimming = Technique(winlogEvents=[4657])
	Bypass_User_Account_Control = Technique(winlogEvents=[4657])
	Image_File_Execution_Options_Injection = Technique(winlogEvents=[4657])
	Port_Monitors = Technique(winlogEvents=[4657])
	Sid_History_Injection = Technique(winlogEvents=[4765,4766])
	Service_Registry_Perms_Weakness = Technique(winlogEvents=[4657])
	Valid_Accounts = Technique(winlogEvents=[528, 552, 4648])
	
	def __init__(self):
		#Store lateral movement techniques as a list
		self.Lateral_Movement_Techniques = [
									self.Apple_Script, 
									self.App_Deployment_Software,
									self.Distributed_Component_Object_Model,
									self.Logon_Scripts,
									self.Pass_The_Hash,
									self.Pass_The_Ticket,
									self.Remote_Desktop_Protocol,
									self.Remote_File_Copy,
									self.SSH_Hijacking,
									self.Shared_Webroot,
									self.Taint_Shared_Content,
									self.Third_Party_Software,
									self.Windows_Admin_Shares,
									self.Windows_Remote_Management ]
		#Store discovery techniques as a list
		self.Discovery_Techniques = [
									self.Network_Service_Scanning,
									self.Network_Share_Discovery,
									self.Query_Registry,
									self.Security_Software_discovery ]
									
		self.Execution_Techniques = []
		#Store privilege escalation techniques as a list
		self.Privilege_Escalation_Techniques = [
									self.Accessibility_Features,
									self.App_Cert_Dll,
									self.App_Init_Dll,
									self.Application_Shimming,
									self.Bypass_User_Account_Control,
									self.Image_File_Execution_Options_Injection,
									self.Port_Monitors,
									self.Sid_History_Injection,
									self.Service_Registry_Perms_Weakness,
									self.Valid_Accounts ]

		#Expose tactics through this table
		self.AttackTable = dict()
		self.AttackTable["lateral_movement"] = self.Lateral_Movement_Techniques
		self.AttackTable["execution"] = self.Execution_Techniques
		self.AttackTable["privilege_escalation"] = self.Privilege_Escalation_Techniques
		self.AttackTable["discovery"] = self.Discovery_Techniques

