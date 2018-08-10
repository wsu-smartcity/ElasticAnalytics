"""
A single manually-defined database of technique attack features, per ATT&CK tactic.
Hence the dependence is tactic -> technique -> features.

Rather than being stored, the features could be shared/automated in some way using stix-like
behavioral analytics or unfetter.
"""

class Technique(object):
	def __init__(self, portList=[], broEvents=[], winlogEvents=[]):
		self.Ports = portList
		self.BroEvents = broEvents
		self.WinlogEvents = winlogEvents


class AttackFeatureModel(object):

	#Each technique consists of a bunch of manually defined features
	
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

		#Expose tactis through this table
		self.AttackTable = dict()
		
		self.AttackTable["lateral_movement"] = self.Lateral_Movement_Techniques
											
	
	
	
	



