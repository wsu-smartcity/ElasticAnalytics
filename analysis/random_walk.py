from __future__ import print_function
import networkx as nx
import numpy as np
import random as rd
import sets as st
from stix2 import TAXIICollectionSource, Filter
from taxii2client import Collection
import matplotlib.pyplot as plt
import traceback

class RandomWalkGenerator(object):
	def __init__(self, show=True):
		"""
		@show: Whether or not to show the networkx plot of the network 
		"""
		self._collection = Collection("https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/")
		self._tc_source = TAXIICollectionSource(self._collection)
		self._stepLimit = 50 #max steps to walk on each walk
		self._show = show
		self._walkFile = "walks.py"

	def _print_stage(self, n, state, curr, attack_path, tactic, techStr, techId, techName):
		print("#" + str(n))
		print("   Node: "   + str(curr) + "  ---  Path: " + str(attack_path))
		print("   Tactic: " + str(tactic))
		print("   Technique")
		print("	  Id:  "   + techId)
		print("	  Name:  " + techName)
		try:
			print("	  Data Source:  " + techStr)
		except KeyError:
			print("	  Data Source: None")
		print("")

	#Query MITRE ATT&CK API
	def _get_technique(self, tactic):
		techs = self._tc_source.query([
			Filter('type', '=', 'attack-pattern'),
			Filter('kill_chain_phases.phase_name', '=', tactic)
		])

		techs_list = [t for t in techs if {
			'kill_chain_name' : 'mitre-attack',
			'phase_name' : tactic,
		} in t.kill_chain_phases]
		
		randnum = rd.randint(0, len(techs_list)-1)
		return techs_list[randnum]

	def _markov_analysis(self, state):

		#			   D,  PE,  LM,  E
		#v = np.matrix([[1,  0,   0,   0]])

		P = np.matrix([ [.33, .33, .33, 0.0],
						[.33, 0.0, .33, .33],
						[.33, .33, 0.0, .33],
						[0.0, 0.0, 0.0, 0.0]])

		base=0
		rand=rd.random()
		for j in range(4):
			base = base + np.array(state*P)[0][j]
			if rand < base:
				break
		state = np.zeros(4)
		state[j] = 1
		return state

	def _build_cyber_graph(self):
		C = nx.Graph()
		#Control Center
		C.add_node("scada")
		C.add_node("hmi")
		C.add_node("sw1")
		C.add_node("fw1")
		C.add_edge("scada","sw1")
		C.add_edge("hmi","sw1")
		C.add_edge("fw1","sw1")
		C.add_edge("eng","sw1")

		# Substation 1
		C.add_node("fw2")
		C.add_node("sw2")
		C.add_node("gw")
		C.add_node("eng")
		C.add_edge("fw2","sw2")
		C.add_edge("gw","sw2")
		C.add_edge("sw1", "sw2")
		
		for i in range(1,9):
			C.add_node("relay"+str(i))
			C.add_edge("relay"+str(i),"sw2")

		# WAN
		#C.add_node("ext")
		#C.add_edge("fw1", "fw2")
		#C.add_edge("ext", "fw1")
		#C.add_edge("ext", "fw2")

		if self._show:
			nx.draw(C, with_labels = True)
			plt.show()
		
		return C
		
	def _build_step(self, n, state, curr, attack_path, tactic, techStr, techId, techName):
		#Just build a representation containing all data for one attack step
		d = {
				"host" : str(curr),
				"attack_path" : str(attack_path),
				"tactic" : str(tactic),
				"technique_id" : techId,
				"technique_name" : techName,
				"technique_data_source" : techStr
			}
			
		return d

	def _generateWalk(self):
		"""
		Original walk script.
		
		NOTE: IF ANY CHANGES ARE MADE TO WALK SCRIPT, THEN BuildRandomWalkMatrix() AND ITS INTERNAL LOGIC WILL NEED TO
		BE UPDATED AND RE-EVALUATED AS WELL, FOR CONSISTENCY. ALSO, CAPITAL LETTERS!!! Just kidding, but also
		any changes here will make any previous walks.py output files obsolte, and those would likely need to be
		regenerated also.
		"""
		### Init Graph ####
		C = self._build_cyber_graph()
		curr = "fw1"
		exec_nodes = set(["hmi", "scada", "gw", "relay1", "relay2", "relay3", "relay4", "relay5", "relay6", "relay7", "relay8", "relay9"])
		attack_path = set([curr])

		### Init Markov Model ####
		state = np.array([1, 0, 0, 0])
		prv_state = state
		n = 0
		update_state = 0
		priv_esc = 0 
		disc = 0
		avail = set([])
		path = []

		while n < self._stepLimit:
			n = n+1
			#TODO: Need Initial Access
				#if state[0]==XYZ: 
			#	tactic = "initial-access"
			#	update_state = 1
			
			#Discovery
			if state[0]==1: #TODO: technically need to discover both local and remote....
				tactic = "discovery"
				disc = disc + 1
				if disc < 3:
					update_state = 1
				else:
					update_state = 0
					
			#Privilege escalation
			if state[1]==1: 
				tactic = "privilege-escalation"
				if priv_esc ==0:
					update_state = 1
					priv_esc = 1
				else: 
					update_state = 0

			#Lateral movement
			if state[2]==1:
				tactic = "lateral-movement"
				avail.update(C.adj[curr])
				avail = avail.difference(attack_path)
				try:
					curr = rd.sample( avail, 1 )[0]
					attack_path.add(curr)
					priv_esc = 0
					update_state = 1
					disc = 0 
				except ValueError:
					update_state = 0

			#Execution
			if state[3]==1:
				if attack_path.intersection(exec_nodes):
					tactic = "execution"
					update_state = 1
				else:
					update_state = 0

			if update_state == 1:
				tech = self._get_technique(tactic)
				#I pull these out here, because they seem to be stateful; indexing @tech twice has led to exceptions, as if 'tech['x_mitre_data_sources']' makes a query of some sort
				techStr = str(tech['x_mitre_data_sources'])
				techId = str(tech['id'])
				techName = str(tech['name'])
				if self._show:
					self._print_stage(n, state, curr, attack_path, tactic, techStr, techId, techName)
				step = self._build_step(n, state, curr, attack_path, tactic, techStr, techId, techName)
				path.append(step)
				prv_state = state
				state = self._markov_analysis(state)
				if tactic == "execution":
					print("EXEC")
					break
			else:
				state = self._markov_analysis(prv_state)
		return path
		
	def BuildRandomWalkMatrix(self, hostWhitelist=None):
		"""
		This class models a distribution over behavior over tactics, given the host model we have provided.
		We can generate a single walk with GenerateWalk(), but also want to simulate many walks, to evaluate
		the frequency of transitions between hosts and the types of tactics hypothetically executed. By
		generating many such walks, we can build a matrix characterizing the frequency of tactics at each host,
		defined by the distribution fixed by this class. 
		
		@hostWhitelist: A list of hosts (by name) to include. Any missing hosts are simply removed from the matrix.
		"""
		
		matrix, hostIndex, tacticIndex = self._buildMatrixFromWalks()
		if hostWhitelist is not None:
			print("Filtering walk matrix with whitelist: {}".format(hostWhitelist))
			matrix, hostIndex = self._filterWalkMatrix(matrix, hostIndex, hostWhitelist)

		return matrix, hostIndex, tacticIndex

	def _filterWalkMatrix(self, M, hostIndex, hostWhitelist):
		"""
		From @M, return a matrix consisting only of the subset of rows/cols included in @hostWhitelist.
		Note the loss of information per transient nodes: say some node often behaves as an intermediary between hosts
		h1 and h2 in @hostWhitelist, but is not in @hostWhitelist. Then this information will be lost. A way to overcome
		this would be to account for filtered hosts during the matrix' construction, such that relevant information is
		retained.
		
		@M: The symmetric tactic frequency matrix for all hosts
		@hostIndex: a map of host names to their corresponding row/col indices in @MITRE
		@hostWhitelist: A list of hosts; only these will be included in the returned items

		Returns: @M_filtered, a matrix consisting only of the host rows/cols included in hostWhitelist,
				@hostIndex_filtered: The same as @hostIndex, but with only the hosts in @hostWhitelist
		"""
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

	def _buildMatrixFromWalks(self):
		"""
		Builds a transition matrix based on the walks stored in walks.py. No hosts are filtered.
		The first and second axes of this matrix are simulated hosts, and the third axis are entries
		containing the frequency of tactic transitions.
		
		1) Reflexive/diagonal elements represent intra-host events. These can be refined differently,
		but a rough way is just to call these privilige escalation and execution.
		2) Off-diagonal elements represent inter-host tactics, like lateral-movement. Some instances of discovery
		should be there as well, but are TODO's for now.
		
		The result of (1) and (2) is that the returned matrix is n x n x numtactics. The diagonal elements represent events/tactics on hosts,
		whereas off diagonal elements represent tactics that involved a transition between hosts. Further, on the diagonal, the only counts
		defined are for intrahost tactics, and interhost tactic counts will be zero; the opposite is true for off diagonal elements. so this
		matrix, though for only a small number of hosts, will be very sparse, and the current implementation could not be generalized to
		larger networks of hosts.
		
		[{'technique_id': 'attack-pattern--15dbf668-795c-41e6-8219-f0447c0e64ce', 'host': 'fw1', 'technique_name': 'Permission Groups Discovery', 'tactic': 'discovery', 'attack_path': "set(['fw1'])", 'technique_data_source': "[u'API monitoring', u'Process command-line parameters', u'Process monitoring']"}, {'technique_id': 'attack-pattern--9b99b83a-1aac-4e29-b975-b374950551a3', 'host': 'fw1', 'technique_name': 'Accessibility Features', 'tactic': 'privilege-escalation', 'attack_path': "set(['fw1'])", 'technique_data_source': "[u'Windows Registry', u'File monitoring', u'Process monitoring']"}, {'technique_id': 'attack-pattern--a257ed11-ff3b-4216-8c9d-3938ef57064c', 'host': 'sw1', 'technique_name': 'Pass the Ticket', 'tactic': 'lateral-movement', 'attack_path': "set(['sw1', 'fw1'])", 'technique_data_source': "[u'Authentication logs']"}, {'technique_id': 'attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81', 'host': 'sw1', 'technique_name': 'Valid Accounts', 'tactic': 'privilege-escalation', 'attack_path': "set(['sw1', 'fw1'])", 'technique_data_source': "[u'Authentication logs', u'Process monitoring']"}, {'technique_id': 'attack-pattern--241814ae-de3f-4656-b49e-f9a80764d4b7', 'host': 'sw1', 'technique_name': 'Security Software Discovery', 'tactic': 'discovery', 'attack_path': "set(['sw1', 'fw1'])", 'technique_data_source': "[u'File monitoring', u'Process command-line parameters', u'Process monitoring']"}, {'technique_id': 'attack-pattern--ffe742ed-9100-4686-9e00-c331da544787', 'host': 'eng', 'technique_name': 'Windows Admin Shares', 'tactic': 'lateral-movement', 'attack_path': "set(['sw1', 'fw1', 'eng'])", 'technique_data_source': "[u'Process use of network', u'Authentication logs', u'Process command-line parameters', u'Process monitoring']"}, {'technique_id': 'attack-pattern--3489cfc5-640f-4bb3-a103-9137b97de79f', 'host': 'eng', 'technique_name': 'Network Share Discovery', 'tactic': 'discovery', 'attack_path': "set(['sw1', 'fw1', 'eng'])", 'technique_data_source': "[u'Process Monitoring', u'Process command-line parameters', u'Network protocol analysis', u'Process use of network']"}, {'technique_id': 'attack-pattern--c3bce4f4-9795-46c6-976e-8676300bbc39', 'host': 'hmi', 'technique_name': 'Windows Remote Management', 'tactic': 'lateral-movement', 'attack_path': "set(['sw1', 'fw1', 'hmi', 'eng'])", 'technique_data_source': "[u'File monitoring', u'Authentication logs', u'Netflow/Enclave netflow', u'Process command-line parameters', u'Process monitoring']"}, {'technique_id': 'attack-pattern--4ae4f953-fe58-4cc8-a327-33257e30a830', 'host': 'hmi', 'technique_name': 'Application Window Discovery', 'tactic': 'discovery', 'attack_path': "set(['sw1', 'fw1', 'hmi', 'eng'])", 'technique_data_source': "[u'API monitoring', u'Process command-line parameters', u'Process monitoring']"}, {'technique_id': 'attack-pattern--8f4a33ec-8b1f-4b80-a2f6-642b2e479580', 'host': 'hmi', 'technique_name': 'Process Discovery', 'tactic': 'discovery', 'attack_path': "set(['sw1', 'fw1', 'hmi', 'eng'])", 'technique_data_source': "[u'Process command-line parameters', u'Process monitoring']"}, {'technique_id': 'attack-pattern--7c93aa74-4bc0-4a9e-90ea-f25f86301566', 'host': 'hmi', 'technique_name': 'Application Shimming', 'tactic': 'privilege-escalation', 'attack_path': "set(['sw1', 'fw1', 'hmi', 'eng'])", 'technique_data_source': "[u'Loaded DLLs', u'System calls', u'Windows Registry', u'Process Monitoring', u'Process command-line parameters']"}, {'technique_id': 'attack-pattern--62b8c999-dcc0-4755-bd69-09442d9359f5', 'host': 'hmi', 'technique_name': 'Rundll32', 'tactic': 'execution', 'attack_path': "set(['sw1', 'fw1', 'hmi', 'eng'])", 'technique_data_source': "[u'File monitoring', u'Binary file metadata', u'Process command-line parameters', u'Process monitoring']"}]
		"""
		
		#only four are of interest currently: discovery, lateral movement, execution, and privilege escalation. These must match the spelling of these tactics as received from MITRE
		tacticIndex = {"discovery" : 0, "lateral-movement" : 1 , "privilege-escalation" : 2, "execution" : 3}
		relational_discovery_techniques = ["Network Service Scanning", "Network Share Discovery", "System Network Connections Discovery", "Remote System Discovery"]
		
		walks = self._getWalks(self._walkFile)
		#build the host index, mapping host names to their row/col index in the matrix
		rowIndex = 0
		hostIndex = dict()
		for walk in walks:
			for step in walk:
				host = step["host"]
				if host not in hostIndex.keys():
					hostIndex[host] = rowIndex
					rowIndex += 1

		#print("HOST INDEX: {}".format(hostIndex))
		#build the matrix itself
		n = len(hostIndex.keys())
		numTactics = len(tacticIndex.keys())
		M = np.zeros(shape=(n,n,numTactics), dtype=np.float)
		
		for walk in walks:
			for i in range(len(walk)):
				step = walk[i]
				host = step["host"]
				tactic = step["tactic"]
				if tactic in tacticIndex:
					tactic_i = tacticIndex[tactic]
					host_i = hostIndex[host]
					#these two tactics are currently treated as intra-host/non-relational, although instances of Discovery can clearly be both: querying a host's registry, or scanning for neighbor systems, and so forth.
					if tactic in ["discovery", "privilege-escalation", "execution"]:
						#intra host, so this is a diagonal element in the event matrix
						M[host_i, host_i, tactic_i] += 1.0
					if tactic in ["lateral-movement", "discovery"]:
						if i > 0: #make sure we're not at start of walk, and have a previous step; for l.m. the walks were recorded as 'lateral-movement' via the previous host/step in the walk
							#lateral movement is a straightfoward case of counting transitions from last host to current host
							if tactic == "lateral-movement":
								prevStep = walk[i-1]
								src_i = hostIndex[ prevStep["host"] ]
								M[src_i, host_i, tactic_i] += 1.0
								M[src_i, src_i, tactic_i] += 1.0
							#only a subset of Discovery techniques are relational/transitional in nature (e.g. network scanning activity, service discovery, etc)
							elif tactic == "discovery" and step["technique_name"] in relational_discovery_techniques:
								prevStep = walk[i-1]
								src_i = hostIndex[ prevStep["host"] ]
								M[src_i, host_i, tactic_i] += 1.0
						#else:
						#	print("Discarding lateral movement tactic step at begining of walk... not an error, just making it known.")
					#else:
					#	print("Tactic >{}< not found in _buildMatrixFromWalks".format(tactic))
				else:
					print("WARNING tactic >{}< not in tacticIndex. Likely not supported.".format(tactic))

		return M, hostIndex, tacticIndex

	def _getWalks(self, walkPath):
		walks = []
		
		with open(walkPath, "r") as ifile:
			for line in ifile:
				if len(line.strip()) > 0:
					try:
						walk = eval(line.strip())
						walks.append(walk)
					except:
						print("WARNING there was an issue evaluating walk in _buildMatrixFromWalks: "+line)
		
		return walks
		
	def GenerateKWalks(self, k, outPath=None, newWalks=True):
		"""
		Generates k walks, each a list as returned by GenerateWalk, then stores these at @outPath.
		Storage allows separating the construction of walks (which can take considerably time) from
		the construction of a frequency matrix per those walks. The walks are just serialized in python
		form, and can be re-read in with eval(line) for each line in the file.
		
		@newWalks: If true, open the output file for write, effectively blowing away old walks. Else, append to current file.
		"""
		if outPath is None:
			outPath = self._walkFile
			
		if newWalks:
			mode = "w+"
		else:
			mode = "a+"
		
		with open(outPath, mode) as ofile:
			for i in range(k):
				walk = self.GenerateWalk()
				ofile.write(str(walk)+"\n")

	def GenerateWalk(self):
		success = False
		retryLimit = 5
		retries = 0
		walk = []
		
		while not success and retries < retryLimit:
			try:
				walk = self._generateWalk()
				success = len(walk) > 0 #success if walk longer than zero
			except:
				traceback.print_exc()
				print("Walk failed for reasons described in exception above; retrying...")
				retries += 1

		return walk
		
def main():
	#whitelist = ["relay6", "relay1", "relay2", "gw", "fw1"]
	generator = RandomWalkGenerator(show=False)
	generator.GenerateKWalks(1000, newWalks=True)
	
	"""
	matrix, hostIndex, tacticIndex = generator.BuildRandomWalkMatrix(whitelist)
	print(str(hostIndex))
	print(str(tacticIndex))
	print(str(matrix))
	print(str(matrix.shape))
	"""
	
if __name__ == "__main__":
	main()
