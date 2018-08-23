from __future__ import print_function
import networkx as nx
import numpy as np
import random as rd
import sets as st
from stix2 import TAXIICollectionSource, Filter
from taxii2client import Collection
import matplotlib.pyplot as plt

class RandomWalkGenerator(object):
	def __init__(self):
		self._collection = Collection("https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/")
		self._tc_source = TAXIICollectionSource(self._collection)
		self._stepLimit = 50 #max steps to walk on each walk
		
	def _print_stage(self, n, state, curr, attack_path, tactic, tech):
		print("#" + str(n))
		print("   Node: "   + str(curr) + "  ---  Path: " + str(attack_path))
		print("   Tactic: " + str(tactic))
		print("   Technique")
		print("	  Id:  "   + str(tech['id']))
		print("	  Name:  " + str(tech['name']))
		try:
			print("	  Data Source:  " + str(tech['x_mitre_data_sources']))
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

		nx.draw(C, with_labels = True)
		plt.show()
		
		return C
		
	def _build_step(self, n, state, curr, attack_path, tactic, tech):
		#Just build a representation containing all data for one attack step
		d = {
				"host" : str(curr),
				"attack_path" : str(attack_path),
				"tactic" : str(tactic),
				"technique_id" : str(tech["id"]),
				"technique_name" : str(tech["name"]),
				"technique_data_source" : str(tech['x_mitre_data_sources'])
			}
			
		return d

	def GenerateWalk(self):
		###############
		#### START ####
		###############

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
					
			#Privilige escalation
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
				self._print_stage(n, state, curr, attack_path, tactic, tech)
				step = self._build_step(n, state, curr, attack_path, tactic, tech)
				path.append(step)
				prv_state = state
				state = self._markov_analysis(state)
				if tactic == "execution":
					print("EXEC")
					break
			else:
				state = self._markov_analysis(prv_state)

		return path
		
def main():
	generator = RandomWalkGenerator()
	path = generator.GenerateWalk()
	print(str(path))
	
	
if __name__ == "__main__":
	main()


			
