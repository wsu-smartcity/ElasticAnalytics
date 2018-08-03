import networkx as nx
import numpy as np
import random as rd
import sets as st
from stix2 import TAXIICollectionSource, Filter
from taxii2client import Collection

def print_stage(n, state, curr, attack_path, tactic, tech):
	print "#" + str(n) 
	print "   Node: "   + str(curr) + "  ---  Path: " + str(attack_path)
	print "   Tactic: " + str(tactic)
	print "   Technique" 
	print "      Id:  "   + str(tech['id']) 
	print "      Name:  " + str(tech['name']) 
	try:
		print "      Data Source:  " + str(tech['x_mitre_data_sources']) 
	except KeyError:
		print "      Data Source: None" 
	print "  "

#Query MITRE ATT&CK API
def get_technique(tactic):
	collection = Collection("https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/")
	tc_source = TAXIICollectionSource(collection)
    	techs = tc_source.query([
        	Filter('type', '=', 'attack-pattern'),
        	Filter('kill_chain_phases.phase_name', '=', tactic)
    	])

    	techs_list = [t for t in techs if {
        	'kill_chain_name' : 'mitre-attack',
        	'phase_name' : tactic,
    	} in t.kill_chain_phases]
	
	randnum = rd.randint(0, len(techs_list)-1)
	return techs_list[randnum]

def create_cyber_graph(C):
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
	for i in range(1,9):
		C.add_node("relay"+str(i))
		C.add_edge("relay"+str(i),"sw2")

	# WAN
	#C.add_node("ext")
	#C.add_edge("fw1", "fw2")
	#C.add_edge("ext", "fw1")
	#C.add_edge("ext", "fw2")

def markov_analysis(state):

	#               D,  PE,  LM,  E
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

###############
#### START ####
###############

### Init Graph ####
C=nx.Graph()
create_cyber_graph(C)
curr = "fw1"
exec_nodes = set(["hmi", "scada", "rtu", "relay1", "relay2", "relay3", "relay4", "relay5", "relay6", "relay7", "relay8", "relay9"])
attack_path = set(["fw1"])

### Init Markov Model ####
state = np.array([1,  0,   0,   0])
prv_state = state
n = 0
update_state = 0
priv_esc = 0 
disc = 0
avail = set([]) 

while n < 50:
	n=n+1
	#TODO: Need Initial Access
        #if state[0]==XYZ: 
	#	tactic = "initial-access"
	#	update_state = 1
        if state[0]==1: #TODO: technically need to discover both local and remote....
		tactic = "discovery"
		disc = disc + 1
		if disc < 3:
			update_state = 1
		else:
			update_state = 0
        if state[1]==1: 
		tactic = "privilege-escalation"
		if priv_esc ==0:
			update_state = 1
			priv_esc = 1
		else: 
			update_state = 0
		
        if state[2]==1: 
		tactic = "lateral-movement"
		avail.update(C.adj[curr])
		avail.difference(attack_path) 
		try:
			curr = rd.sample( avail, 1 )[0]
			attack_path.add(curr)
			priv_esc = 0
			update_state = 1
			disc = 0 
		except ValueError:
			update_state = 0
        if state[3]==1: 
		if attack_path.intersection(exec_nodes):
			tactic = "execution"
			update_state = 1
		else:
			update_state = 0

	if update_state == 1:
		tech = get_technique(tactic)
		print_stage(n, state, curr, attack_path, tactic, tech)
		prv_state = state
		state = markov_analysis(state)
		if tactic == "execution":
			break
	else:
		state = markov_analysis(prv_state)

