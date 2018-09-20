"""
Just a short single-purpose script for analyzing the distribution of walks in walks.py,
for documentation purposes.
"""

ifile = open("walks.py","r")
walks = []
for line in ifile:
	try:
		walk = eval(line.strip())
		walks.append(walk)
	except:
		pass

numWalks = len(walks)
#get the average walk length
avgLen = float(sum(len(walk) for walk in walks)) / float(numWalks)
print("average walk length: {}".format(avgLen))
		
#count tactics
tacticHistogram = dict()
for walk in walks:
	for step in walk:
		tactic = step["tactic"]
		if tactic in tacticHistogram:
			tacticHistogram[tactic] += 1
		else:
			tacticHistogram[tactic] = 1

numTechniques = sum( item[1] for item in tacticHistogram.items() )
print("Tactic histogram: {}".format(tacticHistogram))
print("Total techniques: {}".format(numTechniques))
ifile.close()