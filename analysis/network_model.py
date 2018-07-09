"""
A concrete representation of a network based on netflow data.
This could bea hierarchy of different views of netflow data
suitable for different analyses, but keeping it concrete and simple
for now, as a static graph with edges decorated with frequency data.

This class is a little overboard until statistical analysis shows what kinds of views/queries
on network data are most effective. But it would be good practice for such a class to exist,
one self-describing such network models and encapsulating complex queries.

"""

import igraph

class NetworkModel(object):
	def __init__(self):
		
		
	
