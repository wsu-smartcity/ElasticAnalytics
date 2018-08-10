"""
A stand-alone script for running pca on the netflow data. PCA is appropriate for linear data,
whereas the graphical nature of netflows is, well, graphical and high-dimensional. Instead one
can choose a view under which pca might apply, such as the set of port# distributions between
all hosts, which is tested here. This is risky since in almost every case there are fewer
edges (h * (h-1), for a directed graph with 'h' hosts) than port numbers (65k). OTOH, we expect
a lot of regularity in terms of certain ports being used (e.g., port 80 for http traffic).

This is purely experimental/exploratory. In fact, it should not be included a work without 
a pretty rigorous justification for analyzing PC's for a matrix with many fewer rows than
columns.
"""

from sklearn.decomposition import PCA
from netflow_model import NetFlowModel
import sys
import numpy as np
import igraph
import pandas as pd
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D


def main():
	netflowModel = NetFlowModel()
	netflowModel.Read("netflowModel.pickle")
	#Get the port model as a dictionary of (src-host,dst-host) -> port_histogram
	matrix, colIndex = netflowModel.GetEdgeDistributionMatrix("port")
	#OPTIONAL: convert matrix to log(matrix) form to attempt to linearize the irregular distributions
	#matrix = np.log(matrix) #does not work yet; write your own and handle zero entries since log(0) = -inf
	print("Matrix shape: {}".format(matrix.shape))
	num_components = 16
	pca = PCA(n_components=num_components)
	pca.fit(matrix)
	Z = pca.transform(matrix)

	print("Components' explained variance ratios:\n\t{}".format(pca.explained_variance_ratio_))
	print("Singular values:\n\t".format(pca.singular_values_))
		
	for i in range(num_components-3):
		x2 = Z[:,i]
		y2 = Z[:,i+1]
		print("{}".format(y2))
		plt.scatter(x2,y2)
		plt.show()
		plt.clf()
	
		x3 = Z[:,i]
		y3 = Z[:,i+1]
		z3 = Z[:,i+2]
		fig = plt.figure(1, figsize=(4,3))
		ax = Axes3D(fig)
		print("{}".format(y3))
		ax.scatter(x3,y3,z3)
		plt.show()
		plt.clf()
	
	

	
	
	
	
	
	
if __name__ == "__main__":
	main()

