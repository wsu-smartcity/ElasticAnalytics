"""
OBSOLETE. The packetbeat indices only contain information for 192.168.0.14, the desktop you're probably on.
Just manually assign hostnames to ips, or blacklist lots all hostnames but COM600 and the like. But if
this becomes useful, see below for how to to use an aggs query to effectively execute a mapping from hostnames to ips,
but it only works for packetbeat indices.


An important task for binding netflows and winlog data is being able
to map hostnames in winlogs to host-ips in the netflows. This can be done by 
querying the packetbeat indices, for which documents contain both the hostname 
and the ip address:
		...
          "beat": {
            "hostname": "HP-B58-04",
            "name": "HP-B58-04",
            "version": "5.0.0"
          },
          "bytes_in": 35,
          "bytes_out": 51,
          "client_ip": "192.168.0.14",
		...
		  
This script does not have a home yet, but will be required at some point, somewhere.
Note that this script assumes the packetbeat indices contain enough data samples
such that every host will be listed; otherwise, the returned map will be incomplete.
The query is done through an aggs query, since these return only unique values.

Returns: A map of strings as ip->hostname, for the ips in @whitelist

  "size": 1000,
  "_source": ["beat.hostname", "source.ip"],
  "query":{
    "match_all": {}
  }

"""

from elastic_client import ElasticClient


def getHostnameIpMap(esClient):
	"""
	Given an elastic client, returns a map with ip keys and hostname values (both string).
	This can be done simply by using an aggs query to get a histogram of hostnames and
	their associated client ips.
	
	Here is the query, in case this script becomes relevant again:
	GET packetbeat*/_search
	{
	  "size": 0,
	  "aggs": {
		"hostnames": {
		  "terms": {
			"field": "beat.hostname"
		  },
		  "aggs": {
			"client_ip": {
			  "terms": {
				"field": "source.ip"
			  }
			}
		  }
		}
	  }
	}

def main():

	#whitelist of ips of interest
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

	esClient = ElasticClient()
			
			
	hostmap = getHostnameIpMap(esClient, whitelist)
			
	
			
if __name__ == "__main__":
	main()