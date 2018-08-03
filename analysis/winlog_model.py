"""
The features of interest for winlog analysis are just the event id for now,
and a translation must be done from hostname back the netflow ipaddr-based hosts.

So all this implements right now is a simple aggs query to build per-host histograms
of event-ids. That is, for each hostname, build a histogram of winlog event ids, and
use this as a distribution of their behavior.


Not sure this is needed anymore, since the event-id model is so simple in our project, but
maybe this could expose probability queries to that simple per-host model of events.
"""

class WinlogModel(object):
	def __init__(self):
		pass
		
	def Event

