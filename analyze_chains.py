#!/usr/bin/env python

import sys
import numpy as np

from ConfigParser import SafeConfigParser

from db import DbPool

# Script for analysis of CNAME chain lengths. May require lot of memory for
# huge TLDs like .com, since the CNAME graph forest is created in-memory.

class ChainNode(object):
	
	def __init__(self, name, target=None):
		"""One node of CNAME chain representing single X CNAME Y redirect"""
		self.name = name
		#multiple CNAME targets can be present seen at various times
		self.targets = set()
		if target:
			self.targets.add(target)
	
	def maxDepth(self):
		"""Simple DFS search to determine max depth - acyclic graph expected."""
		return max([1] + [1+target.maxDepth() for target in self.targets])
		
	def __eq__(self, other):
		return self.name == other.name
	
	def __hash__(self):
		return hash(self.name)
	
	def __str__(self):
		return "<%s: [%s]>" % (self.name, ",".join(str(t) for t in self.targets))


if __name__ == '__main__':
	if len(sys.argv) != 2: 
		print >> sys.stderr, "ERROR: usage: <scraper_config>" 
		sys.exit(1)
		
	sqlRowCount = 2000
	
	scraperConfig = SafeConfigParser()
	scraperConfig.read(sys.argv[1])
	
	db = DbPool(scraperConfig, max_connections=1)
	
	# prefix/schema to use in DB:
	prefix = ""
	if scraperConfig.has_option("database", "prefix"):
		prefix = scraperConfig.get("database", "prefix")
	
	#We are using single thread, so let's set the schema using 'set search_path'
	if prefix:
		if not prefix.endswith("."):
			raise ValueError("Sorry, only schemes supported in this script")
		
		sql = "SET search_path = %s"
		sql_data = (prefix[:-1],)
		
		cursor = db.cursor()
		cursor.execute(sql, sql_data)
	
	#named cursor in order to not swap ourselves from the known universe
	cursor = db.cursor(name="dnskeys")
	
	#map known names to nodes for fast lookup
	name2node = {}
	
	sql = """SELECT fqdn, dest from cname_rr
			INNER join domains on (fqdn_id = domains.id)"""
	
	cursor.execute(sql)
	rows = cursor.fetchmany(sqlRowCount)
	roots = set() #roots of every CNAME chain/tree
	
	while rows:
		for row in rows:
			fqdn = row['fqdn']
			dest = row['dest']
			
			node = name2node.get(fqdn)
			
			destNode = name2node.get(dest) or ChainNode(dest)
			name2node[dest] = destNode
			roots.discard(destNode)
			
			if not node:
				node = ChainNode(fqdn, destNode)
				name2node[fqdn] = node
				roots.add(node)
			else:
				node.targets.add(destNode)
				
		rows = cursor.fetchmany(sqlRowCount)
		
	
	depths = [node.maxDepth() for node in roots]
	median = np.median(depths)
	mean = np.mean(depths)
	
	print "CNAME chains mean: %2.2f, median: %2.2f" % (mean, median)


