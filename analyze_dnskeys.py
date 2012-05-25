#!/usr/bin/env python

"""
Looks at each RSA key and prints out all keys that either have small moduli < 1023
bits or small exponents (where a validating resolver implementation might be
susceptible to variants of Bleichenbacher attack).

Reports also keys with big exponents (which slow down verification at resolvers).
"""

import sys

from math import log, ceil
from ConfigParser import SafeConfigParser

from db import DbSingleThreadOverSchema
from dns_scraper import DnskeyAlgo

#minimal modulus size and exponent size that is considered "safe"
#see http://www.keylength.com/en/3/ and referenced ECRYPT II yearly report
b1023 = 1<<1023

#see "Variants of Bleichenbacher's Low-Exponent Attacks on PKCS##1 RSA":
#http://www.cdc.informatik.tu-darmstadt.de/reports/reports/sigflaw.pdf
min_exponent = 65537

#see Adam Langley's blog: http://www.imperialviolet.org/2012/03/17/rsados.html
big_exponent = 0x100000000



if __name__ == '__main__':
	if len(sys.argv) != 2: 
		print >> sys.stderr, "ERROR: usage: <scraper_config>" 
		sys.exit(1)
		
	scraperConfig = SafeConfigParser()
	scraperConfig.read(sys.argv[1])
	
	db = DbSingleThreadOverSchema(scraperConfig)
	
	#named cursor in order to not swap ourselves from the known universe
	cursor = db.cursor(name="dnskeys")
	
	sql = """SELECT dnskey_rr.id AS id, fqdn, rsa_exp, encode(rsa_mod, 'hex') AS rsa_mod_hex
			FROM dnskey_rr INNER JOIN domains ON (fqdn_id=domains.id)
			WHERE algo IN %s
		"""
	
	sql_data = (tuple(DnskeyAlgo.rsaAlgoIds),)
	cursor.execute(sql, sql_data)
	rows = cursor.fetchmany(db.dbRows)
	
	while rows:
		for row in rows:
			rowId = row["id"]
			fqdn = row["fqdn"]
			rsa_exp = row["rsa_exp"]
			rsa_mod_hex = row["rsa_mod_hex"]
			rsa_mod = int(rsa_mod_hex, 16)
			
			bits_in = lambda n: ceil(log(abs(n)+1,2))
			
			if rsa_mod < b1023:
				print "Small modulus: id %s, fqdn %s, %d bits, mod 0x%s" % (rowId, fqdn, bits_in(rsa_mod), rsa_mod_hex)
			
			if rsa_exp == -1: #special value for exponent that won't fit into int64_t
				print "HUGE exponent: id %s, fqdn %s" % (rowId, fqdn)
			elif rsa_exp < min_exponent:
				print "Small exponent %s: id %s, fqdn %s" % (rsa_exp, rowId, fqdn)
			elif rsa_exp > big_exponent:
				print "Big exponent 0x%x: id %s, fqdn %s" % (rsa_exp, rowId, fqdn)
			
			# TODO: check against debian weak keys here, though it's possible in SQL, too
			
		rows = cursor.fetchmany(db.dbRows)
		
		

