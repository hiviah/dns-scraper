#!/usr/bin/env python


#   This file is part of DNS Scraper
#
#   Copyright (C) 2012 Ondrej Mikle, CZ.NIC Labs
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, version 3 of the License.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

import time
import sys
import threading
import Queue
import logging
import struct

from binascii import hexlify
from ConfigParser import SafeConfigParser

from db import DbPool
from unbound import ub_ctx, ub_version, ub_strerror, RR_CLASS_IN, RR_TYPE_DNSKEY, RR_TYPE_A, \
	RR_TYPE_AAAA, RR_TYPE_SSHFP, RR_TYPE_MX, RR_TYPE_DS, RR_TYPE_NSEC, \
	RR_TYPE_NSEC3, RR_TYPE_NSEC3PARAMS, RR_TYPE_RRSIG, RR_TYPE_SOA, \
	RR_TYPE_NS, RR_TYPE_TXT, RCODE_SERVFAIL

RR_TYPE_SPF = 99

class UnboundError(RuntimeError):
	"""Exception for reporting internal unbound errors"""
	def __init__(self, reason):
		super(RuntimeError, self).__init__(reason)

class RRType_Parser(object):
	"""Abstract class for parsing and storing of all RR types. Does up to 3
	attempts on SERVFAIL"""
	
	rrType = 0 #undefined RR type
	rrClass = RR_CLASS_IN
	attempts = 3
	
	def __init__(self, domain, resolver):
		"""Create instance.
		@param domain: domain to scan for
		@param resolver: ub_ctx to use for resolving
		"""
		self.domain = domain
		self.resolver = resolver
	
	def fetch(self):
		"""Generic fetching of record that are not of special form like
		SRV and TLSA.
		
		@returns: result part from (status, result) tupe of ub_ctx.resolve() or None on permanent SERVFAIL
		@throws: UnboundError if unbound reports error
		"""
		for i in range(self.attempts):
			(status, result) = self.resolver.resolve(self.domain, self.rrType, self.rrClass)
			
			if status != 0:
				raise UnboundError("Resolving %s for %s: %s" % \
					(self.__class__.__name__, self.domain, ub_strerror(status)))
			
			if result.rcode != RCODE_SERVFAIL:
				logging.debug("Domain %s type %s: havedata %s, rcode %s", \
					self.domain, self.__class__.__name__, result.havedata, result.rcode_str)
				return result
			
			logging.warn("Permanent SERVFAIL: domain %s type %s", \
				self.domain, self.__class__.__name__)
			return None
		
	def fetchAndStore(self, conn):
		"""Scan records for the domain and store results in DB.
		@param conn: database connection from DBPool.connection()
		"""
		raise NotImplementedError
	

class A_Parser(RRType_Parser):
	
	rrType = RR_TYPE_A
	
	def __init__(self, domain, resolver):
		RRType_Parser.__init__(self, domain, resolver)
	
	def fetchAndStore(self, conn):
		try:
			r = RRType_Parser.fetch(self)
		except UnboundError:
			logging.exception("Fetching of %s failed" % self.domain)
		
		if r.havedata:
			print "%s: %s" % (self.domain, r.data.as_address_list())
	
class RSAKey(object):

	def __init__(self, exponent, modulus, digest_algo, key_purpose):
		self.exponent = exponent
		self.modulus = modulus
		self.digest_algo = digest_algo
		self.key_purpose = key_purpose


class DnskeyAlgo:
	
	algo_map = \
		{ 
		     1: "RSA/MD5",
		     5: "RSA/SHA-1",
		     7: "RSASHA1-NSEC3-SHA1",
		     8: "RSA/SHA-256",
		    10: "RSA/SHA-512",
		}
	
	algo_ids = algo_map.keys()

class DnskeyParser(RRType_Parser):

	rrType = RR_TYPE_DNSKEY
	
	def __init__(self, domain, resolver):
		RRType_Parser.__init__(self, domain, resolver)
	
	def fetchAndStore(self, conn):
		try:
			result = RRType_Parser.fetch(self)
		except UnboundError:
			logging.exception("Fetching of %s failed" % self.domain)
		
		keys = []
		if result.havedata:
			for key in result.data.data:
				flags = struct.unpack("!H", key[:2])[0]
				proto = ord(key[2])
				algo = ord(key[3])
				pubkey = key[4:]
				
				if algo not in DnskeyAlgo.algo_ids or proto != 3: #only RSA/x algorithms, must be DNSSEC protocol
					logging.debug("Skipped key for domain %s - algorithm %s, proto %s, pubkey: %s", domain, algo, proto, hexlify(pubkey))
					continue

				#stupid RFC 2537/3110 exponent length encoding
				exp_len0 = ord(pubkey[0])
				if exp_len0 > 0:
					exp_len = exp_len0
					exp_hdr_len = 1
				else:
					exp_len = ord(pubkey[1]) << 8 + ord(pubkey[2])
					exp_hdr_len = 3

				exponent = pubkey[exp_hdr_len:exp_hdr_len + exp_len]
				modulus  = pubkey[exp_hdr_len + exp_len:]
				digest_algo = DnskeyAlgo.algo_map[algo]

				if flags == 257:
					key_purpose = "KSK"
				elif flags == 256:
					key_purpose = "ZSK"
				else:
					key_purpose = "?SK_%04x" % flags #for revoked bit and other reserved bits

				keys.append(RSAKey(exponent, modulus, digest_algo, key_purpose))
			
			print self.domain, keys
	

class DnsScanThread(threading.Thread):

	def __init__(self, task_queue, ta_file, rr_scanners, db):
		"""Create scanning thread.
		
		@param task_queue: Queue.Queue containing domains to scan as strings
		@param ta_file: trust anchor file for libunbound
		@param rr_scanners: list of subclasses of RRType_Parser to use for scan
		@param db: database connection pool, instance of db.DbPool
		"""
		self.task_queue = task_queue
		self.rr_scanners = rr_scanners
		self.db = db
		
		threading.Thread.__init__(self)
		
		self.resolver = ub_ctx()
		#self.resolver.resolvconf("/etc/resolv.conf")
		#self.resolver.set_fwd("127.0.0.1")
		self.resolver.add_ta_file(ta_file) #read public keys for DNSSEC verification

	def run(self):
		conn = self.db.connection()
		while True:
			domain = self.task_queue.get()
			
			for parserClass in self.rr_scanners:
				try:
					parser = parserClass(domain, self.resolver)
					parser.fetchAndStore(conn)
				except Exception:
					logging.exception("Failed to scan domain %s with %s",
						domain, parserClass.__class__.__name__)
				
			self.task_queue.task_done()


if len(sys.argv) != 5: 
	print >> sys.stderr, "ERROR: usage: <domain_file> <ta_file> <thread_count> <db_config>" 
	sys.exit(1)
	
domain_file = file(sys.argv[1])
ta_file = sys.argv[2]
thread_count = int(sys.argv[3])
db_config = SafeConfigParser()
db_config.read(sys.argv[4])

db = DbPool(db_config)

logging.basicConfig(filename="dns-scraper.log", level=logging.DEBUG,
	format="%(asctime)s %(levelname)s %(message)s [%(pathname)s:%(lineno)d]")

logging.info("Unbound version: %s", ub_version())

task_queue = Queue.Queue(5000)

parsers = [A_Parser, DnskeyParser]

for i in range(thread_count):
	t = DnsScanThread(task_queue, ta_file, parsers, db)
	t.setDaemon(True)
	t.start()

start_time = time.time()
domain_count = 0

for line in domain_file:
	domain = line.rstrip()
	task_queue.put(domain)
	domain_count += 1
	
task_queue.join()

logging.info("Fetch of dnskeys for %d domains took %.2f seconds", domain_count, time.time() - start_time)
