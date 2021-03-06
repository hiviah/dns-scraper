#!/usr/bin/env python
#   This file is part of DNS Scraper
#
#   Copyright (C) 2012 Ondrej Mikle, CZ.NIC Labs
#   And a wee bit also Ralph Holz, TUM :-)
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

"""
The unbound-1.4.16 patch in "patches" directory is required for this to
work. See README.md.

Unbound >= 1.4.17 already has the necessary patch.
"""

import time
import sys
import threading
import Queue
import logging
import struct
import re

from binascii import hexlify
from ConfigParser import SafeConfigParser

import ldns

from psycopg2 import IntegrityError
from db import DbPool
from unbound import ub_ctx, ub_version, ub_strerror, ub_ctx_config, \
	RR_CLASS_IN, RR_TYPE_DNSKEY, RR_TYPE_A, \
	RR_TYPE_AAAA, RR_TYPE_SSHFP, RR_TYPE_MX, RR_TYPE_DS, RR_TYPE_NSEC, \
	RR_TYPE_NSEC3, RR_TYPE_NSEC3PARAMS, RR_TYPE_RRSIG, RR_TYPE_SOA, \
	RR_TYPE_NS, RR_TYPE_TXT, RR_TYPE_CNAME, RR_TYPE_DNAME, RCODE_SERVFAIL

RR_TYPE_SPF = 99
RR_TYPE_TLSA = 52

class DnsError(RuntimeError):
	"""Exception for reporting internal unbound and ldns errors"""
	
	def __init__(self, reason):
		super(DnsError, self).__init__(reason)

class DnsConfigOptions(object):
	"""Container for parameters present in config file related to DNS
	resolution.
	"""
	
	def __init__(self, scraperConfig):
		"""Load options from configParser.
		@param scraperConfig: instance of RawConfigParser or subclass
		"""
		self.unboundConfig = None
		self.forwarder = None
		self.attempts = scraperConfig.getint("dns", "retries")
		
		if scraperConfig.has_option("dns", "unbound_config"):
			self.unboundConfig = scraperConfig.get("dns", "unboundConfig")
		if scraperConfig.has_option("dns", "forwarder"):
			self.forwarder = scraperConfig.get("dns", "forwarder")
			
			
		
def result2pkt(result):
	"""Extract ldns packet from ub_result.
	
	@raises DnsError: on malformed packet
	"""
	status, pkt = ldns.ldns_wire2pkt(result.packet)
	
	if status != 0:
		raise DnsError("Failed to parse DNS packet: %s" % ldns.ldns_get_errorstr_by_id(status))
	
	return pkt
	
def validationToDbEnum(result):
	"""Given ub_result, returns on of three strings usable for the "secure"
	field in DB (secure, insecure, bogus).
	"""
	if result.secure:
		return "secure"
	elif result.bogus:
		logging.warn("Bogus result: %s RR type %d - %s", result.qname, result.qtype, result.why_bogus)
		return "bogus"
	else:
		return "insecure"

def getLdnsBufferData(buf, l):
	"""Return data from ldns_buffer buf of size l as pythonic string."""
	buf.flip()
	s = ""
	for i in range(l):
		s += chr(buf.read_u8())
	return s
	
def getRdfData(rdf):
	"""Return RDF bytes as pythonic string from ldns_rdf.
	If rdf is None, returns None.
	"""
	if rdf is None:
		return None
	l = rdf.size()
	buf = ldns.ldns_buffer(l)
	rdf.write_to_buffer_canonical(buf)
	
	return getLdnsBufferData(buf, l)
	
def getRrData(rr, section=ldns.LDNS_SECTION_ANSWER):
	"""Return RR bytes as pythonic string from ldns_rr."""
	l = rr.uncompressed_size()
	buf = ldns.ldns_buffer(l)
	rr.write_to_buffer_canonical(buf, section)
	
	return getLdnsBufferData(buf, l)

def rdfConvert(rdf, fmt, conv=lambda x: x):
	"""Unpack and convert data from ldns_rdf.
	
	@param rdf: ldns_rdf
	@param fmt: format for struct.unpack
	@param conv: conversion function to call on result of struct.unpack()
	"""
	return conv(struct.unpack(fmt, getRdfData(rdf))[0])
		

def assertRdfCount(count, rr):
	"""Check that ldns_rr has correct number of RDFs.
	
	@param count: how many RDFs there should be
	@param rr: ldns_rr to check
	@raises DnsError: if the RDF count is wrong
	"""
	if rr.rd_count() != count:
		raise DnsError("Invalid RDF count in RR %s" % str(rr))
		
class StorageQueueClient(object):
	"""Client for storing data passing it through queue to StorageThread."""
	
	def __init__(self, dbQueue):
		"""Initialize with queue to DB.
		@param dbQueue: instance of Queue.Queue for passing (sql,
		sql_data) to StorageThread
		"""
		self.dbQueue = dbQueue
	
	def sqlExecute(self, sql, sql_data):
		"""Execute storage command later in StorageThread.
		@param sql: sql query with %s "placeholders"
		@param sql_data: data for placeholders
		"""
		self.dbQueue.put((sql, sql_data))


class DnsMetadata(StorageQueueClient):
	"""Represents DNS(SEC) metadata in answer: RRSIGs, NSEC and NSEC3 RRs.
	These are some things we need to parse from answer packet by ldns.
	"""
	
	rrsigRdfCount = 9
	nsecRdfCount = 2
	nsec3RdfCount = 5 # that's without bitmap, since some RRs don't have bitmap
	
	def __init__(self, pkt, dbQueue, prefix):
		"""Fills self with parsed data from DNS answer.
		
		@param pkt: ldns_pkt DNS answer packet
		@param dbQueue: DB queue for passing to StorageThread
		"""
		self.pkt = pkt
		self.prefix = prefix
		
		StorageQueueClient.__init__(self, dbQueue)
		
	def rrsigs(self, section=ldns.LDNS_SECTION_ANSWER):
		"""Return RRSIGs from selected section"""
		rrsigs = self.pkt.rr_list_by_type(RR_TYPE_RRSIG, section)
		return rrsigs and [rrsigs.rr(i) for i in range(rrsigs.rr_count())] or []
		
	def rrsigsStore(self, domain, rrType, section=ldns.LDNS_SECTION_ANSWER):
		"""Store RRSIGs from from given section of this packet in DB.
		Stores each RRSIG in separate transaction.
		
		@param domain: question domain
		@param rrType: select RRSIGs for this RR type
		@param section: section to look for RRSIGs
		"""
		rrsigs = self.rrsigs(section)
		sql = "INSERT INTO %srrsig_rr " % self.prefix
		sql = sql + """(fqdn_id, ttl, rr_type, algo, labels, orig_ttl,
			sig_expiration, sig_inception,
			keytag, signer, signature)
			VALUES ("""+self.prefix+"""insert_unique_domain(%s), %s, %s, %s, %s, %s,
				to_timestamp(%s), to_timestamp(%s),
				%s, %s, %s)
			"""
		
		for rr in rrsigs:
			try:
				assertRdfCount(self.rrsigRdfCount, rr)
				type_covered = rdfConvert(rr.rrsig_typecovered(), "!H")
				if type_covered != rrType:
					continue
				
				ttl = rr.ttl()
				algo = rdfConvert(rr.rrsig_algorithm(), "B")
				labels = rdfConvert(rr.rrsig_labels(), "B")
				orig_ttl = rdfConvert(rr.rrsig_origttl(), "!I")
				sig_expiration = rdfConvert(rr.rrsig_expiration(), "!I")
				sig_inception = rdfConvert(rr.rrsig_inception(), "!I")
				keytag = rdfConvert(rr.rrsig_keytag(), "!H")
				signer = str(rr.rrsig_signame()).rstrip(".")
				signature = buffer(getRdfData(rr.rrsig_sig()))
				
				sql_data = (domain, ttl, rrType, algo, labels, orig_ttl, sig_expiration,
					    sig_inception, keytag, signer, signature)
				self.sqlExecute(sql, sql_data)
			except:
				logging.exception("Failed to parse RRSIG for domain %s: %s" % (domain, rr))
		
	@staticmethod
	def decodeNsecBitmapWindow(windowNum, bitmap):
		"""Decode one window of NSEC/NSEC3 bitmap and return list of
		covered RR types as integers.
		"""
		rrTypeList = []
		for (charPos, c) in enumerate(bitmap):
			value = ord(c)
			for i in range(8):
				isset = (value << i) & 0x80
				if isset:
					bitpos = (windowNum << 8) + (charPos << 3) + i
					rrTypeList.append(bitpos)
		return rrTypeList
		
	@staticmethod
	def nsecBitmapCoveredTypes(bitmap):
		"""Returns list of RR integers that are covered by NSEC/NSEC3 bitmap.
		
		@param bitmap: bitmap as binary string
		@throws DnsError: if bitmap is malformed
		"""
		pos = 0
		coveredTypes = []
		try:
			while pos < len(bitmap):
				windowNum = ord(bitmap[pos])
				bitmapLen = ord(bitmap[pos+1])
				pos += 2
			
				coveredTypes.extend(DnsMetadata.decodeNsecBitmapWindow(
					windowNum, bitmap[pos:pos+bitmapLen]))
				
				pos += bitmapLen
					
			return coveredTypes
		except IndexError:
			raise DnsError("Malformed NSEC/NSEC3 bitmap: %s", hexlify(bitmap))
			
		
	def nsecs(self):
		"""Return NSEC records from authority section"""
		nsecs  = self.pkt.rr_list_by_type(RR_TYPE_NSEC,  ldns.LDNS_SECTION_AUTHORITY)
		return nsecs  and [nsecs.rr(i)  for i in range(nsecs.rr_count()) ] or []
		
	def nsecsStore(self, domain, result):
		"""Store NSECs and their RRSIGs from this packet in DB.
		
		@param domain: domain from question
		@param result: ub_result from whose return packet this object
		was created
		"""
		nsecs = self.nsecs()
		secure = validationToDbEnum(result)
		rcode = result.rcode
		
		sql = "INSERT INTO %snsec_rr " % self.prefix
		sql = sql + """(secure, fqdn_id, rr_type, owner, ttl, rcode, next_domain, type_bitmap)
			VALUES (%s, """+self.prefix+"""insert_unique_domain(%s), %s, %s, %s, %s, %s, %s)
		"""
		
		for rr in nsecs:
			try:
				assertRdfCount(self.nsecRdfCount, rr)
				ttl = rr.ttl()
				owner = str(rr.owner()).rstrip(".").lower()
				next_domain = str(rr.rdf(0)).rstrip(".").lower()
				type_bitmap = self.nsecBitmapCoveredTypes(getRdfData(rr.rdf(1)))
				
				sql_data = (secure, domain, result.qtype, owner, ttl, rcode,
					next_domain, type_bitmap)
				
				self.sqlExecute(sql, sql_data)
			except:
				logging.exception("Failed to parse NSEC for domain %s: %s" % (domain, rr))
		
		self.rrsigsStore(domain, RR_TYPE_NSEC, ldns.LDNS_SECTION_AUTHORITY)
	
	def nsec3s(self):
		"""Return NSEC3 records from authority section"""
		nsec3s = self.pkt.rr_list_by_type(RR_TYPE_NSEC3, ldns.LDNS_SECTION_AUTHORITY)
		return nsec3s and [nsec3s.rr(i) for i in range(nsec3s.rr_count())] or []
		
	def nsec3sStore(self, domain, result):
		"""Store NSEC3s and their RRSIGs from this packet in DB.
		
		@param domain: domain from question
		@param result: ub_result from whose return packet this object
		was created
		"""
		nsec3s = self.nsec3s()
		secure = validationToDbEnum(result)
		rcode = result.rcode
		
		sql = "INSERT INTO %snsec3_rr " % self.prefix
		sql = sql + """(secure, fqdn_id, rr_type, owner, ttl, rcode, hash_algo, flags,
			iterations, salt, next_owner, type_bitmap)
			VALUES (%s, """+self.prefix+"""insert_unique_domain(%s), %s, %s, %s, %s, %s, %s,
				%s, %s, %s, %s)
		"""
		
		for rr in nsec3s:
			try:
				if rr.rd_count() < self.nsec3RdfCount:
					raise DnsError("Invalid RDF count for NSEC3: %s" % str(rr))
				ttl = rr.ttl()
				owner = str(rr.owner()).rstrip(".").lower()
				hash_algo = ldns.ldns_nsec3_algorithm(rr)
				flags = ldns.ldns_nsec3_flags(rr)
				iterations = ldns.ldns_nsec3_iterations(rr)
				salt = getRdfData(ldns.ldns_nsec3_salt(rr))
				next_owner = str(ldns.ldns_nsec3_next_owner(rr)).rstrip(".").lower()
				bitmapRdf = getRdfData(ldns.ldns_nsec3_bitmap(rr))
				
				if bitmapRdf is not None:
					type_bitmap = self.nsecBitmapCoveredTypes(bitmapRdf)
				else:
					logging.warn("Empty NSEC3 bitmap for %s: %s", domain, rr)
					type_bitmap = []
				
				if len(salt) < 1:
					logging.warn("Short NSEC3 salt for %s: %s",
						domain, rr)
				else:
					#for some obscure reason, ldns_nsec3_salt()
					#has first byte of salt as length
					saltLen = ord(salt[0])
					salt = salt[1:]
					if saltLen != len(salt):
						logging.warn("NSEC3 salt length mismatch for %s, %d != %d: %s",
							domain, saltLen, len(salt), rr)
				
				sql_data = (secure, domain, result.qtype, owner, ttl, rcode,
					hash_algo, flags, iterations, buffer(salt),
					next_owner, type_bitmap)
				
				self.sqlExecute(sql, sql_data)
			except:
				logging.exception("Failed to parse NSEC3 for domain %s: %s" % (domain, rr))
		
		self.rrsigsStore(domain, RR_TYPE_NSEC3, ldns.LDNS_SECTION_AUTHORITY)
		

class RRTypeParser(StorageQueueClient):
	"""Abstract class for parsing and storing of all RR types."""
	
	rrType = 0 #undefined RR type
	rrClass = RR_CLASS_IN
	rdfCount = -1 #bogus number of RDFs
	
	def __init__(self, domain, resolver, opts, dbQueue, prefix):
		"""Create instance.
		@param domain: domain to scan for
		@param resolver: ub_ctx to use for resolving
		@param opts: instance of DnsConfigOptions
		@param dbQueue: DB queue for passing to StorageThread
		@param prefix: prefix to use for schema
		"""
		self.domain = domain
		self.resolver = resolver
		self.opts = opts
		self.prefix = prefix
		
		StorageQueueClient.__init__(self, dbQueue)
	
	def fetch(self):
		"""Generic fetching of record that are not of special form like
		SRV and TLSA.
		
		@returns: result part from (status, result) tupe of ub_ctx.resolve() or None on permanent SERVFAIL
		@throws: DnsError if unbound reports error
		"""
		for i in range(self.opts.attempts):
			(status, result) = self.resolver.resolve(self.domain, self.rrType, self.rrClass)
			
			if status != 0:
				raise DnsError("Resolving %s for %s: %s" % \
					(self.__class__.__name__, self.domain, ub_strerror(status)))
			
			if result.rcode != RCODE_SERVFAIL:
				logging.debug("Domain %s type %s: havedata %s, rcode %s", \
					self.domain, self.__class__.__name__, result.havedata, result.rcode_str)
				return result
			
		logging.info("Permanent SERVFAIL: domain %s type %s", \
			self.domain, self.__class__.__name__)
		return None
	
	def _assertRdfCount(self, rr):
		"""Check that ldns_rr has correct number of RDFs.
		
		@param rr: ldns_rr to check
		@raises DnsError: if the RDF count is wrong
		"""
		assertRdfCount(self.rdfCount, rr)
		
	def fetchAndParse(self):
		"""Fetch the RRs and return result with parsed ldns_pkt.
		
		@returns: tuple (ub_result, ldns_pkt) or (None, None) on SERVFAIL
		or packet parsing error
		"""
		try:
			result = RRTypeParser.fetch(self)
			
			if not result:
				return (None, None)
			
			pkt = result2pkt(result)
			return (result, pkt)
		except DnsError:
			logging.exception("Fetching of RR type %d for %s failed",
				self.rrType, self.domain)
			return (None, None)
		
	def fetchAndStore(self):
		"""Scan records for the domain and store results in DB.
		@return: number of records of given RR type found, or -1 if
		permanent SERVFAIL was encountered
		"""
		raise NotImplementedError
	
	def storeRedirects(self, result, pkt):
		"""Store CNAME/DNAME redirects from response packet.
		@param pkt: ldns_pkt DNS response packet
		@param result: ub_result from ub_resolve()
		"""
		cnames = pkt.rr_list_by_type(RR_TYPE_CNAME, ldns.LDNS_SECTION_ANSWER)
		dnames = pkt.rr_list_by_type(RR_TYPE_DNAME, ldns.LDNS_SECTION_ANSWER)
		secure = validationToDbEnum(result)
		
		for rrs, table in ((cnames, "cname"), (dnames, "dname")):
			if rrs is None:
				continue #stupid None instead of empty rr_list
			
			sql = "INSERT INTO %s%s_rr " % (self.prefix, table)
			sql = sql + """(secure, fqdn_id, ttl, dest)
				VALUES (%s, """+self.prefix+"""insert_unique_domain(%s), %s, %s)
					"""
			for i in range(rrs.rr_count()):
				try:
					rr = rrs.rr(i)
					dest = str(rr.rdf(0)).rstrip(".").lower()
					domain = str(rr.owner()).rstrip(".").lower()
					ttl = rr.ttl()
					
					sql_data = (secure, domain, ttl, dest)
					self.sqlExecute(sql, sql_data)
				except:
					logging.exception("Failed to parse %s for domain %s: %s" % (table.upper(), self.domain, rr))
		
	def storeDnssecData(self, pkt, result, extraSections=[]):
		"""Store DNSSEC-related metadata - RRSIGs, NSECs, NSEC3s.
		
		@param pkt: reply ldns_packet
		@param result: ub_result from which pkt was created
		@param extraSections: list of ldns.LDNS_SECTION_* to reap RRSIGs from
		"""
		meta = DnsMetadata(pkt, self.dbQueue, prefix)
		
		if result.havedata:
			meta.rrsigsStore(self.domain, self.rrType)
		else:
			meta.nsecsStore(self.domain, result)
			meta.nsec3sStore(self.domain, result)
		
		for section in extraSections:
			meta.rrsigsStore(self.domain, self.rrType, section)
	

class AParser(RRTypeParser):
	
	rrType = RR_TYPE_A
	rdfCount = 1
	
	def __init__(self, domain, resolver, opts, dbQueue, prefix):
		RRTypeParser.__init__(self, domain, resolver, opts, dbQueue, prefix)
	
	def fetchAndStore(self):
		(r, pkt) = self.fetchAndParse()
		if not r:
			return -1
		
		self.storeRedirects(r, pkt)
		rrCount = 0
		
		if r.havedata:
			secure = validationToDbEnum(r)
			
			rrs = pkt.rr_list_by_type(self.rrType, ldns.LDNS_SECTION_ANSWER)
			
			sql = "INSERT INTO %saa_rr " % self.prefix
			sql = sql + """(secure, fqdn_id, ttl, addr)
				VALUES (%s, """+self.prefix+"""insert_unique_domain(%s), %s, %s)
				"""
			for i in range(rrs.rr_count()):
				try:
					rr = rrs.rr(i)
					self._assertRdfCount(rr)
					addr = str(rr.a_address())
					ttl = rr.ttl()
					
					sql_data = (secure, self.domain, ttl, addr)
					self.sqlExecute(sql, sql_data)
				except:
					logging.exception("Failed to parse %s for domain %s: %s" % (rr.get_type_str(), self.domain, rr))
				
			rrCount = rrs.rr_count()
		
		self.storeDnssecData(pkt, r)
		
		return rrCount

class AAAAParser(AParser):
	
	rrType = RR_TYPE_AAAA
	
class NSParser(RRTypeParser):
	
	rrType = RR_TYPE_NS
	rdfCount = 1
	
	def __init__(self, domain, resolver, opts, dbQueue, prefix):
		RRTypeParser.__init__(self, domain, resolver, opts, dbQueue, prefix)
	
	def fetchAndStore(self):
		(r, pkt) = self.fetchAndParse()
		if not r:
			return -1
		
		self.storeRedirects(r, pkt)
		rrCount = 0
		
		if r.havedata:
			secure = validationToDbEnum(r)
			
			rrs = pkt.rr_list_by_type(self.rrType, ldns.LDNS_SECTION_ANSWER)
			
			sql = "INSERT INTO %sns_rr " % self.prefix
			sql = sql + """(secure, fqdn_id, ttl, nameserver)
				VALUES (%s, """+self.prefix+"""insert_unique_domain(%s), %s, %s)
				"""
			for i in range(rrs.rr_count()):
				try:
					rr = rrs.rr(i)
					self._assertRdfCount(rr)
					nameserver = str(rr.ns_nsdname()).rstrip(".").lower()
					ttl = rr.ttl()
					
					sql_data = (secure, self.domain, ttl, nameserver)
					self.sqlExecute(sql, sql_data)
				except:
					logging.exception("Failed to parse %s for domain %s: %s" % (rr.get_type_str(), self.domain, rr))
				
			rrCount = rrs.rr_count()
		
		self.storeDnssecData(pkt, r)
		
		return rrCount

	

class DnskeyAlgo:
	
	algoMap = \
		{ 
		     1: "RSA/MD5",
		     5: "RSA/SHA-1",
		     7: "RSASHA1-NSEC3-SHA1",
		     8: "RSA/SHA-256",
		    10: "RSA/SHA-512",
		}
	
	rsaAlgoIds = algoMap.keys()

class DNSKEYParser(RRTypeParser):

	rrType = RR_TYPE_DNSKEY
	rdfCount = 4
	maxDbExp = 9223372036854775807 #maximum exponent that fits in dnskey_rr.rsa_exp field
	
	def __init__(self, domain, resolver, opts, dbQueue, prefix):
		RRTypeParser.__init__(self, domain, resolver, opts, dbQueue, prefix)
	
	def fetchAndStore(self):
		(result, pkt) = self.fetchAndParse()
		if not result:
			return -1
		
		self.storeRedirects(result, pkt)
		secure = validationToDbEnum(result)
		rrCount = 0
		
		if result.havedata:
			rrs = pkt.rr_list_by_type(self.rrType, ldns.LDNS_SECTION_ANSWER)
			
			sql = "INSERT INTO %sdnskey_rr " % self.prefix
			sql = sql + """(secure, fqdn_id, ttl, flags, protocol, algo, rsa_exp, rsa_mod, other_key)
					VALUES(%s, """+self.prefix+"""insert_unique_domain(%s), %s, %s, %s, %s, %s, %s, %s)
				"""
			
			for i in range(rrs.rr_count()):
				try:
					rr = rrs.rr(i)
					self._assertRdfCount(rr)
					ttl = rr.ttl()
					flags = rdfConvert(rr.rdf(0), "!H")
					proto = rdfConvert(rr.rdf(1), "B")
					algo = rdfConvert(rr.rdf(2), "B")
					pubkey = getRdfData(rr.rdf(3))
					
					exponent = None
					modulus = None
					other_key = None
					
					if algo in DnskeyAlgo.rsaAlgoIds: #we have RSA key
						
						#RFC 2537/3110 exponent length encoding
						exp_len0 = ord(pubkey[0])
						if exp_len0 > 0:
							exp_len = exp_len0
							exp_hdr_len = 1
						else:
							exp_len = ord(pubkey[1]) << 8 + ord(pubkey[2])
							exp_hdr_len = 3
		
						exponentBin = pubkey[exp_hdr_len:exp_hdr_len + exp_len]
						if len(exponentBin) > 0 and exponentBin[0] == '\0':
								logging.warn("Leading zero in exponent for %s: %s",
									self.domain, hexlify(exponentBin))
							
						exponent = int(hexlify(exponentBin), 16)
						if exponent > self.maxDbExp: #needs to fit into DB field
							other_key = buffer(pubkey)
							exponent = -1
						else:
							modulus  = pubkey[exp_hdr_len + exp_len:]
							if len(modulus) > 0 and modulus[0] == '\0':
								logging.warn("Leading zero in modulus for %s: %s",
									self.domain, hexlify(modulus))
								modulus = modulus.lstrip('\0')
							modulus = buffer(modulus)
						
					else: #not a RSA key
						other_key = buffer(pubkey)
					
					sql_data = (secure, self.domain, ttl, flags, proto, algo, exponent, modulus, other_key)
					self.sqlExecute(sql, sql_data)
				except:
					logging.exception("Failed to store DNSKEY RR %s", rr)
				
			rrCount = rrs.rr_count()
			
		self.storeDnssecData(pkt, result)
		
		return rrCount
	

class DSParser(RRTypeParser):
	
	rrType = RR_TYPE_DS
	rdfCount = 4
	
	def __init__(self, domain, resolver, opts, dbQueue, prefix):
		RRTypeParser.__init__(self, domain, resolver, opts, dbQueue, prefix)
	
	def fetchAndStore(self):
		(r, pkt) = self.fetchAndParse()
		if not r:
			return -1
		
		self.storeRedirects(r, pkt)
		rrCount = 0
		
		if r.havedata:
			secure = validationToDbEnum(r)
			
			rrs = pkt.rr_list_by_type(self.rrType, ldns.LDNS_SECTION_ANSWER)
			
			sql = "INSERT INTO %sds_rr " % self.prefix
			sql = sql + """(secure, fqdn_id, ttl, keytag,
					algo, digest_type, digest)
				VALUES (%s, """+self.prefix+"""insert_unique_domain(%s), %s, %s,
					%s, %s, %s)
				"""
			for i in range(rrs.rr_count()):
				try:
					rr = rrs.rr(i)
					self._assertRdfCount(rr)
					ttl = rr.ttl()
					keytag = rdfConvert(rr.rdf(0), "!H")
					algo = rdfConvert(rr.rdf(1), "B")
					digest_type = rdfConvert(rr.rdf(2), "B")
					digest = getRdfData(rr.rdf(3))
					
					sql_data = (secure, self.domain, ttl, keytag,
						algo, digest_type, buffer(digest))
					self.sqlExecute(sql, sql_data)
				except:
					logging.exception("Failed to parse %s for domain %s: %s" % (rr.get_type_str(), self.domain, rr))
				
			rrCount = rrs.rr_count()
		
		self.storeDnssecData(pkt, r)
		
		return rrCount

class SOAParser(RRTypeParser):
	
	rrType = RR_TYPE_SOA
	rdfCount = 7
	
	def __init__(self, domain, resolver, opts, dbQueue, prefix):
		RRTypeParser.__init__(self, domain, resolver, opts, dbQueue, prefix)
	
	def fetchAndStore(self):
		(r, pkt) = self.fetchAndParse()
		if not r:
			return -1
		
		self.storeRedirects(r, pkt)
		rrCount = 0
		secure = validationToDbEnum(r)
		
		#we want SOA from authority section as well to distinguish zones
		for (section, authority) in zip([ldns.LDNS_SECTION_ANSWER, ldns.LDNS_SECTION_AUTHORITY], [False, True]):
			rrs = pkt.rr_list_by_type(self.rrType, section)
			if not rrs:
				continue #if no RRs are in given section, rr_list_by_type returns None instead of empty list
			
			sql = "INSERT INTO %ssoa_rr " % self.prefix
			sql = sql + """(secure, fqdn_id, authority, ttl, zone,
				mname, rname, serial, refresh, retry, expire, minimum)
				VALUES (%s, """+self.prefix+"""insert_unique_domain(%s), %s, %s, %s,
					%s, %s, %s, %s, %s, %s, %s)
				"""
			for i in range(rrs.rr_count()):
				try:
					rr = rrs.rr(i)
					self._assertRdfCount(rr)
					ttl = rr.ttl()
					zone = authority and str(rr.owner()).rstrip(".").lower() or None
					
					mname = str(rr.rdf(0)).rstrip(".").lower()
					rname = str(rr.rdf(1)).rstrip(".").lower()
					serial = rdfConvert(rr.rdf(2), "!I")
					refresh = rdfConvert(rr.rdf(3), "!I")
					retry = rdfConvert(rr.rdf(4), "!I")
					expire = rdfConvert(rr.rdf(5), "!I")
					minimum = rdfConvert(rr.rdf(6), "!I")
					
					sql_data = (secure, self.domain, authority, ttl, zone,
						mname, rname, serial, refresh,
						retry, expire, minimum)
					self.sqlExecute(sql, sql_data)
				except:
					logging.exception("Failed to parse %s for domain %s: %s" % (rr.get_type_str(), self.domain, rr))
				
			rrCount += rrs.rr_count()
		
		self.storeDnssecData(pkt, r, [ldns.LDNS_SECTION_AUTHORITY])
		
		return rrCount

class SSHFPParser(RRTypeParser):
	
	rrType = RR_TYPE_SSHFP
	rdfCount = 3
	
	def __init__(self, domain, resolver, opts, dbQueue, prefix):
		RRTypeParser.__init__(self, domain, resolver, opts, dbQueue, prefix)
	
	def fetchAndStore(self):
		(r, pkt) = self.fetchAndParse()
		if not r:
			return -1
		
		self.storeRedirects(r, pkt)
		rrCount = 0
		
		if r.havedata:
			secure = validationToDbEnum(r)
			
			rrs = pkt.rr_list_by_type(self.rrType, ldns.LDNS_SECTION_ANSWER)
			
			sql = "INSERT INTO %ssshfp_rr " %  self.prefix
			sql = sql + """(secure, fqdn_id, ttl,
				algo, fp_type, fingerprint)
				VALUES (%s, """+self.prefix+"""insert_unique_domain(%s), %s,
					%s, %s, %s)
				"""
			for i in range(rrs.rr_count()):
				try:
					rr = rrs.rr(i)
					self._assertRdfCount(rr)
					ttl = rr.ttl()
					
					algo = rdfConvert(rr.rdf(0), "B")
					fp_type = rdfConvert(rr.rdf(1), "B")
					fingerprint = getRdfData(rr.rdf(2))
					
					sql_data = (secure, self.domain, ttl,
						algo, fp_type, buffer(fingerprint))
					self.sqlExecute(sql, sql_data)
				except:
					logging.exception("Failed to parse %s for domain %s: %s" % (rr.get_type_str(), self.domain, rr))
				
			rrCount = rrs.rr_count()
		
		self.storeDnssecData(pkt, r)
		
		return rrCount


class StorageThread(threading.Thread):
	"""Thread taking sql/sql_data from queue and executing it for storage in DB"""

	def __init__(self, db, dbQueue):
		"""Create storage thread.
		
		@param db: database connection pool, instance of db.DbPool
		@param dbQueue: instance of Queue.Queue that stores (sql,
		sql_data) tuples to be executed
		"""
		self.db = db
		self.dbQueue = dbQueue
		
		threading.Thread.__init__(self)

	def run(self):
		conn = self.db.connection()
		while True:
			sqlTuple = self.dbQueue.get()
			lastIntegrityError = None
			
			#To workaround for non-atomicity of
			#insert_unique_domain, we'll do two attempts - if the
			#first fails on duplicate key, second will work.
			for attempt in range(2):
				try:
					cursor = conn.cursor()
					sql, sql_data = sqlTuple
					cursor.execute(sql, sql_data)
					break
				except IntegrityError:
					logging.debug("IntegrityError: failed attempt %d to execute `%s` with `%s`",
						attempt+1, sql, sql_data)
					lastIntegrityError = sys.exc_info()
				except Exception:
					logging.exception("Failed to execute `%s` with `%s`",
						sql, sql_data)
					break
				finally:
					conn.commit()
			else: #this will run unless 'break' is executed in the above for loop
				logging.error("Multiple integrity failures to execute `%s` with `%s`",
					sql, sql_data, exc_info=lastIntegrityError)
				
			self.dbQueue.task_done()

class TXTParser(RRTypeParser):
	
	rrType = RR_TYPE_TXT
	rdfCount = 1 # minimal count, RFC 1035 allows multiple strings
	dbTable = "txt_rr"
	
	def __init__(self, domain, resolver, opts, dbQueue, prefix):
		RRTypeParser.__init__(self, domain, resolver, opts, dbQueue, prefix)
	
	def fetchAndStore(self):
		(r, pkt) = self.fetchAndParse()
		if not r:
			return -1
		
		self.storeRedirects(r, pkt)
		rrCount = 0
		
		if r.havedata:
			secure = validationToDbEnum(r)
			
			rrs = pkt.rr_list_by_type(self.rrType, ldns.LDNS_SECTION_ANSWER)
			
			sql = "INSERT INTO %s%s " % (self.prefix, self.dbTable)
			sql = sql + """(secure, fqdn_id, ttl, value)
					VALUES (%s, """+self.prefix+"""insert_unique_domain(%s), %s, %s)"""
			
			for i in range(rrs.rr_count()):
				try:
					rr = rrs.rr(i)
					if rr.rd_count() < self.rdfCount:
						raise DnsError("TXT RR without any data: %s" % str(rr))
					ttl = rr.ttl()
					records = [str(rr.rdf(rdfIdx)) for rdfIdx in range(rr.rd_count())]
					value = " ".join(records)
					
					sql_data = (secure, self.domain, ttl, buffer(value))
					self.sqlExecute(sql, sql_data)
				except:
					logging.exception("Failed to parse %s for domain %s: %s" % (rr.get_type_str(), self.domain, rr))
				
			rrCount = rrs.rr_count()
		
		self.storeDnssecData(pkt, r)
		
		return rrCount

class SPFParser(TXTParser):
	
	rrType = RR_TYPE_SPF
	rdfCount = 1
	dbTable = "spf_rr"

	def __init__(self, domain, resolver, opts, dbQueue, prefix):
		TXTParser.__init__(self, domain, resolver, opts, dbQueue, prefix)
	
	
class NSEC3PARAMParser(RRTypeParser):
	
	rrType = RR_TYPE_NSEC3PARAMS
	rdfCount = 4
	
	def __init__(self, domain, resolver, opts, dbQueue, prefix):
		RRTypeParser.__init__(self, domain, resolver, opts, dbQueue, prefix)
	
	def fetchAndStore(self):
		(r, pkt) = self.fetchAndParse()
		if not r:
			return -1
		
		self.storeRedirects(r, pkt)
		rrCount = 0
		
		if r.havedata:
			secure = validationToDbEnum(r)
			
			rrs = pkt.rr_list_by_type(self.rrType, ldns.LDNS_SECTION_ANSWER)
			
			sql = "INSERT INTO %snsec3param_rr" % self.prefix
			sql = sql + """(secure, fqdn_id, ttl,
				hash_algo, flags, iterations, salt)
				VALUES (%s, """+self.prefix+"""insert_unique_domain(%s), %s,
					%s, %s, %s, %s)
				"""
			for i in range(rrs.rr_count()):
				try:
					rr = rrs.rr(i)
					self._assertRdfCount(rr)
					self._assertRdfCount(rr)
					ttl = rr.ttl()
					
					hash_algo = rdfConvert(rr.rdf(0), "B")
					flags = rdfConvert(rr.rdf(1), "B")
					iterations = rdfConvert(rr.rdf(2), "!H")
					salt = getRdfData(rr.rdf(3))
					
					if len(salt) < 1:
						logging.warn("Short NSEC3PARAM salt for %s: %s",
							self.domain, rr)
					else:
						#again, salt is prefixed by length byte
						saltLen = ord(salt[0])
						salt = salt[1:]
						if saltLen != len(salt):
							logging.warn("NSEC3PARAM salt length mismatch for %s, %d != %d: %s",
								self.domain, saltLen, len(salt), rr)
					
					sql_data = (secure, self.domain, ttl,
						hash_algo, flags, iterations, buffer(salt))
					self.sqlExecute(sql, sql_data)
				except:
					logging.exception("Failed to parse %s for domain %s: %s" % (rr.get_type_str(), self.domain, rr))
				
			rrCount = rrs.rr_count()
		
		self.storeDnssecData(pkt, r)
		
		return rrCount

class MXParser(RRTypeParser):
	
	rrType = RR_TYPE_MX
	rdfCount = 2
	
	def __init__(self, domain, resolver, opts, dbQueue, prefix):
		RRTypeParser.__init__(self, domain, resolver, opts, dbQueue, prefix)
	
	def fetchAndStore(self):
		(r, pkt) = self.fetchAndParse()
		if not r:
			return -1
		
		self.storeRedirects(r, pkt)
		rrCount = 0
		
		if r.havedata:
			secure = validationToDbEnum(r)
			
			rrs = pkt.rr_list_by_type(self.rrType, ldns.LDNS_SECTION_ANSWER)
			
			sql = "INSERT INTO %smx_rr " % self.prefix
			sql = sql + """(secure, fqdn_id, ttl,
				preference, exchange)
				VALUES (%s, """+self.prefix+"""insert_unique_domain(%s), %s, %s, %s)
				"""
			for i in range(rrs.rr_count()):
				try:
					rr = rrs.rr(i)
					self._assertRdfCount(rr)
					ttl = rr.ttl()
					preference = rdfConvert(rr.mx_preference(), "!H")
					exchange = str(rr.mx_exchange()).rstrip(".").lower()
					
					sql_data = (secure, self.domain, ttl,
						preference, exchange)
					self.sqlExecute(sql, sql_data)
				except:
					logging.exception("Failed to parse %s for domain %s: %s" % (rr.get_type_str(), self.domain, rr))
				
			rrCount = rrs.rr_count()
		
		self.storeDnssecData(pkt, r)
		
		return rrCount

class TLSAParser(RRTypeParser):
	
	rrType = RR_TYPE_TLSA
	rdfCount = 1
	servicePrefix = "_443._tcp." #by default scan for port 443 tcp TLSAs
	
	def __init__(self, domain, resolver, opts, dbQueue, prefix):
		RRTypeParser.__init__(self, domain, resolver, opts, dbQueue, prefix)
	
	def fetchAndStore(self):
		# a bit dirty handling of the prefix
		domainUnprefixed = self.domain
		self.domain = self.servicePrefix + self.domain
		(r, pkt) = self.fetchAndParse()
		self.domain = domainUnprefixed
		if not r:
			return -1
		
		self.storeRedirects(r, pkt)
		rrCount = 0
		
		if r.havedata:
			secure = validationToDbEnum(r)
			
			rrs = pkt.rr_list_by_type(self.rrType, ldns.LDNS_SECTION_ANSWER)
			
			sql = "INSERT INTO %stlsa_rr " % self.prefix
			sql = sql + """(secure, fqdn_id, ttl,
				service_prefix, cert_usage, selector, matching_type, association)
				VALUES (%s, """+self.prefix+"""insert_unique_domain(%s), %s, %s, %s, %s, %s, %s)
				"""
			for i in range(rrs.rr_count()):
				try:
					rr = rrs.rr(i)
					self._assertRdfCount(rr)
					ttl = rr.ttl()
					unparsedRr = getRdfData(rr.rdf(0))
					if len(unparsedRr) < 4:
						raise ValueError("TLSA record for %s.%s too short" % (self.servicePrefix, self.domain))
					
					cert_usage = ord(unparsedRr[0])
					selector = ord(unparsedRr[1])
					matching_type = ord(unparsedRr[2])
					association = buffer(unparsedRr[3:])
					
					sql_data = (secure, self.domain, ttl,
						self.servicePrefix, cert_usage, selector, matching_type, association)
					self.sqlExecute(sql, sql_data)
				except:
					logging.exception("Failed to parse %s for domain %s: %s" % ("TLSA", self.domain, rr))
				
			rrCount = rrs.rr_count()
		
		self.storeDnssecData(pkt, r)
		
		return rrCount



class DnsScanThread(threading.Thread):

	def __init__(self, taskQueue, taFile, rrScanners, dbQueue, opts, prefix):
		"""Create scanning thread.
		
		@param taskQueue: Queue.Queue containing domains to scan as strings
		@param taFile: trust anchor file for libunbound
		@param rrScanners: list of subclasses of RRTypeParser to use for scan.
		NSParser and DSParser are always on and shouldn't be present in the list.
		@param dbQueue: Queue.Queue for passing things to store to StorageThread
		@param opts: instance of DnsConfigOptions
		@param prefix: prefix of schema
		"""
		self.taskQueue = taskQueue
		self.rrScanners = rrScanners
		self.dbQueue = dbQueue
		self.opts = opts
		self.prefix = prefix
		
		threading.Thread.__init__(self)
		
		self.resolver = ub_ctx()
		if opts.forwarder:
			self.resolver.set_fwd(opts.forwarder)
		self.resolver.add_ta_file(taFile) #read public keys for DNSSEC verification

	def run(self):
		while True:
			domain = self.taskQueue.get()
			nsRRcount = 0
			
			try:
				nsParser = NSParser(domain, self.resolver, self.opts, self.dbQueue, prefix)
				nsRRcount = nsParser.fetchAndStore()
				
				#DS RRs are in parent zone
				dsParser = DSParser(domain, self.resolver, self.opts, self.dbQueue, prefix)
				dsParser.fetchAndStore()
				
				#don't scan other RRs dependent on NS if we got SERVFAIL on NS query
				if nsRRcount >= 0:
					for parserClass in self.rrScanners:
						try:
							parser = parserClass(domain, self.resolver, self.opts, self.dbQueue, prefix)
							parser.fetchAndStore()
						except Exception:
							logging.exception("Failed to scan domain %s with %s",
								domain, parserClass.__name__)
				else:
					logging.info("No NS RRs for %s", domain)
			except:
				logging.exception("Error fetching NS RRs for %s", domain)
			finally:
				self.taskQueue.task_done()
				logging.info("Finished scanning domain %s", domain)


def convertLoglevel(levelString):
	"""Converts string 'debug', 'info', etc. into corresponding
	logging.XXX value which is returned.
	
	@raises ValueError if the level is undefined
	"""
	try:
		return getattr(logging, levelString.upper())
	except AttributeError:
		raise ValueError("No such loglevel - %s" % levelString)


class ParserParser(object):
	"""Parses selected parses from config option into class objects.
	Yeah, if we could select more ParserParsers, we'd have ParserParserParser.
	"""
	
	name2class = {
		"A": 		AParser,
		"AAAA": 	AAAAParser,
		"DNSKEY": 	DNSKEYParser,
		"MX": 		MXParser,
		"NSEC3PARAM": 	NSEC3PARAMParser,
		"SOA": 		SOAParser,
		"SPF": 		SPFParser,
		"SSHFP": 	SSHFPParser,
		"TXT": 		TXTParser,
		"TLSA": 	TLSAParser,
	}
	
	def __init__(self, configLine):
		"""Parses "parsers" config value"""
		strRRs = re.split(r",\s*", configLine)
		self.parserClasses = [self.name2class[rr] for rr in strRRs]
		

if __name__ == '__main__':
	if len(sys.argv) != 3: 
		print >> sys.stderr, "ERROR: usage: <domain_file> <scraper_config>" 
		sys.exit(1)
		
	domainFilename = sys.argv[1]
	domainFile = file(domainFilename)
	scraperConfig = SafeConfigParser()
	scraperConfig.read(sys.argv[2])
	
	threadCount = scraperConfig.getint("processing", "scan_threads")

	# prefix/schema to use in DB:
	prefix = ""
	if scraperConfig.has_option("database", "prefix"):
		prefix = scraperConfig.get("database", "prefix")
	
	sourceEncoding = "utf-8"
	if scraperConfig.has_option("dns", "source_encoding"):
		sourceEncoding = scraperConfig.get("dns", "source_encoding")
	
	#DNS resolution options
	taFile = scraperConfig.get("dns", "ta_file")
	opts = DnsConfigOptions(scraperConfig)
	if opts.unboundConfig:
		ub_ctx_config(opts.unboundConfig)
	
	#one DB connection per storage thread
	storageThreads = scraperConfig.getint("processing", "storage_threads")
	db = DbPool(scraperConfig, max_connections=storageThreads)
	
	logfile = scraperConfig.get("log", "logfile")
	loglevel = convertLoglevel(scraperConfig.get("log", "loglevel"))
	if logfile == "-":
		logging.basicConfig(stream=sys.stderr, level=loglevel,
			format="%(asctime)s %(levelname)s %(message)s [%(pathname)s:%(lineno)d]")
	else:
		logging.basicConfig(filename=logfile, level=loglevel,
			format="%(asctime)s %(levelname)s %(message)s [%(pathname)s:%(lineno)d]")
	
	logging.info("Unbound version: %s", ub_version())
	logging.info("Starting scan of domains in file %s using %d threads.", domainFilename, threadCount)
	
	taskQueue = Queue.Queue(5000)
	dbQueue = Queue.Queue(500)
	
	parserParser = ParserParser(scraperConfig.get("dns", "rrs"))
	parsers = parserParser.parserClasses
	
	for i in range(threadCount):
		t = DnsScanThread(taskQueue, taFile, parsers, dbQueue, opts, prefix)
		t.setDaemon(True)
		t.start()
	
	for i in range(storageThreads):
		t = StorageThread(db, dbQueue)
		t.setDaemon(True)
		t.start()
	
	startTime = time.time()
	domainCount = 0
	
	for line in domainFile:
		#automatically punycode-encode any IDN domains
		try:
			domainEncoded = line.rstrip()
			domain = domainEncoded.decode(sourceEncoding).encode("idna").rstrip(".").lower()
		except ValueError: #UnicodeDecodeError etc. are subclasses of ValueError
			logging.error("Could not decode string '%s' from encoding %s",
				domainEncoded, sourceEncoding)
			continue
		taskQueue.put(domain)
		domainCount += 1
		
	taskQueue.join()
	
	logging.info("Waiting for storage threads to finish")
	dbQueue.join()
	
	logging.info("Fetch of dnskeys for %d domains took %.2f seconds", domainCount, time.time() - startTime)
