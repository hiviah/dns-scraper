#   This file is part of the Perspectives Notary Server
#
#   Copyright (C) 2011 Ondrej Mikle, CZ.NIC Labs
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

import logging
import ConfigParser


Config = None #singleton NotaryServerConfig instance

class NotaryServerConfig(object):
	"""Configuration parser for notary server"""

	def __init__(self, filename):
		"""Parses supplied config file, see notary.config.sample
		@raises ConfigParser.Error if entries are badly formed or missing
		"""
		parser = ConfigParser.SafeConfigParser()
		parser.read(filename)

		self.db_host = parser.get("database", "host")
		self.db_port = parser.getint("database", "port")
		self.db_user = parser.get("database", "user")
		self.db_password = parser.get("database", "password")
		self.db_name = parser.get("database", "dbname")
		self.db_min_conn = parser.getint("database", "min_connections")
		self.db_max_conn = parser.getint("database", "max_connections")

		self.keyfile = parser.get("keys", "private")

		self.use_sni = parser.getboolean("server", "use_sni")
		
		self.app_log = parser.get("server", "app_log")
		self.app_loglevel = self.convertLoglevel(parser.get("server", "app_loglevel"))
		self.scanner_log = parser.get("server", "scanner_log")
		self.scanner_loglevel = self.convertLoglevel(parser.get("server", "scanner_loglevel"))
		
		self.cherrypy_config = parser.get("server", "cherrypy_config")
		
		self.on_demand_scan_threads = parser.getint("server", "on_demand_scan_threads")
		self.on_demand_scan_timeout = parser.getint("server", "on_demand_scan_timeout")
		self.on_demand_storage_threads = parser.getint("server", "on_demand_storage_threads")
		
	
	@staticmethod
	def convertLoglevel(levelString):
		"""Converts string 'debug', 'info', etc. into corresponding
		logging.XXX value which is returned.
		@raises ConfigParser.Error if the level is undefined"""
		try:
			return getattr(logging, levelString.upper())
		except AttributeError:
			raise ConfigParser.Error("No such loglevel - %s" % levelString)

def config_initialize(filename):
	"""Initializes Config singleton object using the specifiled filename
	@paramfilename: config filename"""
	
	global Config
	Config = NotaryServerConfig(filename)


