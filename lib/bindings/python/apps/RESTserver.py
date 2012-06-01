"""
Copyright (C) 2011 Politecnico di Torino, Italy

	TORSEC group -- http://security.polito.it
	Author: Paolo Smiraglia <paolo.smiraglia@polito.it>

This file is part of Libsklog.

Libsklog is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Libsklog is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Libsklog.  If not, see <http://www.gnu.org/licenses/>.
"""

import json

import bottle
from bottle import *

import pysklog

class Logservice():
	
	app = None
	t_service = None
	
	def __init__(self):
		
		self.t_service = pysklog.Sklog_T()
		
		if self.t_service is None:
			exit(1)
	
		self.app = Bottle()
		
		self.app.route('/logservice', method='POST', callback=self._logservice)
		self.app.route('/logservice', method='GET', callback=self._index)
		
	def run(self):
		
		bottle.run(self.app, host="127.0.0.1", port=9000)
	
	"""
	Callback
	"""
	
	def _index(self):
		
		return '<html><head><title>TClouds LogService</title></head><body><h1>Welcome to TClouds LogService</h1></body></html>'
	
	def _logservice(self):
		
		"""
		Expected json structure
		
			{
				"operation": "...",
				"data": {
					"...": "..."
					"...": "..."
					"...": "..."
				}
			}
		
		"""
		
		req_data = request.json
		
		req_op = req_data['operation']
		
		if req_op == 'loggingSessionInit':
			return self.loggingSessionInit(self.t_service,
										   req_data['data'])
		elif req_op == 'retrieveLogfiles':
			return self.retrieveLogfiles(self.t_service)
		elif req_op == 'verifyLogfile':
			return self.verifyLogfile(self.t_service, req_data['data'])
		else:
			return '<h1>What???</h1>'
			
	"""
	Methods
	"""
	
	def loggingSessionInit(self, t, req_data):
		"""
		Expected json structure
		
			"data": {
				"m0_msg": "<base64 encoded message>"
			}
		"""
		
		m1 = t.manage_loging_session_init(req_data['m0_msg'])
		
		if m1[0] == 0:
			return '{"result": "failure"}'
		else:
			return '{ "result": "success", "m1_msg": "%s"}' % m1[1]
	
	def retrieveLogfiles(self, t):
		"""
		Expected json structure
		
			"data":{
				...
			}
		"""
		
		rv = t.manage_logfile_retrieve()
		
		if rv == 0:
			return '{"result": "failure"}'
		else:
			json_array = json.JSONEncoder().encode(rv)
			return '{"result": "success", "logfiles": %s}' % json_array
		
	def verifyLogfile(self, t, req_data):
		"""
		Expected json structure
		
			"data": {
				"logfile_id": "fb17310ea4d511e1828c0025b345ca14"
			}
		"""
		logfile_id = req_data['logfile_id']
		r = t.manage_logfile_verify(logfile_id)
		
		if r == 0:
			return '{"operation":"verifyLogfile", "logfile_id": "%s", "result": "system error"}' % logfile_id
		elif r == -1:
			return '{"operation":"verifyLogfile", "logfile_id": "%s", "result": "failure"}' % logfile_id
		else:
			return '{"operation":"verifyLogfile", "logfile_id": "%s", "result": "success"}' % logfile_id
		
#
# main
#		

if __name__ == '__main__':
	
	ls = Logservice()
	ls.run()
