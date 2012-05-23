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

import sys
import json

import bottle
from bottle import *

sys.path.append("%%%LIBDIR%%%") # NOTE: need to be set manually

import libsklog
from libsklog import *

class Logservice():
	
	app = None
	ctx = None
	
	def __init__(self):
		
		self.ctx = SKLOG_T_NewCtx()
		SKLOG_T_InitCtx(self.ctx)
	
		self.app = Bottle()
		
		self.app.route('/logservice', method='POST', callback=self._logservice)
		self.app.route('/logservice', method='GET', callback=self._index)
		
	def run(self):
		bottle.run(self.app, host="127.0.0.1", port=9000)
	
	"""
	Callback
	"""
	
	def _index(self):
		return '<h1>Welcome to TClouds LogService</h1>'
	
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
			
			return self.loggingSessionInit(self.ctx, req_data['data'])
			
		elif req_op == 'retrieveLogfiles':
			
			return self.retrieveLogfiles(self.ctx)
			
		elif req_op == 'verifyLogfile':
			
			return self.verifyLogfile(self.ctx, req_data['data'])
			
		else:
			return '<h1>What???</h1>'
			
	"""
	Methods
	"""
	
	
	def loggingSessionInit(self, ctx, req_data):
		
		"""
		Expected json structure
		
			"data": {
				"m0_msg": "<base64 encoded message>"
			}
		"""
		
		b64 = req_data['m0_msg']
		
		m1 = SKLOG_T_ManageLoggingSessionInit(ctx, b64)
		
		if m1 == 0:
			return '{"result": "failure"}'
		else:
			return '{ "result": "success", "m1_msg": "%s"}' % m1
	
		
	def retrieveLogfiles(self, ctx):
		
		"""
		Expected json structure
		
			"data": {
				"m0_msg": "<base64 encoded message>"
			}
		"""
		
		t = SKLOG_T_ManageLogfileRetrieve(ctx)
		
		if t == 0:
			return '{"result": "failure"}'
		else:
			json_array = json.JSONEncoder().encode(t)
			return '{"result": "success", "logfiles": %s}' % json_array
		
	def verifyLogfile(self, ctx, req_data):
		
		"""
		Expected json structure
		
			"data": {
				"logfile_id": "fb17310ea4d511e1828c0025b345ca14"
			}
		"""
		
		logfile_id = req_data['logfile_id']
		
		r = SKLOG_T_ManageLogfileVerify(ctx, logfile_id)
		
		if r == 0:
			return '{"result": "failure"}'
		else:
			return '{"result": "success"}'
		
#
# main
#		

if __name__ == '__main__':
	
	ls = Logservice()
	ls.run()
