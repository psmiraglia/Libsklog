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
import httplib

import sys
sys.path.append("%%%LIBDIR%%%") # NOTE: need to be set manually

from libsklog import *

"""
Class: Sklog_U
"""
		
class Sklog_U(object):
	
	__Instance = None
	
	# singleton class
	
	class Singleton:
		
		ctx = None
		
		def __init__(self):
			
			rv = SKLOG_U_NewCtx()
			
			if rv[0] == 0:
				self.ctx = None
				return
				
			self.ctx = rv[1]
			
			rv = SKLOG_U_InitCtx(self.ctx)
			
			if rv == 0:
				SKLOG_U_FreeCtx(self.ctx)
				self.ctx = None
				return
				
		def _SKLOG_U_Open_M0(self):
			
			ret = []
			
			rv = SKLOG_U_Open_M0(self.ctx)
			
			if rv[0] == 0:
				return None
				
			ret.append(rv[1])
			ret.append(rv[2])
			
			return ret
			
		def _SKLOG_U_Open_M1(self, m1_msg=None):
			
			rv = SKLOG_U_Open_M1(self.ctx, m1_msg)
			
			if rv[0] == 0:
				return None
			
			return rv[1]
			
		def _SKLOG_U_LogEvent(self, event=None, event_type=None):
			
			ret = []
			
			rv = SKLOG_U_LogEvent(self.ctx, event_type, event)
			
			if rv[0] == 0:
				return None
				
			if rv[0] == 2:
				return 'toRenew'
				
			return rv[1]
			
		def _SKLOG_U_Close(self):
			
			rv = SKLOG_U_Close(self.ctx)
			
			if rv[0] == 0:
				return None
				
			return rv[1]
	
	# methods
	
	def __init__(self):
		
		if Sklog_U.__Instance is None:
			Sklog_U.__Instance = Sklog_U.Singleton()
		self._EventHandler_instance = Sklog_U.__Instance
		
	def open_logging_session(self, hostname=None):
		
		log_entry = []
		rv = []
		
		# first step
		
		rv = self.__Instance._SKLOG_U_Open_M0()
		
		if rv is None:
			print 'Error SKLOG_U_Open_M0()'
			return None
			
		log_entry.append(rv[1])
		json_blob = '{"operation":"loggingSessionInit",\
			"data":{"m0_msg":"%s"}}' % rv[0]
			
		# connect to T
		
		c = httplib.HTTPConnection(hostname)
		c.request("POST", "/logservice", json_blob,
				  {"Content-type": "application/json"})
		r = c.getresponse()
		c.close()
		
		# parse response
		
		json_blob = r.read()
		blob = json.loads(json_blob)
		m1_msg = blob['m1_msg']
		
		# second step
		
		rv = self.__Instance._SKLOG_U_Open_M1(m1_msg)
		
		if rv is None:
			print 'Error SKLOG_U_Open_M1()'
			return None
			
		log_entry.append(rv)
		
		return log_entry
		
	def log_event(self, event_type=None, event=None):
		
		log_entry = self.__Instance._SKLOG_U_LogEvent(event, event_type)
		
		if log_entry is None:
			print 'Error SKLOG_U_LogEvent()'
			return None
			
		if log_entry is 'toRenew':
			return 'toRenew'
			
		return log_entry
		
	def close_logging_session(self):
	
		log_entry = self.__Instance._SKLOG_U_Close()
		
		if log_entry is None:
			print 'Error SKLOG_U_CLose()'
			return None
		
		return log_entry

"""
Class: Sklog_T
"""
	
class Sklog_T(object):
	
	__Instance = None
	
	# singleton class
	
	class Singleton:
		
		ctx = None
		
		def __init__(self):
			
			rv = SKLOG_T_NewCtx()
			
			if rv[0] == 0:
				self.ctx = None
				return
			
			self.ctx = rv[1]
			
			rv = SKLOG_T_InitCtx(self.ctx)
			
			if rv == 0:
				SKLOG_T_FreeCtx(self.ctx)
				return
			
		def _SKLOG_T_ManageLoggingSessionInit(self, m0_msg = None):
			
			rv = SKLOG_T_ManageLoggingSessionInit(self.ctx, m0_msg)
			
			if rv[0] == 0:
				return None
				
			return rv[1]
			
		def _SKLOG_T_ManageLogfileRetrieve(self):
			return SKLOG_T_ManageLogfileRetrieve(self.ctx)
			
		def _SKLOG_T_ManageLogfileVerify(self, logfile_id = None):
			return SKLOG_T_ManageLogfileVerify(self.ctx, logfile_id)
			
			
			return None
	
	# methods
	
	def __init__(self):
		if Sklog_T.__Instance is None:
			Sklog_T.__Instance = Sklog_T.Singleton()
		self._EventHandler_instance = Sklog_T.__Instance
		
	def manage_loging_session_init(self, m0_msg = None):
		return self.__Instance._SKLOG_T_ManageLoggingSessionInit(m0_msg)
		
	def manage_logfile_retrieve(self):
		return self.__Instance._SKLOG_T_ManageLogfileRetrieve()
		
	def manage_logfile_verify(self, logfile_id = None):
		return self.__Instance._SKLOG_T_ManageLogfileVerify(logfile_id)

"""
Class: Sklog_V
"""
	
class Sklog_V(object):
	
	__Instance = None
	
	class Singleton:
		
		def __init__(self):
			return
	
	def __init__(self):
		if Sklog_V.__Instance is None:
			Sklog_V.__Instance = Sklog_V.Singleton()
		self._EventHandler_instance = Sklog_V.__Instance
"""
class LibsklogUCtx(object):
	
	__Instance = None

	class Singleton:
		
		def __init__(self):
			self.uctx = SKLOG_U_NewCtx()
			self.sessionIsOpen = 0
		
		def _sessionIsOpen(self):
			return self.sessionIsOpen
		
		def _open(self):
			if (self.sessionIsOpen == 0):
				rv = SKLOG_U_Open(self.uctx)
				self.sessionIsOpen = 1
				return rv
			return None
			
		def _logEvent(self,eData):
			return SKLOG_U_LogEvent(self.uctx,4,eData)
			
		def _close(self):
			if (self.sessionIsOpen == 1):
				rv = SKLOG_U_Close(self.uctx)
				self.sessionIsOpen = 0
				return rv
			return None
			
		def _freeCtx(self):
			return SKLOG_U_FreeCtx(self.uctx)
	
	def __init__(self):
		if LibsklogUCtx.__Instance is None:
			LibsklogUCtx.__Instance = LibsklogUCtx.Singleton()
		self._EventHandler_instance = LibsklogUCtx.__Instance
		
	def __getattr__(self,aAttr):
		return getattr(self.__Instance,aAttr)
		
	def __setattr__(self,aAttr,aValue):
		return setattr(self.__Instance,aAttr,aValue)
		
	def sklog_open(self):
		return self.__Instance._open()
		
	def sklog_sessionIsOpen(self):
		return self.__Instance._sessionIsOpen()
		
	def sklog_logEvent(self,eData):
		return self.__Instance._logEvent(eData)
		
	def sklog_close(self):
		return self.__Instance._close()
"""
