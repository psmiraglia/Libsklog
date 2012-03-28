'''
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
'''

import sys

sys.path.append("../../.libs")

from libsklog import *

class LibsklogUCtx(object):
	
	__Instance = None

	class Singleton:
		
		def __init__(self):
			self.uctx = SKLOG_U_NewCtx()
			self.sessionIsOpen = 0
		
		def _open(self):
			if (self.sessionIsOpen == 0):
				rv = SKLOG_U_Open(self.uctx)
				self.sessionIsOpen = 1
				return rv
			return ""
			
		def _sessionIsOpen(self):
			return self.sessionIsOpen
			
		def _logEvent(self,eData):
			return SKLOG_U_LogEvent(self.uctx,4,eData)
			
		def _close(self):
			if (self.sessionIsOpen == 1):
				rv = SKLOG_U_Close(self.uctx)
				self.sessionIsOpen = 0
				return rv
			return ""
			
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
		
	def sessionIsOpen(self):
		return self.__Instance._sessionIsOpen()
		
	def sklog_logEvent(self,eData):
		return self.__Instance._logEvent(eData)
		
	def sklog_close(self):
		return self.__Instance._close()

## Test script to prove that it actually works        

if __name__ == "__main__":
	
	le = []
	tmp = []
	
	ctx = LibsklogUCtx()
	
	tmp = ctx.sklog_open()
	le.append(tmp[0])
	le.append(tmp[1])
	le.append(ctx.sklog_log_event("Ciao"))
	le.append(ctx.sklog_log_event("Bao"))
	le.append(ctx.sklog_log_event("Miao"))
	le.append(ctx.sklog_close())
	
	for i in le:
		print i
	
	

