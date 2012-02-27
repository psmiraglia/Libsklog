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

class LibsklogUCtx(object):
	
	__Instance = None
	
	class Singleton:
		def __init__(self):
			self.uctx = None
	
	def __init__(self):
		if LibsklogUCtx.__Instance is None:
			LibsklogUCtx.__Instance = LibsklogUCtx.Singleton()
		self._EventHandler_instance = LibsklogUCtx.__Instance
	
	def __getattr__(self,aAttr):
		return getattr(self.__Instance,aAttr)
		
	def __setattr__(self,aAttr,aValue):
		return setattr(self.__Instance,aAttr,aValue)

## Test script to prove that it actually works        
if __name__ == "__main__":
 
    # create a first object
    a = LibsklogUCtx()
 
    # get and print class variable foo
    print a.uctx
 
    # create a second object
    b = LibsklogUCtx()
 
    # set a string to the class variable foo
    b.uctx = 400
 
    # create a third object
    c = LibsklogUCtx()
 
    # get and print class variable foo for object a
    print a.uctx
 
    # get and print class variable foo for object c
    print c.uctx

