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

import pysklog

if __name__ == '__main__':
	
	log_entry = []
	
	u = pysklog.Sklog_U()
	
	# open logging session
	
	log_entry = u.open_logging_session("localhost:9000")
	
	if log_entry is None:
		print 'Error open_logging_session()'
		exit(1)
	
	print log_entry
	
	# log dummy events
	
	f = open('rawdata.dat', 'r')
	
	for event in f:
		
		log_entry = u.log_event(4, event)
		
		if log_entry is None:
			f.close()
			print 'Error u.log_event()'
			exit(1)
			
		if log_entry is 'toRenew':
			f.close()
			
			log_entry = u.close_logging_session()
			
			u.upload_logfile("localhost:9000")

	
			if log_entry is None:
				print 'Error u.close_logging_session()'
				
			print log_entry
			
			exit(0)
		
		print log_entry
	
	f.close()
	
	u.dump_logfile('fooDump.json')
	
	log_entry = u.close_logging_session()
	
	u.upload_logfile("localhost:9000")
	
	if log_entry is None:
		print 'Error u.close_logging_session()'
		exit(1)
		
	print log_entry
	
	exit(0)
