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

data_to_log = (
	'Etiam ut ornare lacinia arcu ultrices sit.',
	'Neque scelerisque volutpat, orci aptent nisi, ut tellus tincidunt senectus, taciti nostra urna.',
	'Dignissim tempus cum cubilia.',
	'Ligula dolor hymenaeos natoque.',
	'Sapien, ac magnis egestas.',
	'Consectetuer eu commodo mi, facilisi primis, nascetur parturient.',
	'Quam eu massa diam dapibus euismod pede.',
	'At sapien ac dolor.',
	'Velit fames semper libero.',
	'Dictum.',
	'Mauris porta bibendum per, conubia sagittis feugiat accumsan et elit.',
	'Eleifend parturient semper vel, mattis ultrices.',
	'Nulla orci velit, class nostra quis nisl lacus.',
	'Cum rutrum hymenaeos.',
	'Magnis vehicula, ullamcorper habitant iaculis eleifend dictum tortor erat.',
	'VM (instance-00000001.img) creation',
	'Natoque quis, mi leo consequat taciti rutrum lacus dis.',
	'Purus primis sem, inceptos elementum quis scelerisque vivamus dui.',
	'Diam volutpat non, tellus mus taciti, arcu condimentum aliquet fusce quis tempus.',
	'Congue.',
	'Tempor, et sit tincidunt platea a gravida tellus, semper nibh ullamcorper id, tempor rhoncus feugiat auctor pede et.',
	'Purus auctor in habitant nunc facilisi leo, euismod a, nullam fames.',
	'Proin ad hymenaeos pede, integer ipsum.',
	'Sociis odio, dignissim nostra.',
	'Nonummy id, justo.',
	'Ornare venenatis varius lacus pulvinar dignissim pellentesque adipiscing duis hymenaeos varius vestibulum.',
	'Fusce ac netus consectetuer.',
	'Integer, sollicitudin platea etiam eget.',
	'Quam curae luctus eget, mi tincidunt.',
	'Congue convallis platea metus hac.',
	'Ut, mus ut tempor eu.',
	'Sodales quam est mattis quisque, nonummy.',
	'Nulla velit nibh dis eget adipiscing mi, lobortis aptent.',
	'Sit eros vivamus at, vitae et urna lorem.',
	'Odio ut duis interdum auctor.',
	'Tincidunt.',
	'Mi curabitur a, curabitur.',
)

uctx = pysklog.LibsklogUCtx()

init_logs = uctx.sklog_open()

print init_logs[0]
print init_logs[1]

for l in data_to_log:
	log = uctx.sklog_log_event(l)
	print log
	
close_log = uctx.sklog_close()
	

