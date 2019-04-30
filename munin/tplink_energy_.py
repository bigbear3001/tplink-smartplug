#!/usr/bin/env python2
#
# TP-Link Wi-Fi Smart Plug Munin Plugin
# For use with TP-Link HS-100 or HS-110
#
# by Andreas Perhab
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import sys
import socket
from struct import pack
import os.path
import json

version = 0.2

# Check if hostname is valid
def validHostname(hostname):
	try:
		socket.gethostbyname(hostname)
	except socket.error:
		raise Exception("Invalid hostname.")
	return hostname

# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171
def encrypt(string):
	key = 171
	result = pack('>I', len(string))
	for i in string:
		a = key ^ ord(i)
		key = a
		result += chr(a)
	return result

def decrypt(string):
	key = 171
	result = ""
	for i in string:
		a = key ^ ord(i)
		key = ord(i)
		result += chr(a)
	return result

script = os.path.basename(sys.argv[0])
ip = validHostname(script.split('_')[-1])

# Set target IP, port and command to send
port = 9999
cmd = '{"emeter":{"get_realtime":{}}}'
config_cmd = '{"system":{"get_sysinfo":{}}}'

try:
	sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock_tcp.connect((ip, port))

	if len(sys.argv) > 1 and sys.argv[1] == 'config':
		# Send command and receive reply
		sock_tcp.send(encrypt(config_cmd))
		data = sock_tcp.recv(2048)
		sock_tcp.close()

		#	print "Sent:     ", cmd
		#print "Received: ", decrypt(data[4:])
		info = json.loads(decrypt(data[4:]))
		print "graph_title TP-Link %s" % info['system']['get_sysinfo']['alias']
		print "graph_args -l 0"
		print "graph_vlabel A/V/W"
		print "graph_category power"
		print "current.label Current [A]"
		print "voltage.label Voltage [V]"
		print "power.label Power [W]"
		#print "current.value %f" % energy['emeter']['get_realtime']['current']
		#print "voltage.value %f" % energy['emeter']['get_realtime']['voltage']
		#print "power.value %f" % energy['emeter']['get_realtime']['power']
	else:
		sock_tcp.send(encrypt(cmd))
		data = sock_tcp.recv(2048)
		sock_tcp.close()

	#	print "Sent:     ", cmd
	#	print "Received: ", decrypt(data[4:])
		energy = json.loads(decrypt(data[4:]))
		realtime_ = energy['emeter']['get_realtime']
		if 'current' in realtime_:
			print "current.value %f" % realtime_['current']
			print "voltage.value %f" % realtime_['voltage']
			print "power.value %f" % realtime_['power']
		else:
			print "current.value %f" % (realtime_['current_ma'] * 0.001)
			print "voltage.value %f" % (realtime_['voltage_mv'] * 0.001)
			print "power.value %f" % (realtime_['power_mw'] * 0.001)
except socket.error:
	quit("Cound not connect to host " + ip + ":" + str(port))

