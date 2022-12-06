"""
TCP stream extraction using Scapy.
(c) Praetorian
Author: Adam Pridgen <adam.pridgen@praetorian.com> || <adam.pridgen@thecoverofnight.com>
This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation; either version 3, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.
You should have received a copy of the GNU General Public License along
with this program; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301, USA.
Description: tracks TCPStream state between a client and server

"""
#from scapy.all import *
#from random import randint
#from .tcp_snd import Snd
#from .tcp_rcv import Rcv


is_syn_pkt = lambda pkt: 'TCP' in pkt and pkt['TCP'].flags == TCP_FLAGS['S']
is_synack_pkt = lambda pkt: 'TCP' in pkt and pkt['TCP'].flags == (TCP_FLAGS['S'] | TCP_FLAGS['A'])

class Flow:
	def __init__(self, pkt):
		self.src = pkt['IP'].src, pkt['IP'].sport
		self.dst = pkt['IP'].dst, pkt['IP'].dport
	def __hash__(self):
		return hash(self.forward)
	def __lt__(self, rhs):
		return (
			self.src[0] < rhs.src[0] or
			(self.src[0] == rhs.src[0] and self.src[1] < rhs.src[1]) or
			(self.src == rhs.src and
				(self.dst[0] < rhs.dst[0] or
				(self.dst[0] == rhs.dst[0] and self.dst[1] < rhs.dst[1])))
		)
	def __str__(self):
		return f"{self.src[0]:>15}:{self.src[1]:<5} ==> {self.dst[0]:>15}:{self.dst[1]:<5}"
	@property
	def forward(self):
		return self.src, self.dst
	@property
	def reverse(self):
		return self.dst, self.src

#create_pkt_flow = lambda pkt: "%s:%s ==> %s:%s"%(pkt['IP'].src,str(pkt['IP'].sport),pkt['IP'].dst,str(pkt['IP'].dport))


#create_forward_flow = lambda pkt: "%s:%s ==> %s:%s"%(pkt['IP'].src,str(pkt['IP'].sport),pkt['IP'].dst,str(pkt['IP'].dport))
#def create_forward_flow(pkt):
#	return tuple(pkt['IP'].src, pkt['IP'].sport, pkt['IP'].dst, pkt['IP'].dport)

#create_reverse_flow = lambda pkt: "%s:%s ==> %s:%s"%(pkt['IP'].dst,str(pkt['IP'].dport),pkt['IP'].src,str(pkt['IP'].sport))
#def create_reverse_flow(pkt):
#	ff = create_forward_flow(pkt):
#	return tuple(ff[2], ff[3], ff[0], ff[1])

#create_flow = create_forward_flow


TCP_FLAGS = {
	"F":0x1,
	"S":0x2,
	"R":0x4,
	"P":0x8,
	"A":0x10,
	"U":0x20,
	"E":0x40,
	"C":0x80,
	0x1:"F",
	0x2:"S",
	0x4:"R",
	0x8:"P",
	0x10:"A",
	0x20:"U",
	0x40:"E",
	0x80:"C"
}

TCP_STATES = {
	"LISTEN": {
		'S':["SYN_RCVD", 'SA']
	},
	"SYN_SENT": {
		'SA': ["ESTABLISHED", 'A'],
		'S': ["SYN_RCVD", 'SA'],
	},
	"SYN_RCVD": {
		'F': ["FIN_WAIT_1", 'A'],
		'A': ["ESTABLISHED", ''],
		'R': ["LISTEN", ''],
	},
	"LAST_ACK":{},
	"CLOSE_WAIT": {	 # initiated by the server
		"": ["LAST_ACK","F"]
	},
	"LAST_ACK": {
		"A": ["CLOSED",""]
	},
	"ESTABLISHED": {
		"F": ["FIN_WAIT_1",""],
	},
	"FIN_WAIT_1": {
		"A": ["FIN_WAIT_2",""],
		"F": ["CLOSED","A"],
		"FA": ["TIME_WAIT","A"],
	},
	"FIN_WAIT_2": {
		"F":["TIME_WAIT","A"],
	},
	"CLOSED": {
		"A":["TIME_WAIT", ""],
	},
}

TCP_CLIENT_STATES = {
	'CLOSED': {
		'S': 'SYN_SENT',
	}
	'SYN_SENT': {

	}
}

TCP_SERVER_STATES = {
	'LISTEN': {
		'S' : {'SYN_RCVD'}
	}
}


flags_equal = lambda pkt, flag: pkt['TCP'].flags == flag
flags_set = lambda pkt, flag: (pkt['TCP'].flags & flag) != 0

class TCPStateMachine:
	def __init__(self, pkt=None):
		if not pkt is None:
			self.init(pkt)

	def init(self, pkt):
		if not 'TCP' in pkt:
			raise Exception("Not a TCP Packet")
		if not is_syn_pkt(pkt):
			raise Exception("Not valid SYN")

		self.flow = Flow(pkt) # client => server

		# 0 is now, 1 is the future Flags
		self.server_state = "LISTEN"
		self.client_state = "SYN_SENT"

		self.server_close_time = -1.0
		self.client_close_time = -1.0
		self.fin_wait_time = -1.0

	@property
	def client(self):
		return self.flow.src
	@property
	def server(self):
		return self.flow.dst

	def next_state(self, pkt):
		if not 'TCP' in pkt:
			raise Exception("Not a TCP Packet")

		# determine in what context we are handling this packet
		flow = Flow(pkt)
		if flow.forward != self.flow and flow.reverse != self.flow:
			raise Exception("Not a valid packet for this model")

		if flow.dst == self.server:
			v =  self.handle_client_pkt(pkt)
			if self.is_fin_wait():
				self.fin_wait_time = pkt.time
			return v
		else:
			v = self.handle_server_pkt(pkt)
			if self.is_fin_wait():
				self.fin_wait_time = pkt.time
			return v


		raise Exception("Not a valid packet for this model")


	def get_states(self):
		return (self.client_state, self.server_state)


	def build_flags(self, sflags):
		return sum([TCP_FLAGS[i] for i in sflags])


	def active_close(self):
		return (self.client_state == self.server_state and self.server_state == "CLOSED")

	def passive_close(self):
		return (self.client_state == "LAST_ACK" and self.server_state == "CLOSE_WAIT")

	def is_established(self):
		return (self.client_state == self.server_state and self.server_state == "ESTABLISHED")

	def client_prehandshake(self):
		return (self.client_state == "SYN_SENT") or (self.client_state == "SYN_RCVD")

	def server_prehandshake(self):
		return (self.server_state == "SYN_SENT") or (self.server_state == "SYN_RCVD") or (self.server_state == "LISTEN")

	def is_fin_wait(self):
		return self.client_state.find("FIN_WAIT") > -1 or self.server_state.find("FIN_WAIT") > -1
	def is_prehandshake(self):
		return self.client_prehandshake() and self.server_prehandshake()

	def is_closed(self):
		return self.passive_close() or self.active_close()

	def handle_client_pkt(self, pkt):
		flags = pkt['TCP'].flags
		client_got_closed = False
		server_got_closed = False

		if flags == self.build_flags("R"):
			self.client_state = "CLOSED"
			self.server_state = "CLOSED"
			server_got_closed = True
			client_got_closed = True

		elif flags == self.build_flags("RA"):
			self.client_state = "CLOSED"
			self.server_state = "CLOSED"
			server_got_closed = True
			client_got_closed = True
		elif flags == self.build_flags("S"):
			self.server_state = "SYN_SENT"

		elif self.client_state == "SYN_SENT":
			if flags & self.build_flags("A") > 0:
				self.client_state = "ESTABLISHED"
				self.server_state = "ESTABLISHED"
			else:
				self.client_state = "CLOSED"
				server_got_closed = pkt.time
				client_got_closed = pkt.time
				return self.is_closed()

		elif self.client_state == "SYN_SENT":
			if flags & self.build_flags("SA") > 0:
				self.client_state = "SYN_RCVD"

		elif self.client_state == "SYN_RCVD" and\
			  flags & self.build_flags("F") > 0:
				self.client_state = "FIN_WAIT_1"

		elif self.client_state == "ESTABLISHED" and\
			flags == self.build_flags("FA"):
			self.client_state = "FIN_WAIT_1"

		elif self.client_state == "FIN_WAIT_1" and\
			flags == self.build_flags("A"):
			self.client_state = "CLOSED"

		elif self.client_state == "ESTABLISHED" and\
			self.server_state == "CLOSE_WAIT" and\
			flags & self.build_flags("A") > 0:
			self.client_state = "CLOSED"

		if self.server_state == "FIN_WAIT_1" and\
			self.client_state == "CLOSED" and\
			flags == self.build_flags("A"):
			self.server_state = "CLOSED"
			server_got_closed = True
			client_got_closed = True

		if client_got_closed:
			self.client_close_timed = pkt.time
		if server_got_closed:
			self.server_close_timed = pkt.time

		return self.is_closed()

	def handle_server_pkt(self, pkt):
		flags = pkt['TCP'].flags
		server_got_closed = False
		client_got_closed = False

		if flags == self.build_flags("R"):
			self.client_state = "CLOSED"
			self.server_state = "CLOSED"
			server_got_closed = True
			client_got_closed = True

		elif flags == self.build_flags("RA"):
			self.client_state = "CLOSED"
			self.server_state = "CLOSED"
			server_got_closed = True
			client_got_closed = True

		elif flags == self.build_flags("S"):
			self.server_state = "SYN_SENT"
		elif self.server_state == "LISTEN" and\
			flags == self.build_flags("SA"):
			self.server_state = "SYN_RCVD"

		elif self.server_state == "ESTABLISHED" and\
			flags == self.build_flags("FA"):
			self.server_state = "FIN_WAIT_1"

		elif self.server_state == "FIN_WAIT_1" and\
			flags == self.build_flags("A"):
			self.server_state = "CLOSED"
			server_got_closed = True


		elif self.server_state == "SYN_RCVD" and\
			flags == self.build_flags("F"):
			self.server_state = "FIN_WAIT_1"

		elif self.server_state == "FIN_WAIT_1" and\
			flags == self.build_flags("FA"):
			self.server_state = "CLOSED"

		elif self.server_state == "SYN_RCVD" and\
			flags == self.build_flags("A"):
			self.server_state = "ESTABLISHED"

		elif self.server_state == "ESTABLISHED" and\
			flags & self.build_flags("F") > 0:
			self.server_state = "CLOSE_WAIT"

		elif self.client_state == "FIN_WAIT_1" and\
			flags == self.build_flags("FA"):
			self.server_state = "CLOSED"
			server_got_closed = True

		elif self.client_state == "CLOSED" and\
			flags == self.build_flags("A"):
			self.server_state = "CLOSED"
			server_got_closed = True

		if self.client_state == "FIN_WAIT_1" and\
			self.server_state == "CLOSED" and\
			flags == self.build_flags("A"):
			self.client_state = "CLOSED"
			client_got_closed = True

		if client_got_closed:
			self.client_close_timed = pkt.time
		if server_got_closed:
			self.server_close_timed = pkt.time

		return self.is_closed()

