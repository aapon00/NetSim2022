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
Description: tracks extracted streams [TCPStream] and removes the streams if they are timedout

"""


import scapy, threading
import gc
from threading import *
from random import randint
from scapy.all import *

from .tcp_stream import TCPStream
from .tcp_state import Flow, is_syn_pkt

CLEANUP = True
CLEANUP_THREAD = None



def thread_maintanence(timer_val, stream_extractor, timeout=1000):
	new_threads = []
	print ("Maintanence thread was called!")
	stream_extractor.cleanup_timedout_streams(timeout)
	if not stream_extractor.cleanup:
		print ("Maintanence thread was called, but nothing to maintain")
		return
	#gc.collect()
	CLEANUP_THREAD = threading.Timer(timer_val, thread_maintanence, args=(timer_val,stream_extractor ))
	CLEANUP_THREAD.start()




class TCPStreamExtractor:
	def __init__(self, filename, packet_list=None, process_packets=True,
				 outputdir=None, pcap_filters=None, count=-1):
		self.filename = filename

		self.pcap_filter = pcap_filters
		self.outputdir=outputdir

		if not self.outputdir is None:
			if not os.path.exists(self.outputdir):
				os.mkdir(self.outputdir)
			if not os.path.exists(os.path.join(self.outputdir, "pcaps")):
				os.mkdir(os.path.join(self.outputdir, "pcaps"))
			if not os.path.exists(os.path.join(self.outputdir, "flows")):
				os.mkdir(os.path.join(self.outputdir, "flows"))

		self.packet_list = packet_list
		if packet_list is None:
			self.packet_list =scapy.utils.rdpcap(filename, count=count)

		self.pkt_num = 0
		# a stream is mapped under two flow keys
		self.streams = {}
		self.timestamp = 0
		self.DEL_LOCK = threading.Lock()
		self.cleanup = True
		self.timer = 4.0
		self.data_streams = {}


		if process_packets:
			self.process_packets()


	def __next__(self):
		if self.pkt_num >= len(self.packet_list):
			return None

		pkt = self.packet_list[self.pkt_num]

		self.pkt_num += 1
		self.timestamp = int(pkt.time)

		if 'IP' not in pkt or 'TCP' not in pkt:
			return pkt

		flow = Flow(pkt)

		if flow not in self.streams and is_syn_pkt(pkt):
			self.streams[flow] = TCPStream(pkt)
		elif flow in self.streams:
			self.streams[flow].add_pkt(pkt)

		return pkt

	@property
	def fwd_flows(self):
		for s in self.streams:
			yield s.forward
	@property
	def rev_flows(self):
		for s in self.streams:
			yield s.reverse

	def process_packets(self):
		while self.pkt_num < len(self.packet_list):
			next(self)

		# create data streams
		for session, stream in self.streams.items():
			self.data_streams[session] = stream.get_stream_data()
		return self.pkt_num, self.data_streams

	def summary(self):
		for flow in sorted(list(self.streams)):
			c_addr, c_port = self.streams[flow].client
			s_addr, s_port = self.streams[flow].server

			http = self.data_streams[flow]
			c_str_sz = len(http.get(c_port, []))
			s_str_sz = len(http.get(s_port, []))
			n_pkts = len(self.streams[flow].pkts)

			f = f"{flow} (p) {n_pkts:3d} (c) {c_str_sz:3d} (s) {s_str_sz:3d}"
			yield f

	def get_client_server_streams(self, key=None):
		keys = sorted(list(self.streams)) if key is None else [key]
		c_port = lambda f: int(f.split(':')[1].split()[0])
		s_port = lambda f: int(f.split(':')[-1])
		results = {}
		for sess in keys:
			http = self.data_streams[sess]
			client = http[c_port(sess)]
			server = http[s_port(sess)]
			results[sess] = {'client': client, 'server': server}
		# print ('\n'.join(results))
		if len(keys) == 1:
			return list(results.values())[0]
		return results

	def run(self):
		global CLEANUP_THREAD
		try:
			CLEANUP_THREAD = threading.Timer(self.timer, thread_maintanence, args=(self.timer, self ))
			CLEANUP_THREAD.start() # Duh! me needs to start or nom nom nom memories!
			self.process_packets()
		except KeyboardInterrupt:
			self.cleanup = False
			CLEANUP_THREAD.cancel()
			if CLEANUP_THREAD.is_alive():
				CLEANUP_THREAD.join()

		except StopIteration:
			self.cleanup = False
			CLEANUP_THREAD.cancel()
			if CLEANUP_THREAD.is_alive():
				CLEANUP_THREAD.join()
			streams = list(self.streams.keys())
			for stream in streams:
				self.write_stream(stream)


	def cleanup_timedout_streams(self, timeout=180.0):
		timestamp = self.timestamp
		purged_streams = set()

		# dont want streams changing underneath us
		keys = list(self.streams.keys())
		for key in keys:
			if not key in self.streams:
				continue
			pkt_cnt = self.streams[key].len_pkts()
			l_ts = int(self.streams[key].time)
			if (timestamp - l_ts) > timeout:
				print(("Timeout occurred: %s - %s => %s, Writing stream: %s"%(str(timestamp),str(l_ts), str(timestamp-l_ts), key)))
				purged_streams.add(key)
				self.write_stream(key)
				self.remove_stream(key)
				print(("%s purged from current streams"%key))

			elif pkt_cnt > 10000:
				print(("Writing %d of %d packets from stream: %s"%(pkt_cnt,self.streams[key].len_pkts(), self.streams[key].get_stream_name())))
				self.write_stream(key, pkt_cnt)
				self.streams[key].destroy(pkt_cnt)
				print(("***Wrote %d packets for stream: %s"%(pkt_cnt,self.streams[key].get_stream_name())))
		print(("Purged %d streams of %d from evaluated streams\n\n"%(len(purged_streams), len(keys)/2)))

	def get_streams(self):
		return self.data_streams

	def remove_stream(self, key):
		# dont call in cleanup stream, it will deadlock
		if not key in self.streams:
			return
		self.DEL_LOCK.acquire()
		flows = self.streams[key].flows
		self.streams[list(flows)[0]].destroy()
		for i in flows:
			#self.streams[i].destroy()
			del self.streams[i]
		self.DEL_LOCK.release()

	def write_stream(self, key,pkts_cnt=0):
		if not key in self.streams:
			return
		self.DEL_LOCK.acquire()
		stream = self.streams[key]
		stream_name = stream.get_stream_name()
		filename = stream_name
		pcap_fname = filename
		flow_fname = filename

		if not self.outputdir is None:
			odir = os.path.join(self.outputdir, "pcaps")
			pcap_fname = os.path.join(odir, stream_name)
			odir = os.path.join(self.outputdir, "flows")
			flow_fname = os.path.join(odir, stream_name)

		stream.write_pcap(pcap_fname, pkts_cnt)
		stream.write_flow(flow_fname, pkts_cnt)

		self.DEL_LOCK.release()