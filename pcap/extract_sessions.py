#!/usr/bin/env python3

import os
import argparse
import scapy.all

from tcp.tcp_state import Flow, is_syn_pkt

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	ap.add_argument('-o', '--outpath', type=str, default='.')
	ap.add_argument('--quiet', action='store_true')
	ap.add_argument('--limit', type=int)
	ap.add_argument('--checkpoint', type=int, help='print a message every X packets')
	ap.add_argument('--proto', choices=['tcp', 'udp'], default='tcp')
	return ap.parse_args()

def main():
	args = arguments()

	first_ts = None
	f = None
	proto = args.proto.upper()
	reader = None
	count = 0

	sessions = {}
	session_iter = 0

	try:
		reader = Reader(args.infile, limit=args.limit)
#		reader = scapy.all.PcapReader(args.infile)

		for pkt, sec, usec in reader:
			if 'IP' not in pkt:
				continue

			if proto not in pkt:
				continue

			count += 1
			if args.limit and count > args.limit:
				break

			flow = Flow(pkt)

			if is_syn_pkt(pkt) and flow not in sessions:
				sessions[flow] = session_iter
				session_iter += 1

			if flow in sessions:
				fn = os.path.join(args.outpath, f"{sessions[flow]:08d}.pcap")
				print(f"{sec:>10d} {usec:>9d} {flow}")
				writer = scapy.all.PcapWriter(
					fn,
					linktype=reader.pcap.linktype,
					endianness=reader.pcap.endian,
					append=True,
					nano=reader.nano
				)
				writer.write_packet(pkt, sec=sec, usec=usec)
				writer.close()
#				scapy.all.wrpcap(fn, pkt, append=True)

			if args.checkpoint and count % args.checkpoint == 0:
				print(count)
	except:
		raise
	finally:
		if reader is not None:
			reader.close()

class Reader:
	def __init__(self, fn, limit=None, ts_convert=lambda s: float(s[8:])):
		self.pcap = scapy.all.PcapReader(fn)
		self.nano = self.pcap.nano
		try:
			self.times = open(fn.rsplit('.', 1)[0] + '.times')
			self.ts_convert = lambda s: (int(s.split('.', 1)[0]), int(s.split('.', 1)[1]))
			self.nano = True
		except:
			self.times = None
			self.ts_convert = lambda t: (int(t), (t - int(t)) * 1000000)
		self.limit = limit
		self.n_read = 0
	def close(self):
		self.pcap.close()
		if self.times:
			self.times.close()
	def __iter__(self):
		return self
	def __next__(self):
		try:
			if self.limit and self.n_read == self.limit:
				raise StopIteration

			pkt = next(self.pcap)
			if self.times:
				ts = self.times.readline().strip()
			else:
				ts = pkt.time
		except:
			self.close()
			raise

		ts = self.ts_convert(ts)
		self.n_read += 1
		return pkt, ts[0], ts[1]

if __name__ == '__main__':
	main()
