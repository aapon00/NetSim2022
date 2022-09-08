#!/usr/bin/env python3

import os
import argparse
import scapy.all

from tcp.tcp_state import Flow

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	ap.add_argument('--limit', type=int)
	ap.add_argument('--proto', choices=['tcp', 'udp', 'all'], default='tcp')
	return ap.parse_args()

def main():
	args = arguments()

	proto = args.proto.upper()
	reader = None
	count = 0

	try:
		reader = scapy.all.PcapReader(args.infile)

		for pkt in reader:
			if 'IP' not in pkt:
				continue

			if proto not in pkt and proto != 'ALL':
				continue

			flow = Flow(pkt)

			count += 1
			print(f"{pkt.time}  {int(pkt.time):10d}.{int(round((pkt.time - int(pkt.time)) * 1000000000 if reader.nano else 1000000)):09d}  {flow}")

			if args.limit and count == args.limit:
				break
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
