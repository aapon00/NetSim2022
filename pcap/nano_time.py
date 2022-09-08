#!/usr/bin/env python3

import os
import argparse
import scapy.all

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	ap.add_argument('--limit', type=int)
	ap.add_argument('--checkpoint', type=int, help='print a message every X packets')
	ap.add_argument('--proto', choices=['tcp', 'udp', 'all'], default='tcp')
	return ap.parse_args()

def main():
	args = arguments()

	proto = args.proto.upper()
	reader = None
	writer = None
	count = 0

	try:
		reader = Reader(args.infile, limit=args.limit)

		outfile = f"{args.infile.rsplit('.', 1)[0]}.{args.proto}{'.nano' if reader.nano else ''}.pcap"
		writer = scapy.all.PcapWriter(
			outfile,
			linktype=reader.pcap.linktype,
			endianness=reader.pcap.endian,
			append=False,
			nano=reader.nano,
			snaplen=reader.pcap.snaplen
		)
		writer.write_header(None)

		for pkt, sec, usec in reader:
			if 'IP' in pkt and (proto in pkt or proto == 'ALL'):
				writer.write_packet(pkt, sec=sec, usec=usec)
				count += 1

			if args.checkpoint and reader.n_read % args.checkpoint == 0:
				print(f"in: {reader.n_read}  out: {count}")
				writer.flush()

	except:
		raise
	finally:
		if reader is not None:
			reader.close()
		if writer is not None:
			writer.flush()
			writer.close()

class Reader:
	def __init__(self, fn, limit=None):
		self.pcap = scapy.all.PcapReader(fn)
		self.nano = self.pcap.nano
		try:
			self.times = open(fn.rsplit('.', 1)[0] + '.times')
			self.nano = True
		except:
			self.times = None
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
				sec, usec = ts.split('.', 1)
				sec, usec = int(sec), int(usec)
			else:
				ts = pkt.time
				sec = int(ts)
				usec = int((ts - sec) * 1000000)
		except:
			self.close()
			raise

		self.n_read += 1
		return pkt, sec, usec

if __name__ == '__main__':
	main()
