#!/usr/bin/env python3

import argparse
from pcap_util import PcapReader, PcapWriter

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	ap.add_argument('--limit_in', type=int)
	ap.add_argument('--limit_out', type=int)
	ap.add_argument('--checkpoint', type=int, help='print a message every X packets')
	ap.add_argument('--proto', choices=['tcp', 'udp', 'icmp', 'all'], default='tcp')
	return ap.parse_args()

def main():
	args = arguments()

	reader = None
	writer = None

	try:
		reader = Reader(
			args.infile,
			filter=lambda p: 'IP' in p and (args.proto == 'all' or args.proto in p),
			limit_in=args.limit_in,
			limit_out=args.limit_out
		)

		outfile = f"{args.infile.rsplit('.', 1)[0]}.{args.proto}{'.nano' if reader.nano else ''}.pcap"
		writer = PcapWriter(
			outfile,
			endian=reader.pcap.header.endian,
			nano=reader.nano,
			version=reader.pcap.header.version,
			snaplen=reader.pcap.header.snaplen,
			fcs=reader.pcap.header.fcs,
			linktype=reader.pcap.header.linktype
		)
		writer.write_header(None)

		for pkt, sec, usec in reader:
			writer.write_packet(pkt, sec=sec, usec=usec)

			if args.checkpoint and reader.n_read % args.checkpoint == 0:
				print(f"in: {reader.n_read}  out: {reader.n_out}")
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
	def __init__(self, fn, filter=lambda p: True, limit_in=None, limit_out=None):
		self.pcap = PcapReader(fn)
		self.nano = self.pcap.header.nano
		try:
			self.times = open(fn.rsplit('.', 1)[0] + '.times')
			self.nano = True
		except:
			self.times = None
		self.filter = filter
		self.limit_in = limit_in
		self.limit_out = limit_out
		self.n_read = 0
		self.n_out = 0
	def close(self):
		self.pcap.close()
		if self.times:
			self.times.close()
	def __iter__(self):
		return self
	def __next__(self):
		try:
			if self.limit_out is not None and self.n_out == self.limit_out:
				raise StopIteration

			while True:
				if self.limit_in is not None and self.n_read == self.limit_in:
					raise StopIteration

				pkt = next(self.pcap)
				self.n_read += 1

				if self.times:
					ts = self.times.readline()

				if self.filter(pkt):
					break

			if self.times:
				sec, usec = ts.strip().split('.', 1)
				sec, usec = int(sec), int(usec)
			else:
				sec = pkt.time.sec
				usec = pkt.time.nsec if self.nano else pkt.header.ts_usec
		except:
			self.close()
			raise

		self.n_out += 1
		return pkt, sec, usec

if __name__ == '__main__':
	main()
