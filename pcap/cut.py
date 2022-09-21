#!/usr/bin/env python3

import argparse
from pcap_util import PcapReader, PcapWriter

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	ap.add_argument('outfile', type=str)
	ap.add_argument('--checkpoint', type=int, help='print a message every X packets')
	ap.add_argument('--limit', type=int)
	ap.add_argument('--seconds', type=float)
	return ap.parse_args()

def main():
	args = arguments()

	reader = None
	writer = None

	try:
		reader = Reader(args.infile, limit=args.limit, seconds=args.seconds)
		writer = PcapWriter(
			args.outfile,
			endian=reader.pcap.header.endian,
			nano=reader.pcap.header.nano,
			version=reader.pcap.header.version,
			snaplen=reader.pcap.header.snaplen,
			fcs=reader.pcap.header.fcs,
			linktype=reader.pcap.header.linktype
		)

		for pkt in reader:
			writer.write_packet(pkt)

			if args.checkpoint is not None and writer.count % args.checkpoint == 0:
				print(writer.count)

	except:
		raise
	finally:
		if reader is not None:
			reader.close()
		if writer is not None:
			writer.close()

class Reader:
	def __init__(self, infile, limit=None, seconds=None):
		self.pcap = PcapReader(infile)
		self.limit = limit
		self.seconds = seconds

		self.n_read = 0
		self.first_ts = None

	def close(self):
		self.pcap.close()

	def __iter__(self):
		return self
	def __next__(self):
		try:
			if self.limit and self.n_read == self.limit:
				raise StopIteration

			pkt = self.pcap.next()

			if self.first_ts is None:
				self.first_ts = float(pkt.time)

			if self.seconds and (float(pkt.time) - self.first_ts) >= self.seconds:
				raise StopIteration
		except:
			self.close()
			raise

		self.n_read += 1
		return pkt


if __name__ == '__main__':
	main()
