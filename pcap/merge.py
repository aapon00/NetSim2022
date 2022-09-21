#!/usr/bin/env python3

import argparse
from pcap_util import PcapReader, PcapWriter, Record

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infiles', nargs='+', type=str)
	ap.add_argument('outfile', type=str)
	ap.add_argument('--checkpoint', type=int, help='print a message every X packets')
	ap.add_argument('--limit', type=int)
	ap.add_argument('--seconds', type=float)
	ap.add_argument('--smallest', action='store_true')
	ap.add_argument('--scapy', action='store_true')
	return ap.parse_args()

def main():
	args = arguments()
	reader = None
	writer = None

	try:
		reader = DualReader(
			args.infiles,
			limit=args.limit,
			seconds=args.seconds,
			stop_smallest=args.smallest,
			scapy=args.scapy
		)

		writer = PcapWriter(
			args.outfile,
			endian=reader.header.endian,
			nano=reader.header.nano,
			version=reader.header.version,
			snaplen=reader.header.snaplen,
			fcs=reader.header.fcs,
			linktype=reader.header.linktype
		)

		for pkt in reader:
			writer.write_packet(pkt)

			if args.checkpoint and reader.n_read % args.checkpoint == 0:
				print(reader.n_read)

	except:
		raise
	finally:
		if reader is not None:
			reader.close()
		if writer is not None:
			writer.close()

class DualReader:
	def __init__(self, infiles, limit=None, seconds=None, stop_smallest=False, scapy=False):
		self.readers = [PcapReader(fn) for fn in infiles]
		self.header = self.readers[0].header

		self.limit = limit
		self.seconds = seconds
		self.stop_smallest = stop_smallest

		self.n_read = 0
		self.first_ts = None
		self.min_index = None

		try:
			for reader in self.readers:
				reader.next()
		except StopIteration:
			raise Exception(f"File {reader.fn} is empty, aborting.")

	def close(self):
		for reader in self.readers:
			if reader is not None:
				reader.close()

	def __iter__(self):
		return self
	def __next__(self):
		try:
			if self.limit is not None and self.n_read >= self.limit:
				raise StopIteration

			if self.min_index is not None:
				try:
					self.readers[self.min_index].next()
				except StopIteration:
					if self.stop_smallest:
						raise

					self.readers[self.min_index].close()
					self.readers[self.min_index] = None
					self.readers = [r for r in self.readers if r is not None]

				self.min_index = None

			for i, reader in enumerate(self.readers):
				if self.min_index is None or reader.record.time < self.readers[self.min_index].record.time:
					self.min_index = i

			if self.min_index is None:
				raise StopIteration

			record: Record = self.readers[self.min_index].record

			if self.first_ts is None:
				self.first_ts = float(record.time)

			if self.seconds is not None and (float(record.time) - self.first_ts) >= self.seconds:
				raise StopIteration
		except:
			self.close()
			raise

		self.n_read += 1
		return record


if __name__ == '__main__':
	main()
