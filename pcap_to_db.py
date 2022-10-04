#!/usr/bin/env python3

import os
import struct
import argparse
import sqlite3 as sql
from pcap.pcap_util import PcapReader, Timestamp
from generator.checksum import Checksum, invert, sum_words
from pcap.tcp_util import Flow

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infiles', type=str, nargs='+')
	ap.add_argument('outfile', type=str)
	ap.add_argument('--limit_in', type=int)
	ap.add_argument('--limit_out', type=int)
	ap.add_argument('--seconds', type=float)
	ap.add_argument('--verbose', action='store_true')
	ap.add_argument('--checkpoint', type=int, help='print a message every X packets')
	return ap.parse_args()

def main():
	args = arguments()

	reader = None
	db = None

	try:
		db = sql.connect(args.outfile, isolation_level=None)
		db.execute('PRAGMA journal_mode = OFF;')
		db.execute('PRAGMA synchronous = 0;')
		db.execute('PRAGMA cache_size = 1000000;')
		db.execute('PRAGMA locking_mode = EXCLUSIVE;')
		db.execute('PRAGMA temp_store = MEMORY;')
		db.execute('BEGIN')

		db.execute('CREATE TABLE IF NOT EXISTS pcap(filenum int PRIMARY KEY, fn, endian, nano, version, snaplen, fcs, linktype) WITHOUT ROWID')

		max_filenum = int(db.execute('SELECT IFNULL(MAX(filenum), 0) FROM pcap').fetchone()[0])
		infiles = [(infile, max_filenum + i + 1) for i, infile in enumerate(args.infiles)]

		reader = MultiReader(
			infiles,
			filter=lambda p: 'ip' in p and 'tcp' in p,
			limit_in=args.limit_in,
			limit_out=args.limit_out,
			seconds=args.seconds
		)

		for infile, filenum in infiles:
			db.execute('insert into pcap values(?,?,?,?,?,?,?,?)', (
				filenum,
				os.path.split(infile)[-1],
				reader.header.endian,
				reader.header.nano,
				reader.header.version,
				reader.header.snaplen,
				reader.header.fcs,
				reader.header.linktype
			))

		fields = [
			'sec int', 'nsec int', 'len int',
			'ip_version int', 'ip_hl int', 'ip_tos int', 'ip_len int', 'ip_id int', 'ip_off int',
			'ip_ttl int', 'ip_proto int', 'ip_csum int', 'ip_src text', 'ip_dst text', 'ip_options blob',
			'tcp_sport int', 'tcp_dport int', 'tcp_seq int', 'tcp_ack int', 'tcp_len int', 'tcp_flags int',
			'tcp_win int', 'tcp_csum int', 'tcp_urgent int', 'tcp_options blob',
			'plen int', 'pcrc int', 'flow int', 'filenum int'
		]

		db.execute(f"CREATE TABLE IF NOT EXISTS packets({','.join(fields)})") #, PRIMARY KEY (sec, nsec)) WITHOUT ROWID""")

		def iter_obj(reader, args):
			flow = None
			for pkt, filenum in reader:
				if args.verbose:
					print(filenum, pkt.time.sec, pkt.time.nsec)

				if args.checkpoint and reader.n_out % args.checkpoint == 0:
					print(f"in: {reader.n_read:9d}  out:{reader.n_out:9d}")

				ip = pkt['ip']
				tcp = pkt['tcp']

				if flow is None:
					flow = Flow(pkt)
				else:
					flow.src.ip, flow.dst.ip = ip.src, ip.dst
					flow.src.port, flow.dst.port = tcp.sport, tcp.dport

				yield (
					pkt.time.sec, pkt.time.nsec, pkt.header.orig_len,
					ip.version, ip.ihl, ip.tos, ip.len, ip.id, ip.off, ip.ttl, ip.proto, ip.csum, ip.src, ip.dst, ip.options,
					tcp.sport, tcp.dport, tcp.seq, tcp.ack, tcp.len, tcp.flags, tcp.win, tcp.csum, tcp.urgent, tcp.options,
					ip.len - len(ip) - len(tcp), int(payload_checksum(pkt)), repr(flow), filenum
				)

		db.executemany(f"insert into packets values({','.join(['?' for _ in fields])})", iter_obj(reader, args))
		db.commit()

	except:
		raise
	finally:
		if reader is not None:
			reader.close()
		if db is not None:
			db.close()


class Reader:
	def __init__(self, fn):
		self.pcap = PcapReader(fn)
		self.nano = self.pcap.header.nano
		try:
			self.times = open(fn.rsplit('.', 1)[0] + '.times')
			self.nano = True
			self.pcap.record.time = Timestamp()
		except:
			self.times = None
		self.n_read = 0
	@property
	def record(self):
		return self.pcap.record
	def close(self):
		self.pcap.close()
		if self.times:
			self.times.close()
	def __iter__(self):
		return self
	def __next__(self):
		try:
			next(self.pcap)

			if self.times:
				ts = self.times.readline()
				sec, nsec = ts.strip().split('.', 1)
				self.pcap.record.time.sec = int(sec)
				self.pcap.record.time.nsec = int(nsec)
		except:
			self.close()
			raise

		self.n_read += 1
		return self.record
	def next(self):
		return next(self)


class MultiReader:
	def __init__(self, infiles, filter=lambda p: True, limit_in=None, limit_out=None, seconds=None, stop_smallest=False):
		self.readers = []
		for fn, filenum in infiles:
			reader = Reader(fn)
			reader.filenum = filenum
			self.readers.append(reader)
		self.header = self.readers[0].pcap.header

		self.filter = filter
		self.limit_in = limit_in
		self.limit_out = limit_out
		self.seconds = seconds
		self.stop_smallest = stop_smallest

		self.n_read = 0
		self.n_out = 0
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
			if self.limit_out is not None and self.n_out == self.limit_out:
				raise StopIteration

			while True:
				if self.limit_in is not None and self.n_read >= self.limit_in:
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
					if self.min_index is None or reader.record.time < min_reader.record.time:
						min_reader = reader
						self.min_index = i

				if self.min_index is None:
					raise StopIteration

				self.n_read += 1

				if self.filter(min_reader.record):
					break

			if self.first_ts is None:
				self.first_ts = float(min_reader.record.time)

			if self.seconds is not None and (float(min_reader.record.time) - self.first_ts) >= self.seconds:
				raise StopIteration
		except:
			self.close()
			raise

		self.n_out += 1
		return min_reader.record, min_reader.filenum

def payload_checksum(pkt):
	if 'L7' in pkt:
		return Checksum(bytes(pkt['L7']))

	L3 = pkt['L3']
	L4 = pkt['L4']

	# IPV4 pseudo header: src, dst, proto, tcp segment length
	# TCP pseudo header: TCP header without checksum
	pseudo = L3.bsrc + L3.bdst + struct.pack('!HH', L3.proto, L3.len - len(L3))
	b = bytes(L4)

	if L4.type == 'tcp':
		pseudo += b[0:16] + b[18:]
	elif L4.type == 'udp':
		pseudo += b[0:6]

	return invert(invert(L4.csum) - sum_words(pseudo))
#	return Checksum(L4.csum) - pseudo


if __name__ == '__main__':
	main()
