#!/usr/bin/env python3

import struct
import argparse
import sqlite3 as sql
from pcap.pcap_util import PcapReader
from generator.checksum import Checksum, invert, sum_words
from pcap.tcp_util import Flow

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	ap.add_argument('-o', '--outfile', type=str)
	ap.add_argument('--limit_in', type=int)
	ap.add_argument('--limit_out', type=int)
	ap.add_argument('--quiet', action='store_true')
	ap.add_argument('--checkpoint', type=int, help='print a message every X packets')
	ap.add_argument('--tag', type=int)
	return ap.parse_args()

def main():
	args = arguments()

	reader = None
	db = None
	args.outfile = args.outfile or (args.infile.rsplit('.', 1)[0] + '.db')

	try:
		reader = Reader(
			args.infile,
			filter=lambda p: 'ip' in p and 'tcp' in p,
			limit_in=args.limit_in,
			limit_out=args.limit_out
		)

		db = sql.connect(args.outfile, isolation_level=None)
		db.execute('PRAGMA journal_mode = OFF;')
		db.execute('PRAGMA synchronous = 0;')
		db.execute('PRAGMA cache_size = 1000000;')
		db.execute('PRAGMA locking_mode = EXCLUSIVE;')
		db.execute('PRAGMA temp_store = MEMORY;')
		db.execute('BEGIN')

		db.execute('create table if not exists pcap(fn primary key, endian, nano, version, snaplen, fcs, linktype, tag)')
		db.execute('insert into pcap values(?,?,?,?,?,?,?,?)', (
			args.infile,
			reader.pcap.header.endian,
			reader.pcap.header.nano,
			reader.pcap.header.version,
			reader.pcap.header.snaplen,
			reader.pcap.header.fcs,
			reader.pcap.header.linktype,
			args.tag
		))

		fields = [
			'sec', 'nsec', 'len',
			'ip_version', 'ip_hl', 'ip_tos', 'ip_len', 'ip_id', 'ip_off', 'ip_ttl', 'ip_proto', 'ip_csum', 'ip_src', 'ip_dst', 'ip_options',
			'tcp_sport', 'tcp_dport', 'tcp_seq', 'tcp_ack', 'tcp_len', 'tcp_flags', 'tcp_win', 'tcp_csum', 'tcp_urgent', 'tcp_options',
			'plen', 'pcrc', 'flow', 'tag'
		]

		db.execute(f"create table if not exists packets({','.join(fields)})")

		def iter_obj(reader, args):
			flow = None
			for pkt, sec, nsec in reader:
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
					sec, nsec, pkt.header.orig_len,
					ip.version, ip.ihl, ip.tos, ip.len, ip.id, ip.off, ip.ttl, ip.proto, ip.csum, ip.src, ip.dst, ip.options,
					tcp.sport, tcp.dport, tcp.seq, tcp.ack, tcp.len, tcp.flags, tcp.win, tcp.csum, tcp.urgent, tcp.options,
					ip.len - len(ip) - len(tcp), int(payload_checksum(pkt)), hash(flow), args.tag
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
				sec, nsec = ts.strip().split('.', 1)
				sec, nsec = int(sec), int(nsec)
			else:
				sec = pkt.time.sec
				nsec = pkt.time.nsec if self.nano else pkt.header.ts_usec * 1000
		except:
			self.close()
			raise

		self.n_out += 1
		return pkt, sec, nsec

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
