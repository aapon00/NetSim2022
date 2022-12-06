#!/usr/bin/env python3

import os
import struct
import argparse
from collections import namedtuple
import csv
import sqlite3 as sql
from base64 import b64encode

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	ap.add_argument('-o', '--outpath', type=str, default='.')
	ap.add_argument('--quiet', action='store_true')
	ap.add_argument('--limit', type=int)
	ap.add_argument('--checkpoint', type=int, help='print a message every X packets')
	return ap.parse_args()

def fmt(p):
	ts = f"{p['ts']}:>012.9f" if isinstance(p['ts'], float) else p['ts']
	return f"{ts:>12}  {str(p['src']):>15}:{str(p['sport']):<5}  {str(p['dst']):>15}:{str(p['dport']):<5}  {p['len']:>4}  {p['plen']:>4}  {p['crc']:>5}  {p.get('pcrc', ''):>5}  {p.get('flags'):>2}  {p.get('seq')}"

db_fields = "sec, nsec, ip_src, tcp_sport, ip_dst, tcp_dport, ip_len, plen, tcp_csum, pcrc, tcp_flags, tcp_seq, flow"
Packet = namedtuple('Packet', 'sec nsec src sport dst dport len plen crc pcrc flags seq flow')
def packet_factory(cursor, row):
	return Packet(*row)

def main():
	args = arguments()

	db = None
	writer = None
	count = 0
	debug = False

	fieldnames = [
		'ts',
		'src',
		'sport',
		'dst',
		'dport',
		'len',
		'plen',
		'crc',
		'pcrc',
		'flags',
		'seq',
	]

#	packet_list = scapy.all.rdpcap(args.infile, count=args.limit)

	try:
		db = sql.connect(args.infile)
		db.row_factory = packet_factory
		session = (None, None)

# need index on flow, sec, nsec, tcp_flags, (other fields) to fulfill query from index
# flow, sec, nsec are first to preserve ordering
# IN is faster than INNER JOIN on distinct
# select all out_fields in inner and outer query to avoid searching table
# order after 'flow' comes naturally from index, but also if inserted into table in order
		query = f"""
select
  {db_fields}
from (
  select
    {db_fields},
    count(*) over (partition by flow) as c
  from packets
  where flow in (
    select distinct flow from packets where tcp_flags = 2
  )
)
where c > 3
order by flow
{('limit ' + str(args.limit)) if args.limit is not None else ''}
"""
# without join, "where flow in (select distinct flow from packets where tcp_flags = 2)"
		if not args.quiet:
			# print a header
			print(fmt({k:k for k in fieldnames}))

		for count, pkt in enumerate(db.execute(query)):
			if pkt.flow != session[0] or (pkt.flags == 2 and pkt.seq != session[1]):
#				debug = False
				if pkt.flags != 2:
#					debug = True
					continue # remainder of partial session before new SYN

				session = (pkt.flow, pkt.seq)

				if debug or not args.quiet:
					print(f"{pkt.src}:{pkt.sport} => {pkt.dst}:{pkt.dport}  {pkt.flow}  {hex(pkt.seq)[2:]}")

				if writer:
					f.close()

				seq = str(b64encode(struct.pack('!I', pkt.seq)))[2:-1]
				fn = f"{pkt.flow}_{seq}.csv".replace('+', '-').replace('/', '_').replace('=', '')
				outfile = os.path.join(args.outpath, fn)

				f = open(outfile, 'w')
				writer = csv.writer(f)
				writer.writerow(fieldnames)

			row = (
				f"{pkt.sec % 100}.{str(pkt.nsec).zfill(9)}",
				pkt.src,
				pkt.sport,
				pkt.dst,
				pkt.dport,
				pkt.len,
				pkt.plen,
				pkt.crc,
				pkt.pcrc,
				pkt.flags,
				pkt.seq,
			)

			if writer:
				writer.writerow(row)

			if args.checkpoint and count % args.checkpoint == 0:
				print(count)
			if debug or not args.quiet:
				print(fmt({fieldnames[i]:row[i] for i in range(len(row))}))
	except:
		raise
	finally:
		if db is not None:
			db.close()

		if writer is not None:
			f.close()

if __name__ == '__main__':
	main()
