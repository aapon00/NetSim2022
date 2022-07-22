#!/usr/bin/env python3

import argparse
import scapy.all
import csv

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	ap.add_argument('-o', '--outfile', type=str)
	ap.add_argument('--quiet', action='store_true')
	ap.add_argument('--limit', type=int, default=-1)
	return ap.parse_args()

def fmt(p):
	return f"{p['ts']:>8}  {str(p['src']):>15}:{str(p['sport']):<5}  {str(p['dst']):>15}:{str(p['dport']):<5}  {p['len']:>4}  {p['crc']:>5}"

def main():
	args = arguments()

	packet_list = scapy.all.rdpcap(args.infile, count=args.limit)
	first_ts = None
	rows = []
	f = None

	fieldnames = [
		'ts',
		'src',
		'sport',
		'dst',
		'dport',
		'len',
		'crc',
	]

	try:
		if args.outfile:
			f = open(args.outfile, 'w')
			writer = csv.writer(f)
			writer.writerow(fieldnames)

		if not args.quiet:
			# print a header
			print(fmt({k:k for k in fieldnames}))

		for pkt in packet_list:
			if 'IP' not in pkt or 'TCP' not in pkt:
				continue

			if first_ts is None:
				first_ts = pkt.time

			row = (
				pkt.time - first_ts,
				pkt.src,
				pkt.sport,
				pkt.dst,
				pkt.dport,
				pkt['IP'].len,
				pkt['TCP'].chksum,
			)

			if args.outfile:
				writer.writerow(row)

			if not args.quiet:
				print(fmt({fieldnames[i]:row[i] for i in range(len(row))}))
	except:
		raise
	finally:
		if args.outfile:
			f.close()




if __name__ == '__main__':
	main()
