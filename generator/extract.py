#!/usr/bin/env python3

import argparse
import scapy.all
import csv
import struct
import array

from checksum import checksum, remove_from_checksum

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	ap.add_argument('-o', '--outfile', type=str)
	ap.add_argument('--quiet', action='store_true')
	ap.add_argument('--limit', type=int)
	ap.add_argument('--checkpoint', type=int, help='print a message every X packets')
	ap.add_argument('--proto', choices=['tcp', 'udp'], default='tcp')
	return ap.parse_args()

def fmt(p):
	return f"{p['ts']:>8}  {p['proto']:5}  {str(p['src']):>15}:{str(p['sport']):<5}  {str(p['dst']):>15}:{str(p['dport']):<5}  {p['len']:>4}  {p['crc']:>5}  {p.get('pcrc', ''):>5}"

def main():
	args = arguments()

	first_ts = None
	f = None
	proto = args.proto.upper()
	reader = None
	count = 0

	fieldnames = [
		'ts',
		'proto',
		'src',
		'sport',
		'dst',
		'dport',
		'len',
		'crc',
		'pcrc',
	]

#	packet_list = scapy.all.rdpcap(args.infile, count=args.limit)

	try:
		reader = scapy.all.PcapReader(args.infile)

		if args.outfile:
			f = open(args.outfile, 'w')
			writer = csv.writer(f)
			writer.writerow(fieldnames)

		if not args.quiet:
			# print a header
			print(fmt({k:k for k in fieldnames}))

		for pkt in reader:
			if 'IP' not in pkt:
				continue

			if proto not in pkt:
				continue

			count += 1
			if args.limit and count > args.limit:
				break

			if first_ts is None:
				first_ts = pkt.time

			row = (
				pkt.time - first_ts,
				proto,
				pkt.src,
				pkt.sport,
				pkt.dst,
				pkt.dport,
				pkt['IP'].len,
				pkt[proto].chksum,
				payload_checksum(pkt, proto),
			)

			if args.outfile:
				writer.writerow(row)

			if args.checkpoint and count % args.checkpoint == 0:
				print(count)
			if not args.quiet:
				print(fmt({fieldnames[i]:row[i] for i in range(len(row))}))
	except:
		raise
	finally:
		if reader is not None:
			reader.close()

		if args.outfile:
			f.close()

def payload_checksum(pkt: scapy.all.Packet, proto: str):
	ib = bytes(pkt['IP'])
	pb = bytes(pkt[proto])
	ilen = pkt['IP'].len
	plen = ilen - pkt.ihl * 4

	if len(ib) == ilen:
		payload = pb[20 if proto == 'TCP' else 8:]
		return checksum(payload)

	# IPV4 pseudo header: src, dst, proto, tcp segment length
	# TCP pseudo header: TCP header without checksum
	pseudo = ib[12:20] + struct.pack('!HH', pkt['IP'].proto, plen)
	
	if proto == 'TCP':
		pseudo += pb[0:16] + pb[18:20]
	elif proto == 'UDP':
		pseudo += pb[0:6]

	return remove_from_checksum(pkt[proto].chksum, pseudo)

if __name__ == '__main__':
	main()
