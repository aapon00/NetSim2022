#!/usr/bin/env python3

import argparse
import csv
import struct
import logging as log
from binascii import hexlify

from generator.checksum import Checksum
from pcap.pcap_util import PcapReader, Record

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	ap.add_argument('-o', '--outfile', type=str)
	ap.add_argument('--quiet', action='store_true')
	ap.add_argument('--limit', type=int)
	ap.add_argument('--checkpoint', type=int, help='print a message every X packets')
	ap.add_argument('--proto', choices=['tcp', 'udp', 'icmp', 'all'], default='tcp')
	ap.add_argument('--relative_ts', action='store_true', help='start timestamps at zero')
	ap.add_argument('--debug', action='store_true')
	return ap.parse_args()

def fmt(p):
	ts = f"{p['ts']}:>012.9f" if isinstance(p['ts'], float) else p['ts']
	return f"{ts:>17}  {p['proto']:5}  {str(p['src']):>15}:{str(p['sport']):<5}  {str(p['dst']):>15}:{str(p['dport']):<5}  {p['len']:>4}  {p['plen']:>4}  {p['crc']:>5}  {p.get('pcrc', ''):>5}"

def main():
	args = arguments()

	if args.debug:
		log.basicConfig(level=log.DEBUG)

	first_ts = None
	f = None
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
		'plen',
		'crc',
		'pcrc',
	]

#	packet_list = scapy.all.rdpcap(args.infile, count=args.limit)

	try:
		reader = PcapReader(args.infile)

		if args.outfile:
			f = open(args.outfile, 'w')
			writer = csv.writer(f)
			writer.writerow(fieldnames)

		if not args.quiet:
			print(str(reader.header) + '\n')
			# print a header
			print(fmt({k:k for k in fieldnames}))

		for pkt in reader:
			log.debug(pkt.header) # record header ts/len
			log.debug(f"{hexlify(pkt.data)}")

			if 'IP' not in pkt:
				log.debug("IP not in pkt")
				continue

			if args.proto != 'all' and args.proto not in pkt:
				log.debug("proto not in pkt")
				continue

			count += 1
			if args.limit and count > args.limit:
				break

			if first_ts is None:
				first_ts = int(pkt.time)

			sec, usec = str(pkt.time).split('.', 1)

			row = (
				f"{int(sec) - (first_ts if args.relative_ts else 0)}.{usec}",
				pkt['L4'].type,
				pkt['L3'].src,
				pkt['L4'].sport,
				pkt['L3'].dst,
				pkt['L4'].dport,
				pkt['L3'].len,
				pkt['L3'].len - len(pkt['L3']) - len(pkt['L4']),
				pkt['L4'].csum,
				int(payload_checksum(pkt)),
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

def payload_checksum(pkt: Record):
	if 'L7' in pkt:
		return Checksum(bytes(pkt['L7']))

	L4_bytes = bytes(pkt['L4'])

	# IPV4 pseudo header: src, dst, proto, tcp segment length
	# TCP pseudo header: TCP header without checksum
	pseudo = bytes(pkt['L3'])[12:20] + struct.pack('!HH', pkt['L3'].proto, pkt['L3'].len - len(pkt['L3']))
	b = bytes(pkt['L4'])

	if pkt['L4'].type == 'TCP':
		pseudo += b[0:16] + b[18:]
	elif pkt['L4'].type == 'UDP':
		pseudo += b[0:6]

	return Checksum(pkt['L4'].csum) - pseudo

if __name__ == '__main__':
	main()
