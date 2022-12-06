#!/usr/bin/env python3

import argparse
from pcap_util import PcapReader

from tcp.flow import Flow

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	ap.add_argument('--limit', type=int)
	ap.add_argument('--proto', choices=['tcp', 'udp', 'all'], default='tcp')
	ap.add_argument('--scapy', action='store_true')
	return ap.parse_args()

def main():
	args = arguments()

	proto = args.proto.upper()
	reader = None
	count = 0

	try:
		if args.scapy:
			from scapy.all import PcapReader
			reader = PcapReader(args.infile)
		else:
			from pcap_util import PcapReader
			reader = PcapReader(args.infile)
			print(reader.header)

		for pkt in reader:
#			if 'IP' not in pkt:
#				continue

#			if proto not in pkt and proto != 'ALL':
#				continue

			count += 1

			if 'ethernet' in pkt:
				print(pkt['ethernet'].src)
#			print(pkt.proto)
#			print(pkt)

			if args.limit and count == args.limit:
				break
	except:
		raise
	finally:
		if reader is not None:
			reader.close()

if __name__ == '__main__':
	main()
