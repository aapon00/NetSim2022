#!/usr/bin/env python3

import argparse
from pcap_util import PcapReader

from tcp.flow import Flow

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	ap.add_argument('--limit', type=int)
	ap.add_argument('--proto', choices=['tcp', 'udp', 'all'], default='tcp')
	return ap.parse_args()

def main():
	args = arguments()

	proto = args.proto.upper()
	reader = None
	count = 0

	try:
		reader = PcapReader(args.infile)

		for pkt in reader:
			if 'IP' not in pkt:
				continue

			if proto not in pkt and proto != 'ALL':
				continue

			count += 1
			print(pkt)

			if args.limit and count == args.limit:
				break
	except:
		raise
	finally:
		if reader is not None:
			reader.close()

if __name__ == '__main__':
	main()
