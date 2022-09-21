#!/usr/bin/env python3

import os
import argparse
import scapy.all

from tcp.tcp_state import Flow, is_syn_pkt

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	ap.add_argument('outfile', type=str)
	ap.add_argument('--seconds', type=float)
	ap.add_argument('--checkpoint', type=int, help='print a message every X packets')
	return ap.parse_args()

def main():
	args = arguments()

	first_ts = None
	reader = None
	writer = None

	try:
		reader = scapy.all.PcapReader(args.infile)
		writer = scapy.all.PcapWriter(args.outfile, linktype=reader.linktype, endianness=reader.endian)

		for pkt in reader:
			if first_ts is None:
				first_ts = pkt.time
			elif pkt.time - first_ts > args.seconds:
				break

			writer.write_packet(pkt, sec=int(pkt.time), usec=round((pkt.time % 1) * 1000000))

	except:
		raise
	finally:
		if reader is not None:
			reader.close()
		if writer is not None:
			writer.close()

if __name__ == '__main__':
	main()
