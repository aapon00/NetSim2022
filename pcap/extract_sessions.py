#!/usr/bin/env python3

import os
import argparse
from pcap_util import PcapReader, PcapWriter
from tcp_util import Flow, is_syn_pkt

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	ap.add_argument('-o', '--outpath', type=str, default='.')
	ap.add_argument('--quiet', action='store_true')
	ap.add_argument('--limit', type=int)
	ap.add_argument('--checkpoint', type=int, help='print a message every X packets')
	return ap.parse_args()

def main():
	args = arguments()

	reader = None
	writer = None
	count = 0

	sessions = {}
	session_iter = 0

	try:
		reader = PcapReader(args.infile)
		writer = PcapWriter(
			None,
			endian=reader.header.endian,
			nano=reader.header.nano,
			version=reader.header.version,
			snaplen=reader.header.snaplen,
			fcs=reader.header.fcs,
			linktype=reader.header.linktype,
			append=True,
		)

		for pkt in reader:
			count += 1
			if args.limit and count > args.limit:
				break

			flow = Flow(pkt)

			if is_syn_pkt(pkt): # and flow not in sessions:
				sessions[flow] = session_iter
				session_iter += 1

			if flow in sessions:
				if not args.quiet:
					print(sessions[flow], pkt)
				addr = flow.ordered
				writer.fn = os.path.join(args.outpath, f"{addr[0].ip}:{addr[0].port}_{addr[1].ip}:{addr[1].port}.pcap")
				writer.open()
				writer.write_packet(pkt)
				writer.close()

			if args.checkpoint and count % args.checkpoint == 0:
				print(count)
	except:
		raise
	finally:
		if reader is not None:
			reader.close()
		if writer is not None:
			writer.close()

if __name__ == '__main__':
	main()
