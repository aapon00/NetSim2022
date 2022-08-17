#!/usr/bin/env python3

from operator import attrgetter
import random
import csv
from packet_sim import Node, Stream, Event, add_args, modify_streams

def arguments():
	import argparse
	ap = argparse.ArgumentParser()

	ap.add_argument('--nodes_min', type=int, default=2)
	ap.add_argument('--nodes_max', type=int, default=2)
	ap.add_argument('--partners_min', type=int, default=1)
	ap.add_argument('--partners_max', type=int, default=1)

	ap.add_argument('-o', '--outfile', type=str)
	ap.add_argument('--quiet', action='store_true')

	add_args(ap)
	return ap.parse_args()


def main():
	args = arguments()

	n_nodes = random.randint(args.nodes_min, args.nodes_max)
	nodes = {Node() for _ in range(n_nodes)}
	streams = []

	for src in nodes:
		n_dsts = random.randint(args.partners_min, args.partners_max)
		dsts = [n for n in nodes if n != src] # make a list excluding host
		for dst in random.sample(dsts, k=n_dsts):
			streams.append(Stream(src, dst))

	modify_streams(streams, args)
	events = []

	# init receive partners and RNGs for each host
	for stream in streams:
		for event in stream.generate(args):
			events.append(event)

	try:
		if args.outfile:
			f = open(args.outfile, 'w')
			writer = csv.writer(f)
			writer.writerow(Event._fields)

		if not args.quiet:
			# print a header
			print(Event.fmt({k:k for k in Event._fields}))

		for event in sorted(events, key=attrgetter(Event.sort_key)):
			row = tuple(event)

			if args.outfile:
				writer.writerow(row)

			if not args.quiet:
				print(Event.fmt({Event._fields[i]:row[i] for i in range(len(row))}))
	except:
		raise
	finally:
		if args.outfile:
			f.close()

if __name__ == '__main__':
	main()
