#!/usr/bin/env python3

import random
import numpy

def arguments():
	import argparse
	ap = argparse.ArgumentParser()

	ap.add_argument('--N_min', type=int, default=2)
	ap.add_argument('--N_max', type=int, default=2)
	ap.add_argument('--P_min', type=int, default=1)
	ap.add_argument('--P_max', type=int, default=1)

	ap.add_argument('--mean', type=float, default=10, help='mean milliseconds between packets')
	ap.add_argument('--length', type=float, default=10, help='number of seconds')
	return ap.parse_args()

class Host:
    def __init__(self):
        self.crc_rng = random.Random()
        self.ip = random.randint(0, 100)
        self.port = random.randint(0, 100)
    def new_message(self, ts):
        dst = random.choice(self.partners)
        crc = self.crc_rng.randrange(0, 4294967296)
        return Message(ts, self, dst, crc)
    def __str__(self):
    	return f"{self.ip}:{self.port}"

class Message:
    def __init__(self, ts, src, dst, crc):
        self.ts, self.src, self.dst, self.crc = ts, src, dst, crc
    def csv(self):
        return ','.join([str(self.ts), str(self.src), str(self.dst), str(self.crc)])

def main():
	args = arguments()
	N = random.randint(args.N_min, args.N_max)

	hosts = [Host() for _ in range(N)]

	for host in hosts:
		n_partners = random.randint(args.P_min, args.P_max)
		partners = [p for p in hosts if p is not host] # make a list excluding host
		host.partners = random.sample(partners, k=n_partners)

	messages = []

	# init receive partners and RNGs for each host

	for host in hosts:
	    timestamp_ms = 0
	    gaps = numpy.random.poisson(args.mean, int(args.length*1000/args.mean))
	    for gap in gaps:
	        timestamp_ms += gap
	        messages.append(host.new_message(timestamp_ms/1000))

	for message in sorted(messages, key=lambda m: m.ts):
	    print(message.csv())

if __name__ == '__main__':
	main()
