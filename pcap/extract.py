#!/usr/bin/env python3

import dpkt
from dpkt.utils import mac_to_str, inet_to_str
import struct

def arguments():
	import argparse
	ap = argparse.ArgumentParser()
	ap.add_argument('infile', type=str)
	return ap.parse_args()


def main():
	args = arguments()

	payloads = []

	with open(args.infile, 'rb') as f:
		pcap = dpkt.pcap.Reader(f)
		ip = dpkt.ip.IP()
		print(dir(pcap))
		print(pcap.snaplen)

		for ts, buf in pcap:
			try:
				eth = dpkt.ethernet.Ethernet(buf)
			except dpkt.dpkt.NeedData as e:
				continue

#			print('Ethernet Frame: ', mac_to_str(eth.src), mac_to_str(eth.dst), eth.type, len(eth.data))
#			continue

#			fields = struct.unpack("!BBH", eth.data[:4])
#			print(f"version: {fields[0] >> 4}")
#			print(f"IHL:     {fields[0] & 15}")

#			print(fields)
#			print(eth.data.hex())
#			ip.unpack(eth.data)

#			print(eth.data.__class__.__name__)

			if not isinstance(eth.data, dpkt.ip.IP):
				continue

			ip = eth.data
			print(dir(ip))

			if not isinstance(ip.data, dpkt.tcp.TCP):
				print('not TCP packet')

			tcp = ip.data
			print(dir(tcp))
			print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' %
              (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, ip.df, ip.mf, ip.offset))
			print(f"TCP: ")

def main2():
	args = arguments()

	import scapy.utils
#	pcap = scapy.rdpcap(args.infile)
#	with open(args.infile, 'rb') as f:
#		pcap = dpkt.pcap.Reader(f)

	pcap = scapy.utils.rdpcap(args.infile)
	sessions = pcap.sessions()
	print(sessions)

	for session in sessions:
		dir(session)
#		for packet in sessions[session]:
#			print(packet)

if __name__ == '__main__':
	main2()
