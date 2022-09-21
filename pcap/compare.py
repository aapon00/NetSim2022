#!/usr/bin/env python3

import pcap_util
import sys
import binascii

infile1 = sys.argv[1]
infile2 = sys.argv[2]

if (len(sys.argv) >= 4):
	end=int(sys.argv[3])
else:
	end=None

count = 0


with pcap_util.PcapReader(infile1) as reader1:
    print('-------------')
    with pcap_util.PcapReader(infile2) as reader2:
        print('-------------')
        while True:
            count += 1
            if end is not None and count > end:
                break

            try:
                pkt1 = reader1.next()
                pkt2 = reader2.next()
            except StopIteration:
                break

            if bytes(pkt1) != bytes(pkt2):
                print(pkt1)
                print(binascii.hexlify(bytes(pkt1)))
                print(pkt2)
                print(binascii.hexlify(bytes(pkt2)))
                print('-------------')
