#!/usr/bin/env python3

import pcap_util
import sys

infile = sys.argv[1]

if (len(sys.argv) >= 3):
	end=int(sys.argv[2])
else:
	end=None

count = 0


with pcap_util.PcapReader(infile) as reader:
    with pcap_util.PcapWriter(
        'test.pcap',
        endian=reader.header.endian,
        nano=reader.header.nano,
        version=reader.header.version,
        snaplen=reader.header.snaplen,
        fcs=reader.header.fcs,
        linktype=reader.header.linktype
    ) as writer:
        print(reader.header)

        for pkt in reader:
            count += 1

            if end is not None and count > end:
                break

            print(bytes(pkt))

#            writer.write(pkt)


