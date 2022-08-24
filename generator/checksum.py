import array
import struct

if struct.pack("H", 1) == b"\x00\x01":  # big endian
    checksum_endian_transform = lambda chk: chk
else:
    checksum_endian_transform = lambda chk: ((chk >> 8) & 0xff) | chk << 8

def checksum_prepare(data):
    if len(data) % 2 == 1:
        data += b"\0"

    return sum(array.array("H", data))

def checksum_transform(c):
    c = (c >> 16) + (c & 0xffff)
    c += c >> 16
    c = ~c
    return checksum_endian_transform(c) & 0xffff

def checksum(data):
    c = checksum_prepare(data)
    return checksum_transform(c)

def remove_from_checksum(c, data):
    # undo the inversions for endian and one's complement
    c = checksum_endian_transform(c)
    c = ~c & 0xffff

    # subtract the crc of the data, apply a correction for the number of wraps past 0
    #for word in array.array("H", pseudo):
    #    c -= word
    #    if c < 0:
    #        c += 2**16 - 2
    c -= checksum_prepare(data)

    # re-apply the one's complement
    return checksum_transform(c)
