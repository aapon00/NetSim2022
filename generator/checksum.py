import array
import struct

###
# Methods and convenience class for calculating TCP and UDP checksums
#

# Convenience class for storing, adding, subtracting checksums
class Checksum:
    def __init__(self, data=None):
        if data is None:
            data = invert(0)
        elif isinstance(data, Checksum):
            self.csum = data.csum
        elif isinstance(data, int):
            self.csum = data
        elif isinstance(data, bytes):
            self.csum = invert(sum_words(data))
        else:
            raise "Checksum initialization needs to be integer checksum or byte array."

    @property
    def inverse(self):
        return invert(self.csum)

    def __int__(self):
        return self.csum
    def __str__(self):
        return str(int(self))

    def __eq__(self, rhs):
        return self.csum == Checksum(rhs).csum

    def __add__(self, rhs):
        return Checksum(invert(self.inverse + Checksum(rhs).inverse))
    def __sub__(self, rhs):
        return Checksum(invert(self.inverse - Checksum(rhs).inverse))

    # radd and rsub are used in both "x + Checksum" and "sum" which adds like "0 + Checksum + Checksum..."
    # assume that 0 is nothing and >0 is a checksum, so that csum + Checksum works
    def __radd__(self, lhs):
        return self if lhs == 0 else (Checksum(lhs) + self)
    def __rsub__(self, lhs):
        return self if lhs == 0 else (Checksum(lhs) - self)


# "The checksum field is the 16 bit one's complement of the one's complement sum of all
#  16-bit words in the header and text.  If a segment contains an odd number of header
#  and text octets to be checksummed, the last octet is padded on the right with zeros
#  to form a 16-bit word for checksum purposes." - RFC 793
def checksum(data):
    return invert(sum_words(data))

# Compute the one's complement of the one's complement sum and then fix for network-endian.
# Double purposed to prepare a checksum for adding/subtracting, since the addition of carry
# bits does nothing to a computed checksum and merely applies NOT and swapping bytes.
def invert(c):
    # apply carried bits, these do nothing if the number is in 0-65535 (i.e. c is a checksum)
    c = (c >> 16) + (c & 0xffff)
    c += c >> 16

    # NOT bits and swap bytes (if necessary), order of these two lines doesn't matter
    c = ~c
    c = checksum_endian_transform(c)

    # cut left bits, also converts negatives like -1 to 65534
    return c & 0xffff

# Compute sum of 2-byte words in a 16-bit (plus carry bits) number.  Right-pad if necessary.
def sum_words(data):
    if len(data) % 2 == 1:
        data += b"\0"

    return sum(array.array("H", data))

# Swap bytes in 2-byte word if little-endian:  0xABCD -> 0xCDAB
if struct.pack("H", 1) == b"\x00\x01":  # big endian
    checksum_endian_transform = lambda chk: chk
else:
    checksum_endian_transform = lambda chk: ((chk >> 8) & 0xff) | ((chk & 0xff) << 8)
