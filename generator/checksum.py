import array

def calc_crc(data, offset=0, start=0):
    if offset % 2 == 1:
        data = b"\0" + data
    if len(data) % 2 == 1:
        data += b"\0"

    s = start
    s += sum(array.array("H", data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return s & 0xffff

def sub_crc(crc, data, offset=0):
    if offset % 2 == 1:
        data = b"\0" + data
    if len(data) % 2 == 1:
        data += b"\0"

    # undo the inversion
    s = ~crc
    s &= 0xffff

    # subtract the crc of the data, apply a correction for the number of wraps past 0
    sub = sum(array.array("H", data))
    correction = int(abs(s - sub) / (2**16))
    s -= sub
    s -= correction

    # redo the inversion
    s = ~s
    return s & 0xffff
