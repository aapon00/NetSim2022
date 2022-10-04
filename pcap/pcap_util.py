import binascii
import struct
import socket
import functools
import os

RECORD_HEADER_LEN = 16
CHUNK_SIZE = 65535

class LayerException(Exception):
	pass
class UnknownL3Exception(LayerException):
	pass
class UnknownL4Exception(LayerException):
	pass

class PcapHeader:
	def __init__(self, data: bytes, **kwargs):
		if data:
			magic = data[:4]
			self.endian = '>' if magic[0] == 0xA1 else '<'
			self.nano = magic[0 if self.endian == '<' else 3] == 0x4D

			version_major, version_minor, _, _, self.snaplen, network = \
				struct.unpack(self.endian + 'HHIIII', data[4:24])

			self.version = float(f"{version_major}.{version_minor}")
			self.fcs = (network >> 29) if (network & 0x1fffffff) else 0 # first 3 bits if 4th bit is set
			self.linktype = network & 0xfffffff # last 28 bits

#			print(binascii.hexlify(data[:24]))
#			print(binascii.hexlify(bytes(self)))
		else:
			self.endian = kwargs.get('endian', '>')
			self.nano = kwargs.get('nano', False)
			self.version = kwargs.get('version', 2.4)
			self.snaplen = kwargs.get('snaplen', 65536)
			self.fcs = kwargs.get('fcs', 0)
			self.linktype = kwargs.get('linktype', 101)

	@property
	def magic(self):
		magic = bytes.fromhex('a1b2' + ('3c4d' if self.nano else 'c3d4'))
		return magic[::-1] if self.endian == '<' else magic
	@property
	def sigfigs(self):
		return 9 if self.nano else 6

	def __len__(self):
		return 24

	def __str__(self):
		return f"""magic:    {binascii.hexlify(self.magic)}  {self.endian}
version:  {self.version}
sigfigs:  {self.sigfigs}
snaplen:  {self.snaplen}
fcs:      {self.fcs}
linktype: {self.linktype}"""

	def __bytes__(self):
		b = bytearray(self.magic)
		b += struct.pack(self.endian + 'HHIIII',
			*[int(v) for v in str(self.version).split('.', 1)],
			0,
			0,
			self.snaplen,
			self.fcs << 29 | (1 if self.fcs else 0) << 28 | self.linktype
		)
		return bytes(b)

class Pcap:
	def __init__(self, fn: str):
		self.fn = fn
		self.f = None
		self.count = 0
	def close(self):
		if self.f:
			self.f.close()
		self.f = None
	def __enter__(self):
		if not self.f:
			self.open()
		return self
	def __exit__(self, type, value, traceback):
		self.close()

class PcapWriter(Pcap):
	def __init__(self, fn: str, append=False, sync=False, **kwargs):
		super().__init__(fn)
		self.append = append
		self.sync = sync
		self.header = PcapHeader(None, **kwargs)
	@property
	def header(self) -> PcapHeader:
		return self._header
	@header.setter
	def header(self, header: PcapHeader):
		self._header = header

	def open(self):
		if self.append and os.path.exists(self.fn):
			self.len = os.path.getsize(self.fn) 
		else:
			self.len = 0
		self.f = open(self.fn, f"{'a' if self.append else 'w'}b")
	def write(self, b):
		if self.f is None:
			self.open()
		self.f.write(b)
		self.len += len(b)
		if self.sync:
			self.flush()
	def flush(self):
		if self.f:
			self.f.flush()
	def close(self):
		self.flush()
		super().close()
	def write_header(self, _dummy=None):
		b = bytes(self.header)
		self.write(b)
	def write_packet(self, pkt, **kwargs):
		if self.len == 0:
			self.write_header()

		b = bytes(pkt)

		if 'sec' in kwargs or 'usec' in kwargs:
			b = struct.pack(
				pkt.endian + 'II',
				kwargs.get('sec', pkt.header.ts_sec),
				kwargs.get('usec', pkt.header.ts_usec)
			) + b[8:]

		self.write(b)
		self.count += 1

class PcapReader(Pcap):
	def __init__(self, fn: str):
		super().__init__(fn)
		self.record: Record = Record(self)
		self.open()
		self.pos = 0
	@property
	def header(self) -> PcapHeader:
		return self._header
	@header.setter
	def header(self, header: PcapHeader):
		self._header = header

	def open(self):
		self.f = open(self.fn, 'rb')
		self.buffer = self.f.read(24 + RECORD_HEADER_LEN)
		self.header = PcapHeader(self.buffer[:24])

	def next(self):
		return next(self)

	def __iter__(self):
		return self
	def __next__(self):
		self.buffer = self.buffer[len(self.record) if self.count > 0 else 24:]

		if len(self.buffer) < RECORD_HEADER_LEN:
			raise StopIteration

		self.record.header.update()
		self.buffer += self.f.read(self.record.header.incl_len + RECORD_HEADER_LEN)

		if len(self.buffer) < len(self.record):
			raise StopIteration

#		print(binascii.hexlify(self.record[RECORD_HEADER_LEN:len(self.record)]))
		try:
			self.record.update()
		except Exception as e:
			print(len(self.buffer), self.record.header.incl_len, bytes(self.record))
			print(self.record._pointers)
			print(self.record.layers[1].valid, self.record.layers[2].valid)
			raise e

		self.count += 1
		return self.record

class BufferedPcapReader(PcapReader):
	def __init__(self, fn: str):
		super().__init__(fn)
		self.record = Record(self)
		self.pos = None

		self.open()

	def open(self):
		self.f = open(self.fn, 'rb')
		self.buffer = self.f.read(CHUNK_SIZE)
		self.header = PcapHeader(self.buffer)
		self.next_pos = len(self.header)

	def next(self):
		return next(self)

	def __iter__(self):
		return self
	def __next__(self):
		self.pos = self.next_pos

		if len(self.buffer) - self.pos < RECORD_HEADER_LEN:
			raise StopIteration

		self.record.header.update()

		# try to get enough bytes for the whole record plus the next header
		while len(self.buffer) - self.pos < len(self.record) + RECORD_HEADER_LEN:
			bytes_read = self.f.read(CHUNK_SIZE)

			if len(bytes_read) == 0:
				break
			
			self.buffer += bytes_read

			if self.pos > 0:
				self.buffer = self.buffer[self.pos:]
				self.pos = 0

		# could be incomplete record at the tail
		if len(self.buffer) - self.pos < len(self.record):
			raise StopIteration

#		print(binascii.hexlify(self.record[RECORD_HEADER_LEN:len(self.record)]))

		self.record.update()

		self.next_pos = self.pos + len(self.record)
		self.count += 1
		return self.record

class Record:
	def __init__(self, pcap: PcapReader, L2=False, L3=True, L4=True):
		self.pcap = pcap
		self._pointers = {}
		self.header = RecordHeaderView(self)
		self.time = TimestampView(self)
		self.valid = False
		self.layers = [
			L2HeaderView(self) if L2 else None,
			L3HeaderView(self) if L3 else None,
			L4HeaderView(self) if L4 else None
		]
	def update(self):
		self._pointers.clear()
		offset = len(self.header)

		for index in range(len(self.layers)):
			layer = self.layers[index]
			L = index + 2

			if offset >= len(self):
				break

			if layer is not None:
				layer.update(offset)

				if not layer.valid:
					break

				self[f'L{L}'] = layer
				self[layer.type] = layer

				if len(layer) == 0:
					break

				offset += len(layer)

	@property
	def data(self):
		return self.pcap.buffer
	@property
	def offset(self):
		return self.pcap.pos
	@property
	def endian(self):
		return self.pcap.header.endian

	def __len__(self):
		return len(self.header) + self.header.incl_len
	def __getitem__(self, key):
		if isinstance(key, str):
			return self._pointers[key.lower()]
		elif isinstance(key, slice):
			start, stop, step = key.indices(len(self))
			return self.data[start + self.offset : stop + self.offset : step]
		elif isinstance(key, int):
			return self.data[key + self.offset]
		else:
			raise TypeError('Invalid argument type: {}'.format(type(key)))
	def __setitem__(self, key, data):
		if isinstance(key, str):
			self._pointers[key.lower()] = data
		else:
			raise TypeError('Invalid argument type: {}'.format(type(key)))
	def __contains__(self, key):
		if isinstance(key, str):
			return key.lower() in self._pointers
		else:
			raise TypeError('Invalid argument type: {}'.format(type(key)))
	def __str__(self):
		return f"{str(self.time)} {self.header.incl_len} {self.header.orig_len}  {self['ip'].src}:{self['tcp'].sport} ==> {self['ip'].dst}:{self['tcp'].dport}"
	def __bytes__(self):
		return self[:]

class MutableRecord(Record):
	def update(self):
		self._data = self.pcap.buffer[self.pcap.pos:self.pcap.pos + len(self)]
	@property
	def data(self):
		return self._data
	@property
	def offset(self):
		return 0

@functools.total_ordering
class Timestamp:
	def __init__(self, sec=0, usec=0, nsec=None):
		self.sec = int(sec)
		self._sigfigs = 9 if nsec is not None else 6
		self.nsec = nsec if nsec is not None else usec * 1000
	@property
	def usec(self) -> int:
		return int(self.nsec / 1000)
	@property
	def sigfigs(self) -> int:
		return self._sigfigs
	@property
	def frac(self) -> float:
		return self.usec / 10**self.sigfigs
	def __str__(self):
		return f"{self.sec}.{str(self.nsec if self.sigfigs == 9 else self.usec).zfill(self.sigfigs)}"
	def __int__(self):
		return self.sec
	def __float__(self):
		return self.sec + self.frac
	def __lt__(self, rhs):
		return self.sec < rhs.sec or (self.sec == rhs.sec and self.nsec < rhs.nsec)
	def __eq__(self, rhs):
		return self.sec == rhs.sec and self.nsec == rhs.nsec

class TimestampView(Timestamp):
	def __init__(self, record: Record):
		self.record = record
	@property
	def sec(self) -> int:
		return self.record.header.ts_sec
	@property
	def usec(self) -> int:
		return int(self.record.header.ts_usec / 10**(abs(6-self.sigfigs)))
	@property
	def nsec(self) -> int:
		return self.record.header.ts_usec * 10**(9-self.sigfigs)
	@property
	def sigfigs(self) -> int:
		return self.record.pcap.header.sigfigs


class RecordHeaderView:
	def __init__(self, record: Record):
		self.record = record
		self.incl_len = len(self) # prevent circularity
	def update(self):
		self.ts_sec, self.ts_usec, self.incl_len, self.orig_len = struct.unpack(
			self.record.endian + 'IIII',
			self.record[:RECORD_HEADER_LEN]
		)
	def __len__(self):
		return RECORD_HEADER_LEN

class PacketHeaderView:
	def __init__(self, record: Record):
		self.record = record
	def update(self, offset: int):
		self.valid = True

		try:
			self._update(offset)
		except LayerException as e:
			self.valid = False

	def _update(self, offset: int):
		pass

class L2HeaderView(PacketHeaderView):
	def __init__(self, record: Record):
		super().__init__(record)
		self.record = record
		self.type = None
	def __len__(self):
		return 0
	def __bytes__(self):
		return b''

class L3HeaderView(PacketHeaderView):
	def __init__(self, record: Record):
		super().__init__(record)
	def _update(self, offset: int):
		self.offset = offset
		b = self.record[offset]
		self.version = (b >> 4) & 0x0f

		if self.version == 4:
			self.type = 'ip'
			self.ihl = b & 0x0f
			b = bytes(self)

			self.tos, self.len, self.id, self.off, self.ttl, self.proto, self.csum = \
				struct.unpack('!BHHHBBH', b[1:12])
			self.bsrc = b[12:16]
			self.bdst = b[16:20]
			self.options = b[20:len(self)]
		# elif self.version == 6:
		# 	self.type = 'ip6'
		# 	self.ihl = 10
		# 	b = bytes(self)

		# 	self.traffic_class = ((b[0] & 0x0f) << 4) | ((b[1] >> 4) & 0x0f)
		# 	self.flow_label = ((b[1] & 0x0f) << 16) | (b[2] << 8) | b[3]
		# 	self.payload_len, self.next_header, self.hop_limit = struct.unpack('!HBB', b[4:8])
		# 	self.bsrc = b[8:24]
		# 	self.bdst = b[24:40]
		else:
			self.type = None
			raise LayerException(f"Unknown L3 version {self.version}")
	@property
	def src(self):
		return socket.inet_ntoa(self.bsrc) if self.valid else ''
	@property
	def dst(self):
		return socket.inet_ntoa(self.bdst) if self.valid else ''
	def __len__(self):
		return self.ihl * 4 if self.valid else 0
	def __bytes__(self):
		return self.record[self.offset:self.offset+ self.ihl*4]

class L4HeaderView(PacketHeaderView):
	def __init__(self, record: Record):
		super().__init__(record)
	def _update(self, offset: int):
		self.offset = offset
		proto = self.record['L3'].proto

		if proto == 6:
			self.type = 'tcp'
			self.sport, self.dport, self.seq, self.ack, self.data_off, self.flags, self.win, self.csum, self.urgent = \
				struct.unpack('!HHIIBBHHH', self.record[offset:offset+20])
			self.flags |= ((self.data_off & 0x01) << 8)
			self.len = ((self.data_off >> 4) & 0x0f) * 4
			self.options = self.record[offset+20:offset+len(self)]
		elif proto == 17:
			self.type = 'udp'
			self.sport, self.dport, self.total_len, self.csum = \
				struct.unpack('!HHHH', self.record[offset:offset+8])
			self.len = 8
		elif proto == 1:
			self.type = 'icmp'
			self.mtype, self.code, self.csum, self.data = \
				struct.unpack('!BBHI', self.record[offset:offset+8])
			self.len = 8
		else:
			self.type = None
			raise LayerException(f"Unknown L3 protocol {proto}")
	def __len__(self):
		return self.len if self.valid else 0
	def __bytes__(self):
		return self.record[self.offset:self.offset+self.len]
