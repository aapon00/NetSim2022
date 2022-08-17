from collections import namedtuple
import random
import numpy
import struct
from checksum import calc_crc

def add_args(ap):
	ap.add_argument('--gap_shape', type=float, default=1.5, help='message gap distribution shape')
#	ap.add_argument('--gap_loc', type=float, default=0, help='message gap distribution location (mean)')
	ap.add_argument('--gap_scale', type=float, default=0.001, help='message gap distribution scale')

	ap.add_argument('--n_duplicates', type=int, default=1, help='number of duplicate streams')

	ap.add_argument('--length', type=float, default=10, help='number of seconds')

class Node:
    def __init__(self):
        self.ip = random.randrange(0, 2**32)
        self.port = random.randrange(0, 2**16)
    def __str__(self):
    	return f"{self.ip}:{self.port}"

class Stream:
	def __init__(self, src, dst):
		self.src = src
		self.dst = dst
		self.data_rng = random.Random()
		self.time_rng = numpy.random.default_rng()
		self.data_add = struct.pack('!IIHH', src.ip, dst.ip, src.port, dst.port)
	def generate(self, args):
		ts = 0
		print(self.data_rng.randint(1,100))
		while ts < args.length:
			# ts
			gap = self.time_rng.weibull(args.gap_shape)
			gap *= args.gap_scale
			ts += gap

			# payload length
			plen = self.data_rng.randrange(40, 1500)

			# crc
			data_sum = self.data_rng.randrange(0, 2**16)
			crc = calc_crc(self.data_add, start=data_sum)

			yield Event(ts, self.src.ip, self.src.port, self.dst.ip, self.dst.port, plen, crc)

def modify_streams(streams, args):
	if args.n_duplicates < 2:
		return
	for stream in random.sample(streams, k=args.n_duplicates):
		stream.data_rng.seed = 0

Event = namedtuple('Event', [
	'ts',
	'src',
	'sport',
	'dst',
	'dport',
	'len',
	'crc',
])
Event.fmt = lambda p: f"{p['ts']:>8}  {str(p['src']):>15}:{str(p['sport']):<5}  {str(p['dst']):>15}:{str(p['dport']):<5}  {p['len']:>4}  {p['crc']:>5}"
Event.sort_key = 'ts'
