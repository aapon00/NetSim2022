import pcap_util
import heapq
import time

HEADER_LEN = 16
INCL_OFFSET = 8
ORIG_OFFSET = 12

class Stats:
	def __init__(self):
		self.file_reads = 0
		self.bytes_tested = 0
		self.solutions_tested = 0
		self.nonmerges = 0

class Solution:
	def __init__(self, last_i, next_i):
		self.last_index = last_i
		self.next_index = next_i
		self.length = 0
	def __repr__(self):
		return "(%d,%d,%d)" % (self.last_index, self.next_index, self.length)
	def __eq__(self, c):
		if self.next_index == c.next_index: return True
		return False
	def __gt__(self, c):
		if self.next_index > c.next_index: return True
		return False
	def __lt__(self, c):
		if self.next_index < c.next_index: return True
		return False
	def __ge__(self, c):
		return self > c or self == c
	def __le__(self, c):
		return self < c or self == c

def validate_header(byte_array, index, snap_len, swap):
	incl_len = pcap_util.btoint(byte_array[index+8 : index+12], swap)
	orig_len = pcap_util.btoint(byte_array[index+12 : index+16], swap)

	if incl_len > 0 and incl_len == min(orig_len, snap_len):
		return incl_len

	return 0

def find_start(file, snap_len, swap, stats):
	# grab chunks in size of complete max length packet and header
	packet_len = snap_len + HEADER_LEN

#	print 'using chunk size', packet_len

	# candidate list of tuples (next_header_index, start_index) to make it simpler to use
	# bisect for insertion, because python compares tuples by first element first.
	# candidates are all possible header start bytes, avoiding partial header at the end
	# we keep this list in reverse order so all removals are from the back, and we insert
	# (in order) rarely
	#
	# in theory, the ideal data structure here would be one optimized for insert and
	# peek/removal of minimum.  a BST can do both in O(lg n), maybe a hybrid BST over
	# linked list for O(lg n) insertion and O(1) popmin?
	solutions = []
	heapq.heapify(solutions)

	# worst case: missing first byte of header at start, with a max length
	# packet.  need to get the complete next header.
	chunk = file.read(packet_len + HEADER_LEN - 1)
	file_offset = 0
	stats.file_reads += 1

#	print 'initial sample is %d bytes' % (len(chunk))

	# differentiate between candidates and solutions: candidates are untested, solutions
	# have passed initial test.  needed for coalescing: a tree solution is when two solutions
	# point to the same index, not candidates.  also, all candidates exist in the first read

#	start = time.clock()

	for index in range(packet_len):
#		header = pcap_util.PacketHeader(chunk, index, swap)
		incl_len = validate_header(chunk, index, snap_len, swap)
		if incl_len != 0:
			s = Solution(index, index + incl_len + HEADER_LEN)
			heapq.heappush(solutions, s)

#	print 'initial parse:', time.clock() - start
#	print 'initial solutions:', solutions

	if len(solutions) == 0:
		raise ValueError("No solution")

	# test solutions
	while len(chunk) >= HEADER_LEN:
#		start = time.clock()

		max_index = file_offset + len(chunk) - HEADER_LEN
#		print 'max index:', max_index

		while solutions[0].next_index <= max_index:
#			print solutions
			s = heapq.heappop(solutions)

			stats.bytes_tested = s.next_index + HEADER_LEN
			stats.solutions_tested += 1

#			print 'testing solution', s

			# here we check for a tree solution, which is multiple candidates pointing
			# to the same index.  it's impossible to tell which is correct, so we'll
			# coalesce and mark the solution as a tree for later removal.  if this results
			# in an empty solution set, it will be caught when the loop exits as a single
			# tree solution
			while len(solutions) > 0 and solutions[0].next_index == s.next_index:
#				print 'converging with solution', solutions[0]
				s.last_index = s.next_index
				a = heapq.heappop(solutions)
				s.length = max(s.length, a.length) + 1

			header_index = s.next_index - file_offset
			incl_len = validate_header(chunk, header_index, snap_len, swap)
#			header = pcap_util.PacketHeader(chunk, header_index, swap)

#			if header.valid(snap_len):
			if incl_len != 0:
				if len(solutions) == 0:
#					print 'iteration:', time.clock() - start
					return s.last_index

				if s.next_index != s.last_index:
					stats.nonmerges += 1

				s.next_index += incl_len + HEADER_LEN
#				print 'validated, new solution is', s
				heapq.heappush(solutions, s)
#			else:
#				print 'throwing away solution', s

#			print 'next solution to test will be', solutions[0]

#		print 'iteration:', time.clock() - start

		file_offset += packet_len
		chunk = chunk[packet_len:] + file.read(packet_len)
#		print '*** reading file, %d candidates left' % (len(solutions))
		stats.file_reads += 1

	# parallel solutions
	raise ValueError("Parallel solutions")

