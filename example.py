random.seed(SEED)
numpy.random.seed(NUMPY_SEED)
CRC_SEED = 0

def make_src():
	pass
def make_dst(src):
	# return one dst:port pair
	pass
def generate_messages(src, seed):
	N_DST = 5
	messages = []

	for _ in range(N_DST):
		timestamp = 0

		dst = make_dst()

		# generate messages using crc_rng for CRC code
		crc_rng = random.Generator(seed)

		gaps = numpy.random.weibull(1, 10000)
		for gap in gaps:
			timestamp += gap
			message = make_message(src, dst, timestamp, crc_rng.randint())
			messages.append(message)

	# use default rng for timestamps (numpy.random.weibull)
	return messages

def generate_for_one_source(seed):
	src = make_src()
	dst = make_dst(src)
	messages = generate_messages(src, dst, seed)
	return messages




all_messages = []

random_sources = 8
same_sources = 2

for i in range(same_sources):
	all_messages += generate_for_one_source(CRC_SEED)

for i in range(random_sources):
	all_messages += generate_for_one_source(random.randint())

all_messages.sort(key=lambda m: m[0])    # 0 = index of TIMESTAMP in message
