
is_syn_pkt = lambda pkt: 'TCP' in pkt and pkt['TCP'].flags == TCP_FLAGS['S']
is_synack_pkt = lambda pkt: 'TCP' in pkt and pkt['TCP'].flags == (TCP_FLAGS['S'] | TCP_FLAGS['A'])

TCP_FLAGS = {"F":0x1, "S":0x2, "R":0x4, "P":0x8,
			  "A":0x10, "U":0x20, "E":0x40, "C":0x80,
			  0x1:"F", 0x2:"S", 0x4:"R", 0x8:"P",
			  0x10:"A", 0x20:"U", 0x40:"E", 0x80:"C"}

class Address:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
    def __hash__(self):
        return hash((self.ip, self.port))
    def __lt__(self, rhs):
        return self.ip < rhs.ip or (self.ip == rhs.ip and self.port < rhs.port)
    def __eq__(self, rhs):
        return self.ip == rhs.ip and self.port == rhs.port
    def __str__(self):
        return f"{self.ip:>15}:{self.port:<5}"

class Flow:
    def __init__(self, pkt):
        self.src = Address(pkt['IP'].src, pkt['TCP'].sport)
        self.dst = Address(pkt['IP'].dst, pkt['TCP'].dport)
    def __hash__(self):
        return hash(self.ordered)
    def __lt__(self, rhs):
        return self.src < rhs.src or (self.src == rhs.src and self.dst < rhs.dst)
    def __eq__(self, rhs):
        return self.ordered == rhs.ordered
    def __str__(self):
        return f"{self.src} ==> {self.dst}"
    @property
    def ordered(self):
        return (self.src, self.dst) if self.src < self.dst else (self.dst, self.src)
    @property
    def forward(self):
        return self
    @property
    def reverse(self):
        return self.__class__(self.dst, self.src)

class TCPSession:
    def __init__(self, pkt=None):

        if not 'TCP' in pkt:
            raise Exception("Not a TCP Packet")
        if not is_syn_pkt(pkt):
            raise Exception("Not valid SYN")

        self.flow = Flow(pkt) # client => server
        self.packets = []

        # 0 is now, 1 is the future Flags
        self.server_state = "LISTEN"
        self.client_state = "CLOSED"

        if pkt is None:
            return

        self.handle_packet(pkt)
#       self.server_close_time = -1.0
#       self.client_close_time = -1.0
#       self.fin_wait_time = -1.0

    @property
    def client(self):
        return self.flow.src
    @property
    def server(self):
        return self.flow.dst

    def add(self, pkt):
        if not 'TCP' in pkt:
            raise Exception("Not a TCP Packet")

        # determine in what context we are handling this packet
#        flow = Flow(pkt)
#        if flow.forward != self.flow and flow.reverse != self.flow:
#            raise Exception("Not a valid packet for this model")

        self.handle_packet(pkt)
#		if flow.dst == self.server:
#			v =  self.add_client_pkt(pkt)
#			if self.is_fin_wait():
#				self.fin_wait_time = pkt.time
#			return v
#		else:
#			v = self.add_server_pkt(pkt)
#			if self.is_fin_wait():
#				self.fin_wait_time = pkt.time
#			return v
#		raise Exception("Not a valid packet for this model")

    def handle_packet(self, pkt):
        flags = ''.join(f for f,x in FLAGS.items() if x & pkt['TCP'].flags)

        print(Flow(pkt), flags, len(pkt.payload))
#        flags = pkt['TCP'].flags

        flags = ''.join(f for f in FLAGS_ORDER if f in flags)

        self.client_state = CLIENT_STATES[self.client_state].get(flags) or self.client_state
        self.server_state = SERVER_STATES[self.server_state].get(flags) or self.server_state
        print(self.client_state, self.server_state)
        
        self.packets.append(pkt)

CLIENT_STATES = {
    'CLOSED': {
        'S': 'SYN_SENT',
    },
    'SYN_SENT': {
        'A': 'ESTABLISHED',
        # deal with timeout to go back to CLOSED
    },
    'ESTABLISHED': {
        'F': 'FIN_WAIT_1', # (FIN comes from client)
    },
    'FIN_WAIT_1' : {
        'A': 'FIN_WAIT_2', # passive close, client sends nothing
        'F': 'CLOSING', # simultaneous close, client sends ACK
        'FA': 'TIME_WAIT', # FIN and ACK in one packet, same as simultaneous close, client sends ACK
    },
    'CLOSING': {
        'A': 'TIME_WAIT', # client sends nothing
    },
    'FIN_WAIT_2': {
        'F': 'TIME_WAIT', # could wait for timeout, but all transitions to this state lead to CLOSED
    },
}

SERVER_STATES = {
    'LISTEN': {
        'SA' : 'SYN_RCVD', # SYNACK
    },
    'SYN_RCVD': {
        '': 'ESTABLISHED', # ACK
        'R': 'LISTEN', # RESET
        'F': 'FIN_WAIT_1' # active close
    },
    'ESTABLISHED': {
        'F': 'CLOSE_WAIT', # server sends ACK
    },
    'CLOSE_WAIT': {
        'F': 'LAST_ACK', # (FIN comes from server) server sends FIN
    },
    'LAST_ACK': {
        'A': 'CLOSED',
    }
}

CLOSING_STATES = {
    'ESTABLISHED': {
        'F': 'CLOSE_WAIT', # server sends ACK
    },
    'CLOSE_WAIT': {
        'F': 'LAST_ACK', # (FIN comes from server) server sends FIN
    },
    'LAST_ACK': {
        'A': 'CLOSED',
    }

}
