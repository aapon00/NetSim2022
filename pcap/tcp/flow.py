class Address:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
    def __hash__(self):
        return hash((self.ip, self.port))
    def __lt__(self, rhs):
        return self.ip < rhs.ip or (self.ip == rhs.ip and self.port < rhs.port)
    def __eq__(self, rhs):
        return not (self < rhs or rhs < self)
    def __str__(self):
        return f"{self.ip:>15}:{self.port:<5}"

class Flow:
    def __init__(self, pkt):
        self.src = Address(pkt['IP'].src, pkt['TCP'].sport)
        self.dst = Address(pkt['IP'].dst, pkt['TCP'].dport)
    def __hash__(self):
        return hash(self.ordered)
    def __eq__(self, rhs):
        return self.ordered == rhs.ordered
    def __lt__(self, rhs):
        return (
            self.src[0] < rhs.src[0] or
            (self.src[0] == rhs.src[0] and self.src[1] < rhs.src[1]) or
            (self.src == rhs.src and
                (self.dst[0] < rhs.dst[0] or
                (self.dst[0] == rhs.dst[0] and self.dst[1] < rhs.dst[1])))
        )
    def __str__(self):
        return f"{self.src} ==> {self.dst}"
    @property
    def ordered(self):
        return tuple(sorted([self.src, self.dst]))
        